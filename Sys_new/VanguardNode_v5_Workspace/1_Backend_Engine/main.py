import os
import json
import asyncio
import io
import uvicorn
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, ConfigDict

from event_store import (
    init_db, record_scan, get_scan_by_id, get_replay_sequence,
    record_training_attempt, record_patch_event, get_finding_by_id,
    get_all_scans
)
from checkov_parser import run_checkov_scan
from risk_engine import calculate_risk
from patch_service import apply_patch, execute_rollback
from report_generator import generate_pdf_report

app = FastAPI(title="Vanguard Backend Engine")
event_queue: asyncio.Queue = asyncio.Queue()

init_db()


class FindingModel(BaseModel):
    findingId: str = Field(..., alias="finding_id")
    filePath: str = Field(..., alias="file_path")
    lineNumber: int = Field(..., alias="line_number")
    ruleId: str = Field(..., alias="rule_id")
    ruleTitle: Optional[str] = Field("", alias="rule_title")
    severity: Optional[str] = Field("MEDIUM", alias="severity")
    status: str = Field("VULNERABLE", alias="status")
    codeSnippet: Optional[str] = Field("", alias="code_snippet")
    remediationHint: Optional[str] = Field("", alias="remediation_hint")
    rFile: float = Field(0.0, alias="r_file")

    model_config = ConfigDict(populate_by_name=True)


class PatchRequest(BaseModel):
    findingId: str = Field(..., alias="finding_id")
    scanId: Optional[str] = Field(None, alias="scan_id")
    targetDir: Optional[str] = Field(None, alias="target_dir")
    filePath: Optional[str] = Field(None, alias="file_path")

    model_config = ConfigDict(populate_by_name=True)


class BatchPatchRequest(BaseModel):
    targetDir: Optional[str] = Field(None, alias="target_dir")
    patches: List[PatchRequest]

    model_config = ConfigDict(populate_by_name=True)

class RollbackRequest(BaseModel):
    targetDir: Optional[str] = Field(None, alias="target_dir")
    patchId: Optional[str] = None
    filePath: Optional[str] = Field(None, alias="file_path")
    target_file: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)


class TrainingScoreRequest(BaseModel):
    scenarioId: str
    score: float
    completionTimeSec: float


class ScanRequest(BaseModel):
    target_directory: Optional[str] = Field(None, alias="target_dir")
    target_dir: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)

    def resolved_target_dir(self) -> str:
        path = self.target_directory or self.target_dir or ""
        return "" if path.strip().lower() in ("", "string") else path.strip()


@app.post("/api/scan")
async def execute_scan(req: Optional[ScanRequest] = None, target_dir: Optional[str] = None):
    query_dir = target_dir.strip() if (target_dir and target_dir.strip().lower() != "string") else ""
    body_dir = req.resolved_target_dir() if req else ""
    
    effective_dir = query_dir or body_dir
    
    if not effective_dir:
        raise HTTPException(status_code=400, detail="Target directory must be provided in request body or query param")

    if not os.path.exists(effective_dir):
        raise HTTPException(status_code=404, detail=f"Target directory '{effective_dir}' not found")

    raw_scan = run_checkov_scan(effective_dir)
    risk_data = calculate_risk(raw_scan.get("Findings", []))

    scan_id = raw_scan.get("ScanId", f"scan_{os.urandom(4).hex()}")

    flat_findings = []
    for file_entry in risk_data.get("files", []):
        for finding in file_entry.get("findings", []):
            f_id = finding.get("FindingId") or finding.get("finding_id")
            f_path = finding.get("FilePath") or finding.get("file_path")
            r_id = finding.get("RuleId") or finding.get("rule_id")
            r_title = finding.get("RuleTitle") or finding.get("rule_title", "")
            sev = (finding.get("Severity") or finding.get("severity") or "MEDIUM").upper()
            line_num = finding.get("LineNumber") or finding.get("line_number", 0)
            snippet = finding.get("CodeSnippet") or finding.get("code_snippet", "")
            hint = finding.get("RemediationHint") or finding.get("remediation_hint", "")

            flat_findings.append({
                "findingId": f_id,
                "finding_id": f_id,
                "filePath": f_path,
                "file_path": f_path,
                "ruleId": r_id,
                "rule_id": r_id,
                "ruleTitle": r_title,
                "rule_title": r_title,
                "severity": sev,
                "lineNumber": line_num,
                "line_number": line_num,
                "status": finding.get("Status") or finding.get("status", "VULNERABLE"),
                "codeSnippet": snippet,
                "code_snippet": snippet,
                "remediationHint": hint,
                "remediation_hint": hint,
                "computed_score": finding.get("computed_score", 0),
                "exposure": finding.get("exposure", "internal_only"),
                "r_file": finding.get("r_file", 0.0)
            })

    record_scan(
        scan_id=scan_id,
        target_dir=effective_dir,
        mode="api",
        source="api",
        total_findings=len(flat_findings),
        findings=flat_findings,
        r_global=risk_data.get("R_global", 0.0),
        files_data=risk_data.get("files", [])
    )

    payload = {
        "scanId": scan_id,
        "totalFindings": len(flat_findings),
        "findings": flat_findings
    }
    
    await event_queue.put({"event": "NEW_SCAN", "data": payload})
    return payload


@app.get("/api/history")
async def get_history():
    return get_all_scans()


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    findings = [FindingModel(**f).dict(by_alias=True) for f in scan_data.get("findings", [])]
    return {
        "scanId": scan_data["scan_id"],
        "globalRisk": scan_data.get("r_global", 0.0),
        "findings": findings
    }


@app.get("/api/replay/{scan_id}")
async def replay_sequence(scan_id: str):
    events = get_replay_sequence(scan_id)
    return [
        {
            "eventId": e.get("event_id"),
            "findingId": e.get("finding_id"),
            "filePath": e.get("file_path"),
            "timestamp": e.get("timestamp")
        }
        for e in events
    ]


@app.get("/api/report/{scan_id}")
async def stream_report(scan_id: str):
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    pdf_bytes = generate_pdf_report(scan_data)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=audit_{scan_id}.pdf"}
    )


@app.post("/api/patch")
async def apply_single_patch(req: PatchRequest):
    finding = get_finding_by_id(req.findingId)
    
    if not finding and not req.filePath:
        raise HTTPException(status_code=404, detail=f"Finding '{req.findingId}' not found in database and no file path provided.")

    rule_id = finding.get("rule_id", "") if finding else ""
    line_num = finding.get("line_number", 0) if finding else 0

    # Auto-resolve target file path if missing
    file_path = req.filePath or (finding.get("file_path") if finding else None)
    if not file_path:
        raise HTTPException(status_code=400, detail="Target file path could not be resolved from request or database.")

    # Auto-resolve target directory via scan record if missing
    target_dir = req.targetDir
    if not target_dir:
        scan_id = req.scanId or (finding.get("scan_id") if finding else None)
        if scan_id:
            scan_data = get_scan_by_id(scan_id)
            if scan_data:
                target_dir = scan_data.get("target_path")
    if not target_dir:
        target_dir = "."

    success, msg = apply_patch(
        target_dir=target_dir,
        file_path_rel=file_path,
        rule_id=rule_id,
        line_num=line_num
    )

    if not success:
        raise HTTPException(status_code=400, detail=msg)

    backup_path = f"{file_path}.vanguard_backup"
    record_patch_event(req.findingId, backup_path)

    await event_queue.put({"event": "PATCH_APPLIED", "findingId": req.findingId})
    return {"status": "SUCCESS", "message": msg}


@app.post("/api/patch_batch")
async def apply_batch_patch(req: BatchPatchRequest):
    patches_with_line_info = []
    
    for item in req.patches:
        finding = get_finding_by_id(item.findingId)
        line_num = finding.get("line_number", 0) if finding else 0
        rule_id = finding.get("rule_id", "") if finding else ""
        
        file_path = item.filePath or (finding.get("file_path") if finding else None)
        target_dir = item.targetDir or req.targetDir
        if not target_dir and finding:
            scan_id = item.scanId or finding.get("scan_id")
            if scan_id:
                scan_data = get_scan_by_id(scan_id)
                if scan_data:
                    target_dir = scan_data.get("target_path")
        target_dir = target_dir or "."

        if file_path:
            patches_with_line_info.append({
                "line_num": line_num,
                "rule_id": rule_id,
                "file_path": file_path,
                "target_dir": target_dir,
                "item": item
            })

    # Sort descending by line number to protect top line offsets during batch modifications
    patches_with_line_info.sort(key=lambda x: x["line_num"], reverse=True)

    applied = []
    for patch_info in patches_with_line_info:
        item = patch_info["item"]
        f_path = patch_info["file_path"]
        t_dir = patch_info["target_dir"]

        success, _ = apply_patch(
            target_dir=t_dir,
            file_path_rel=f_path,
            rule_id=patch_info["rule_id"],
            line_num=patch_info["line_num"]
        )

        if success:
            record_patch_event(item.findingId, f"{f_path}.vanguard_backup")
            applied.append(item.findingId)

    await event_queue.put({"event": "BATCH_PATCH_COMPLETED", "appliedCount": len(applied)})
    return {"status": "SUCCESS", "appliedFindingIds": applied}


@app.post("/api/rollback")
async def rollback_patch(req: RollbackRequest):
    target_dir = req.targetDir or req.target_dir or "."
    file_path = req.filePath or req.target_file

    if not file_path:
        raise HTTPException(status_code=400, detail="Rollback failed: missing target file path ('filePath' or 'target_file')")

    result = execute_rollback(target_dir, file_path)
    if result.get("status") != "success":
        raise HTTPException(status_code=400, detail=result.get("message", "Rollback failed"))
    return result


@app.post("/api/training/submit")
async def submit_training_score(req: TrainingScoreRequest):
    attempt_id = record_training_attempt(req.scenarioId, int(req.score), req.completionTimeSec)
    return {"status": "SUCCESS", "attemptId": attempt_id}


@app.get("/api/events/stream")
async def stream_events(request: Request):
    async def event_generator():
        while True:
            if await request.is_disconnected():
                break
            try:
                data = await asyncio.wait_for(event_queue.get(), timeout=1.0)
                yield f"data: {json.dumps(data)}\n\n"
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

