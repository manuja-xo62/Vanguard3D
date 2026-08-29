import os
import json
import asyncio
import io
import uvicorn
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, ConfigDict
import subprocess
import git_manager
import event_store
from pathlib import Path
import sys
import shutil

from event_store import (
    init_db, record_scan, get_scan_by_id, get_replay_sequence,
    record_training_attempt, record_patch_event, get_finding_by_id,
    get_all_scans
)
from checkov_parser import run_checkov_scan
from risk_engine import calculate_risk
from patch_service import apply_patch, execute_rollback
from report_generator import generate_pdf_report
from sarif_generator import generate_sarif_report

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
    findingId: Optional[str] = Field("", alias="finding_id")
    scanId: Optional[str] = Field(None, alias="scan_id")
    targetDir: Optional[str] = Field(None, alias="target_dir")
    filePath: Optional[str] = Field(None, alias="file_path")
    ruleId: Optional[str] = Field(None, alias="rule_id")
    lineNumber: Optional[int] = Field(0, alias="line_number")

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

class PipelineRunRequest(BaseModel):
    scan_id: str
    target_dir: str

class GitPRRequest(BaseModel):
    targetDir: str = Field(..., alias="target_dir")
    branchName: Optional[str] = Field("security/vanguard-remediation-patch", alias="branch_name")
    scanId: Optional[str] = Field("scan_manual", alias="scan_id")

    model_config = ConfigDict(populate_by_name=True)


def sanitize_file_path(path: str) -> str:
    if not path:
        return ""
    # Normalize backslashes to forward slashes and strip leading slashes
    return path.replace("\\", "/").lstrip("/")


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
            f_path = sanitize_file_path(finding.get("FilePath") or finding.get("file_path") or "")
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
        "scan_id": scan_id,
        "total_Findings": len(flat_findings),
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

@app.get("/api/report/sarif/{scan_id}")
async def stream_sarif_report(scan_id: str):
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan ID not found")

    sarif_json_str = generate_sarif_report(scan_data)
    return StreamingResponse(
        io.BytesIO(sarif_json_str.encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=sarif_{scan_id}.sarif"}
    )


@app.post("/api/patch")
async def apply_single_patch(req: PatchRequest):
    
    # Try fetching finding from DB if finding_id is provided
    finding = get_finding_by_id(req.findingId) if req.findingId else None
    
    # Resolve parameters from DB record first, fallback to incoming request fields
    rule_id = (finding.get("rule_id") if finding else None) or req.ruleId or ""
    line_num = (finding.get("line_number") if finding else None) or req.lineNumber or 0
    raw_file_path = req.filePath or (finding.get("file_path") if finding else None)
    file_path = sanitize_file_path(raw_file_path or "")

    if not file_path:
        raise HTTPException(status_code=400, detail="Target file path could not be resolved from request or database.")

    # Resolve target directory
    target_dir = req.targetDir
    if not target_dir and finding:
        scan_id = req.scanId or finding.get("scan_id")
        if scan_id:
            scan_data = get_scan_by_id(scan_id)
            if scan_data:
                target_dir = scan_data.get("target_path")

    # Fallback to the most recent scan directory if still unresolved
    if not target_dir:
        all_scans = get_all_scans()
        if all_scans:
            target_dir = all_scans[0].get("target_path", ".")
        else:
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
    if req.findingId:
        record_patch_event(req.findingId, backup_path)

    await event_queue.put({"event": "PATCH_APPLIED", "findingId": req.findingId})
    return {"status": "SUCCESS", "message": msg}


@app.post("/api/patch/batch")
async def apply_batch_patch_endpoint(req: BatchPatchRequest):
    patches_with_line_info = []
    
    for item in req.patches:
        finding = get_finding_by_id(item.findingId) if item.findingId else None
        line_num = (finding.get("line_number", 0) if finding else 0) or item.lineNumber or 0
        rule_id = (finding.get("rule_id", "") if finding else "") or item.ruleId or ""
        
        raw_file_path = item.filePath or (finding.get("file_path") if finding else None)
        file_path = sanitize_file_path(raw_file_path or "")

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

    # Group by file_path, then sort descending by line_num per file
    from collections import defaultdict
    file_groups = defaultdict(list)
    for p in patches_with_line_info:
        file_groups[p["file_path"]].append(p)

    applied = []
    for f_path, group in file_groups.items():
        group.sort(key=lambda x: x["line_num"], reverse=True)
        for patch_info in group:
            item = patch_info["item"]
            t_dir = patch_info["target_dir"]

            success, _ = apply_patch(
                target_dir=t_dir,
                file_path_rel=f_path,
                rule_id=patch_info["rule_id"],
                line_num=patch_info["line_num"]
            )

            if success:
                if item.findingId:
                    record_patch_event(item.findingId, f"{f_path}.vanguard_backup")
                applied.append(item.findingId or f_path)

    await event_queue.put({"event": "BATCH_PATCH_COMPLETED", "appliedCount": len(applied)})
    return {"status": "SUCCESS", "appliedFindingIds": applied}


@app.post("/api/rollback")
async def rollback_patch(req: RollbackRequest):
    target_dir = req.targetDir or "."
    
    # Fallback to finding lookup if filePath is missing
    raw_file_path = req.filePath or req.target_file
    if not raw_file_path and req.patchId:
        finding = get_finding_by_id(req.patchId)
        if finding:
            raw_file_path = finding.get("file_path")
            if not req.targetDir and finding.get("scan_id"):
                scan_data = get_scan_by_id(finding.get("scan_id"))
                if scan_data:
                    target_dir = scan_data.get("target_path", ".")

    file_path = sanitize_file_path(raw_file_path or "")

    if not file_path:
        raise HTTPException(
            status_code=400, 
            detail="Rollback failed: missing target file path ('filePath' or 'target_file')"
        )

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

@app.post("/api/pipeline/verify_delta")
async def verify_delta_scan(req: PipelineRunRequest):
    # Fetch baseline scan record to calculate dynamic deltas
    baseline_scan = get_scan_by_id(req.scan_id)
    pre_risk = baseline_scan.get("r_global", 0.0) if baseline_scan else 0.0
    baseline_findings = baseline_scan.get("findings", []) if baseline_scan else []

    # Run live Checkov scan with PATH and sys.executable fallback
    try:
        checkov_bin = shutil.which("checkov")
        cmd = [checkov_bin, "-d", req.target_dir, "-o", "json"] if checkov_bin else [sys.executable, "-m", "checkov.main", "-d", req.target_dir, "-o", "json"]
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        
        try:
            parsed_output = json.loads(result.stdout)
        except json.JSONDecodeError:
            parsed_output = {}

        # Handle Checkov returning a list (multi-framework) or a dict (single-framework)
        findings = []
        if isinstance(parsed_output, list):
            for framework in parsed_output:
                findings.extend(framework.get("results", {}).get("failed_checks", []))
        else:
            findings = parsed_output.get("results", {}).get("failed_checks", [])

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scanner execution failed: {str(e)}")
        
    # Calculate live risk scores dynamically
    post_risk = sum(10.0 if f.get("severity") == "CRITICAL" else 5.0 for f in findings)
    compliance_score = max(0, 100 - int(post_risk))

    # Calculate dynamic resolved counts by comparing baseline IDs against current scan
    current_finding_ids = {f.get("check_id") for f in findings if f.get("check_id")}
    
    critical_resolved = 0
    high_resolved = 0
    
    for base_f in baseline_findings:
        b_id = base_f.get("finding_id") or base_f.get("rule_id")
        b_sev = str(base_f.get("severity", "")).upper()
        
        if b_id and b_id not in current_finding_ids:
            if b_sev == "CRITICAL":
                critical_resolved += 1
            elif b_sev == "HIGH":
                high_resolved += 1

    # Format findings array safely to prevent KeyErrors
    triage_logs = [{
        "FindingId": f.get("check_id", "UNKNOWN_RULE"), 
        "Severity": (f.get("severity") or "HIGH").upper(), 
        "FilePath": sanitize_file_path(f.get("file_path", ""))
    } for f in findings]
    
    event_store.log_post_scan(req.scan_id, pre_risk, post_risk, triage_logs)
    
    return {
        "status": "SUCCESS",
        "PrePatchRiskScore": pre_risk,
        "PostPatchRiskScore": post_risk,
        "CriticalResolved": critical_resolved,
        "HighResolved": high_resolved,
        "ComplianceScore": compliance_score,
        "TriageLogs": triage_logs
    }

@app.post("/api/pipeline/purge_backups")
async def purge_backups(req: PipelineRunRequest):
    target = Path(req.target_dir)
    if not target.exists():
        raise HTTPException(status_code=404, detail="Target directory not found")
        
    purged_count = 0
    for backup_file in target.rglob("*.vanguard_backup"):
        try:
            backup_file.unlink(missing_ok=True)
            purged_count += 1
        except OSError:
            continue
            
    return {"status": "SUCCESS", "files_purged": purged_count}

@app.post("/api/pipeline/git/create_pr")
@app.post("/api/git/pr")
async def trigger_pr(req: GitPRRequest):
    baseline_scan = get_scan_by_id(req.scanId) if req.scanId else None
    current_risk = baseline_scan.get("r_global", 0.0) if baseline_scan else 0.0
    compliance_score = max(0, 100 - int(current_risk))
    
    result = git_manager.create_remediation_pr(req.targetDir, req.scanId, compliance_score)
    if result.get("status") != "SUCCESS":
        raise HTTPException(status_code=500, detail=result.get("error", "Git PR creation failed"))
    return result