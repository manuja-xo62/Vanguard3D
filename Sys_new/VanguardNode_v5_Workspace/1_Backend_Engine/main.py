import os
import json
import asyncio
import io
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from event_store import (
    init_db, record_scan, get_scan_by_id, get_replay_sequence,
    record_training_attempt, record_patch_event, get_finding_by_id
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
    status: str
    rFile: float = Field(0.0, alias="r_file")

    class Config:
        populate_by_name = True


class PatchRequest(BaseModel):
    scanId: str
    findingId: str
    targetDir: str
    filePath: str


class BatchPatchRequest(BaseModel):
    targetDir: str
    patches: List[PatchRequest]


class RollbackRequest(BaseModel):
    targetDir: str
    patchId: Optional[str] = None
    filePath: str


class TrainingScoreRequest(BaseModel):
    scenarioId: str
    score: float
    completionTimeSec: float


@app.post("/api/scan")
async def execute_scan(target_dir: str):
    if not os.path.exists(target_dir):
        raise HTTPException(status_code=404, detail=f"Target directory '{target_dir}' not found")

    raw_scan = run_checkov_scan(target_dir)
    risk_data = calculate_risk(raw_scan.get("Findings", []))

    scan_id = raw_scan.get("ScanId", f"scan_{os.urandom(4).hex()}")

    record_scan(
        scan_id=scan_id,
        target_dir=target_dir,
        mode="api",
        source="api",
        total_findings=raw_scan.get("TotalFindings", 0),
        r_global=risk_data.get("R_global", 0.0),
        files_data=risk_data.get("files", [])
    )

    payload = {
        "scanId": scan_id,
        "globalRisk": risk_data.get("R_global", 0.0),
        "files": risk_data.get("files", [])
    }
    await event_queue.put({"event": "NEW_SCAN", "data": payload})
    return payload


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
    rule_id = finding.get("rule_id", "") if finding else ""
    line_num = finding.get("line_number", 0) if finding else 0

    success, msg = apply_patch(
        target_dir=req.targetDir,
        file_path_rel=req.filePath,
        rule_id=rule_id,
        line_num=line_num
    )

    if not success:
        raise HTTPException(status_code=400, detail=msg)

    backup_path = f"{req.filePath}.vanguard_backup"
    record_patch_event(req.findingId, backup_path)

    await event_queue.put({"event": "PATCH_APPLIED", "findingId": req.findingId})
    return {"status": "SUCCESS", "message": msg}


@app.post("/api/patch_batch")
async def apply_batch_patch(req: BatchPatchRequest):
    applied = []
    for item in req.patches:
        finding = get_finding_by_id(item.findingId)
        rule_id = finding.get("rule_id", "") if finding else ""
        line_num = finding.get("line_number", 0) if finding else 0

        success, _ = apply_patch(
            target_dir=req.targetDir,
            file_path_rel=item.filePath,
            rule_id=rule_id,
            line_num=line_num
        )

        if success:
            record_patch_event(item.findingId, f"{item.filePath}.vanguard_backup")
            applied.append(item.findingId)

    await event_queue.put({"event": "BATCH_PATCH_COMPLETED", "appliedCount": len(applied)})
    return {"status": "SUCCESS", "appliedFindingIds": applied}


@app.post("/api/rollback")
async def rollback_patch(req: RollbackRequest):
    result = execute_rollback(req.targetDir, req.filePath)
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