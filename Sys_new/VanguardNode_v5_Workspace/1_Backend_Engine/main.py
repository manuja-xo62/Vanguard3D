import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from checkov_parser import run_checkov_scan
from patch_service import apply_patch_to_file, apply_sequential_patches, execute_rollback
from risk_engine import calculate_risk
from event_store import (
    init_db,
    record_scan,
    record_event,
    get_all_scans,
    get_finding_by_id,
    load_scenario_data,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle context manager initializing database state."""
    init_db()
    yield


app = FastAPI(title="VanguardNode Backend Engine", version="5.1.0", lifespan=lifespan)


class ScanRequest(BaseModel):
    target_directory: str = "../sample_repo"
    mode: str = "live"
    scenario_id: Optional[str] = None


class PatchRequest(BaseModel):
    finding_id: str


class SequentialPatchRequest(BaseModel):
    findings: List[Dict[str, Any]]


class RollbackRequest(BaseModel):
    finding_id: Optional[str] = None
    target_file: str
    target_dir: Optional[str] = "."


class PREventRequest(BaseModel):
    pr_number: int
    repository: str
    commit_sha: str
    scan_payload: Dict[str, Any]


class PRCommentRequest(BaseModel):
    pr_number: int
    repository: str
    comment_body: str


@app.get("/")
def health_check():
    """Diagnostic health check."""
    return {"status": "ONLINE", "service": "VanguardNode Engine", "version": "5.1.0"}


@app.post("/api/scan")
def trigger_scan(payload: ScanRequest):
    """Triggers Checkov AST scan or loads pre-seeded scenario datasets."""
    if payload.mode == "training" and payload.scenario_id:
        try:
            return load_scenario_data(payload.scenario_id)
        except Exception as e:
            raise HTTPException(status_code=404, detail=f"Failed to load training scenario: {str(e)}")

    target_path = Path(payload.target_directory).resolve()
    if not target_path.exists():
        raise HTTPException(status_code=400, detail=f"Target directory '{payload.target_directory}' does not exist.")

    try:
        scan_payload = run_checkov_scan(str(target_path))
        findings = scan_payload.get("Findings", [])
        risk_summary = calculate_risk(findings)
        scan_payload["RiskScores"] = risk_summary
        scan_payload["Mode"] = payload.mode
        
        record_scan(
            scan_id=scan_payload.get("ScanId"),
            target_dir=str(target_path),
            mode=payload.mode,
            total_findings=scan_payload.get("TotalFindings", 0),
            findings=findings,
            risk_summary=risk_summary
        )
        
        return scan_payload
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan execution failed: {str(e)}")


@app.post("/api/scan-event")
def ingest_ci_scan_event(payload: PREventRequest):
    """Ingests scan payloads directly from CI/CD pipeline triggers."""
    try:
        record_event(
            event_type="CI_SCAN_INGESTED",
            pr_number=payload.pr_number,
            repository=payload.repository,
            commit_sha=payload.commit_sha,
            payload=payload.scan_payload
        )
        return {"status": "success", "message": f"CI scan event recorded for PR #{payload.pr_number}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to ingest CI event: {str(e)}")


@app.post("/api/comment-pr")
def post_pr_comment(payload: PRCommentRequest):
    """Dispatches automated PR comments into CI integration workflows."""
    try:
        record_event(
            event_type="PR_COMMENT_POSTED",
            pr_number=payload.pr_number,
            repository=payload.repository,
            payload={"comment": payload.comment_body}
        )
        return {"status": "success", "message": f"Comment dispatched to PR #{payload.pr_number}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to post PR comment: {str(e)}")


@app.post("/api/patch")
def apply_single_patch(payload: PatchRequest):
    """Applies dynamic scope-aware remediation patch for a single finding."""
    finding = get_finding_by_id(payload.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding ID '{payload.finding_id}' not found in event store.")

    target_file = finding.get("file_path") or finding.get("FilePath")
    rule_id = finding.get("rule_id") or finding.get("RuleId")
    line_num = finding.get("line_number") or finding.get("LineNumber") or 0

    if not target_file or not os.path.exists(target_file):
        raise HTTPException(status_code=404, detail=f"Target file '{target_file}' not found on disk.")

    patch_success, message = apply_patch_to_file(target_file, rule_id, line_num=line_num)
    if not patch_success:
        raise HTTPException(status_code=400, detail=message)

    record_event(
        event_type="PATCH_APPLIED",
        finding_id=payload.finding_id,
        target_file=target_file,
        rule_id=rule_id
    )

    return {"status": "success", "message": f"Patch for {payload.finding_id} applied successfully.", "file": target_file}


@app.post("/api/patch_batch")
def apply_patches_sorted(payload: SequentialPatchRequest):
    """Applies multiple patches sequentially, descending by line number to eliminate drift."""
    results = apply_sequential_patches(payload.findings)
    return {"status": "success", "applied": results}


@app.post("/api/rollback")
def rollback_patch(payload: RollbackRequest):
    """Reverts target file using its .vanguard_backup file safely."""
    result = execute_rollback(payload.target_dir or ".", payload.target_file)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("message"))
    elif result.get("status") == "failed":
        raise HTTPException(status_code=404, detail=result.get("message"))

    record_event(
        event_type="ROLLBACK_EXECUTED",
        target_file=payload.target_file,
        finding_id=payload.finding_id
    )

    return result


@app.get("/api/history")
def get_scan_history():
    """Retrieves historical scan records from SQLite database."""
    try:
        history = get_all_scans()
        return {"status": "success", "history": history}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve scan history: {str(e)}")