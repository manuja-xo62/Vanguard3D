import os
import shutil
from contextlib import asynccontextmanager
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Internal module imports
from checkov_parser import run_checkov_scan
from patch_service import apply_patch_to_file
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
    """Lifecycle context manager replacing deprecated @app.on_event startup/shutdown handlers."""
    init_db()
    yield


app = FastAPI(title="VanguardNode Backend Engine", version="5.0.0", lifespan=lifespan)

# --- Pydantic API Request Schemas ---

class FindingModel(BaseModel):
    finding_id: str
    rule_id: str
    rule_title: Optional[str] = ""
    severity: str
    file_path: str
    line_number: int
    is_internet_facing: Optional[bool] = False
    resource_type: Optional[str] = "container"
    code_snippet: Optional[str] = ""
    remediation_hint: Optional[str] = ""


class ScanRequest(BaseModel):
    target_directory: str = "../sample_repo"
    mode: str = "live"  # Supported modes: live, replay, training
    scenario_id: Optional[str] = None


class PatchRequest(BaseModel):
    finding_id: str


class SequentialPatchRequest(BaseModel):
    findings: List[dict]


class RollbackRequest(BaseModel):
    finding_id: str
    target_file: str


class PREventRequest(BaseModel):
    pr_number: int
    repository: str
    commit_sha: str
    scan_payload: dict


class PRCommentRequest(BaseModel):
    pr_number: int
    repository: str
    comment_body: str


# --- API Endpoints ---

@app.get("/")
def health_check():
    """Diagnostic health check for UE4 Settings & Diagnostics Screen."""
    return {"status": "ONLINE", "service": "VanguardNode Engine", "version": "5.0.0"}


@app.post("/api/scan")
def trigger_scan(payload: ScanRequest):
    """
    Triggers Checkov AST scan or loads pre-seeded scenario datasets (Training mode).
    Enriches findings with deterministic risk scores (R_file, R_global) and logs events.
    """
    if payload.mode == "training" and payload.scenario_id:
        try:
            return load_scenario_data(payload.scenario_id)
        except Exception as e:
            raise HTTPException(status_code=404, detail=f"Failed to load training scenario: {str(e)}")

    if not os.path.exists(payload.target_directory):
        raise HTTPException(status_code=400, detail=f"Target directory '{payload.target_directory}' does not exist.")

    try:
        # 1. Execute Checkov AST Scan
        scan_payload = run_checkov_scan(payload.target_directory)
        
        # 2. Enrich payload with Risk Scoring Engine
        findings = scan_payload.get("Findings", [])
        risk_summary = calculate_risk(findings)
        scan_payload["RiskScores"] = risk_summary
        scan_payload["Mode"] = payload.mode
        
        # 3. Persist scan record and timeline event into Event Store SQLite DB
        record_scan(
            scan_id=scan_payload.get("ScanId"),
            target_dir=payload.target_directory,
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
    """
    Ingests scan payloads directly from CI/CD pipeline triggers (e.g. GitHub Actions).
    Stores event metadata for PR context rendering and Replay mode streaming.
    """
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
    """
    Dispatches automated PR comments and feedback into CI integration workflows.
    """
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
    """
    Applies remediation patch for a single finding passed from UE4 Holo Slate UI.
    Includes .vanguard_backup creation for zero-trust safety.
    """
    finding = get_finding_by_id(payload.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding ID '{payload.finding_id}' not found in event store.")

    target_file = finding.get("file_path") or finding.get("FilePath")
    rule_id = finding.get("rule_id") or finding.get("RuleId")

    if not target_file or not os.path.exists(target_file):
        raise HTTPException(status_code=404, detail=f"Target file '{target_file}' not found on disk.")

    # Create zero-trust backup before file mutation
    backup_file = f"{target_file}.vanguard_backup"
    if not os.path.exists(backup_file):
        try:
            shutil.copyfile(target_file, backup_file)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to create zero-trust backup: {str(e)}")

    # Execute patch
    patch_success, message = apply_patch_to_file(target_file, rule_id)
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
    """
    Applies multiple patches sequentially.
    Sorts modifications descending by line number (bottom-to-top) to eliminate line drift.
    Fault-tolerant key resolution supports both PascalCase and snake_case models.
    """
    sorted_findings = sorted(
        payload.findings,
        key=lambda x: x.get('LineNumber', x.get('line_number', 0)),
        reverse=True
    )
    applied_results = []

    for finding in sorted_findings:
        target_file = finding.get('FilePath') or finding.get('file_path')
        rule_id = finding.get('RuleId') or finding.get('rule_id')
        finding_id = finding.get('FindingId') or finding.get('finding_id')

        if target_file and os.path.exists(target_file):
            backup_file = f"{target_file}.vanguard_backup"
            if not os.path.exists(backup_file):
                try:
                    shutil.copyfile(target_file, backup_file)
                except Exception as e:
                    applied_results.append({"finding_id": finding_id, "status": "FAILED", "reason": f"Backup failed: {str(e)}"})
                    continue

            success, msg = apply_patch_to_file(target_file, rule_id)
            if success:
                applied_results.append({"finding_id": finding_id, "status": "PATCHED"})
                record_event(
                    event_type="BATCH_PATCH_APPLIED",
                    finding_id=finding_id,
                    target_file=target_file,
                    rule_id=rule_id
                )
            else:
                applied_results.append({"finding_id": finding_id, "status": "FAILED", "reason": msg})
        else:
            applied_results.append({"finding_id": finding_id, "status": "FAILED", "reason": f"File path '{target_file}' invalid or missing."})

    return {"status": "success", "applied": applied_results}


@app.post("/api/rollback")
def rollback_patch(payload: RollbackRequest):
    """
    Reverts target file using its .vanguard_backup file.
    Invoked by UE4 ExecuteRollback delegate.
    """
    original_file = payload.target_file
    backup_file = f"{original_file}.vanguard_backup"

    if not os.path.exists(backup_file):
        raise HTTPException(status_code=404, detail=f"No backup file found for '{original_file}'.")

    try:
        shutil.copyfile(backup_file, original_file)
        os.remove(backup_file)
        
        record_event(
            event_type="ROLLBACK_EXECUTED",
            target_file=original_file,
            finding_id=payload.finding_id
        )
        return {"status": "success", "message": f"Successfully reverted {original_file}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Rollback failed: {str(e)}")


@app.get("/api/history")
def get_scan_history():
    """
    Retrieves historical scan records from SQLite database.
    Populates UI data grid in WBP_ArchivePanel.
    """
    try:
        history = get_all_scans()
        return {"status": "success", "history": history}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve scan history: {str(e)}")