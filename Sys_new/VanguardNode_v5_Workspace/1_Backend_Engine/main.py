import os
import shutil
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Internal module imports
from checkov_parser import run_checkov_scan
from patch_service import apply_patch_to_file
from event_store import init_db, record_scan, get_all_scans, get_finding_by_id

app = FastAPI(title="VanguardNode Backend Engine", version="2.2.0")

# Initialize SQLite database schemas on engine boot
@app.on_event("startup")
def startup_event():
    init_db()

# --- Pydantic API Request Schemas ---

class ScanRequest(BaseModel):
    target_directory: str = "../sample_repo"

class PatchRequest(BaseModel):
    finding_id: str

class SequentialPatchRequest(BaseModel):
    findings: List[dict]

class RollbackRequest(BaseModel):
    finding_id: str
    target_file: str


# --- API Endpoints ---

@app.get("/")
def health_check():
    """Diagnostic health check for UE4 Settings & Diagnostics Screen."""
    return {"status": "ONLINE", "service": "VanguardNode Engine", "version": "2.2.0"}


@app.post("/api/scan")
def trigger_scan(payload: ScanRequest):
    """
    Triggers Checkov scan against target directory and records session in SQLite.
    Returns FVanguardScanPayload structured JSON to UE4.
    """
    if not os.path.exists(payload.target_directory):
        raise HTTPException(status_code=400, detail=f"Target directory '{payload.target_directory}' does not exist.")

    try:
        scan_payload = run_checkov_scan(payload.target_directory)
        
        # Persist scan results in SQLite database for Archive mode
        record_scan(
            scan_id=scan_payload.get("ScanId"),
            target_dir=payload.target_directory,
            total_findings=scan_payload.get("TotalFindings", 0),
            findings=scan_payload.get("Findings", [])
        )
        
        return scan_payload
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan execution failed: {str(e)}")


@app.post("/api/patch")
def apply_single_patch(payload: PatchRequest):
    """
    Applies remediation patch for a single finding passed from UE4 Holo Slate UI.
    Includes .vanguard_backup creation for zero-trust safety.
    """
    finding = get_finding_by_id(payload.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding ID '{payload.finding_id}' not found in event store.")

    target_file = finding.get("file_path")
    rule_id = finding.get("rule_id")

    if not os.path.exists(target_file):
        raise HTTPException(status_code=404, detail=f"Target file '{target_file}' not found on disk.")

    # Create backup before mutation if it doesn't already exist
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

    return {"status": "success", "message": f"Patch for {payload.finding_id} applied successfully.", "file": target_file}


@app.post("/api/patch_batch")
def apply_patches_sorted(payload: SequentialPatchRequest):
    """
    Applies multiple patches sequentially.
    Sorts modifications descending by line number (bottom-to-top) to eliminate line drift.
    """
    # Sort findings in descending order by line number to protect index alignment
    sorted_findings = sorted(payload.findings, key=lambda x: x.get('LineNumber', 0), reverse=True)
    applied_results = []

    for finding in sorted_findings:
        target_file = finding.get('FilePath')
        rule_id = finding.get('RuleId')
        finding_id = finding.get('FindingId')

        if target_file and os.path.exists(target_file):
            backup_file = f"{target_file}.vanguard_backup"
            if not os.path.exists(backup_file):
                shutil.copyfile(target_file, backup_file)

            success, msg = apply_patch_to_file(target_file, rule_id)
            if success:
                applied_results.append({"finding_id": finding_id, "status": "PATCHED"})
            else:
                applied_results.append({"finding_id": finding_id, "status": "FAILED", "reason": msg})

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