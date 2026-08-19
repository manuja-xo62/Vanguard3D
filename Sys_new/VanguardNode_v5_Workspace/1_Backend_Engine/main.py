import uuid
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

#importing validated modules from other scripts
from checkov_parser import run_checkov_scan
from risk_engine import calculate_risk
from patch_service import apply_patch
from event_store import (
    record_scan, record_patch_event, get_scan_history,
    get_scan_by_id, get_replay_sequence, record_training_attempt, init_db)
from report_generator import generate_pdf_report
from patch_service import execute_rollback

@asynccontextmanager
async def lifespan(app: FastAPI):
    ##Ensure the database is initialzied when the server starts
    init_db()
    yield

app = FastAPI(title = "VanguardNode API", version = "5.0", description="Zero Trust Backend Engine", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#pydantic models for input validation
class ScanRequest(BaseModel):
    target_directory: str = "../sample_repo"

class RollbackRequest(BaseModel):
    target_directory: str
    file_path_rel: str

class PatchRequest(BaseModel):
    file_path_rel: str
    rule_id: str
    line_range: list
    target_directory: str = "../sample_repo"
    finding_id: str

class TrainingScoreRequest(BaseModel):
    scenario_id: str
    score: int
    time_taken_seconds: float

#API endpoints

@app.post("/api/scan")
def trigger_scan(req: ScanRequest):
    ##Execute the checkhov scan to calculate the risks and logs the event
    try:
        #Parsing
        raw_findings = run_checkov_scan(req.target_directory)
    
        #Calculating Risks
        risk_data = calculate_risk(raw_findings)

        #Store the event in the DB
        scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        record_scan(scan_id, "api", req.target_directory, risk_data["R_global"], risk_data["files"])

        return {"status": "success", "scan_id": scan_id, "data": risk_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/patch")
def trigger_patch(req: PatchRequest):
    ##Execute the AST guided patch and records the event int the DB

    success, msg = apply_patch(
        req.target_directory,
        req.file_path_rel,
        req.rule_id,
        req.line_range,
    )
    if success:
        if "already compliant" in msg:
            return{"status": "skipped", "message": msg}
        
        #log the patch event in the DB
        event_id = record_patch_event(req.finding_id, msg)
        return {"status": "patched", "event_id": event_id, "backup_path": msg}
    else:
        raise HTTPException(status_code=400, detail=msg)

@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str):
    ##retreive the scan history for replay mode
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="ScanID not found")
    return scan

@app.get("/api/events")
def list_events():
    return get_scan_history()

@app.get("/api/events/{scan_id}/replay")
def get_replay(scan_id: str):
    return get_replay_sequence(scan_id)

@app.get("/api/training/scenarios")
def list_training_scenarios():
    scenarios_dir = Path(__file__).parent / "training_scenarios"
    if not scenarios_dir.exists():
        return []
    scenarios = []
    for item in scenarios_dir.iterdir():
        if item.is_dir():
            scenarios.append({"id": item.name, "name": item.name.replace("_", " ").title(), "path": str(item)})
    return scenarios

@app.post("/api/training/score")
def submit_score(req: TrainingScoreRequest):
    ##Record the training score in the DB
    attempt_id = record_training_attempt(req.scenario_id, req.score, req.time_taken_seconds)
    return {"status": "success", "attempt_id": attempt_id}

@app.get("/api/report/{scan_id}")
def download_pdf_report(scan_id: str):
    try:
        scan_data = get_scan_by_id(scan_id)
        if not scan_data:
            raise HTTPException(status_code=404, detail=f"ScanID '{scan_id}' not found in database.")
        
        pdf_bytes = generate_pdf_report(scan_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=vanguard_report_{scan_id}.pdf"}
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF Error: {type(e).__name__} - {str(e)}")
        
@app.post("/api/rollback")
def rollback_patch(req: RollbackRequest):
    ##rollback the previous patch

    result = execute_rollback(req.target_directory, req.file_path_rel)

    if result["status"] == "failed":
        raise HTTPException(status_code=404, detail=result["message"])
    elif result["status"] == "error":
        raise HTTPException(status_code=500, detail=result["message"])

    return result
     

if __name__ == "__main__":
    print("--- Starting Vanguard API on Port 8000---")
    uvicorn.run(app, host="0.0.0.0", port=8000)