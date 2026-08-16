import uuid
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

#importing validated modules from other scripts
from checkov_parser import run_checkov_scan
from risk_engine import calculate_risk
from patch_service import apply_patch
from event_store import record_scan, record_patch_event, get_scan_history, init_db

app = FastAPI(title = "VanguardNode API", version = "5.0", description="Zero Trust Backend Engine")

#pydantic models for input validation
class ScanRequest(BaseModel):
    target_directory: str = "../sample_repo"

class PatchRequest(BaseModel):
    file_path_rel: str
    rule_id: str
    line_range: list
    target_directory: str = "../sample_repo"
    finding_id: str

#API endpoints
@app.on_event("startup")
def startup_event():
    ##Ensure the database is initialzied when the server starts
    init_db()

@app.post("/scan")
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

@app.post("/patch")
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
@app.get("/history")
def get_history():
    ##retreive the scan history for replay mode
    return{"status": "success", "history": get_scan_history()}

if __name__ == "__main__":
    print("--- Starting Vanguard API on Port 8000---")
    uvicorn.run(app, host="0.0.0.0", port=8000)


