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
class ScanRequesr(BaseModel):
    target_directory: str = "../sample_repo"

class PatchRequest(BaseModel):
    file_path_rel: str
    rule_id: str
    line_range: list
    target_directory: str = "../sample_repo"
    finding_id: str
    