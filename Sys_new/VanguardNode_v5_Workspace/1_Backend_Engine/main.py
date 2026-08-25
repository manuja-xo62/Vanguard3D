import os
import io
import json
import sqlite3
import asyncio
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# --- Database & WAL Initialization ---
DB_PATH = "vanguard.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA busy_timeout=5000;")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            global_risk_score REAL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            scan_id TEXT,
            file_path TEXT,
            line_number INTEGER,
            rule_id TEXT,
            status TEXT,
            r_file REAL,
            FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patch_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            finding_id TEXT,
            file_path TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS training_scores (
            attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            scenario_id TEXT,
            score REAL,
            completion_time_sec REAL
        )
    """)
    conn.commit()
    conn.close()

init_db()
app = FastAPI(title="Vanguard Backend Engine")
event_queue = asyncio.Queue()

# --- Utility Functions & Path Resolver ---
def safe_resolve_path(target_dir: str, relative_file: str) -> str:
    """Resolves relative file paths safely against the target directory root context."""
    base_path = os.path.abspath(target_dir)
    resolved_path = os.path.abspath(os.path.join(base_path, relative_file))
    if not resolved_path.startswith(base_path):
        raise HTTPException(status_code=400, detail="Path traversal outside target directory.")
    return resolved_path

# --- Standardized Schemas for UVanguardHttpClient ---
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
    patchId: str

class TrainingScoreRequest(BaseModel):
    userId: str
    scenarioId: str
    score: float
    completionTimeSec: float

# --- Stubbed Engine Integrations ---
def calculate_risk_scores(raw_findings: list):
    """Calculates risk scores for individual files and the global system context."""
    enriched = []
    total_risk = 0.0
    for idx, f in enumerate(raw_findings):
        r_file = round(0.5 + (idx * 0.1), 2)
        total_risk += r_file
        enriched.append({
            "finding_id": f.get("FindingId", f"FIND-{idx}"),
            "file_path": f.get("FilePath", "terraform/main.tf"),
            "line_number": f.get("LineNumber", 1),
            "rule_id": f.get("RuleId", "CKV_AWS_1"),
            "status": "VULNERABLE",
            "r_file": r_file
        })
    global_score = round(total_risk / max(len(raw_findings), 1), 2)
    return enriched, global_score

def generate_pdf_report(scan_id: str) -> bytes:
    """Generates audit PDF bytes for report streaming endpoints."""
    return f"%PDF-1.4 Audit Report for Scan {scan_id}\n1 0 obj<<>>endobj".encode("utf-8")

# --- API Endpoints ---

@app.post("/api/scan")
async def execute_scan(target_dir: str, raw_findings: list):
    enriched_findings, global_risk = calculate_risk_scores(raw_findings)
    scan_id = f"SCAN-{os.urandom(4).hex()}"
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO scans (scan_id, global_risk_score) VALUES (?, ?)", (scan_id, global_risk))
    for f in enriched_findings:
        c.execute("""
            INSERT INTO findings (finding_id, scan_id, file_path, line_number, rule_id, status, r_file)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (f["finding_id"], scan_id, f["file_path"], f["line_number"], f["rule_id"], f["status"], f["r_file"]))
    conn.commit()
    conn.close()

    payload = {"scanId": scan_id, "globalRisk": global_risk, "findings": enriched_findings}
    await event_queue.put({"event": "NEW_SCAN", "data": payload})
    return payload

@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT scan_id, global_risk_score FROM scans WHERE scan_id = ?", (scan_id,))
    scan = c.fetchone()
    if not scan:
        conn.close()
        raise HTTPException(status_code=404, detail="Scan ID not found")
    
    c.execute("SELECT finding_id, file_path, line_number, rule_id, status, r_file FROM findings WHERE scan_id = ?", (scan_id,))
    rows = c.fetchall()
    conn.close()
    
    findings = [FindingModel(finding_id=r[0], file_path=r[1], line_number=r[2], rule_id=r[3], status=r[4], r_file=r[5]).dict(by_alias=True) for r in rows]
    return {"scanId": scan[0], "globalRisk": scan[1], "findings": findings}

@app.get("/api/replay/{scan_id}")
async def get_replay_sequence(scan_id: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT event_id, finding_id, file_path, timestamp FROM patch_events WHERE scan_id = ?", (scan_id,))
    events = c.fetchall()
    conn.close()
    return [{"eventId": e[0], "findingId": e[1], "filePath": e[2], "timestamp": e[3]} for e in events]

@app.get("/api/report/{scan_id}")
async def stream_report(scan_id: str):
    pdf_bytes = generate_pdf_report(scan_id)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=audit_{scan_id}.pdf"}
    )

@app.post("/api/patch")
async def apply_patch(req: PatchRequest):
    abs_path = safe_resolve_path(req.targetDir, req.filePath)
    if not os.path.exists(abs_path):
        raise HTTPException(status_code=404, detail=f"Target file not found at {abs_path}")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE findings SET status = 'PATCHED' WHERE finding_id = ?", (req.findingId,))
    c.execute("INSERT INTO patch_events (scan_id, finding_id, file_path) VALUES (?, ?, ?)", (req.scanId, req.findingId, abs_path))
    conn.commit()
    conn.close()

    await event_queue.put({"event": "PATCH_APPLIED", "findingId": req.findingId})
    return {"status": "SUCCESS", "patchedFile": abs_path}

@app.post("/api/patch_batch")
async def apply_patch_batch(req: BatchPatchRequest):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    applied = []

    for item in req.patches:
        abs_path = safe_resolve_path(req.targetDir, item.filePath)
        if os.path.exists(abs_path):
            c.execute("UPDATE findings SET status = 'PATCHED' WHERE finding_id = ?", (item.findingId,))
            c.execute("INSERT INTO patch_events (scan_id, finding_id, file_path) VALUES (?, ?, ?)", (item.scanId, item.findingId, abs_path))
            applied.append(item.findingId)

    conn.commit()
    conn.close()
    
    await event_queue.put({"event": "BATCH_PATCH_COMPLETED", "appliedCount": len(applied)})
    return {"status": "SUCCESS", "appliedFindingIds": applied}

@app.post("/api/rollback")
async def rollback_patch(req: RollbackRequest):
    backup_file = safe_resolve_path(req.targetDir, f".vanguard_backup/{req.patchId}.bak")
    if not os.path.exists(backup_file):
        raise HTTPException(status_code=404, detail="Backup snapshot not found.")
    return {"status": "SUCCESS", "restoredFrom": backup_file}

@app.post("/api/training/submit")
async def submit_training_score(req: TrainingScoreRequest):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO training_scores (user_id, scenario_id, score, completion_time_sec)
        VALUES (?, ?, ?, ?)
    """, (req.userId, req.scenarioId, req.score, req.completionTimeSec))
    conn.commit()
    conn.close()
    return {"status": "SUCCESS"}

@app.get("/api/events/stream")
async def stream_events(request: Request):
    """Server-Sent Events (SSE) stream allowing Unreal Engine client to receive push notifications."""
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