import os
import time
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Initialize the app
app = FastAPI(
    title="VanguardNode 3D Intelligence Backend",
    version="4.0.0",
    description="Asynchronous SAST & ML Threat Remediation Engine"
)

# Enable CORS for local comms
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health Check Model
class HealthStatus(BaseModel):
    status: str
    timestamp: float
    engine_version: str

@app.get("/health", response_model=HealthStatus)
async def get_health():
    """
    Heartbeat ping utilized by UE4 VaRest to confirm backend availability.
    """
    return HealthStatus(
        status="ONLINE",
        timestamp=time.time(),
        engine_version="v4.0.0"
    )

@app.get("/api/status")
async def get_system_status():
    """
    Returns high-level system telemetry for UI Screen 00 logs.
    """
    return {
        "flask_ping": "DISABLED (Migrated to FastAPI Async)",
        "osc_listener": "ACTIVE (Port 8000)",
        "vosk_stt": "INITIALIZING",
        "watchdog": "STANDBY"
    }

if __name__ == "__main__":
    import uvicorn
    # Bind to local port 8000 
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)