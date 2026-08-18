import argparse
import sys
import json
import uuid
from pathlib import Path

#adding the backend to a sys.path so it doens't depend on the network
backend_path = Path(__file__).parent.parent / "1_Backend_Engine"
sys.path.append(str(backend_path.resolve()))

try:
    from checkov_parser import run_checkov_scan #type: ignore
    from risk_engine import calculate_risk #type: ignore
    from event_store import record_scan, init_db #type: ignore
except ImportError as e:
    print(f"FATAL: Could not load backend modules. Ensure 1_Backend_Engine exist alongside 2_CLI_Action. Error : {e}")
    sys.exit(1)

