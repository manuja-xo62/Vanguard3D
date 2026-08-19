import time
import sys
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from checkov_parser import run_checkov_scan
from risk_engine import calculate_risk
from event_store import record_scan, init_db