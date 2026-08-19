import time
import sys
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from checkov_parser import run_checkov_scan
from risk_engine import calculate_risk
from event_store import record_scan, init_db

class IaCChangedHandler(FileSystemEventHandler):
    def __init__(self, target_dir: str):
        self.target_dir = target_dir
    
    def on_modified(self, event):
        if event.is_directort or event.src_path.endswith(".vanguard_backup"):
            return

        if any(event.src_path.endswith(ext) for ext in [".tf", ".yaml", ".yml", "Dockerfile"]):
            print(f"\n[Watchdog] Detected Change in: {event.src_path}. Executing auto-scan")
            try:
                findings = run_checkov_scan(self.target_dir)
                risk_data = calculate_risk(findings)
                record_scan(f"wd_{int(time.time())}", "watchdog", self.target_dir, risk_data["R_global"], risk_data["files"])
                print(f"[Watchdog] Auto-Scan logged. New R_global: {risk_data['R_global']:.2f}")
            except Exception as e:
                print(f"[Watchdog Error] {e}")

def start_daemon(target_directory: str):
    init_db()
    event_handler = IaCChangedHandler(target_directory)
    observer = Observer()
    observer.schedule(event_handler, path=target_directory, recursive=True)
    observer.start()
    print(f"--- vanguard Watchdog Daemon Active on '{target_directory}' ---")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "../sample_repo"
    start_daemon(target)
