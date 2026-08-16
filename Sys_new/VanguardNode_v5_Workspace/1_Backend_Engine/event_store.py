import sqlite3
import datetime
import uuid
from pathlib import Path
from typing import Dict, List, Any

DB_PATH = Path(__file__).parent / "vanguard.db"

def get_db_connection():
    ##Returns a SQLite connection object with row factory enabled
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    ##initialzes the database schema is tables do not exist
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.executescript(
        """
    CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        source TEXT,
        target_path TEXT,
        r_global REAL,
        timestamp TEXT
    );

    CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY,
        scan_id TEXT REFERENCES scans(scan_id),
        file_path TEXT,
        rule_id TEXT,
        severity TEXT,
        resource_type TEXT,
        r_file REAL,
        status TEXT
    );

    CREATE TABLE IF NOT EXISTS patch_events (
        event_id TEXT PRIMARY KEY,
        finding_id TEXT REFERENCES findings(finding_id),
        backup_path TEXT,
        timestamp TEXT
    );
    """
    )

    conn.commit()
    conn.close()

def record_scan(scan_id: str, source: str, target_path: str, r_global: float, files_data: List[Dict[str, Any]]):
    #logs new scans and the findings to databases
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    cursor.execute(
        "INSERT INTO scans (scan_id, source, target_path, r_global, timestamp) VALUES (?, ?, ?, ?, ?)",
        (scan_id, source, target_path, r_global, now_iso)
    )

    for file_entry in files_data:
        r_file = file_entry.get("R_file", 0.0)
        for f in file_entry.get("findings", []):
            cursor.execute(
                """
                INSERT INTO findings 
                (finding_id, scan_id, file_path, rule_id, severity, resource_type, r_file, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f.get("finding_id", f"fnd_{uuid.uuid4().hex[:8]}"),
                    scan_id,
                    f.get("file_path", ""),
                    f.get("rule_id", ""),
                    f.get("severity", "MEDIUM"),
                    f.get("resource_type", "default"),
                    r_file,
                    f.get("status", "open")
                )
            )
    conn.commit()
    conn.close()

def record_patch_event(finding_id: str, backup_path: str) -> str:
    ##Logs the patch evets and updates the successful records status into patched
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    new_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    event_id = f"evnt_{uuid.uuid4().hex[:8]}"

    #updating status
    cursor.execute(
        "UPDATE findings SET status = 'patched' WHERE finding_id = ?",
        (finding_id,))    
    
    conn.commit()
    conn.close()
    return event_id

def get_scan_history() -> List[Dict[str,Any]]:
    #retrieves the past scans for replay mode
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT scan_id, source, target_path, r_global, timestamp FROM scans ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]

if __name__ == "__main__":
    print("-- Testing SQLite Event Store---")
    init_db()
    print("Database `vanguard.db` initialized successfully.")

    #simulating saving a scan from risk engine
    test_scan_id = f"scan_{uuid.uuid4().hex[:9]}"
    sample_files = [{
        "file_path": "main.tf",
        "R_file": 14.0,
        "findings": [{
            "finding_id": "fnd_test123",
            "file_path": "main.tf",
            "rule_id": "CKV_AWS_20",
            "severity": "HIGH",
            "resource_type": "aws_s3_bucket",
            "status": "open"
        }]
    }]

    record_scan(test_scan_id, "api", "../sample_repo", 14.0, sample_files)
    print(f"Recorded Scan: {test_scan_id}")
    
    history = get_scan_history()
    print(f"Total stored scans: {len(history)}")