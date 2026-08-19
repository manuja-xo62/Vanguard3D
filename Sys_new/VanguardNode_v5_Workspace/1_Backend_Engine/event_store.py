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
    ##Initializes the database tables if they do not exist
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.executescript("""
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

    CREATE TABLE IF NOT EXISTS training_attempts (
        attempt_id TEXT PRIMARY KEY,
        scenario_id TEXT,
        score INTEGER,
        time_taken_seconds REAL,
        timestamp TEXT
    """)

    conn.commit()
    conn.close()


def record_scan(scan_id: str, source: str, target_path: str, r_global: float, files_data: List[Dict[str, Any]]):
    ##logs new scan data into the tables
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    cursor.execute(
        "INSERT OR REPLACE INTO scans (scan_id, source, target_path, r_global, timestamp) VALUES (?, ?, ?, ?, ?)",
        (scan_id, source, target_path, r_global, now_iso)
    )

    for file_entry in files_data:
        r_file = file_entry.get("R_file", 0.0)
        for f in file_entry.get("findings", []):
            cursor.execute(
                """
                INSERT OR REPLACE INTO findings 
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
    ## logs the successfully patched files
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    event_id = f"evt_{uuid.uuid4().hex[:8]}"

    # Update finding status
    cursor.execute(
        "UPDATE findings SET status = 'patched' WHERE finding_id = ?",
        (finding_id,)
    )

    # Record event log
    cursor.execute(
        "INSERT OR REPLACE INTO patch_events (event_id, finding_id, backup_path, timestamp) VALUES (?, ?, ?, ?)",
        (event_id, finding_id, backup_path, now_iso)
    )

    conn.commit()
    conn.close()
    return event_id


def get_scan_history() -> List[Dict[str, Any]]:
    ##Retrieves past scans 
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor() 
    
    cursor.execute("SELECT scan_id, source, target_path, r_global, timestamp FROM scans ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_scan_by_id(scan_id: str) -> Dict[str,Any]:
    init_db()
    conn = get_db_connection()
    cursor = conn-cursor()
    cursor.execute("SELECT *FROM scans Where scan_id = ?", {scan_id,})
    scan = cursor.fetchone()
    if not scan:
        conn.close()
        return{}
    
    cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
    findings = [dict(row) for row in cursor.fetchall()]
    conn.close()

    result = dict(scan)
    result["findings"] = findings
    return result
    
    


if __name__ == "__main__":
    print("--- Testing SQLite Event Store ---")
    init_db()
    print("Database `vanguard.db` initialized successfully.")
    
    # Simulate saving a scan from the Risk Engine with a dynamic finding ID
    test_scan_id = f"scan_{uuid.uuid4().hex[:8]}"
    sample_files = [{
        "file_path": "main.tf",
        "R_file": 14.0,
        "findings": [{
            "finding_id": f"fnd_{uuid.uuid4().hex[:8]}",
            "file_path": "main.tf",
            "rule_id": "CKV_AWS_20",
            "severity": "HIGH",
            "resource_type": "aws_s3_bucket",
            "status": "open"
        }]
    }]
    
    record_scan(test_scan_id, "api", "../sample_repo", 14.0, sample_files)
    print(f"Recorded test scan: {test_scan_id}")
    
    history = get_scan_history()
    print(f"Total stored scans: {len(history)}")