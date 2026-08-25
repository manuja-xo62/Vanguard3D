import sqlite3
import datetime
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional

DB_PATH = Path(__file__).parent / "vanguard.db"


def get_db_connection():
    ##Returns a SQLite connection object with row factory enabled.
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    ##Initializes the database tables if they do not exist.
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        source TEXT,
        target_path TEXT,
        r_global REAL,
        total_findings INTEGER DEFAULT 0,
        timestamp TEXT
    );

    CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY,
        scan_id TEXT REFERENCES scans(scan_id),
        file_path TEXT,
        rule_id TEXT,
        rule_title TEXT,
        severity TEXT,
        resource_type TEXT,
        line_number INTEGER DEFAULT 0,
        code_snippet TEXT,
        remediation_hint TEXT,
        r_file REAL DEFAULT 0.0,
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
    );
    """)

    conn.commit()
    conn.close()


def record_scan(
    scan_id: str,
    target_dir: str = "",
    total_findings: int = 0,
    findings: Optional[List[Dict[str, Any]]] = None,
    source: str = "api",
    target_path: str = "",
    r_global: float = 0.0,
    files_data: Optional[List[Dict[str, Any]]] = None
):

    ##Logs scan data into SQLite tables. Accommodates both direct finding lists and structured risk engine file records.

    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    effective_target = target_dir or target_path
    
    # Handle direct findings payload vs Risk Engine files_data structure
    raw_findings = findings if findings is not None else []
    if files_data and not raw_findings:
        for file_entry in files_data:
            raw_findings.extend(file_entry.get("findings", []))

    effective_total = total_findings if total_findings > 0 else len(raw_findings)

    cursor.execute(
        """
        INSERT OR REPLACE INTO scans 
        (scan_id, source, target_path, r_global, total_findings, timestamp) 
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (scan_id, source, effective_target, r_global, effective_total, now_iso)
    )

    for f in raw_findings:
        f_id = f.get("FindingId") or f.get("finding_id") or f"fnd_{uuid.uuid4().hex[:8]}"
        file_p = f.get("FilePath") or f.get("file_path", "")
        r_id = f.get("RuleId") or f.get("rule_id", "UNKNOWN")
        r_title = f.get("RuleTitle") or f.get("rule_title", "")
        sev = f.get("Severity") or f.get("severity", "MEDIUM")
        res_type = f.get("resource_type", "default")
        line_num = f.get("LineNumber") or f.get("line_number", 0)
        snippet = f.get("CodeSnippet") or f.get("code_snippet", "")
        hint = f.get("RemediationHint") or f.get("remediation_hint", "")
        stat = f.get("Status") or f.get("status", "VULNERABLE")

        cursor.execute(
            """
            INSERT OR REPLACE INTO findings 
            (finding_id, scan_id, file_path, rule_id, rule_title, severity, 
             resource_type, line_number, code_snippet, remediation_hint, r_file, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f_id,
                scan_id,
                file_p,
                r_id,
                r_title,
                sev,
                res_type,
                line_num,
                snippet,
                hint,
                0.0,
                stat
            )
        )

    conn.commit()
    conn.close()


def get_all_scans() -> List[Dict[str, Any]]:
    ##Retrieves all historical scan records from SQLite.
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT scan_id, source, target_path, total_findings, r_global, timestamp FROM scans ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_finding_by_id(finding_id: str) -> Optional[Dict[str, Any]]:
    ##Retrieves a single finding by its ID for patching operations.
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def record_patch_event(finding_id: str, backup_path: str) -> str:
    ##Logs successfully patched files.
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    event_id = f"evt_{uuid.uuid4().hex[:8]}"

    cursor.execute(
        "UPDATE findings SET status = 'patched' WHERE finding_id = ?",
        (finding_id,)
    )

    cursor.execute(
        "INSERT OR REPLACE INTO patch_events (event_id, finding_id, backup_path, timestamp) VALUES (?, ?, ?, ?)",
        (event_id, finding_id, backup_path, now_iso)
    )

    conn.commit()
    conn.close()
    return event_id


def get_scan_history() -> List[Dict[str, Any]]:
    ##Alias for get_all_scans for backward compatibility.
    return get_all_scans()


def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    ##Retrieves a scan and all of its associated findings.
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
    scan_row = cursor.fetchone()

    if not scan_row:
        conn.close()
        return None

    scan_dict = dict(scan_row)

    cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
    findings_rows = cursor.fetchall()
    scan_dict["findings"] = [dict(row) for row in findings_rows]

    conn.close()
    return scan_dict


def get_replay_sequence(scan_id: str) -> List[Dict[str, Any]]:
    ##Retrieves chronological patch events for a scan session.
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(""" 
        SELECT p.event_id, p.timestamp, p.backup_path, f.finding_id, f.file_path, f.rule_id, f.severity
        FROM patch_events p
        JOIN findings f ON p.finding_id = f.finding_id
        WHERE f.scan_id = ?
        ORDER BY p.timestamp ASC
    """, (scan_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def record_training_attempt(scenario_id: str, score: int, time_taken: float) -> str:
    ##Logs scenario scores for interactive exercises.
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    attempt_id = f"att_{uuid.uuid4().hex[:8]}"
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    cursor.execute(
        "INSERT INTO training_attempts (attempt_id, scenario_id, score, time_taken_seconds, timestamp) VALUES (?, ?, ?, ?, ?)",
        (attempt_id, scenario_id, score, time_taken, now_iso)
    )
    conn.commit()
    conn.close()
    return attempt_id


if __name__ == "__main__":
    print("--- Testing SQLite Event Store ---")
    init_db()
    print("Database `vanguard.db` initialized successfully.")
    
    test_scan_id = f"scan_{uuid.uuid4().hex[:8]}"
    sample_findings = [{
        "FindingId": f"fnd_{uuid.uuid4().hex[:8]}",
        "FilePath": "main.tf",
        "RuleId": "CKV_AWS_20",
        "RuleTitle": "S3 Bucket Public Read",
        "Severity": "HIGH",
        "LineNumber": 12,
        "CodeSnippet": "acl = 'public-read'",
        "RemediationHint": "Set ACL to private",
        "Status": "VULNERABLE"
    }]
    
    record_scan(
        scan_id=test_scan_id,
        target_dir="../sample_repo",
        total_findings=len(sample_findings),
        findings=sample_findings
    )
    print(f"Recorded test scan: {test_scan_id}")
    
    history = get_all_scans()
    print(f"Total stored scans: {len(history)}")