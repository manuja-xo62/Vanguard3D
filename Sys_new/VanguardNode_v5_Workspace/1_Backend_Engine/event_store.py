import sqlite3
import datetime
import uuid
import json
from pathlib import Path
from typing import Dict, List, Any, Optional

DB_PATH = Path(__file__).parent / "vanguard.db"


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        source TEXT,
        target_path TEXT,
        mode TEXT DEFAULT 'live',
        r_global REAL DEFAULT 0.0,
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
        status TEXT DEFAULT 'VULNERABLE'
    );

    CREATE TABLE IF NOT EXISTS patch_events (
        event_id TEXT PRIMARY KEY,
        finding_id TEXT REFERENCES findings(finding_id),
        backup_path TEXT,
        timestamp TEXT
    );

    CREATE TABLE IF NOT EXISTS timeline_events (
        event_id TEXT PRIMARY KEY,
        event_type TEXT,
        pr_number INTEGER,
        repository TEXT,
        commit_sha TEXT,
        finding_id TEXT,
        target_file TEXT,
        rule_id TEXT,
        payload TEXT,
        timestamp TEXT
    );

    CREATE TABLE IF NOT EXISTS training_attempts (
        attempt_id TEXT PRIMARY KEY,
        scenario_id TEXT,
        score INTEGER,
        time_taken_seconds REAL,
        timestamp TEXT
    );

    CCREATE TABLE IF NOT EXISTS pipeline_runs (
        scan_id TEXT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        pre_risk_score REAL,
        post_risk_score REAL,
        triage_payload TEXT
    );
    """)

    conn.commit()
    conn.close()


def record_scan(
    scan_id: str,
    target_dir: str = "",
    mode: str = "live",
    total_findings: int = 0,
    findings: Optional[List[Dict[str, Any]]] = None,
    risk_summary: Optional[Dict[str, Any]] = None,
    source: str = "api",
    target_path: str = "",
    r_global: float = 0.0,
    files_data: Optional[List[Dict[str, Any]]] = None
):
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    effective_target = target_dir or target_path

    if risk_summary and isinstance(risk_summary, dict):
        r_global = risk_summary.get("global_risk_score", risk_summary.get("r_global", risk_summary.get("R_global", r_global)))

    raw_findings = findings if findings is not None else []
    if files_data and not raw_findings:
        for file_entry in files_data:
            raw_findings.extend(file_entry.get("findings", []))

    effective_total = total_findings if total_findings > 0 else len(raw_findings)

    cursor.execute(
        """
        INSERT OR REPLACE INTO scans 
        (scan_id, source, target_path, mode, r_global, total_findings, timestamp) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (scan_id, source, effective_target, mode, r_global, effective_total, now_iso)
    )

    for f in raw_findings:
        f_id = f.get("FindingId") or f.get("finding_id") or f"fnd_{uuid.uuid4().hex[:8]}"
        file_p = f.get("FilePath") or f.get("file_path", "")
        r_id = f.get("RuleId") or f.get("rule_id", "UNKNOWN")
        r_title = f.get("RuleTitle") or f.get("rule_title", "")
        sev = f.get("Severity") or f.get("severity", "MEDIUM")
        res_type = f.get("resource_type", f.get("ResourceType", "default"))
        line_num = f.get("LineNumber") or f.get("line_number", 0)
        snippet = f.get("CodeSnippet") or f.get("code_snippet", "")
        hint = f.get("RemediationHint") or f.get("remediation_hint", "")
        stat = f.get("Status") or f.get("status", "VULNERABLE")
        r_file = f.get("R_file", f.get("r_file", 0.0))

        cursor.execute(
            """
            INSERT OR REPLACE INTO findings 
            (finding_id, scan_id, file_path, rule_id, rule_title, severity, 
             resource_type, line_number, code_snippet, remediation_hint, r_file, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (f_id, scan_id, file_p, r_id, r_title, sev, res_type, line_num, snippet, hint, r_file, stat)
        )

    conn.commit()
    conn.close()


def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
    scan_row = cursor.fetchone()

    if not scan_row:
        conn.close()
        return None

    scan_dict = dict(scan_row)
    cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
    scan_dict["findings"] = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return scan_dict


def get_finding_by_id(finding_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def record_patch_event(finding_id: str, backup_path: str) -> str:
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    event_id = f"evt_{uuid.uuid4().hex[:8]}"

    cursor.execute("UPDATE findings SET status = 'PATCHED' WHERE finding_id = ?", (finding_id,))
    cursor.execute(
        "INSERT OR REPLACE INTO patch_events (event_id, finding_id, backup_path, timestamp) VALUES (?, ?, ?, ?)",
        (event_id, finding_id, backup_path, now_iso)
    )

    conn.commit()
    conn.close()
    return event_id


def get_replay_sequence(scan_id: str) -> List[Dict[str, Any]]:
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


def record_event(
    event_type: str,
    pr_number: Optional[int] = None,
    repository: Optional[str] = None,
    commit_sha: Optional[str] = None,
    finding_id: Optional[str] = None,
    target_file: Optional[str] = None,
    rule_id: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None
) -> str:
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    event_id = f"evt_{uuid.uuid4().hex[:8]}"

    payload_str = json.dumps(payload) if payload else "{}"

    cursor.execute(
        """
        INSERT INTO timeline_events 
        (event_id, event_type, pr_number, repository, commit_sha, finding_id, target_file, rule_id, payload, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (event_id, event_type, pr_number, repository, commit_sha, finding_id, target_file, rule_id, payload_str, now_iso)
    )

    conn.commit()
    conn.close()
    return event_id


def get_all_scans() -> List[Dict[str, Any]]:
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT scan_id, source, target_path, mode, total_findings, r_global, timestamp FROM scans ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_baseline(scan_id: str) -> float:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT pre_risk_score FROM pipeline_runs WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        return row[0] if row else 0.0

def log_post_scan(scan_id: str, pre_risk: float, post_risk: float, payload: list):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            REPLACE INTO pipeline_runs (scan_id, pre_risk_score, post_risk_score, triage_payload)
            VALUES (?, ?, ?, ?)
        """, (scan_id, pre_risk, post_risk, json.dumps(payload)))