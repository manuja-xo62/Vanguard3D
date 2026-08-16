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
    