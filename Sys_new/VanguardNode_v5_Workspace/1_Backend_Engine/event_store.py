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