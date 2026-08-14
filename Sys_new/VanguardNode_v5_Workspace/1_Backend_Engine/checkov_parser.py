import json
import subprocess
import uuid
from pathlib import Path
from typing import Dict, List, Any

def parse_checkhov_finding(raw_check: Dict[str, Any], target_dir: str) -> Dict[str, Any]:
    #normalizing single chekhov findings into the app's standard data structure

    #extracting file path relative to the target_dir if it is possible
    file_abs = raw_check.get("file_path", "")
    try:
        rel_path = str(Path(file_abs). relative_to(Path(target_dir). resolve()))
    except ValueError:
        #fallback : if path manipation fails
        rel_path = file_abs.lstrip("/")
    
    #chekhov severity might be missing
    severity = raw_check.get("severity") or "MEDIUM"

    #extract line lange for path_service ASt targeting funciton
    file_line_range = raw_check.get("file_line_range", [0,0])

    return{
        "finding_id": f"find_{uuid.uuid4().hex[:8]}",
        "rule_id": raw_check.get("check_id", "UNKNOWN_RULE"),
        "rule_title": raw_check.get("check_name", "Unspecified Configuration Issue"),
        "severity" : severity.upper(),
        "file_path": rel_path,
        "resource_type": raw_check.get("resource", "defualt"),
        "file_line_range": file_line_range,
        "code_block": raw_check.get("code_block", []),
        "status": "open"
    }