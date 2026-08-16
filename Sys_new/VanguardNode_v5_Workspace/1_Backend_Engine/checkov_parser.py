import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Dict, List, Any


def parse_checkov_finding(raw_check: Dict[str, Any], target_dir: str) -> Dict[str, Any]:
    ##Normalizes single Checkov findings into the app's standard data structure
    file_abs = raw_check.get("file_path", "")
    try:
        rel_path = str(Path(file_abs).relative_to(Path(target_dir).resolve()))
    except ValueError:
        rel_path = file_abs.lstrip("/")

    severity = raw_check.get("severity") or "MEDIUM"
    file_line_range = raw_check.get("file_line_range", [0, 0])

    return {
        "finding_id": f"fnd_{uuid.uuid4().hex[:8]}",
        "rule_id": raw_check.get("check_id", "UNKNOWN_RULE"),
        "rule_title": raw_check.get("check_name", "Unspecified Configuration Issue"),
        "severity": severity.upper(),
        "file_path": rel_path,
        "resource_type": raw_check.get("resource", "default"),
        "file_line_range": file_line_range,
        "code_block": raw_check.get("code_block", []),
        "status": "open"
    }


def run_checkov_scan(target_dir: str) -> List:
    ##Executes Checkov CLI against the target directory and returns structured findings
    target_path = Path(target_dir).resolve()
    
    if not target_path.exists():
        raise FileNotFoundError(f"Target directory does not exist: {target_dir}")

    target_path_str = str(target_path)

    # Dynamically resolve checkov path or fall back to module execution
    checkov_bin = shutil.which("checkov")
    if checkov_bin:
        cmd = [checkov_bin, "-d", target_path_str, "-o", "json", "--quiet"]
    else:
        # Fallback: Run via active python interpreter module
        cmd = [sys.executable, "-m", "checkov.main", "-d", target_path_str, "-o", "json", "--quiet"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False
        )
    except Exception as e:
        raise RuntimeError(f"Failed to execute Checkov subprocess: {e}")

    raw_output = result.stdout.strip()
    if not raw_output:
        if result.stderr:
            print(f"[Checkov Parser Warning] Stderr: {result.stderr}")
        return []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        print("[Checkov Parser Error] Failed to parse JSON output from Checkov.")
        return []

    parsed_findings = []

    # Checkov returned a list (multiple frameworks)
    if isinstance(data, list):
        for framework_results in data:
            results_obj = framework_results.get("results", {})
            failed_checks = results_obj.get("failed_checks", [])
            for check in failed_checks:
                parsed_findings.append(parse_checkov_finding(check, target_path_str))

    # Checkov returned a single dict (single framework)
    elif isinstance(data, dict):
        results_obj = data.get("results", {})
        failed_checks = results_obj.get("failed_checks", [])
        for check in failed_checks:
            parsed_findings.append(parse_checkov_finding(check, target_path_str))

    return parsed_findings


if __name__ == "__main__":
    test_dir = "../sample_repo" if len(sys.argv) < 2 else sys.argv[1]
    print(f"--- Testing Checkov Parser against '{test_dir}' ---")
    try:
        findings = run_checkov_scan(test_dir)
        print(f"Successfully extracted {len(findings)} findings:\n")
        print(json.dumps(findings, indent=2))
    except Exception as e:
        print(f"Parser Test Failed: {e}")