import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Dict, List, Any


def parse_checkov_finding(raw_check: Dict[str, Any], target_dir: str) -> Dict[str, Any]:
    ##Normalizes a single Checkov finding into the exact PascalCase keys required by the front end.

    file_abs = raw_check.get("file_path", "")
    try:
        rel_path = str(Path(file_abs).relative_to(Path(target_dir).resolve()))
    except ValueError:
        rel_path = file_abs.lstrip("/")

    # Safe extraction of line number
    file_line_range = raw_check.get("file_line_range", [0, 0])
    line_num = file_line_range[0] if file_line_range else 0

    # Code block to string extraction
    code_block = raw_check.get("code_block", "")
    if isinstance(code_block, list):
        code_snippet_str = "".join([line[1] for line in code_block if len(line) > 1])
    else:
        code_snippet_str = str(code_block)

    # Key names match FVanguardFinding in C++ exactly
    return {
        "FindingId": f"fnd_{uuid.uuid4().hex[:8]}",
        "RuleId": str(raw_check.get("check_id", "UNKNOWN_RULE")),
        "RuleTitle": str(raw_check.get("check_name", "Unspecified Configuration Issue")),
        "Severity": str(raw_check.get("severity", "HIGH")).capitalize(),
        "FilePath": rel_path,
        "LineNumber": int(line_num),
        "Status": "VULNERABLE",
        "CodeSnippet": code_snippet_str,
        "RemediationHint": str(raw_check.get("guideline", "Review configuration guidelines."))
    }


def run_checkov_scan(target_dir: str) -> Dict[str, Any]:
    ##Executes Checkov CLI against the target directory and returns a structured payload matching the front end requirements.

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
        return {
            "ScanId": f"scan_{uuid.uuid4().hex[:8]}",
            "TotalFindings": 0,
            "Findings": []
        }

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        print("[Checkov Parser Error] Failed to parse JSON output from Checkov.")
        return {
            "ScanId": f"scan_{uuid.uuid4().hex[:8]}",
            "TotalFindings": 0,
            "Findings": []
        }

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

    # Returns exact match for FVanguardScanPayload
    return {
        "ScanId": f"scan_{uuid.uuid4().hex[:8]}",
        "TotalFindings": len(parsed_findings),
        "Findings": parsed_findings
    }


if __name__ == "__main__":
    test_dir = "../sample_repo" if len(sys.argv) < 2 else sys.argv[1]
    print(f"--- Testing Checkov Parser against '{test_dir}' ---")
    try:
        payload = run_checkov_scan(test_dir)
        print(f"Successfully extracted {payload['TotalFindings']} findings:\n")
        print(json.dumps(payload, indent=2))
    except Exception as e:
        print(f"Parser Test Failed: {e}")