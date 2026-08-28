import json
import shutil
import subprocess
import sys
import uuid
import re
from pathlib import Path
from typing import Dict, List, Any
from risk_engine import load_config


def parse_checkov_finding(raw_check: Dict[str, Any], target_dir: str) -> Dict[str, Any]:
    file_abs = raw_check.get("file_path", "")
    try:
        rel_path = str(Path(file_abs).relative_to(Path(target_dir).resolve()))
    except ValueError:
        rel_path = file_abs.lstrip("/")

    file_line_range = raw_check.get("file_line_range", [0, 0])
    line_num = file_line_range[0] if file_line_range else 0

    rule_id = str(raw_check.get("check_id", "UNKNOWN_RULE"))
    code_block = raw_check.get("code_block", "")

    # Look up remediation search pattern to locate the exact line of the finding
    config = load_config()
    template = config.get("remediation_templates", {}).get(rule_id, {})
    search_pattern = template.get("search_pattern")

    precise_line = None
    if isinstance(code_block, list):
        code_lines = []
        for item in code_block:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                code_lines.append((item[0], item[1]))
            elif isinstance(item, str):
                code_lines.append((0, item))

        if search_pattern:
            try:
                pattern = re.compile(search_pattern)
                for l_no, l_str in code_lines:
                    if pattern.search(l_str):
                        precise_line = l_no
                        break
            except re.error:
                pass

        code_snippet_str = "".join([l_str for _, l_str in code_lines])
    else:
        code_snippet_str = str(code_block)

    if precise_line is not None and precise_line > 0:
        line_num = precise_line

    raw_sev = raw_check.get("severity")
    severity = str(raw_sev).capitalize() if raw_sev and str(raw_sev).lower() != "none" else "Medium"

    return {
        "FindingId": f"fnd_{uuid.uuid4().hex[:8]}",
        "RuleId": rule_id,
        "RuleTitle": str(raw_check.get("check_name", "Unspecified Configuration Issue")),
        "Severity": severity,
        "FilePath": rel_path,
        "LineNumber": int(line_num),
        "Status": "VULNERABLE",
        "CodeSnippet": code_snippet_str,
        "RemediationHint": str(raw_check.get("guideline", "Review configuration guidelines."))
    }


def run_checkov_scan(target_dir: str) -> Dict[str, Any]:
    target_path = Path(target_dir).resolve()

    if not target_path.exists():
        raise FileNotFoundError(f"Target directory does not exist: {target_dir}")

    target_path_str = str(target_path)
    checkov_bin = shutil.which("checkov")

    if checkov_bin:
        cmd = [checkov_bin, "-d", target_path_str, "-o", "json", "--quiet"]
    else:
        cmd = [sys.executable, "-m", "checkov.main", "-d", target_path_str, "-o", "json", "--quiet"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=False)
    except Exception as e:
        raise RuntimeError(f"Failed to execute Checkov subprocess: {e}")

    raw_output = result.stdout.strip()
    if not raw_output:
        return {"ScanId": f"scan_{uuid.uuid4().hex[:8]}", "TotalFindings": 0, "Findings": []}

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return {"ScanId": f"scan_{uuid.uuid4().hex[:8]}", "TotalFindings": 0, "Findings": []}

    parsed_findings = []

    if isinstance(data, list):
        for framework_results in data:
            results_obj = framework_results.get("results", {})
            for check in results_obj.get("failed_checks", []):
                parsed_findings.append(parse_checkov_finding(check, target_path_str))
    elif isinstance(data, dict):
        results_obj = data.get("results", {})
        for check in results_obj.get("failed_checks", []):
            parsed_findings.append(parse_checkov_finding(check, target_path_str))

    return {
        "ScanId": f"scan_{uuid.uuid4().hex[:8]}",
        "TotalFindings": len(parsed_findings),
        "Findings": parsed_findings
    }