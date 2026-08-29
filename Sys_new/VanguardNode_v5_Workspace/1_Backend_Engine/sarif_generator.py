import json
from typing import Dict, Any, List

def severity_to_sarif_level(severity: str) -> str:
    sev = str(severity).upper()
    if sev in ["CRITICAL", "HIGH"]:
        return "error"
    elif sev == "MEDIUM":
        return "warning"
    elif sev == "LOW":
        return "note"
    return "none"

def generate_sarif_report(scan_data: Dict[str, Any]) -> str:
    """
    Converts Vanguard scan data from the database into a standard SARIF v2.1.0 JSON string.
    """
    findings: List[Dict[str, Any]] = scan_data.get("findings", [])
    scan_id: str = scan_data.get("scan_id", "unknown_scan")

    rules_map = {}
    results = []

    for finding in findings:
        rule_id = finding.get("rule_id") or "UNKNOWN_RULE"
        rule_title = finding.get("rule_title") or "Unspecified Security Issue"
        severity = finding.get("severity") or "MEDIUM"
        file_path = finding.get("file_path") or "unknown_file"
        line_number = max(1, int(finding.get("line_number") or 1))
        remediation_hint = finding.get("remediation_hint") or "No remediation hint available."
        code_snippet = finding.get("code_snippet") or ""

        # Aggregate dynamic rule definitions
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": rule_title},
                "fullDescription": {"text": f"{rule_title} - Vanguard Security Engine Rule"},
                "help": {"text": remediation_hint},
                "properties": {
                    "problem.severity": severity.lower()
                }
            }

        # Format individual SARIF result
        sarif_result = {
            "ruleId": rule_id,
            "level": severity_to_sarif_level(severity),
            "message": {
                "text": f"{rule_title}: Line {line_number} in {file_path}. {remediation_hint}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path.replace("\\", "/").lstrip("/")
                        },
                        "region": {
                            "startLine": line_number,
                            "snippet": {
                                "text": code_snippet
                            }
                        }
                    }
                }
            ]
        }
        results.append(sarif_result)

    sarif_structure = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Vanguard Security Engine",
                        "semanticVersion": "1.0.0",
                        "rules": list(rules_map.values())
                    }
                },
                "automationLogicalId": scan_id,
                "results": results
            }
        ]
    }

    return json.dumps(sarif_structure, indent=2)