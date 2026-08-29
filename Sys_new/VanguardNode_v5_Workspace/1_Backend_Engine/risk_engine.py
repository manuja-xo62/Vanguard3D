import fnmatch
import yaml
from pathlib import Path
from typing import Dict, List, Any, Union

CONFIG_PATH = Path(__file__).parent / "vanguard_config.yml"


def load_config(config_path: str = str(CONFIG_PATH)) -> Dict[str, Any]:
    cfg_file = Path(config_path)
    if not cfg_file.exists():
        return {
            "severity_weights": {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 15},
            "exposure_multiplier": {"internet_facing": 2.0, "internal_only": 1.0},
            "blast_radius_weights": {"iam_role": 3.0, "security_group": 2.0, "storage_bucket": 2.0, "default": 1.0},
            "criticality_weights": {"prod/**": 3.0, "staging/**": 1.5, "**": 1.0},
            "remediation_templates": {
                "CKV_AWS_20": {
                    "search_pattern": r'acl\s*=\s*"public-read"',
                     "patch_text": 'acl    = "private" # [VANGUARD NANO-PATCH APPLIED]',
                    "type": "replace"
            },
                "CKV_AWS_21": {
                    "search_pattern": r'(resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{)',
                    "patch_text": r'\1' + "\n  versioning {\n    enabled = true\n  } # [VANGUARD NANO-PATCH APPLIED]",
                    "type": "replace"
            },
                "CKV_DOCKER_3": {
                    "action": "insert_user",
                    "patch_text": "USER vanguard_svc # [VANGUARD NANO-PATCH APPLIED]\n",
                    "type": "insert"
            }
            }
        }

    try:
        with open(cfg_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[Risk Engine Warning] Failed to parse config file '{config_path}': {e}")
        return load_config("non_existent_path_to_trigger_fallback")


def is_internet_facing(finding: Dict[str, Any]) -> bool:
    rule_id = str(finding.get("RuleId") or finding.get("rule_id") or "")
    rule_title = str(finding.get("RuleTitle") or finding.get("rule_title") or "").lower()
    resource_type = str(finding.get("ResourceType") or finding.get("resource_type") or "").lower()

    public_indicators = ["public", "0.0.0.0/0", "acl", "exposure", "unauthenticated"]
    if any(ind in rule_id.lower() or ind in rule_title for ind in public_indicators):
        return True
    if "s3_bucket" in resource_type and ("acl" in rule_id.lower() or "read" in rule_title):
        return True

    return False


def get_file_criticality(file_path: str, criticality_weights: Dict[str, float]) -> float:
    normalized_path = file_path.replace("\\", "/").lstrip("/")

    sorted_patterns = sorted(
        criticality_weights.items(),
        key=lambda item: (item[0] == "**", item[0] == "*", -len(item[0]))
    )

    for pattern, weight in sorted_patterns:
        if fnmatch.fnmatch(normalized_path, pattern) or fnmatch.fnmatch(Path(normalized_path).name, pattern):
            return weight
    return criticality_weights.get("**", 1.0)


def calculate_risk(findings: Union[List[Dict[str, Any]], Dict[str, Any]], config_path: str = str(CONFIG_PATH)) -> Dict[str, Any]:
    if isinstance(findings, dict):
        findings = findings.get("Findings") or findings.get("findings") or []

    config = load_config(config_path)
    sev_weights = config.get("severity_weights", {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 15})
    exp_mult = config.get("exposure_multiplier", {"internet_facing": 2.0, "internal_only": 1.0})
    blast_weights = config.get("blast_radius_weights", {"default": 1.0})
    crit_weights = config.get("criticality_weights", {"**": 1.0})

    files_map: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        f_path = f.get("FilePath") or f.get("file_path") or "unknown"
        files_map.setdefault(f_path, []).append(f)

    file_results = []
    total_weighted_risk = 0.0
    total_criticality_sum = 0.0

    for file_path, file_findings in files_map.items():
        r_file = 0.0
        processed_findings = []

        for finding in file_findings:
            status = str(finding.get("Status") or finding.get("status") or "VULNERABLE").upper()
            severity = str(finding.get("Severity") or finding.get("severity") or "MEDIUM").upper()
            w_sev = sev_weights.get(severity, 3)

            facing = "internet_facing" if is_internet_facing(finding) else "internal_only"
            w_exp = exp_mult.get(facing, 1.0)

            res_type = str(finding.get("ResourceType") or finding.get("resource_type") or "default").lower()
            w_blast = blast_weights.get("default", 1.0)
            for k, val in blast_weights.items():
                if k in res_type:
                    w_blast = val
                    break

            finding_score = w_sev * w_exp * w_blast

            # Correct arithmetic inversion: Do not calculate risk for remediated findings
            if status != "PATCHED":
                r_file += finding_score

            finding_copy = finding.copy()
            finding_copy["computed_score"] = finding_score
            finding_copy["exposure"] = facing
            finding_copy["r_file"] = finding_score
            processed_findings.append(finding_copy)

        w_crit = get_file_criticality(file_path, crit_weights)

        file_results.append({
            "file_path": file_path,
            "FilePath": file_path,
            "findings_count": len(file_findings),
            "R_file": round(r_file, 2),
            "r_file": round(r_file, 2),
            "file_criticality": w_crit,
            "findings": processed_findings
        })

        total_weighted_risk += (r_file * w_crit)
        total_criticality_sum += w_crit

    r_global = round(total_weighted_risk / total_criticality_sum, 2) if total_criticality_sum > 0 else 0.0

    return {
        "R_global": r_global,
        "r_global": r_global,
        "files": file_results
    }