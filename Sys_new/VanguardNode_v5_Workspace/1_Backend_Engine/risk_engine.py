import fnmatch
import yaml
from pathlib import Path
from typing import Dict, List, Any, Union


def load_config(config_path: str = "vanguard_config.yml") -> Dict[str, Any]:
    """Loads the editable risk weighting configuration file."""
    cfg_file = Path(config_path)
    if not cfg_file.exists():
        return {
            "severity_weights": {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 15},
            "exposure_multiplier": {"internet_facing": 2.0, "internal_only": 1.0},
            "blast_radius_weights": {"iam_role": 3.0, "security_group": 2.0, "storage_bucket": 2.0, "default": 1.0},
            "criticality_weights": {"prod/**": 3.0, "staging/**": 1.5, "**": 1.0}
        }
    
    with open(cfg_file, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def is_internet_facing(finding: Dict[str, Any]) -> bool:
    """Detects exposure from Checkov resource metadata or rule characteristics."""
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
    """Matches file path against wildcard patterns in criticality weights, prioritizing specific rules over catch-alls."""
    normalized_path = file_path.replace("\\", "/").lstrip("/")
    
    # Sort patterns so universal wildcards ('**') are always evaluated last regardless of YAML key insertion order
    sorted_patterns = sorted(
        criticality_weights.items(),
        key=lambda item: (item[0] == "**", item[0] == "*", -len(item[0]))
    )
    
    for pattern, weight in sorted_patterns:
        if fnmatch.fnmatch(normalized_path, pattern) or fnmatch.fnmatch(Path(normalized_path).name, pattern):
            return weight
    return criticality_weights.get("**", 1.0)


def calculate_risk(findings: Union[List[Dict[str, Any]], Dict[str, Any]], config_path: str = "vanguard_config.yml") -> Dict[str, Any]:
    """
    Applies the deterministic risk formula across all findings and files:
    R_file = Σ (w_severity * w_exposure * w_blast_radius)
    R_global = Σ (R_file * w_criticality) / Σ (w_criticality)
    """
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
            r_file += finding_score

            finding_copy = finding.copy()
            finding_copy["computed_score"] = finding_score
            finding_copy["exposure"] = facing
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


if __name__ == "__main__":
    import sys
    import json
    from checkov_parser import run_checkov_scan

    target_dir = "../sample_repo" if len(sys.argv) < 2 else sys.argv[1]
    print(f"--- Testing Risk Engine against '{target_dir}' ---")
    try:
        raw_findings = run_checkov_scan(target_dir)
        risk_output = calculate_risk(raw_findings)
        print(json.dumps(risk_output, indent=2))
    except Exception as e:
        print(f"Risk Engine Test Failed: {e}")