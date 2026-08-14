import fnmatch
import yaml
from pathlib import Path
from typing import Dict, List, Any

def load_config(config_path: str = "vanguard_config.yml") -> Dict[str,Any]:
    #Loads the editable risk weighting configuration file
    cfg_file = Path(config_path)
    if not cfg_file.exists():
        #fallback default values if config is missing
        return{
            "severity_weights": {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 15},
            "exposure_multiplier": {"internet_facing": 2.0, "internal_only": 1.0},
            "blast_radius_weights": {"iam_role": 3.0, "security_group": 2.0, "storage_bucket": 2.0, "default": 1.0},
            "criticality_weights": {"prod/**": 3.0, "staging/**": 1.5, "**": 1.0}
        }
    with open(cfg_file, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def is_internet_facing(finding: Dict[str, Any]) -> bool:
    #Detects exposure from chekhov resource metadata or rule characterists

    rule_id = finding.get("rule_id", "")
    rule_title = finding.get("rule_title", "").lower()
    resource_type = finding.get(resource_type, "").lower()

    #Known rules or indicators
    public_indicators = ["public", "0.0.0.0/0", "acl", "exposure", "unauthenticated"]
    if any(ind in rule_id.lower() or ind in rule_title for ind in public_indicators):
        return True
    if "s3_bucket" in resource_type and ("acl" in rule_id.lower() or "read" in rule_title):
        return True

    return False

def get_file_criticality(file_path: str, criticality_weights: Dict[str,float]) -> float:
    #matching file path to the wildcard patterns in crticality weights

    #nnormalizing path seperators
    normalized_path = file_path.replace("\\", "/"). lstrip("/")

    for pattern, weight in criticality_weights.items():
        if fnmatch.fnmatch(normalized_path, pattern) or fnmatch.fnmatch(Path(normalized_path).name, pattern):
            return weight
        return criticality_weights.get("**", 1.0)


