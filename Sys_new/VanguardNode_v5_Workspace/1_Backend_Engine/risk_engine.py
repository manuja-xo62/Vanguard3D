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