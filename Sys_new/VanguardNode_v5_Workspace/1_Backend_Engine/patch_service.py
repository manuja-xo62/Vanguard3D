import os
import shutil
from pathlib import Path
from typing import Dict, Any, Tuple

#dictionary mapping chekhov rule ids to speific fix logic
#the rules trigged by the testing files (for testing)

REMEDIATION_TEMPLATES = {
    "CKV_AWS_20": {
        "target_text": 'acl    = "public-read"',
        "patch_text": 'acl    = "private" # [VANGUARD NANO-PATCH APPLIED]'
    },
    "CKV_DOCKER_3": {
        "action": "insert_before_last",
        "patch_text": "USER vanguard_svc # [VANGUARD NANO-PATCH APPLIED]\n"
    }
}

#extra rules will be added later
