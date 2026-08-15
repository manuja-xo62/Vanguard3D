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
def create_backup(file_path: Path) -> Path:
    #creates a backup of the target file first. It needs to succeed before any patch is applied.
    backup_path = file_path.with_name(file_path.name + ".vanguard_backup")
    try:
        shutil.copy2(file_path, backup_path)
        return backup_path
    except Exception as e:
        #abort entirely if this copy fails
        raise RuntimeError(f"FATAL: Backup creation failed for {file_path}. Aborting patch. Error: {e}")
