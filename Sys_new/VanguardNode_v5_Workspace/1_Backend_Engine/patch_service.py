import os
import shutil
import re
from pathlib import Path
from typing import Dict, Any, Tuple


def is_docker_user_patched(content: str) -> bool:
    ##Checks if a non-comment USER instruction or patch tag is present.
    if "VANGUARD NANO-PATCH APPLIED" in content:
        return True
    for line in content.splitlines():
        stripped = line.strip()
        # Ignore Dockerfile comments (#) and check for actual USER instruction
        if not stripped.startswith("#") and stripped.upper().startswith("USER "):
            return True
    return False


def is_s3_acl_patched(content: str) -> bool:
    ##Returns True only if ACL is set to private and no public-read remains.
    has_private = bool(re.search(r'acl\s*=\s*"private"', content))
    has_public = bool(re.search(r'acl\s*=\s*"public-read"', content))
    return has_private and not has_public


# CIS-compliant remediation templates
REMEDIATION_TEMPLATES = {
    "CKV_AWS_20": {
        "search_pattern": r'acl\s*=\s*"public-read"',
        "patch_text": 'acl    = "private" # [VANGUARD NANO-PATCH APPLIED]',
        "check_already_patched": is_s3_acl_patched
    },
    "CKV_DOCKER_3": {
        "action": "insert_user",
        "patch_text": "USER vanguard_svc # [VANGUARD NANO-PATCH APPLIED]\n",
        "check_already_patched": is_docker_user_patched
    }
}

#More rules will be added later


def create_backup(file_path: Path) -> Path:
    ##Creates a zero-trust backup of the target file before mutation.
    backup_path = file_path.with_name(file_path.name + ".vanguard_backup")
    try:
        shutil.copy2(file_path, backup_path)
        return backup_path
    except Exception as e:
        raise RuntimeError(f"FATAL: Backup creation failed for {file_path}. Aborting patch. Error: {e}")


def apply_patch(target_dir: str, file_path_rel: str, rule_id: str, line_range: list) -> Tuple[bool, str]:
   ##Executes the zero-trust patching sequence with comment-aware safeguards.
    target_path = Path(target_dir).resolve()
    file_path = (target_path / file_path_rel.lstrip("\\/")).resolve()

    if not file_path.exists():
        return False, f"File not found: {file_path}"

    if rule_id not in REMEDIATION_TEMPLATES:
        return False, f"No nano-patch template available for rule: {rule_id}"

    with open(file_path, 'r', encoding='utf-8') as f:
        file_content = f.read()

    template = REMEDIATION_TEMPLATES[rule_id]

    #Check idempotency using comment-aware logic
    if template.get("check_already_patched") and template["check_already_patched"](file_content):
        return True, f"File {file_path_rel} is already compliant. No patch required."

    #Zero-trust backup creation
    try:
        backup_path = create_backup(file_path)
    except RuntimeError as e:
        return False, str(e)

    lines = file_content.splitlines(keepends=True)
    start_line_idx = max(0, line_range[0] - 1)
    end_line_idx = min(len(lines), line_range[1])

    patch_applied = False

    #Apply AST-targeted modification
    if "search_pattern" in template:
        pattern = re.compile(template["search_pattern"])
        for i in range(start_line_idx, end_line_idx):
            if pattern.search(lines[i]):
                lines[i] = pattern.sub(template["patch_text"], lines[i])
                patch_applied = True
                break

    elif template.get("action") == "insert_user":
        for i in range(start_line_idx, end_line_idx):
            clean_line = lines[i].strip().upper()
            if clean_line.startswith("CMD") or clean_line.startswith("ENTRYPOINT"):
                lines.insert(i, template["patch_text"])
                patch_applied = True
                break
        
        if not patch_applied and lines:
            insert_idx = min(end_line_idx, len(lines))
            lines.insert(insert_idx, template["patch_text"])
            patch_applied = True

    if not patch_applied:
        if backup_path.exists():
            os.remove(backup_path)
        return False, "Failed to locate mutable target line within AST range."

    # Write back modified lines
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
    except Exception as e:
        shutil.copy2(backup_path, file_path)
        return False, f"Failed to save patched file. Rolled back to backup. Error: {e}"

    return True, str(backup_path)

def execute_rollback(target_dir: str, file_path_rel: str) -> dict:
    ##Restores the orginal file from the backup
    base_dir = Path(target_dir).resolve()
    active_file = base_dir / file_path_rel
    backup_file = base_dir / f"{file_path_rel}.vanguard_backup"

    if not backup_file.exists():
        return {
            "Status": "Failed",
             "message": f"No backup found for {file_path_rel}"
             }
    try:
        #overwrite the active patched file
        shutil.copy2(backup_file, active_file)

        return{
            "status": "success",
            "message": f"Successfully rolled back {file_path_rel} to its original state"
        }

    except Exception as e:
        return {
            "status": "error",
            "message": f"Rollback operation failed: {str(e)}"
        }



if __name__ == "__main__":
    import sys
    
    test_dir = "../sample_repo" if len(sys.argv) < 2 else sys.argv[1]
    print("--- Testing Idempotent Zero-Trust Patch Service ---")
    
    demo_payloads = [
        {"file": "main.tf", "rule": "CKV_AWS_20", "lines": [1, 8]},
        {"file": "Dockerfile", "rule": "CKV_DOCKER_3", "lines": [1, 6]}
    ]
    
    for payload in demo_payloads:
        print(f"\nAttempting to patch {payload['rule']} in {payload['file']}...")
        success, msg = apply_patch(test_dir, payload["file"], payload["rule"], payload["lines"])
        if success:
            print(f"[STATUS] {msg}")
        else:
            print(f"[FAILED] {msg}")