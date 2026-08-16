import os
import shutil
import re
from pathlib import Path
from typing import Dict, Any, Tuple

# CIS-compliant remediation templates
REMEDIATION_TEMPLATES = {
    "CKV_AWS_20": {
        "search_pattern": r'acl\s*=\s*"public-read"',
        "patch_text": 'acl    = "private" # [VANGUARD NANO-PATCH APPLIED]',
        "check_already_patched": lambda content: "VANGUARD NANO-PATCH APPLIED" in content or 'acl    = "private"' in content
    },
    "CKV_DOCKER_3": {
        "action": "insert_user",
        "patch_text": "USER vanguard_svc # [VANGUARD NANO-PATCH APPLIED]\n",
        "check_already_patched": lambda content: "USER " in content.upper() or "VANGUARD NANO-PATCH APPLIED" in content
    }
}

def create_backup(file_path: Path) -> Path:
    ##Creates a zero-trust backup of the target file before mutation.
    backup_path = file_path.with_name(file_path.name + ".vanguard_backup")
    try:
        shutil.copy2(file_path, backup_path)
        return backup_path
    except Exception as e:
        raise RuntimeError(f"FATAL: Backup creation failed for {file_path}. Aborting patch. Error: {e}")

def apply_patch(target_dir: str, file_path_rel: str, rule_id: str, line_range: list) -> Tuple[bool, str]:
    #Executes the strict zero-trust patching sequence with Idempotency checks.

    target_path = Path(target_dir).resolve()
    file_path = (target_path / file_path_rel.lstrip("\\/")).resolve()

    if not file_path.exists():
        return False, f"File not found: {file_path}"

    if rule_id not in REMEDIATION_TEMPLATES:
        return False, f"No nano-patch template available for rule: {rule_id}"

    with open(file_path, 'r', encoding='utf-8') as f:
        file_content = f.read()

    template = REMEDIATION_TEMPLATES[rule_id]

    # check If file is already patched or compliant, terminate safely.
    if template.get("check_already_patched") and template["check_already_patched"](file_content):
        return True, f"File {file_path_rel} is already compliant. No patch required."

    # Zero-trust backup creation
    try:
        backup_path = create_backup(file_path)
    except RuntimeError as e:
        return False, str(e)

    lines = file_content.splitlines(keepends=True)
    start_line_idx = max(0, line_range[0] - 1)
    end_line_idx = min(len(lines), line_range[1])

    patch_applied = False

    # Apply AST-targeted modification
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
            os.remove(backup_path) # Clean up redundant backup
        return False, "Failed to locate mutable target line within AST range."

    #Write back modified lines
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
    except Exception as e:
        shutil.copy2(backup_path, file_path)
        return False, f"Failed to save patched file. Rolled back to backup. Error: {e}"

    return True, str(backup_path)


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