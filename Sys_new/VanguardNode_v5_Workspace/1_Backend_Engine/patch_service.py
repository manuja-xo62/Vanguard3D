import os
import re
import shutil
from pathlib import Path
from typing import Dict, Any, Tuple, List


def is_docker_user_patched(content: str) -> bool:
    """Checks if a non-comment USER instruction or patch tag is present."""
    if "VANGUARD NANO-PATCH APPLIED" in content:
        return True
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped.startswith("#") and stripped.upper().startswith("USER "):
            return True
    return False


def is_s3_acl_patched(content: str) -> bool:
    """Returns True only if ACL is set to private and no public-read remains."""
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
    },
}


def create_backup(file_path: Path) -> Path:
    """Creates a zero-trust backup before mutation, preserving the initial unpatched backup across multi-patch calls."""
    backup_path = file_path.with_name(file_path.name + ".vanguard_backup")
    if backup_path.exists():
        # Preserve original backup to avoid overwriting unpatched baseline
        return backup_path
    try:
        shutil.copy2(file_path, backup_path)
        return backup_path
    except Exception as e:
        raise RuntimeError(f"FATAL: Backup creation failed for {file_path}. Aborting patch. Error: {e}")


def apply_patch(target_dir: str, file_path_rel: str, rule_id: str, line_range: list) -> Tuple[bool, str]:
    """Executes the zero-trust patching sequence with comment-aware safeguards and strict path checks."""
    target_path = Path(target_dir).resolve()
    file_path = (target_path / file_path_rel.lstrip("\\/")).resolve()

    # Prevent directory traversal attacks
    if not str(file_path).startswith(str(target_path)):
        return False, f"Access denied: Target path '{file_path_rel}' escapes base directory."

    if not file_path.exists():
        return False, f"File not found: {file_path}"

    if rule_id not in REMEDIATION_TEMPLATES:
        return False, f"No nano-patch template available for rule: {rule_id}"

    with open(file_path, 'r', encoding='utf-8') as f:
        file_content = f.read()

    template = REMEDIATION_TEMPLATES[rule_id]

    if template.get("check_already_patched") and template["check_already_patched"](file_content):
        return True, f"File {file_path_rel} is already compliant. No patch required."

    try:
        backup_path = create_backup(file_path)
    except RuntimeError as e:
        return False, str(e)

    lines = file_content.splitlines(keepends=True)
    
    # Fallback to full file if line_range is missing or invalid
    if not line_range or len(line_range) < 2 or line_range == [0, 0]:
        start_line_idx = 0
        end_line_idx = len(lines)
    else:
        start_line_idx = max(0, line_range[0] - 1)
        end_line_idx = min(len(lines), line_range[1])

    patch_applied = False

    if "search_pattern" in template:
        pattern = re.compile(template["search_pattern"])
        for i in range(start_line_idx, end_line_idx):
            if i < len(lines) and pattern.search(lines[i]):
                lines[i] = pattern.sub(template["patch_text"], lines[i])
                patch_applied = True
                break

    elif template.get("action") == "insert_user":
        for i in range(start_line_idx, end_line_idx):
            if i < len(lines):
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
        return False, "Failed to locate mutable target line within AST range."

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
    except Exception as e:
        if backup_path.exists():
            shutil.copy2(backup_path, file_path)
        return False, f"Failed to save patched file. Rolled back to backup. Error: {e}"

    return True, f"Successfully patched {rule_id}"


def apply_patch_to_file(file_path: str, rule_id: str, line_range: list = None) -> Tuple[bool, str]:
    """Wrapper function to interface cleanly with main.py API endpoint calls, accepting optional line_range."""
    path_obj = Path(file_path).resolve()
    if not path_obj.exists():
        return False, f"File not found: {file_path}"
        
    parent_dir = str(path_obj.parent)
    file_name = path_obj.name
    effective_range = line_range if line_range is not None else [0, 0]
    return apply_patch(parent_dir, file_name, rule_id, effective_range)


def apply_sequential_patches(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Line Drift Mitigation Engine: Sorts findings descending by LineNumber (bottom-to-top execution)."""
    sorted_findings = sorted(
        findings, 
        key=lambda f: f.get("LineNumber") or f.get("line_number") or 0, 
        reverse=True
    )

    results = []
    for finding in sorted_findings:
        f_id = finding.get("FindingId") or finding.get("finding_id", "UNKNOWN")
        f_path = finding.get("FilePath") or finding.get("file_path", "")
        r_id = finding.get("RuleId") or finding.get("rule_id", "")
        line_num = finding.get("LineNumber") or finding.get("line_number") or 0
        
        line_range = [line_num, line_num + 5] if line_num > 0 else [0, 0]

        if not f_path or not os.path.exists(f_path):
            results.append({"finding_id": f_id, "status": "FAILED", "reason": f"File not found: {f_path}"})
            continue

        path_obj = Path(f_path).resolve()
        success, msg = apply_patch(str(path_obj.parent), path_obj.name, r_id, line_range)
        if success:
            results.append({"finding_id": f_id, "status": "PATCHED", "details": msg})
        else:
            results.append({"finding_id": f_id, "status": "FAILED", "reason": msg})

    return results


def execute_rollback(target_dir: str, file_path_rel: str) -> dict:
    """Restores the original file from the backup."""
    base_dir = Path(target_dir).resolve()
    active_file = (base_dir / file_path_rel.lstrip("\\/")).resolve()
    
    if not str(active_file).startswith(str(base_dir)):
        return {"status": "error", "message": "Access denied: Path escapes target directory"}

    backup_file = active_file.with_name(active_file.name + ".vanguard_backup")

    if not backup_file.exists():
        return {
            "status": "failed",
            "message": f"No backup found for {file_path_rel}"
        }
    try:
        shutil.copy2(backup_file, active_file)
        os.remove(backup_file)

        return {
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