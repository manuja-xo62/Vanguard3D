import os
import re
import shutil
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional
from risk_engine import load_config


def resolve_adaptive_range(lines: List[str], line_num: int, default_padding: int = 25) -> Tuple[int, int]:
    """Dynamically locates AST resource block boundaries ({ ... }) or falls back to an expanded window."""
    if line_num <= 0 or not lines:
        return 0, len(lines)

    start_idx = max(0, line_num - 1)
    end_idx = min(len(lines), line_num + default_padding)

    # Expand window forward until block end / closing brace balance is achieved
    open_braces = 0
    braces_found = False
    
    for idx in range(start_idx, len(lines)):
        line = lines[idx]
        open_count = line.count('{')
        close_count = line.count('}')
        if open_count > 0:
            braces_found = True
        open_braces += open_count - close_count
        
        if braces_found and open_braces <= 0 and idx >= start_idx:
            end_idx = idx + 1
            break

    # Look back slightly to ensure we didn't start after the resource declaration
    lookback_start = max(0, start_idx - 10)
    return lookback_start, end_idx


def is_already_patched(content: str, template: Dict[str, Any]) -> bool:
    """Generic check to verify if patch text or tag already exists."""
    if "[VANGUARD NANO-PATCH APPLIED]" in content:
        return True
    
    search_pattern = template.get("search_pattern")
    if search_pattern:
        # If search pattern is not in content, it might already be changed
        return not bool(re.search(search_pattern, content))
    return False


def create_backup(file_path: Path) -> Path:
    """Creates a zero-trust backup before mutation, preserving baseline state."""
    backup_path = file_path.with_name(file_path.name + ".vanguard_backup")
    if backup_path.exists():
        return backup_path
    try:
        shutil.copy2(file_path, backup_path)
        return backup_path
    except Exception as e:
        raise RuntimeError(f"FATAL: Backup creation failed for {file_path}. Aborting patch. Error: {e}")


def get_remediation_template(rule_id: str) -> Optional[Dict[str, Any]]:
    """Dynamically loads patch templates from configuration file."""
    config = load_config()
    templates = config.get("remediation_templates", {})
    return templates.get(rule_id)


def apply_patch(
    target_dir: str, 
    file_path_rel: str, 
    rule_id: str, 
    line_range: Optional[List[int]] = None, 
    line_num: int = 0
) -> Tuple[bool, str]:
    """Executes dynamic scope-aware zero-trust remediation."""
    target_path = Path(target_dir).resolve()
    file_path = (target_path / file_path_rel.lstrip("\\/")).resolve()

    if not str(file_path).startswith(str(target_path)):
        return False, f"Access denied: Target path '{file_path_rel}' escapes base directory."

    if not file_path.exists():
        return False, f"File not found: {file_path}"

    template = get_remediation_template(rule_id)
    if not template:
        return False, f"No remediation template registered for rule: {rule_id}"

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            file_content = f.read()
    except Exception as e:
        return False, f"Failed to read target file: {e}"

    lines = file_content.splitlines(keepends=True)

    # Adaptive Scope Window Calculation
    if line_range and len(line_range) == 2 and line_range != [0, 0]:
        start_line_idx, end_line_idx = line_range[0] - 1, line_range[1]
    elif line_num > 0:
        start_line_idx, end_line_idx = resolve_adaptive_range(lines, line_num)
    else:
        start_line_idx, end_line_idx = 0, len(lines)

    start_line_idx = max(0, start_line_idx)
    end_line_idx = min(len(lines), end_line_idx)

    patch_applied = False

    if "search_pattern" in template:
        pattern = re.compile(template["search_pattern"])
        for i in range(start_line_idx, end_line_idx):
            if i < len(lines) and pattern.search(lines[i]):
                lines[i] = pattern.sub(template["patch_text"], lines[i])
                patch_applied = True
                break

    elif template.get("action") == "insert_user":
        # Check if already patched
        if "vanguard_svc" in file_content or "[VANGUARD NANO-PATCH APPLIED]" in file_content:
            return True, f"File {file_path_rel} is already compliant."

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
        return False, f"Failed to locate mutable target line for {rule_id} within scope lines {start_line_idx+1}-{end_line_idx}."

    try:
        backup_path = create_backup(file_path)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
    except Exception as e:
        backup_path = file_path.with_name(file_path.name + ".vanguard_backup")
        if backup_path.exists():
            shutil.copy2(backup_path, file_path)
        return False, f"Failed to write patched file. Rolled back. Error: {e}"

    return True, f"Successfully patched {rule_id}"


def apply_patch_to_file(
    file_path: str, 
    rule_id: str, 
    line_range: Optional[List[int]] = None, 
    line_num: int = 0
) -> Tuple[bool, str]:
    """Wrapper function to interface cleanly with API endpoints and CLI calls."""
    path_obj = Path(file_path).resolve()
    if not path_obj.exists():
        return False, f"File not found: {file_path}"
        
    parent_dir = str(path_obj.parent)
    file_name = path_obj.name
    return apply_patch(parent_dir, file_name, rule_id, line_range=line_range, line_num=line_num)


def apply_sequential_patches(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Line Drift Mitigation Engine: Sorts findings descending by LineNumber."""
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

        if not f_path or not os.path.exists(f_path):
            results.append({"finding_id": f_id, "status": "FAILED", "reason": f"File not found: {f_path}"})
            continue

        path_obj = Path(f_path).resolve()
        success, msg = apply_patch(str(path_obj.parent), path_obj.name, r_id, line_num=line_num)
        
        if success:
            results.append({"finding_id": f_id, "status": "PATCHED", "details": msg})
        else:
            results.append({"finding_id": f_id, "status": "FAILED", "reason": msg})

    return results


def execute_rollback(target_dir: str, file_path_rel: str) -> dict:
    """Restores the original file from its backup."""
    base_dir = Path(target_dir).resolve()
    active_file = (base_dir / file_path_rel.lstrip("\\/")).resolve()
    
    if not str(active_file).startswith(str(base_dir)):
        return {"status": "error", "message": "Access denied: Path escapes target directory"}

    backup_file = active_file.with_name(active_file.name + ".vanguard_backup")

    if not backup_file.exists():
        return {"status": "failed", "message": f"No backup found for {file_path_rel}"}

    try:
        shutil.copy2(backup_file, active_file)
        os.remove(backup_file)
        return {"status": "success", "message": f"Successfully rolled back {file_path_rel}"}
    except Exception as e:
        return {"status": "error", "message": f"Rollback operation failed: {str(e)}"}