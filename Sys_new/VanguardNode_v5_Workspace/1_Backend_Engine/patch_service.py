import os
import re
import shutil
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional
from risk_engine import load_config


def resolve_adaptive_range(lines: List[str], line_num: int, default_padding: int = 25) -> Tuple[int, int]:
    if line_num <= 0 or not lines:
        return 0, len(lines)

    start_idx = max(0, line_num - 1)
    end_idx = min(len(lines), line_num + default_padding)

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

    lookback_start = max(0, start_idx - 10)
    return lookback_start, end_idx


def create_backup(file_path: Path) -> Path:
    backup_path = file_path.with_name(file_path.name + ".vanguard_backup")
    if backup_path.exists():
        return backup_path
    try:
        shutil.copy2(file_path, backup_path)
        return backup_path
    except Exception as e:
        raise RuntimeError(f"FATAL: Backup creation failed for {file_path}. Aborting patch. Error: {e}")


def get_remediation_template(rule_id: str) -> Optional[Dict[str, Any]]:
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
    target_path = Path(target_dir).resolve()
    file_path = (target_path / file_path_rel.lstrip("\\/")).resolve()

    try:
        file_path.relative_to(target_path)
    except ValueError:
        return False, f"Access denied: Target path escapes base directory."

    if not file_path.exists():
        return False, f"File not found: {file_path}"

    template = get_remediation_template(rule_id)
    if not template:
        # Safer fallback: appends a manual review flag instead of destructive replacement
        return False, f"No remediation template configured for rule {rule_id}"

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            file_content = f.read()
    except Exception as e:
        return False, f"Failed to read target file: {e}"

    lines = file_content.splitlines(keepends=True)

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
        # Implemented Multiline Regex Support
        flags = re.MULTILINE | re.DOTALL
        pattern = re.compile(template["search_pattern"], flags=flags)
        
        block_text = "".join(lines[start_line_idx:end_line_idx])
        if pattern.search(block_text):
            new_block = pattern.sub(template["patch_text"], block_text)
            # Ensure multi-line string replacement preserves individual line items
            new_lines = new_block.splitlines(keepends=True)
            lines[start_line_idx:end_line_idx] = new_lines
            patch_applied = True
            
        if not patch_applied:
            full_text = "".join(lines)
            if pattern.search(full_text):
                new_full_text = pattern.sub(template["patch_text"], full_text)
                lines.clear()
                lines.extend(new_full_text.splitlines(keepends=True))
                patch_applied = True

    elif template.get("action") == "insert_healthcheck":
        if "HEALTHCHECK" in file_content or "[VANGUARD NANO-PATCH APPLIED]" in file_content:
            return True, f"File {file_path_rel} already contains a healthcheck."

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

    elif template.get("action") == "insert_user":
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
        return False, f"Failed to locate mutable target line for {rule_id}."

    try:
        create_backup(file_path)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
    except Exception as e:
        backup_path = file_path.with_name(file_path.name + ".vanguard_backup")
        if backup_path.exists():
            shutil.copy2(backup_path, file_path)
        return False, f"Failed to write patched file. Rolled back. Error: {e}"

    return True, f"Successfully patched {rule_id}"


def execute_rollback(target_dir: str, file_path_rel: str) -> dict:
    base_dir = Path(target_dir).resolve()
    active_file = (base_dir / file_path_rel.lstrip("\\/")).resolve()

    try:
        active_file.relative_to(base_dir)
    except ValueError:
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