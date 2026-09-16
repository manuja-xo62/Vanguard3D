import os
import re
import shutil
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional
from risk_engine import load_config
_META_OR_TOO_GENERIC_KEYS = {'resource_type', 'type', 'kind', 'name', 'id', 'engine', 'provider', 'metadata', 'tags', 'labels', 'properties', 'config', 'settings'}
_NEGATIVE_PHRASE = re.compile('not\\s+(be\\s+)?enabled|should\\s+not|must\\s+not|\\bdisabled?\\b', re.IGNORECASE)
_POSITIVE_PHRASE = re.compile('\\benabled\\b|\\benable\\b|\\bbe\\s+true\\b', re.IGNORECASE)

def _looks_like_simple_enable_check(rule_title: str) -> bool:
    if not rule_title:
        return False
    if _NEGATIVE_PHRASE.search(rule_title):
        return False
    return bool(_POSITIVE_PHRASE.search(rule_title))

def _pick_boolean_attribute(rule_title: str, evaluated_keys: List[str]) -> Optional[str]:
    candidates = []
    for raw_key in evaluated_keys or []:
        if '[' in raw_key or '*' in raw_key:
            continue
        segments = raw_key.split('/')
        base = segments[0].strip()
        if not base or base in _META_OR_TOO_GENERIC_KEYS:
            continue
        if len(segments) > 1 and any(('-' in seg for seg in segments[1:])):
            continue
        if not re.fullmatch('[a-z][a-z0-9_]{2,}', base):
            continue
        candidates.append(base)
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    title_norm = (rule_title or '').lower()
    matches = [c for c in candidates if c.replace('_', ' ') in title_norm]
    return matches[0] if len(matches) == 1 else None

def try_generic_fix(rule_title: str, evaluated_keys: List[str]) -> Optional[Dict[str, str]]:
    if not _looks_like_simple_enable_check(rule_title):
        return None
    key = _pick_boolean_attribute(rule_title, evaluated_keys)
    if not key:
        return None
    patch_text = f'{key} = true # [VANGUARD AUTO-PATCH APPLIED - AUTO-GENERATED, PLEASE VERIFY]'
    return {'search_pattern': f'{re.escape(key)}\\s*=\\s*false', 'patch_text': patch_text, 'type': 'auto_generated'}

def resolve_adaptive_range(lines: List[str], line_num: int, default_padding: int=25) -> Tuple[int, int]:
    if line_num <= 0 or not lines:
        return (0, len(lines))
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
        if braces_found and open_braces <= 0 and (idx >= start_idx):
            end_idx = idx + 1
            break
    lookback_start = max(0, start_idx - 10)
    return (lookback_start, end_idx)

def create_backup(file_path: Path) -> Path:
    backup_path = file_path.with_name(file_path.name + '.vanguard_backup')
    if backup_path.exists():
        return backup_path
    try:
        shutil.copy2(file_path, backup_path)
        return backup_path
    except Exception as e:
        raise RuntimeError(f'FATAL: Backup creation failed for {file_path}. Aborting patch. Error: {e}')

def get_remediation_template(rule_id: str) -> Optional[Dict[str, Any]]:
    config = load_config()
    templates = config.get('remediation_templates', {})
    return templates.get(rule_id)

def _already_applied(patch_text: str, file_content: str) -> bool:
    if not re.search('\\\\\\d', patch_text):
        return patch_text.strip() in file_content
    decoded = patch_text.replace('\\n', '\n').replace('\\t', '\t')
    tail = re.split('\\\\\\d+', decoded)[-1]
    if '\n' in tail:
        tail = tail.split('\n', 1)[1]
    tail = tail.strip()
    return bool(tail) and tail in file_content

def _resolve_current_line(file_content: str, lines: List[str], line_num: int, code_snippet: str) -> int:
    if not code_snippet:
        return line_num
    anchor = code_snippet.strip().splitlines()[0].strip() if code_snippet.strip() else ''
    if not anchor:
        return line_num
    matches = [i for i, line in enumerate(lines) if line.strip() == anchor]
    if len(matches) == 1:
        return matches[0] + 1
    return line_num
REVIEW_TAG = '[VANGUARD REVIEW NEEDED]'

def _build_review_comment(rule_id: str, rule_title: str, remediation_hint: str, indent: str) -> str:
    hint = (remediation_hint or '').strip()
    if not hint or hint.lower() == 'none':
        hint = f"No guidance provided by Checkov for this rule - search checkov.io or the Checkov GitHub repo for '{rule_id}'."
    hint = ' '.join(hint.split())
    if len(hint) > 200:
        hint = hint[:197] + '...'
    title = (rule_title or '').strip()
    header = f'{rule_id} ({title})' if title else rule_id
    return f'{indent}# {REVIEW_TAG} {header}: {hint}\n'

def annotate_for_review(target_dir: str, file_path_rel: str, rule_id: str, rule_title: str='', remediation_hint: str='', line_num: int=0, code_snippet: str='') -> Tuple[bool, str]:
    target_path = Path(target_dir).resolve()
    file_path = (target_path / file_path_rel.lstrip('\\/')).resolve()
    try:
        file_path.relative_to(target_path)
    except ValueError:
        return (False, 'Access denied: Target path escapes base directory.')
    if not file_path.exists():
        return (False, f'File not found: {file_path}')
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            file_content = f.read()
    except Exception as e:
        return (False, f'Failed to read target file: {e}')
    if f'{REVIEW_TAG} {rule_id}' in file_content:
        return (True, f'File {file_path_rel} is already flagged for review for {rule_id}.')
    lines = file_content.splitlines(keepends=True)
    if line_num <= 0 or not lines:
        return (False, f'No line reference available to place a review comment for {rule_id}.')
    target_line_num = _resolve_current_line(file_content, lines, line_num, code_snippet)
    insert_idx = max(0, min(target_line_num - 1, len(lines)))
    anchor_line = lines[insert_idx] if insert_idx < len(lines) else lines[-1] if lines else ''
    indent = anchor_line[:len(anchor_line) - len(anchor_line.lstrip())]
    comment = _build_review_comment(rule_id, rule_title, remediation_hint, indent)
    lines.insert(insert_idx, comment)
    try:
        create_backup(file_path)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
    except Exception as e:
        backup_path = file_path.with_name(file_path.name + '.vanguard_backup')
        if backup_path.exists():
            shutil.copy2(backup_path, file_path)
        return (False, f'Failed to write review comment: {e}')
    return (True, f'Flagged {rule_id} for manual review at line {target_line_num} (see inline comment).')

def apply_patch(target_dir: str, file_path_rel: str, rule_id: str, line_range: Optional[List[int]]=None, line_num: int=0, rule_title: str='', evaluated_keys: Optional[List[str]]=None, code_snippet: str='') -> Tuple[bool, str]:
    target_path = Path(target_dir).resolve()
    file_path = (target_path / file_path_rel.lstrip('\\/')).resolve()
    try:
        file_path.relative_to(target_path)
    except ValueError:
        return (False, f'Access denied: Target path escapes base directory.')
    if not file_path.exists():
        return (False, f'File not found: {file_path}')
    template = get_remediation_template(rule_id)
    auto_generated = False
    if not template:
        template = try_generic_fix(rule_title, evaluated_keys or [])
        if not template:
            return (False, f"No remediation template configured for rule {rule_id}, and Vanguard couldn't confidently auto-generate one (needs manual review).")
        auto_generated = True
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            file_content = f.read()
    except Exception as e:
        return (False, f'Failed to read target file: {e}')
    lines = file_content.splitlines(keepends=True)
    patch_applied = False
    if 'search_pattern' in template:
        if _already_applied(template['patch_text'], file_content):
            return (True, f'File {file_path_rel} is already patched for {rule_id}.')
        flags = re.MULTILINE | re.DOTALL
        pattern = re.compile(template['search_pattern'], flags=flags)
        if pattern.search(file_content):
            new_file_content = pattern.sub(template['patch_text'], file_content, count=1)
            lines = new_file_content.splitlines(keepends=True)
            patch_applied = True
        else:
            patch_text = template['patch_text']
            has_backreference = bool(re.search('\\\\\\d', patch_text))
            if not has_backreference and line_num > 0 and lines:
                corrected_line_num = _resolve_current_line(file_content, lines, line_num, code_snippet)
                block_start, block_end = resolve_adaptive_range(lines, corrected_line_num)
                insert_idx = None
                for idx in range(max(0, corrected_line_num - 1), min(block_end, len(lines))):
                    if '{' in lines[idx]:
                        insert_idx = idx + 1
                        break
                if insert_idx is not None:
                    if _already_applied(patch_text, file_content):
                        return (True, f'File {file_path_rel} is already patched for {rule_id}.')
                    opener = lines[insert_idx - 1]
                    indent = opener[:len(opener) - len(opener.lstrip())] + '  '
                    lines.insert(insert_idx, f'{indent}{patch_text.strip()}\n')
                    patch_applied = True
    elif template.get('action') in ('insert_healthcheck', 'insert_user'):
        if '[VANGUARD NANO-PATCH APPLIED]' in file_content:
            return (True, f'File {file_path_rel} is already patched.')
        for i, line in enumerate(lines):
            clean_line = line.strip().upper()
            if clean_line.startswith('CMD') or clean_line.startswith('ENTRYPOINT'):
                lines.insert(i, template['patch_text'])
                patch_applied = True
                break
        if not patch_applied and lines:
            lines.append(template['patch_text'])
            patch_applied = True
    if not patch_applied:
        return (False, f'Failed to locate mutable target line for {rule_id}.')
    try:
        create_backup(file_path)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
    except Exception as e:
        backup_path = file_path.with_name(file_path.name + '.vanguard_backup')
        if backup_path.exists():
            shutil.copy2(backup_path, file_path)
        return (False, f'Failed to write patched file: {e}')
    if auto_generated:
        return (True, f'Successfully patched {rule_id} (auto-generated fix - please review the change)')
    return (True, f'Successfully patched {rule_id}')

def execute_rollback(target_dir: str, file_path_rel: str) -> dict:
    base_dir = Path(target_dir).resolve()
    active_file = (base_dir / file_path_rel.lstrip('\\/')).resolve()
    try:
        active_file.relative_to(base_dir)
    except ValueError:
        return {'status': 'error', 'message': 'Access denied: Path escapes target directory'}
    backup_file = active_file.with_name(active_file.name + '.vanguard_backup')
    if not backup_file.exists():
        return {'status': 'failed', 'message': f'No backup found for {file_path_rel}'}
    try:
        shutil.copy2(backup_file, active_file)
        os.remove(backup_file)
        return {'status': 'success', 'message': f'Successfully rolled back {file_path_rel}'}
    except Exception as e:
        return {'status': 'error', 'message': f'Rollback operation failed: {str(e)}'}

def purge_backup_files(target_dir: str) -> Tuple[bool, int, str]:
    base_path = Path(target_dir).resolve()
    if not base_path.exists() or not base_path.is_dir():
        return (False, 0, f'Target directory does not exist: {target_dir}')
    purged_count = 0
    try:
        for backup_file in base_path.rglob('*.vanguard_backup'):
            if backup_file.is_file():
                backup_file.unlink(missing_ok=True)
                purged_count += 1
        return (True, purged_count, f'Successfully purged {purged_count} backup file(s).')
    except Exception as e:
        return (False, purged_count, f'Error purging backup files: {str(e)}')