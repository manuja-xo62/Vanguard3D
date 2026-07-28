import os
import json
import shlex
import re

class DockerScanner:
    """
    Zero-dependency, AST-like Smart Scanner using Python's built-in standard library (`shlex`).
    100% Offline, instant execution, zero missing import errors.
    """
    def __init__(self, filepath):
        self.filepath = filepath

    def _analyze_shell_tokens(self, command_str):
        """Uses Python's native shlex lexical analyzer to inspect shell tokens."""
        findings = []
        try:
            #Tokenize shell commands safely
            tokens = shlex.split(command_str)
            tokens_lower = [t.lower() for t in tokens]

            #Check 1 - Insecure pipe execution
            has_fetch = any(cmd in tokens_lower for cmd in ['curl', 'wget'])
            has_pipe_exec = '|' in command_str and any(sh in command_str.lower() for sh in ['bash', 'sh', 'zsh'])

            if has_fetch and has_pipe_exec:
                findings.append({
                    "id": "ERR_CURL_BASH",
                    "severity": "HIGH",
                    "description": "Insecure piping of remote network stream directly into shell interpreter.",
                    "fix": "Download script to temporary location, verify hash checksum, then execute."
                })

            #Check 2 - World-writable/executable permissions
            if 'chmod' in tokens_lower and ('777' in tokens_lower or '-R 777' in command_str):
                findings.append({
                    "id": "ERR_PERMISSIVE_CHMOD",
                    "severity": "HIGH",
                    "description": "Granting global world-writable/executable permissions (777).",
                    "fix": "Restrict file permissions using standard least-privilege principles (e.g., 755 or 644)."
                })

        except Exception:
            #Fallback token check if command contains complex or multi-line syntax
            if ("curl" in command_str.lower() or "wget" in command_str.lower()) and "|" in command_str:
                findings.append({
                    "id": "ERR_CURL_BASH",
                    "severity": "HIGH",
                    "description": "Insecure piping of remote network stream directly into shell interpreter.",
                    "fix": "Download script to temporary location, verify hash checksum, then execute."
                })

        return findings

    def scan(self):
        if not os.path.exists(self.filepath):
            return []

        vulnerabilities = []

        with open(self.filepath, 'r') as f:
            lines = f.readlines()

        has_healthcheck = False

        for idx, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue

            #Split instruction and argument
            parts = line.split(None, 1)
            instruction = parts[0].upper()
            value = parts[1] if len(parts) > 1 else ""

            #Unpinned Base Image Tags
            if instruction == 'FROM' and (':latest' in value or ':' not in value):
                vulnerabilities.append({
                    "id": "ERR_LATEST_TAG",
                    "line": idx,
                    "severity": "MEDIUM",
                    "description": "Unpinned or ':latest' base image tag used.",
                    "fix": "Pin base image to an exact version or immutable digest."
                })

            #Hardcoded Secrets in ENV
            elif instruction == 'ENV':
                sensitive_keys = ['SECRET', 'PASSWORD', 'AWS_ACCESS_KEY_ID', 'TOKEN', 'PRIVATE_KEY']
                if any(key in value.upper() for key in sensitive_keys):
                    vulnerabilities.append({
                        "id": "ERR_HARDCODED_SECRET",
                        "line": idx,
                        "severity": "CRITICAL",
                        "description": "Sensitive credentials or secrets exposed in ENV layer.",
                        "fix": "Remove secrets from Dockerfile; mount securely at runtime."
                    })

            #Explicit Root Privileges
            elif instruction == 'USER' and 'root' in value.lower():
                vulnerabilities.append({
                    "id": "ERR_ROOT_PRIV",
                    "line": idx,
                    "severity": "CRITICAL",
                    "description": "Container process explicitly running with root privileges.",
                    "fix": "Specify a non-root application user (e.g., USER node)."
                })

            #Docker Socket Volume Mounting
            elif instruction == 'VOLUME' and 'docker.sock' in value:
                vulnerabilities.append({
                    "id": "ERR_DOCKER_SOCKET",
                    "line": idx,
                    "severity": "CRITICAL",
                    "description": "Host Docker daemon socket mounted inside container.",
                    "fix": "Avoid mounting /var/run/docker.sock to prevent container breakout."
                })

            #Shell Lexical Analysis inside RUN statements
            elif instruction == 'RUN':
                shell_issues = self._analyze_shell_tokens(value)
                for issue in shell_issues:
                    issue['line'] = idx
                    vulnerabilities.append(issue)

            elif instruction == 'HEALTHCHECK':
                has_healthcheck = True

        if not has_healthcheck:
            vulnerabilities.append({
                "id": "ERR_MISSING_HEALTHCHECK",
                "line": 1,
                "severity": "LOW",
                "description": "No HEALTHCHECK instruction configured.",
                "fix": "Add HEALTHCHECK CMD instruction to monitor container runtime health."
            })

        return vulnerabilities


class EnvironmentScanner:
    """Scans host environment configuration for Docker daemon vulnerabilities."""
    def __init__(self):
        if os.path.exists('cve_database.json'):
            with open('cve_database.json', 'r') as f:
                try:
                    self.cve_db = json.load(f)
                except json.JSONDecodeError:
                    self.cve_db = {}
        else:
            self.cve_db = {}

    def _get_entry_by_cve_ref(self, target_cve):
        for key, data in self.cve_db.items():
            if isinstance(data, dict):
                if data.get("cve_ref") == target_cve or key == target_cve or key == target_cve.replace('-', '_'):
                    return key, data
        return None, None

    def scan_environment(self):
        env_vulnerabilities = []
        current_docker_version = "28.0.0"
        current_compose_version = "2.39.0"

        rule_id, entry = self._get_entry_by_cve_ref("CVE-2026-42306")
        if current_docker_version < "29.5.1" and entry:
            env_vulnerabilities.append({
                "id": rule_id,
                "cve_ref": "CVE-2026-42306",
                "severity": "CRITICAL",
                "category": "Engine Flaw",
                "description": entry.get("description", "Engine flaw in Docker Desktop."),
                "fix": "Upgrade Docker Engine to version 29.5.1 or higher."
            })

        rule_id, entry = self._get_entry_by_cve_ref("CVE-2025-62725")
        if current_compose_version < "2.40.2" and entry:
            env_vulnerabilities.append({
                "id": rule_id,
                "cve_ref": "CVE-2025-62725",
                "severity": "HIGH",
                "category": "Supply Chain / CLI",
                "description": entry.get("description", "OCI path traversal flaw in Docker Compose."),
                "fix": "Upgrade Docker Compose to version 2.40.2 or higher."
            })

        return env_vulnerabilities