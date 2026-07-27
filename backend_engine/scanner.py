import json
import os
import re

class DockerScanner:
    def __init__(self, target_file):
        self.target_file = target_file

    def scan(self):
        vulnerabilities = []
        if not os.path.exists(self.target_file):
            return vulnerabilities

        with open(self.target_file, 'r') as f:
            lines = f.readlines()

        for idx, line in enumerate(lines, 1):
            clean_line = line.strip()

            #Running as root
            if clean_line.startswith("USER root"):
                vulnerabilities.append({
                    "id": "ERR_ROOT_PRIV",
                    "severity": "CRITICAL",
                    "description": "Container explicitly running as root user.",
                    "fix": "USER node",
                    "line": idx
                })

            #Curling/piping directly to bash
            if "curl" in clean_line and "|" in clean_line and "bash" in clean_line:
                vulnerabilities.append({
                    "id": "ERR_CURL_BASH",
                    "severity": "HIGH",
                    "description": "Insecure piping of remote script directly to shell.",
                    "fix": "Download and verify script checksum before execution.",
                    "line": idx
                })

        return vulnerabilities

    def remediate(self, line_num, replacement):
        if not os.path.exists(self.target_file):
            return False

        with open(self.target_file, 'r') as f:
            lines = f.readlines()

        if 0 < line_num <= len(lines):
            lines[line_num - 1] = f"{replacement}\n"
            with open(self.target_file, 'w') as f:
                f.writelines(lines)
            return True

        return False


class EnvironmentScanner:
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
        """
        Helper method: Searches the database for a matching cve_ref or key,
        ensuring lookups work even after key migrations.
        """
        for key, data in self.cve_db.items():
            if isinstance(data, dict):
                #Match against cve_ref or the primary dictionary key
                if data.get("cve_ref") == target_cve or key == target_cve or key == target_cve.replace('-', '_'):
                    return key, data
        return None, None

    def scan_environment(self):
        env_vulnerabilities = []
        current_docker_version = "30.0.0"   # Higher than 29.5.1
        current_compose_version = "2.45.0"  # Higher than 2.40.2

        #Check for CVE-2026-42306
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

        #Check for CVE-2025-62725
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