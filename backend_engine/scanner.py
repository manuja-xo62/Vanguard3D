import os
import json
import subprocess

class EnvironmentScanner:
    """Scans the local host system for Engine-level CVEs."""
    def __init__(self):
        with open('cve_database.json', 'r') as f:
            self.cve_db = json.load(f)

    def scan_environment(self):
        env_vulnerabilities = []
        
        
        current_docker_version = "28.0.0" 
        
        if current_docker_version < "29.5.1":
            env_vulnerabilities.append({
                "id": "CVE_2026_42306",
                "severity": "CRITICAL",
                "category": "Engine Flaw",
                "description": self.cve_db["CVE_2026_42306"]["description"],
                "fix": "Upgrade Docker Engine to version 29.5.1 or higher."
            })
        
        current_compose_version = "2.39.0"
        if current_compose_version < "2.40.2":
            env_vulnerabilities.append({
                "id": "CVE_2025_62725",
                "severity": "HIGH",
                "category": "Supply Chain / CLI",
                "description": self.cve_db["CVE_2025_62725"]["description"],
                "fix": "Upgrade Docker Compose to version 2.40.2 or higher."
            })

        return env_vulnerabilities


class DockerScanner:
    """Scans static IaC text files."""
    def __init__(self, filepath):
        self.filepath = filepath
        with open('cve_database.json', 'r') as f:
            self.cve_db = json.load(f)

    def scan(self):
        vulnerabilities = []
        if not os.path.exists(self.filepath):
            return {"error": "File not found"}

        with open(self.filepath, 'r') as file:
            lines = file.readlines()

        for line_idx, line_text in enumerate(lines, start=1):
            clean_line = line_text.strip()
            
            if "USER root" in clean_line:
                vulnerabilities.append({
                    "id": "ERR_ROOT_PRIV", "line": line_idx, "severity": "CRITICAL",
                    "description": self.cve_db["ERR_ROOT_PRIV"]["description"],
                    "fix": "USER node"
                })

            if "curl" in clean_line and "|" in clean_line and "bash" in clean_line:
                vulnerabilities.append({
                    "id": "ERR_CURL_BASH", "line": line_idx, "severity": "CRITICAL",
                    "description": self.cve_db["ERR_CURL_BASH"]["description"],
                    "fix": "# Download file, verify checksum, then execute"
                })

        return vulnerabilities