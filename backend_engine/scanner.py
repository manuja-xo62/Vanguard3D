import os

class BaseScanner:
    """Base class for all infrastructure code scanners."""
    def __init__(self, filepath):
        self.filepath = filepath

    def scan(self):
        raise NotImplementedError("Subclasses must implement the scan() method.")
        
    def remediate(self, line_number, new_content):
        """Rewrites a specific line in the target file to fix a vulnerability."""
        if not os.path.exists(self.filepath):
            return False
        
        with open(self.filepath, 'r') as f:
            lines = f.readlines()

        if 0 < line_number <= len(lines):
            lines[line_number - 1] = new_content + '\n'

            with open(self.filepath, 'w') as f:
                f.writelines(lines)
            return True
            
        return False

class DockerScanner(BaseScanner):
    """Scanning class dedicated for Dockerfile analysis."""
    def scan(self):
        vulnerabilities = []

        if not os.path.exists(self.filepath):
            return {"error": f"File not found: {self.filepath}"}

        # Fixed indentation: File reading now happens outside the error check
        with open(self.filepath, 'r') as file:
            lines = file.readlines()

        for line_idx, line_text in enumerate(lines, start=1):
            clean_line = line_text.strip()

            # Detecting root privileges
            if "USER root" in clean_line:
                vulnerabilities.append({
                    "id": "ERR_ROOT_PRIV",
                    "line": line_idx,
                    "severity": "CRITICAL",
                    "category": "Privilege Escalation",
                    "description": "Container running with root privileges.",
                    "fix": "USER node"
                })

            # Detecting exposed SSH port 22
            if "EXPOSE 22" in clean_line:
                vulnerabilities.append({
                    "id": "ERR_OPEN_PORT_22",
                    "line": line_idx,
                    "severity": "HIGH",
                    "category": "Network Security",
                    "description": "Insecure SSH port 22 exposed directly.",
                    "fix": "# EXPOSE 22 (Disabled for security)"
                })
        
        # Fixed indentation: Returns the array ONLY after the loop finishes scanning all lines
        return vulnerabilities