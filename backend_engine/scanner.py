from os import linesep
import os

class BaseScanner:
    #Base class for all infrastructure code scanners.
    def __init__(self,filepath):
        self.filpathath = filepath

    def scan(self):
        raise NotImplementedError("ubclasses must implement the scan() method.")
    def remidate(self,line_number,new_content):
        #rewrites a speicifc line in te target file to fix a vulnerbility
        if not os.path.exists(self.filepath):
            return False
        
        with open(self.filepath, 'r') as f:
            lines = f.readlines()

        if 0 < line_number <=len(lines):
            lines[line_number-1]=new_content + '\n'

            with open(self.filepath, 'w') as f:
                f.writelines(lines)
            return True
        return False

class DockerScanner(BaseScanner):
    #scanning class dedicated for docerfile analysis
    def scan(self):
        vulnerbilities = []

        if not os.path.exists(self.filpathath):
            return{"error": f"File not found: {self.filepath}"}

            with open(self.filpathath, 'r') as file:
                lines = file.readlines()

            for line_idx, line_text in enumerate(lines, start = 1):
                clean_line = line_text.strip()

                #detecting root previlages
                if "USER root" in clean_line:
                    vulnerbilities.append({
                        "id":"ERR_ROOT_PRIV",
                        "line":line_idx,
                        "severity":"CRITICAL",
                        "category":"Previlege Escalation",
                        "description":"Container running with root previlages",
                        "fix": "USER node"
                    })

                #detecting exposed ssh port 22
                if "EXPOSE 22" in clean_line:
                    vulnerbilities.append({
                        "id":"ERR_OPEN_PORT_22",
                        "line":line_idx,
                        "severity":"HIGH",
                        "category":"Network Security",
                        "description":"Insecure SSH port 22 exposed directly",
                        "fix": "# EXPOSE 22 (Disabled for security)"
                    })
            
                return vulnerbilities





        
