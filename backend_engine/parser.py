import json

def scan_file(filepath):
    vulneribilities = []

    #opening the config files
    with open(filepath, 'r') as file:
        lines = file.readlines()

        #scan all lines
        for line_number, line_text in enumerate(lines, start=1):
            #check for root access flaws
            if "USER root" in line_text:
                vulneribilities.append({
                    "issue_id": "ERR_ROOT",
                    "description": "Root previleges granted.",
                    "line": line_number
                })
               
            #check for open port 22 flaw
            if "EXPOSE 22" in line_text:
                vulneribilities.append({
                    "issue_id": "ERR_PORT_22",
                    "description": "SSH port lef topen",
                    "line": line_number
                })
        #output the findings
        print(f"scan Complete. Found {len(vulneribilities)} Vulnerbititis.")
        print(json.dumps(vulneribilities, incident=4))
    #running the scanner on the test file
    scan_file('test_dockerfile.txt') 