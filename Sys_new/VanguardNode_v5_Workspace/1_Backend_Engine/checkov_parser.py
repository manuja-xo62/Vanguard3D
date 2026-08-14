import json
import subprocess
import uuid
from pathlib import Path
from typing import Dict, List, Any

def parse_checkhov_finding(raw_check: Dict[str, Any], target_dir: str) -> Dict[str, Any]:
    #normalizing single chekhov findings into the app's standard data structure

    #extracting file path relative to the target_dir if it is possible
    file_abs = raw_check.get("file_path", "")
    try:
        rel_path = str(Path(file_abs). relative_to(Path(target_dir). resolve()))
    except ValueError:
        #fallback : if path manipation fails
        rel_path = file_abs.lstrip("/")
    
    #chekhov severity might be missing
    severity = raw_check.get("severity") or "MEDIUM"

    #extract line lange for path_service ASt targeting funciton
    file_line_range = raw_check.get("file_line_range", [0,0])

    return{
        "finding_id": f"find_{uuid.uuid4().hex[:8]}",
        "rule_id": raw_check.get("check_id", "UNKNOWN_RULE"),
        "rule_title": raw_check.get("check_name", "Unspecified Configuration Issue"),
        "severity" : severity.upper(),
        "file_path": rel_path,
        "resource_type": raw_check.get("resource", "defualt"),
        "file_line_range": file_line_range,
        "code_block": raw_check.get("code_block", []),
        "status": "open"
    }

    def run_checkhov_scan(target_dir: str) -> dict[str, Any]:
        #Executing the checkhov CLI against the target location and return structured fundings that suits app's requirements

        target_path = Path(target_dir).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target location does not exist : {target_dir}")
        
        #Run Chekckhob as a subprocess requesting a JSON format output with the findings
        cmd = [
            "checkhov",
            "-d", str(target_path),
            "-o", "json",
            "--quiet"
        ]

        try:
            #chekhov return an exit code 1 or 2 when findings are found
            #Cpaturing stdout /stderr without throwing a subprocess/calledprocesserror
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False
            )
        except FileNotFoundError:
            raise RuntimeError("Checkhov is not installed or not available in PATH")
        
        raw_output = result.stdout.strip()
        if not raw_output:
            #if the output is empty check if stderr contains vital errors
            if result.stderr:
                print(f"[Checkhov Parser Warning] Stderr output: {result.stderr}")
            return[] 
        
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            print("[Checkhob Parser Error] Failed to parse JSON output from Chekhov.")
            return[]

        parsed_findings = []
        
        #Chekhov returning a list (when multiple files are scanned, terraform + Docker)
        if isinstance(data,list):
            for framework_results in data:
                results_obj = framework_results.get("results", {})
                failed_checks = results_obj.get("failed_checks", [])
                for check in failed_checks:
                    parsed_findings.append(parse_checkhov_finding(check, str(target_path)))

        #checkhov returning a dictionary (single file scan)
        elif isinstance(data, dict):
            results_obj = data.get("results", {})
            failed_checks = results_obj.get("failed_checks", [])
            for check in failed_checks:
                parsed_findings.append(parse_checkhov_finding(check, str(target_path)))

        return parsed_findings

    if __name__ == "__main__":
        import sys
        #quick cli self test execution
        test_dir = "../sample_repo" if len(sys.argv) < 2 else sys.argv[1]
        print(f"---Testing Checkhov Parser against '{test_dir}")
        try:
            findings = run_checkhov_scan(test_dir)
            print(f"Successfully extracted {len(findings)} findings : \n")
            print(json.dumps(findings, indent=2))
        except Exception as e:
            print(f"Error during Checkhov scan : {e}")
        