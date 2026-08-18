import argparse
import sys
import json
import uuid
from pathlib import Path

#adding the backend to a sys.path so it doens't depend on the network
backend_path = Path(__file__).parent.parent / "1_Backend_Engine"
sys.path.append(str(backend_path.resolve()))

try:
    from checkov_parser import run_checkov_scan #type: ignore
    from risk_engine import calculate_risk #type: ignore
    from event_store import record_scan, init_db #type: ignore
except ImportError as e:
    print(f"FATAL: Could not load backend modules. Ensure 1_Backend_Engine exist alongside 2_CLI_Action. Error : {e}")
    sys.exit(1)

def run_scan(target: str, output_json: bool):
    ##Run the scan and logs it in DB
    init_db()

    target_path = Path(target).resolve()
    if not target_path.exists():
        print(f"Error: Target Path '{target}' does not exist.")
        sys.exit(1)
    
    if not output_json:
        print(f"--- Vanguard CLI : Scanning {target_path} ---")
    
    try:
        #parshing ASt
        raw_findings = run_checkov_scan(str(target_path))

        #Calculate risk scores
        risk_data = calculate_risk(raw_findings)

        #log the event in the DB
        scan_id = f"clu_{uuid.uuid4(). hex[:8]}"
        record_scan(scan_id, "cli", str(target_path), risk_data["R_global"], risk_data["files"])

        #Output Results
        if output_json:
            #machineredable output for GitHub Actions / CI
            print(json.dumps({"scan_id": scan_id, "data": risk_data}, indent=2))
        else:
            #human readable output
            print(f"\n[+] Scan Complete. ID: {scan_id}")
            print(f"[+] Global Risk Score (R_global): {risk_data['R_global']:.2f}")
            print(f"[+] Files Processed: {len(risk_data['files'])}")
            print("-" * 50)

            for f in risk_data['files']:
                print(f"  > {f['file']} | R_file: {f['R_file']:.2f} | Findings: {len(f['findings'])}")
    except Exception as e:
        print(f"Error during scan execution: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="VanguardNode CLI - Zero-Trust DecSecOps Scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run a full scan on a target directory")
    scan_parser.add_argument("path", help="Target directory to scan")
    scan_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON for CI integration")

    # comment-pr command
    pr_parser = subparsers.add_parser("comment-pr", help="Post findings as a GitHub PR comment")
    pr_parser.add_argument("--results", required=True, help="Path to the JSON results file from a previous scan")

    args = parser.parse_args()
    
    if args.command == "scan":
        run_scan(args.path, args.json)
    elif args.command == "comment-pr":
        print("GitHub PR Integration Module coming soon...")


if __name__ == "__main__":
    main()