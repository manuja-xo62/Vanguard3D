import os
import json
import re
import urllib.request
import subprocess

AKAOMA_URL = "https://cve.akaoma.com/vendor/docker"
CVE_DB_PATH = "cve_database.json"

def fetch_akaoma_docker_cves():
    """Scrapes live threat intelligence from Akaoma using standard library modules."""
    print(f"[*] Connecting to live threat feed: {AKAOMA_URL}...")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36"
    }
    
    scraped_cves = {}

    try:
        req = urllib.request.Request(AKAOMA_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=12) as response:
            html_text = response.read().decode('utf-8', errors='ignore')

        # Extract all cve idenitfiers
        cve_matches = re.findall(r'(CVE-\d{4}-\d{4,7})', html_text)
        unique_cves = list(dict.fromkeys(cve_matches))

        print(f"[+] Successfully extracted {len(unique_cves)} unique CVE identifiers from live feed.")

        for cve_id in unique_cves:
            scraped_cves[cve_id] = {
                "weight": 80.0,
                "type": "env_cve",
                "description": f"Engine/Daemon vulnerability tracked under {cve_id}.",
                "source": "Akaoma Live Threat Feed"
            }

    except Exception as e:
        print(f"[!] Warning: Failed to fetch online data ({e}). Preserving existing local database.")

    return scraped_cves


def update_cve_database():
    """Merges newly scraped CVEs into cve_database.json and triggers retrain loop."""
    if os.path.exists(CVE_DB_PATH):
        with open(CVE_DB_PATH, 'r') as f:
            try:
                db = json.load(f)
            except json.JSONDecodeError:
                db = {}
    else:
        db = {}

    live_cves = fetch_akaoma_docker_cves()

    new_entries_count = 0
    for cve_id, metadata in live_cves.items():
        if cve_id not in db:
            db[cve_id] = metadata
            new_entries_count += 1

    with open(CVE_DB_PATH, 'w') as f:
        json.dump(db, f, indent=4)

    print(f"[+] Knowledge base updated! Added {new_entries_count} new entries. Total database size: {len(db)} entries.")

    print("\n[*] Initiating automated MLOps retrain loop...")
    python_bin = os.path.join('venv', 'Scripts', 'python.exe') if os.path.exists(os.path.join('venv', 'Scripts', 'python.exe')) else 'python'
    
    if os.path.exists('dataset_builder.py'):
        subprocess.run([python_bin, 'dataset_builder.py'])
    
    if os.path.exists('ml_engine.py'):
        subprocess.run([python_bin, 'ml_engine.py'])

if __name__ == '__main__':
    update_cve_database()