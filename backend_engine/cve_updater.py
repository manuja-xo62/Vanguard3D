import json
import re
import requests
import time
import os

DB_PATH = 'cve_database.json'

def fetch_cve_metadata(cve_id):
    """
    Queries the CIRCL Public CVE API to dynamically fetch real vulnerability data.
    """
    # Normalize ID to standard hyphen format for the API
    normalized_id = cve_id.replace('_', '-')
    api_url = f"https://cve.circl.lu/api/cve/{normalized_id}"
    
    print(f"[*] Fetching live metadata for {normalized_id}...")
    try:
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data:
                # 1. Fetch Real Description
                description = data.get("summary", f"Vulnerability tracked under {normalized_id}.")
                
                # 2. Fetch CVSS Score & Calculate Weight (Scale 10.0 to 100.0)
                cvss_score = data.get("cvss")
                weight = float(cvss_score) * 10.0 if cvss_score else 70.0
                
                # 3. Extract Affected Versions (Parse from CPE strings)
                affected_versions = []
                cpes = data.get("vulnerable_configuration", [])
                for cpe in cpes:
                    parts = cpe.split(":")
                    
                    if len(parts) >= 6 and parts[5] != "*":
                        affected_versions.append(f"<={parts[5]}")
                
                # Remove duplicates and limit to top 3 to keep DB clean
                affected_versions = list(set(affected_versions))[:3]
                if not affected_versions:
                    affected_versions = ["<unknown>"]
                    
                return {
                    "weight": round(weight, 1),
                    "type": "env",  # Fixed to perfectly match your manual schema
                    "description": description,
                    "affected_versions": affected_versions,
                    "source": "Akaoma / CIRCL Live Sync"
                }
    except Exception as e:
        print(f"[!] Failed to fetch {normalized_id}: {e}")
        
    # Absolute fallback if API is unreachable
    return {
        "weight": 70.0,
        "type": "env",
        "description": f"Vulnerability tracked under {normalized_id}.",
        "affected_versions": ["<unknown>"],
        "source": "Akaoma Live Threat Feed"
    }

def update_cve_database():
    # Load existing DB
    if os.path.exists(DB_PATH):
        with open(DB_PATH, 'r') as f:
            cve_db = json.load(f)
    else:
        cve_db = {}

    #Repair existing corrupted stubs
    print("--- Checking for Legacy Stubs to Repair ---")
    for cve_id, data in list(cve_db.items()):
        # Identify stubs by the generic type or placeholder description
        if data.get("type") == "env_cve" or "Engine/Daemon vulnerability" in data.get("description", ""):
            print(f"[*] Repairing legacy stub: {cve_id}")
            cve_db[cve_id] = fetch_cve_metadata(cve_id)
            time.sleep(1)

    # Scrape Akaoma for new IDs
    print("\n--- Scraping Akaoma for New Threats ---")
    try:
        # FIXED: Pointing back to the specific Docker threat feed
        response = requests.get('https://cve.akaoma.com/vendor/docker', timeout=10)
        html_text = response.text
        # Regex extracts standard CVE IDs
        cve_matches = re.findall(r'(CVE-\d{4}-\d{4,7})', html_text)
        unique_cves = list(set(cve_matches))
        
        for cve_id in unique_cves:
            if cve_id not in cve_db:
                cve_db[cve_id] = fetch_cve_metadata(cve_id)
                time.sleep(1)
    except Exception as e:
        print(f"[!] Akaoma sync failed: {e}")

    #Save the repaired and updated DB
    with open(DB_PATH, 'w') as f:
        json.dump(cve_db, f, indent=4)
        
    print("\n[+] CVE Database successfully repaired and updated!")

if __name__ == "__main__":
    update_cve_database()