import json
import urllib.request
import re
import os
import time
import subprocess

DB_PATH = 'cve_database.json'
INDEX_URL = "https://cve.akaoma.com/vendor/docker"

def generate_descriptive_id(cve_id, description):
    """
    Analyzes the vulnerability text and converts generic terms into 
    standardized, human-readable threat IDs (e.g., ERR_BIND_MOUNT_RACE_CONDITION).
    """
    desc_lower = description.lower()

    # Rule-based pattern matching for primary threat categories
    if "blank password" in desc_lower or "empty password" in desc_lower:
        return "ERR_MEMCACHED_BLANK_PASSWORD"
    elif "race condition" in desc_lower or "bind mount" in desc_lower:
        return "ERR_BIND_MOUNT_RACE_CONDITION"
    elif "trusts oci" in desc_lower or "path traversal" in desc_lower or "overwrite" in desc_lower:
        return "ERR_COMPOSE_PATH_TRAVERSAL"
    elif "isolation" in desc_lower or "socket" in desc_lower or "bypass" in desc_lower:
        return "ERR_CONTAINER_ISOLATION_BYPASS"
    elif "privilege escalation" in desc_lower or "supplementary groups" in desc_lower:
        return "ERR_PRIVILEGE_ESCALATION"
    elif "out-of-bounds" in desc_lower or "memory" in desc_lower:
        return "ERR_KERNEL_MEMORY_READ"
    elif "unauthenticated" in desc_lower or "remote api" in desc_lower:
        return "ERR_UNAUTH_REMOTE_API"
    elif "certificate" in desc_lower or "handshake" in desc_lower or "disclosure" in desc_lower:
        return "ERR_CLIENT_CERT_DISCLOSURE"

    # Automated keyword extraction fallback for unmapped descriptions
    words = re.findall(r'\b[A-Za-z]{4,}\b', description)
    stopwords = {
        'contains', 'official', 'images', 'using', 'docker', 'deployed', 
        'affected', 'versions', 'container', 'allow', 'remote', 'attacker', 
        'achieve', 'under', 'vulnerability', 'tracked', 'system', 'before',
        'engine', 'daemon', 'moby', 'prior', 'version', 'higher', 'which'
    }
    keywords = [w.upper() for w in words if w.lower() not in stopwords][:3]

    if keywords:
        return f"ERR_{'_'.join(keywords)}"

    # Secondary fallback using sanitized CVE ID
    clean_cve = cve_id.replace('-', '_').replace('ERR_', '')
    return f"ERR_{clean_cve}"


def fetch_exact_akaoma_data(cve_id):
    """Scrapes raw HTML from a specific Akaoma CVE page."""
    url = f"https://cve.akaoma.com/{cve_id.lower()}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            html = response.read().decode('utf-8', errors='ignore')

        #Parse CVSS Weight
        cvss_match = re.search(r'CVSS(?:[:\s]*)([0-9]{1,2}\.[0-9])', html, re.IGNORECASE)
        cvss = float(cvss_match.group(1)) if cvss_match else 7.0
        weight = cvss * 10.0

        #Parse Description
        desc_match = re.search(r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if desc_match:
            description = desc_match.group(1).strip()
        else:
            clean_text = re.sub(r'<[^>]+>', ' ', html)
            clean_text = re.sub(r'\s+', ' ', clean_text)
            fallback_match = re.search(rf'{cve_id}.*?(?:CVSS[:\s]*[0-9.]+)?\s*\)?\s*([A-Z].*?)(?=\s*All CVEs|\s*Top|\s*$)', clean_text, re.IGNORECASE)
            description = fallback_match.group(1).strip() if fallback_match else f"Engine vulnerability tracked under {cve_id}."

        #Parse Affected Versions
        affected_versions = []
        for v in re.findall(r'before\s+([0-9a-zA-Z.-]+)', description, re.IGNORECASE):
            affected_versions.append(f"<={v}")

        descriptive_id = generate_descriptive_id(cve_id, description)

        return {
            "descriptive_id": descriptive_id,
            "cve_ref": cve_id.upper(),
            "weight": round(weight, 1),
            "type": "env",
            "description": description,
            "affected_versions": list(set(affected_versions)) if affected_versions else ["<unknown>"],
            "source": f"Akaoma Exact Match ({url})"
        }

    except Exception as e:
        print(f"[!] Target extraction failed for {cve_id}: {e}")
        return None


def update_cve_database():
    print("[*] Starting Full Database Migration and Sync...")

    #Load Existing Database
    if os.path.exists(DB_PATH):
        with open(DB_PATH, 'r') as f:
            try:
                cve_db = json.load(f)
            except json.JSONDecodeError:
                cve_db = {}
    else:
        cve_db = {}

    #MIGRATE ALL EXISTING ENTRIES to New ID Structure
    migrated_db = {}
    migration_count = 0

    for key, value in cve_db.items():
        #Identify legacy keys
        if key.startswith("CVE_") or key.startswith("ERR_CVE_") or "CVE-" in key:
            cve_ref = value.get("cve_ref") or key.replace("ERR_", "").replace("_", "-")
            desc = value.get("description", "")
            
            #Generate new descriptive key
            new_id = value.get("descriptive_id") or generate_descriptive_id(cve_ref, desc)
            
            #Attach structural metadata
            value["descriptive_id"] = new_id
            value["cve_ref"] = cve_ref
            
            migrated_db[new_id] = value
            migration_count += 1
            print(f"[~] Migrated Legacy Key: '{key}' -> '{new_id}'")
        else:
            #Keep standard static rules or already migrated keys
            migrated_db[key] = value

    cve_db = migrated_db
    print(f"[+] Successfully migrated {migration_count} legacy database keys.")

    #SCRAPE FULL AKAOMA INDEX FOR NEW / UNTRACKED CVES
    print(f"\n[*] Scanning live Akaoma index at {INDEX_URL}...")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    try:
        req = urllib.request.Request(INDEX_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as response:
            index_html = response.read().decode('utf-8', errors='ignore')
            
        cve_matches = re.findall(r'(CVE-\d{4}-\d{4,7})', index_html, re.IGNORECASE)
        unique_cves = list(set([c.upper() for c in cve_matches]))
        print(f"[+] Found {len(unique_cves)} total CVE identifiers on Akaoma.")
        
    except Exception as e:
        print(f"[!] Could not fetch live index ({e}). Using migrated database.")
        unique_cves = []

    #Build set of already tracked CVE references to avoid duplicate requests
    existing_cve_refs = {
        val.get("cve_ref") for val in cve_db.values() if isinstance(val, dict) and "cve_ref" in val
    }

    #FETCH MISSING CVES FROM AKAOMA
    new_scraped = 0
    for cve_id in unique_cves:
        if cve_id not in existing_cve_refs:
            exact_data = fetch_exact_akaoma_data(cve_id)
            if exact_data:
                new_id = exact_data["descriptive_id"]
                cve_db[new_id] = exact_data
                existing_cve_refs.add(cve_id)
                new_scraped += 1
                print(f"[+] Scraped and mapped new CVE: {cve_id} -> '{new_id}'")
                time.sleep(1.2) # Friendly rate limiting

    #SAVE MIGRATED & UPDATED DATABASE
    with open(DB_PATH, 'w') as f:
        json.dump(cve_db, f, indent=4)

    print(f"\n[+] Database fully synchronized! Saved to {DB_PATH}.")
    print(f"[+] Total database size: {len(cve_db)} active rules.")

    #RETRAIN ML MODEL
    print("\n[*] Retraining ML engine with updated feature set...")
    python_bin = os.path.join('venv', 'Scripts', 'python.exe') if os.path.exists(os.path.join('venv', 'Scripts', 'python.exe')) else 'python'
    
    if os.path.exists('dataset_builder.py'):
        subprocess.run([python_bin, 'dataset_builder.py'])
    
    if os.path.exists('ml_engine.py'):
        subprocess.run([python_bin, 'ml_engine.py'])

if __name__ == "__main__":
    update_cve_database()