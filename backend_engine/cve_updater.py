import json
import urllib.request
import re
import os
import time
import subprocess

DB_PATH = 'cve_database.json'
INDEX_URL = "https://cve.akaoma.com/vendor/docker"

# Standard static rules to guarantee seed coverage in feature matrix
DEFAULT_STATIC_RULES = {
    "ERR_LATEST_TAG": {"weight": 6.0, "severity": "MEDIUM", "description": "Unpinned or :latest base image tag used."},
    "ERR_HARDCODED_SECRET": {"weight": 20.0, "severity": "CRITICAL", "description": "Sensitive credentials exposed in ENV layer."},
    "ERR_ROOT_PRIV": {"weight": 20.0, "severity": "CRITICAL", "description": "Container process explicitly running with root privileges."},
    "ERR_DOCKER_SOCKET": {"weight": 20.0, "severity": "CRITICAL", "description": "Host Docker daemon socket mounted inside container."},
    "ERR_CURL_BASH": {"weight": 12.0, "severity": "HIGH", "description": "Insecure piping of remote network stream into shell."},
    "ERR_PERMISSIVE_CHMOD": {"weight": 12.0, "severity": "HIGH", "description": "Global world-writable permissions (777) granted."},
    "ERR_MISSING_HEALTHCHECK": {"weight": 2.0, "severity": "LOW", "description": "No HEALTHCHECK instruction configured."}
}

def generate_descriptive_id(cve_id, description):
    desc_lower = description.lower()
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

    words = re.findall(r'\b[A-Za-z]{4,}\b', description)
    stopwords = {'contains', 'official', 'images', 'using', 'docker', 'deployed', 'affected', 'versions', 'container', 'allow', 'remote', 'attacker', 'engine', 'daemon', 'moby'}
    keywords = [w.upper() for w in words if w.lower() not in stopwords][:3]

    if keywords:
        return f"ERR_{'_'.join(keywords)}"

    clean_cve = cve_id.replace('-', '_').replace('ERR_', '')
    return f"ERR_{clean_cve}"


def fetch_exact_akaoma_data(cve_id):
    url = f"https://cve.akaoma.com/{cve_id.lower()}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            html = response.read().decode('utf-8', errors='ignore')

        cvss_match = re.search(r'CVSS(?:[:\s]*)([0-9]{1,2}\.[0-9])', html, re.IGNORECASE)
        cvss = float(cvss_match.group(1)) if cvss_match else 7.0
        
        # Scale CVSS weight appropriately
        weight = round(cvss * 2.0, 1)

        desc_match = re.search(r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        description = desc_match.group(1).strip() if desc_match else f"Engine vulnerability tracked under {cve_id}."

        affected_versions = re.findall(r'before\s+([0-9a-zA-Z.-]+)', description, re.IGNORECASE)
        descriptive_id = generate_descriptive_id(cve_id, description)

        return {
            "descriptive_id": descriptive_id,
            "cve_ref": cve_id.upper(),
            "weight": weight,
            "type": "env",
            "description": description,
            "affected_versions": [f"<={v}" for v in set(affected_versions)] if affected_versions else ["<unknown>"],
            "source": f"Akaoma Exact Match ({url})"
        }
    except Exception as e:
        print(f"[!] Target extraction failed for {cve_id}: {e}")
        return None


def update_cve_database():
    print("[*] Starting Full Database Synchronization...")

    cve_db = {}
    if os.path.exists(DB_PATH):
        with open(DB_PATH, 'r') as f:
            try:
                cve_db = json.load(f)
            except json.JSONDecodeError:
                cve_db = {}

    #Seed static rules if missing
    for rule_id, rule_data in DEFAULT_STATIC_RULES.items():
        if rule_id not in cve_db:
            cve_db[rule_id] = rule_data

    #Migrate legacy weights down to normalized scale
    for key, value in cve_db.items():
        if isinstance(value, dict):
            current_weight = value.get("weight", 10.0)
            if current_weight > 25.0:
                value["weight"] = round(current_weight / 5.0, 1)

    #Scrape live index
    try:
        req = urllib.request.Request(INDEX_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as response:
            index_html = response.read().decode('utf-8', errors='ignore')
        cve_matches = re.findall(r'(CVE-\d{4}-\d{4,7})', index_html, re.IGNORECASE)
        unique_cves = list(set([c.upper() for c in cve_matches]))
    except Exception:
        unique_cves = []

    existing_refs = {val.get("cve_ref") for val in cve_db.values() if isinstance(val, dict) and "cve_ref" in val}

    for cve_id in unique_cves:
        if cve_id not in existing_refs:
            exact_data = fetch_exact_akaoma_data(cve_id)
            if exact_data:
                cve_db[exact_data["descriptive_id"]] = exact_data
                existing_refs.add(cve_id)
                time.sleep(0.5)

    with open(DB_PATH, 'w') as f:
        json.dump(cve_db, f, indent=4)

    print(f"[+] Database synchronized with {len(cve_db)} active rules.")

    # Retrain ML pipeline
    python_bin = os.path.join('venv', 'Scripts', 'python.exe') if os.path.exists(os.path.join('venv', 'Scripts', 'python.exe')) else 'python'
    if os.path.exists('dataset_builder.py'):
        subprocess.run([python_bin, 'dataset_builder.py'])
    if os.path.exists('ml_engine.py'):
        subprocess.run([python_bin, 'ml_engine.py'])

if __name__ == "__main__":
    update_cve_database()