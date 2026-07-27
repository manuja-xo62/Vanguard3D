import json
import urllib.request
import re
import os
import time

DB_PATH = 'cve_database.json'
INDEX_URL = "https://cve.akaoma.com/vendor/docker"

def fetch_exact_akaoma_data(cve_id):
    """
    Directly scrapes the specific CVE page on Akaoma and extracts raw text data 
    using the exact validated logic.
    """
    url = f"https://cve.akaoma.com/{cve_id.lower()}"
    print(f"[*] Targeting specific intelligence page: {url}")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0"
    }
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            html = response.read().decode('utf-8', errors='ignore')
            
        #Extract Exact CVSS Score
        cvss_match = re.search(r'CVSS(?:[:\s]*)([0-9]{1,2}\.[0-9])', html, re.IGNORECASE)
        cvss = float(cvss_match.group(1)) if cvss_match else 7.0 
        weight = cvss * 10.0
        
        #Extract Exact Description Text
        desc_match = re.search(r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        
        if desc_match:
            description = desc_match.group(1).strip()
        else:
            clean_text = re.sub(r'<[^>]+>', ' ', html)
            clean_text = re.sub(r'\s+', ' ', clean_text)
            fallback_match = re.search(rf'{cve_id}.*?(?:CVSS[:\s]*[0-9.]+)?\s*\)?\s*([A-Z].*?)(?=\s*All CVEs|\s*Top|\s*$)', clean_text, re.IGNORECASE)
            description = fallback_match.group(1).strip() if fallback_match else f"Engine/Daemon vulnerability tracked under {cve_id}."
            
        #Extract Affected Versions
        affected_versions = []
        version_matches = re.findall(r'before\s+([0-9a-zA-Z.-]+)', description, re.IGNORECASE)
        for v in version_matches:
            affected_versions.append(f"<={v}")
            
        if not affected_versions:
            affected_versions = ["<unknown>"]
            
        return {
            "weight": round(weight, 1),
            "type": "env",
            "description": description,
            "affected_versions": list(set(affected_versions)),
            "source": f"Akaoma Exact Match ({url})"
        }
        
    except Exception as e:
        print(f"[!] Target extraction failed for {cve_id}: {e}")
        return None

def update_cve_database():
    print("[*] Initializing Full-Scope Akaoma Synchronizer...")
    
    #Load Existing Database
    if os.path.exists(DB_PATH):
        with open(DB_PATH, 'r') as f:
            try:
                cve_db = json.load(f)
            except json.JSONDecodeError:
                cve_db = {}
    else:
        cve_db = {}

    #Scrape the Main Index for all CVE IDs
    print(f"[*] Scanning main threat index: {INDEX_URL}")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0"
    }
    
    try:
        req = urllib.request.Request(INDEX_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as response:
            index_html = response.read().decode('utf-8', errors='ignore')
            
        # Regex to find all standard CVE identifiers
        cve_matches = re.findall(r'(CVE-\d{4}-\d{4,7})', index_html, re.IGNORECASE)
        
        # Remove duplicates by converting to a set, then back to a list
        unique_cves = list(set([c.upper() for c in cve_matches]))
        print(f"[+] Found {len(unique_cves)} total CVEs listed on Akaoma.")
        
    except Exception as e:
        print(f"[!] Failed to retrieve main index: {e}")
        return

    #Cross-Reference and Fetch New Data
    new_entries_count = 0
    for cve_id in unique_cves:
        formatted_id = cve_id.replace('-', '_')
        
        #Only trigger a web request if the entry does NOT exist in our DB
        if formatted_id not in cve_db:
            exact_data = fetch_exact_akaoma_data(cve_id)
            
            if exact_data:
                cve_db[formatted_id] = exact_data
                new_entries_count += 1
                print(f"[+] Successfully added new intelligence for {cve_id}")
                
                #Pause briefly to prevent the server from banning IP
                time.sleep(1.5) 
        else:
            # Silently skip existing entries to save time and bandwidth
            pass

    #Save Updates to Disk
    if new_entries_count > 0:
        with open(DB_PATH, 'w') as f:
            json.dump(cve_db, f, indent=4)
        print(f"\n[+] Database synchronization complete! Added {new_entries_count} new entries. Total entries: {len(cve_db)}")
    else:
        print(f"\n[+] Database is already up to date. Total entries: {len(cve_db)}")

if __name__ == "__main__":
    update_cve_database()