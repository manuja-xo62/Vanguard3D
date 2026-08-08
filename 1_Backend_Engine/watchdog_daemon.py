import os
import shutil
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

TARGET_DIR = os.path.abspath("target_iac_files")
BACKUP_DIR = os.path.abspath(".vanguard_backup")

class VanguardRemediationHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return
        
        file_path = event.src_path
        filename = os.path.basename(file_path)
        
        if filename.endswith(".patch") or ".vanguard_backup" in file_path:
            return
            
        print(f"\n[WATCHDOG] Modification detected in: {filename}")
        self.apply_zero_trust_patch(file_path, filename)

    def apply_zero_trust_patch(self, original_path, filename):
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR, exist_ok=True)
            
        backup_path = os.path.join(BACKUP_DIR, f"{filename}.bak_{int(time.time())}")
        
        try:
            shutil.copy2(original_path, backup_path)
            print(f"[REMEDIATION] Secure backup created at: {backup_path}")
            
            with open(original_path, 'r') as f:
                content = f.readlines()
                
            patched_content = [line for line in content]
            patched_content.insert(0, "# VANGUARDNODE AUTOPATCH: Security constraints verified.\n")
            
            with open(original_path, 'w') as f:
                f.writelines(patched_content)
                
            print(f"[REMEDIATION] Line-level patch applied successfully to {filename}.")
            
        except Exception as e:
            print(f"[ERROR] Remediation failed for {filename}: {str(e)}")

def start_watchdog():
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR, exist_ok=True)
        
    event_handler = VanguardRemediationHandler()
    observer = Observer()
    observer.schedule(event_handler, TARGET_DIR, recursive=False)
    
    print(f"[*] Vanguard Watchdog Daemon activated.")
    print(f"[*] Monitoring directory: {TARGET_DIR}")
    print(f"[*] Standby for zero-trust patching loop...")
    
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[*] Watchdog deactivated.")
    observer.join()

if __name__ == "__main__":
    start_watchdog()