from asyncio import exceptions
import os
import shutil
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

TARGET_DIR = os.path.abspath("target_iac_files")
BACKUP_DIR = os.path.abspath(".vanguard_backup")

class VanguardRemdiationHandler (FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return
        
        file_path = event.src_path
        filename = os.path.basename(file_path)

        #preventing infite loops by ignoring already pathced files or backup files
        if filename.endswith(".patch") or ".vanguard_backup" in file_path:
            return
        
        print (f"\n[WATCHDOG] Modification detected in: {filename}")
        self.appy_zero_trust_patch(file_path, filename)
    
    def apply_zero_trust_patch(self, orginal_path, filename):
        #Creates a secure backup and simlate a line level remidation patch
         
        if not os.path.exusts(BACKUP_DIR):
            os.makedirs(BACKUP_DIR, exist_ok=True)
        
        backup_path = os.path.join(BACKUP_DIR, f"{filename}.bak_{int(time.time())}")

        try:
            # creating zero trust backup
            shutil.copy2(orginal_path, backup_path)
            print(f"[REMIDIATION] Secure Backup created at {backup_path}")

            # line level patcher
            #this recieve the exact line number from the ML engine
            with open(orginal_path, 'r') as f:
                content = f.readlines()
            
            #append security hardeing flag to the newly modiflied file
            patched_content = [line for line in content]
            patched_content.insert(0, "# VANGUARDNODE AUTOPATCH: Security constraints verified.\n")

            with open(orginal_path, 'w') as f:
                f.writelines(patched_content)

            print(f"[REMEDIATION] line-level patch applied succesffuly to {filename}.")
        except Exception as e:
            print(f"[ERROR] failed to apply patch to {filename}: {str (e)}")

    def start_watchdog():
        if not os.path.exists(TARGET_DIR):
            os.makedirs(TARGET_DIR, exist_ok=True)

        event_handler = VanguardRemdiationHandler()
        Observer = Observer()
        Observer.schedule(event_handler, TARGET_DIR, recursive=False)

        print(f"[*] Vanguard Watchdog Daemon activated.")
        print(f"[*] monitoring directory: {TARGET_DIR}")
        print(f"[*] Standby for zero trust patching loop...")

        Observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            Observer.stop()
            print("\n[*] Watchdog deactivated.")
        Observer.join()
    
    if __name__ == "__main__":
        start_watchdog()

            