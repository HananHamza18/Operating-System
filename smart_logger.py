import psutil
from datetime import datetime

LOG_FILE = "security_report.txt"

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} | {msg}\n")

def scan_processes():
    log("=== PROCESS SCAN STARTED ===")
    suspicious = 0

    for p in psutil.process_iter(['pid','name','username','exe']):
        try:
            name = p.info['name']
            user = p.info['username']
            exe  = p.info['exe']

            if user == 'root' and exe and '/tmp' in exe:
                log(f"[ALERT] Root process running from /tmp → {name} ({exe})")
                suspicious += 1
            else:
                log(f"PROCESS | {name} | USER={user}")
        except:
            pass

    log(f"=== PROCESS SCAN FINISHED | Suspicious={suspicious} ===\n")

if __name__ == "__main__":
    log("===== SMART LOGGER STARTED =====")
    scan_processes()
