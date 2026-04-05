from collections import defaultdict
import time
from database import log_event

# Track failed logins
failed_login_tracker = defaultdict(list)

# Track file deletions
file_delete_tracker = defaultdict(list)

# Suspicious process names
SUSPICIOUS_PROCESSES = ["nmap", "hydra", "nc", "netcat", "msfconsole"]

def detect_failed_login(user, timestamp):
    failed_login_tracker[user].append(timestamp)

    # Keep only last 60 seconds
    failed_login_tracker[user] = [
        t for t in failed_login_tracker[user]
        if timestamp - t < 60
    ]

    if len(failed_login_tracker[user]) >= 5:
        alert_msg = f"Brute force suspected for user: {user}"
        print("[ALERT]", alert_msg)
        log_event("ALERT", "auth", alert_msg, "HIGH")

def detect_suspicious_process(process_name):
    for suspicious in SUSPICIOUS_PROCESSES:
        if suspicious in process_name.lower():
            alert_msg = f"Suspicious process detected: {process_name}"
            print("[ALERT]", alert_msg)
            log_event("ALERT", "process", alert_msg, "HIGH")
            break


def detect_mass_file_deletion(file_path, timestamp):
    file_delete_tracker["global"].append(timestamp)

    file_delete_tracker["global"] = [
        t for t in file_delete_tracker["global"]
        if timestamp - t < 30
    ]

    if len(file_delete_tracker["global"]) >= 10:
        alert_msg = "Mass file deletion detected!"
        print("[ALERT]", alert_msg)
        log_event("ALERT", "filesystem", alert_msg, "HIGH")
