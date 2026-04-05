import time
import threading
import subprocess
import re
from collections import defaultdict

from detection_engine import detect_failed_login
from file_monitor import monitor_files
from process_monitor import monitor_processes
from database import init_db, log_event

print("=== REAL-TIME DEFENSE SYSTEM STARTED ===")

# Initialize database
init_db()

# Dictionary to track failed attempts per IP
ip_failures = defaultdict(int)

# Start process monitor thread
process_thread = threading.Thread(target=monitor_processes, daemon=True)
process_thread.start()

# Start file monitor thread
file_thread = threading.Thread(target=monitor_files, daemon=True)
file_thread.start()

# Start journalctl in follow mode
process = subprocess.Popen(
    ["sudo", "journalctl", "-f"],
    stdout=subprocess.PIPE,
    text=True
)

for line in process.stdout:

    # ----------------------------
    # Detect Failed Login
    # ----------------------------
    if "Failed password" in line:

        # Extract username
        user_match = re.search(r"Failed password for (invalid user )?(\w+)", line)

        # Extract IP address
        ip_match = re.search(r"from ([\d\.:]+)", line)

        if user_match:
            user = user_match.group(2)
            message = f"Failed login attempt for user {user}"
            print("[AUTH FAILED]", message)
            log_event("AUTH", "ssh", message, "MEDIUM")

            # Call user-based brute-force detection
            detect_failed_login(user, time.time())

        if ip_match:
            ip = ip_match.group(1)
            ip_failures[ip] += 1

            if ip_failures[ip] >= 3:
                alert_msg = f"Brute force suspected from {ip} ({ip_failures[ip]} attempts)"
                print("[ALERT]", alert_msg)
                log_event("ALERT", "ssh", alert_msg, "HIGH")
                ip_failures[ip] = 0  # reset counter

    # ----------------------------
    # Detect Successful Login
    # ----------------------------
    if "Accepted password" in line:
        success_msg = line.strip()
        print("[SUCCESS LOGIN]", success_msg)
        log_event("AUTH", "ssh", success_msg, "LOW")

    # ----------------------------
    # Detect Sudo Usage
    # ----------------------------
    if "sudo" in line and "COMMAND=" in line:
        sudo_msg = line.strip()
        print("[SUDO USAGE]", sudo_msg)
        log_event("PRIV_ESC", "sudo", sudo_msg, "MEDIUM")

