import subprocess
import re
from collections import defaultdict

print("=== JOURNAL SECURITY MONITOR STARTED ===\n")

# Get journal logs from today
command = ["sudo", "journalctl", "--since", "today"]
result = subprocess.run(command, capture_output=True, text=True)

logs = result.stdout.split("\n")

failed_count = 0
sudo_count = 0
ip_failures = defaultdict(int)

for line in logs:

    # Detect failed SSH login
    if "Failed password" in line:
        failed_count += 1
        print("[FAILED LOGIN] ->", line)

        # Extract IP address
        match = re.search(r'from ([\d\.:]+)', line)
        if match:
            ip = match.group(1)
            ip_failures[ip] += 1

    # Detect successful login
    if "Accepted password" in line:
        print("[SUCCESS LOGIN] ->", line)

    # Detect sudo usage
    if "sudo" in line and "COMMAND=" in line:
        sudo_count += 1
        print("[SUDO USAGE] ->", line)

print("\n=== BRUTE FORCE ANALYSIS ===")
for ip, count in ip_failures.items():
    if count >= 3:
        print(f"[ALERT] Possible brute force from {ip} | Attempts: {count}")

print("\n=== SUMMARY ===")
print("Total Failed Logins:", failed_count)
print("Total Sudo Commands:", sudo_count)
print("=== MONITOR FINISHED ===")

