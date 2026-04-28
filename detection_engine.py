"""
detection_engine.py  —  Security Logging & Reporting System
All threat detection logic lives here.

Bugs fixed vs original GitHub version:
  1. Brute force threshold was 5 — changed to 3
  2. No IP-based brute force tracker — added
  3. No sudo / su failure trackers — added
  4. Suspicious process used substring match causing false positives
     e.g. "nc" matched "systemd-timesyncd" — changed to exact match
  5. No alert cooldown — same event spammed repeatedly — added 120s cooldown
  6. Mass file deletion had no noise filtering and no cooldown — both added
  7. No reset of failure counters after alert fired — added
"""

from collections import defaultdict
import time
from database import log_event

# ── Thresholds ────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 3     # failures before alert
BRUTE_FORCE_WINDOW    = 60    # seconds to look back
ALERT_COOLDOWN        = 120   # seconds before re-alerting same key

MASS_DELETE_THRESHOLD = 10
MASS_DELETE_WINDOW    = 30
MASS_DELETE_COOLDOWN  = 60

# ── Per-source failure trackers ───────────────────────────
_ssh_user_tracker = defaultdict(list)
_ssh_ip_tracker   = defaultdict(list)
_sudo_tracker     = defaultdict(list)
_su_tracker       = defaultdict(list)

# Cooldown store: key -> last alert epoch
_cooldowns = defaultdict(float)

# ── Mass deletion tracking ────────────────────────────────
_delete_tracker         = defaultdict(list)
_last_mass_delete_alert = 0.0

# Paths excluded from mass-deletion count (browser/system noise)
MASS_DELETE_IGNORE_DIRS = [
    ".cache/mozilla", ".mozilla/firefox",
    "safebrowsing", ".local/share/gvfs-metadata",
    ".config/xfce4", ".config/qterminal.org",
]

# ── Suspicious processes — EXACT match only ───────────────
# Exact match prevents false positives like "nc" inside "systemd-timesyncd"
SUSPICIOUS_PROCESSES = {
    "nmap", "hydra", "nc", "netcat",
    "msfconsole", "metasploit", "sqlmap",
    "aircrack-ng", "hashcat", "john",
    "wireshark", "tcpdump", "ettercap",
    "nikto", "dirb", "gobuster",
}


# ── Internal helpers ──────────────────────────────────────

def _prune(lst, now, window):
    return [t for t in lst if now - t < window]


def _fire_alert(source, cd_key, count, label, now):
    """Emit alert if threshold reached and cooldown has passed."""
    if count >= BRUTE_FORCE_THRESHOLD and now - _cooldowns[cd_key] > ALERT_COOLDOWN:
        msg = f"[BRUTE FORCE] {label} — {count} failures in {BRUTE_FORCE_WINDOW}s"
        print("[ALERT]", msg)
        log_event("ALERT", source, msg, "HIGH")
        _cooldowns[cd_key] = now
        return True
    return False


# ── Public detection functions ────────────────────────────

def detect_failed_login(user, timestamp):
    """SSH failed login — track per username."""
    _ssh_user_tracker[user].append(timestamp)
    _ssh_user_tracker[user] = _prune(_ssh_user_tracker[user], timestamp, BRUTE_FORCE_WINDOW)
    if _fire_alert("ssh", f"ssh:user:{user}", len(_ssh_user_tracker[user]),
                   f"SSH user '{user}'", timestamp):
        _ssh_user_tracker[user] = []


def detect_failed_ip(ip, timestamp):
    """SSH failed login — track per source IP."""
    _ssh_ip_tracker[ip].append(timestamp)
    _ssh_ip_tracker[ip] = _prune(_ssh_ip_tracker[ip], timestamp, BRUTE_FORCE_WINDOW)
    if _fire_alert("ssh", f"ssh:ip:{ip}", len(_ssh_ip_tracker[ip]),
                   f"SSH from IP {ip}", timestamp):
        _ssh_ip_tracker[ip] = []


def detect_sudo_failure(user, timestamp):
    """Wrong sudo password — track per username."""
    _sudo_tracker[user].append(timestamp)
    _sudo_tracker[user] = _prune(_sudo_tracker[user], timestamp, BRUTE_FORCE_WINDOW)
    count = len(_sudo_tracker[user])
    print(f"[SUDO FAIL] user='{user}' | {count}/{BRUTE_FORCE_THRESHOLD} in window")
    if _fire_alert("sudo", f"sudo:user:{user}", count,
                   f"sudo wrong password for '{user}'", timestamp):
        _sudo_tracker[user] = []


def detect_su_failure(user, timestamp):
    """Failed su attempt — track per username."""
    _su_tracker[user].append(timestamp)
    _su_tracker[user] = _prune(_su_tracker[user], timestamp, BRUTE_FORCE_WINDOW)
    count = len(_su_tracker[user])
    print(f"[SU FAIL] user='{user}' | {count}/{BRUTE_FORCE_THRESHOLD} in window")
    if _fire_alert("su", f"su:user:{user}", count,
                   f"su failure for '{user}'", timestamp):
        _su_tracker[user] = []


def detect_suspicious_process(process_name):
    """Exact match against known attack tool names."""
    if process_name.lower().strip() in SUSPICIOUS_PROCESSES:
        msg = f"Suspicious process detected: {process_name}"
        print("[ALERT]", msg)
        log_event("ALERT", "process", msg, "HIGH")


def detect_mass_file_deletion(file_path, timestamp):
    """Alert on 10+ real file deletions within 30 seconds."""
    global _last_mass_delete_alert

    # Skip browser/system noise paths
    if any(d in file_path for d in MASS_DELETE_IGNORE_DIRS):
        return

    _delete_tracker["global"].append(timestamp)
    _delete_tracker["global"] = _prune(
        _delete_tracker["global"], timestamp, MASS_DELETE_WINDOW
    )

    if (len(_delete_tracker["global"]) >= MASS_DELETE_THRESHOLD
            and timestamp - _last_mass_delete_alert > MASS_DELETE_COOLDOWN):
        msg = "Mass file deletion detected!"
        print("[ALERT]", msg)
        log_event("ALERT", "filesystem", msg, "HIGH")
        _last_mass_delete_alert = timestamp
        _delete_tracker["global"] = []
