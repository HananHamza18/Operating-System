import time
import threading
import subprocess
import re
import os
import glob
import pwd
from collections import defaultdict

from detection_engine import (
    detect_failed_login, detect_failed_ip,
    detect_sudo_failure, detect_su_failure
)
from file_monitor import monitor_files
from process_monitor import monitor_processes
from database import init_db, log_event

print("=== REAL-TIME DEFENSE SYSTEM STARTED ===")
init_db()


# ══════════════════════════════════════════════════════════
#  REGEX — matched against ACTUAL Kali journal output
#
#  What journalctl REALLY outputs on Kali (verified):
#
#  sudo wrong password:
#    pam_unix(sudo:auth): conversation failed
#    pam_unix(sudo:auth): auth could not identify password for [kali]
#
#  sudo success:
#    sudo[PID]: kali : TTY=pts/0 ; ... COMMAND=/usr/bin/...
#    pam_unix(sudo:session): session opened for user root...
#
#  SSH failed:
#    Failed password for kali from 192.168.x.x port ...
#
#  SSH success:
#    Accepted password for kali from 192.168.x.x port ...
#
#  su wrong password  →  appears in /var/log/auth.log (rsyslog)
#    pam_unix(su:auth): authentication failure; ... user=kali
#    su: FAILED SU (to fakeuser) kali on /dev/pts/0
# ══════════════════════════════════════════════════════════

# sudo PAM failure — matches BOTH real Kali formats
RE_SUDO_CONV_FAIL = re.compile(
    r"pam_unix\(sudo:auth\):\s+(?:conversation failed|auth could not identify password for \[(\w+)\])"
)
RE_SUDO_USER_FROM_PROC = re.compile(r"sudo\[(\d+)\]:\s+(\w+)\s+:")  # sudo[PID]: user :
RE_SUDO_CMD      = re.compile(r"sudo\[?\d*\]?:.*COMMAND=")
RE_SUDO_SESSION  = re.compile(r"pam_unix\(sudo:session\): session opened for user \w+ by (\w+)")

# SSH
RE_FAILED_SSH_USER = re.compile(r"Failed password for (?:invalid user )?(\w+)")
RE_FAILED_SSH_IP   = re.compile(r"from ([\d\.]+)")
RE_ACCEPTED_SSH    = re.compile(r"(?:Accepted password|Accepted publickey) for (\w+) from ([\d\.]+)")

# su (appears in auth.log via rsyslog, not in journalctl on Kali)
RE_SU_FAIL_PAM   = re.compile(r"pam_unix\(su(?:-l)?:auth\): authentication failure.*?user=(\w+)")
RE_SU_FAIL_LOG   = re.compile(r"su: FAILED SU \(to (\w+)\) (\w+)")
RE_SU_SUCCESS    = re.compile(r"Successful su for (\w+) by (\w+)")

# Generic PAM failure for other services
RE_PAM_FAIL      = re.compile(r"pam_unix\((\w+):auth\): authentication failure.*?user=(\w+)")

# Track which sudo PIDs we've already extracted the username from
_sudo_fail_pids = {}   # pid -> username


def _parse_line(line, now, source_label="journal"):
    """
    Parse one line from journalctl or auth.log.
    Fires the appropriate detection function AND logs to DB.
    """

    # ── sudo: PAM conversation failed (Kali-specific format) ──
    # This is what Kali actually logs instead of "authentication failure"
    if "pam_unix(sudo:auth)" in line:
        if "conversation failed" in line or "auth could not identify" in line:
            # Extract username from the process line pattern sudo[PID]: user :
            # We can't get it from this line directly — look it up from /proc
            # using the PID in the line
            pid_match = re.search(r"sudo\[(\d+)\]", line)
            user = "unknown"
            if pid_match:
                pid = pid_match.group(1)
                try:
                    with open(f"/proc/{pid}/status") as f:
                        for l in f:
                            if l.startswith("Uid:"):
                                uid = int(l.split()[1])
                                user = pwd.getpwuid(uid).pw_name
                                break
                except Exception:
                    pass
                _sudo_fail_pids[pid] = user

            # Also try extracting from "auth could not identify password for [user]"
            bracket_match = re.search(r"for \[(\w+)\]", line)
            if bracket_match:
                user = bracket_match.group(1)

            msg = f"Wrong sudo password for user '{user}'"
            print("[SUDO FAIL]", msg)
            log_event("AUTH_FAIL", "sudo", msg, "MEDIUM")
            detect_sudo_failure(user, now)
            return

    # ── sudo: session opened = successful sudo ───────────────
    if "pam_unix(sudo:session): session opened" in line:
        m = RE_SUDO_SESSION.search(line)
        user = m.group(1) if m else "unknown"
        msg = f"sudo session opened by '{user}'"
        print("[SUDO SUCCESS]", msg)
        log_event("AUTH_SUCCESS", "sudo", msg, "LOW")
        return

    # ── sudo: COMMAND= line (privilege escalation log) ───────
    if RE_SUDO_CMD.search(line):
        # Extract user from "sudo[PID]: username :"
        m = RE_SUDO_USER_FROM_PROC.search(line)
        user = m.group(2) if m else "unknown"
        # Extract command
        cmd_match = re.search(r"COMMAND=(.+)", line)
        cmd = cmd_match.group(1).strip() if cmd_match else line.strip()
        msg = f"sudo command by '{user}': {cmd}"
        print("[SUDO USAGE]", msg)
        log_event("PRIV_ESC", "sudo", msg, "MEDIUM")
        return

    # ── SSH: failed password ─────────────────────────────────
    if "Failed password" in line:
        m_user = RE_FAILED_SSH_USER.search(line)
        m_ip   = RE_FAILED_SSH_IP.search(line)
        if m_user:
            user = m_user.group(1)
            msg  = f"Failed SSH login for user '{user}'"
            print("[AUTH FAILED]", msg)
            log_event("AUTH_FAIL", "ssh", msg, "MEDIUM")
            detect_failed_login(user, now)
        if m_ip:
            ip  = m_ip.group(1)
            msg = f"Failed SSH login from IP {ip}"
            log_event("AUTH_FAIL", "ssh", msg, "MEDIUM")
            detect_failed_ip(ip, now)
        return

    # ── SSH: successful login ────────────────────────────────
    if "Accepted password" in line or "Accepted publickey" in line:
        m = RE_ACCEPTED_SSH.search(line)
        if m:
            msg = f"Successful SSH login — user '{m.group(1)}' from {m.group(2)}"
        else:
            msg = line.strip()
        print("[SSH LOGIN]", msg)
        log_event("AUTH_SUCCESS", "ssh", msg, "LOW")
        return

    # ── su: PAM authentication failure (in auth.log) ─────────
    if "pam_unix(su" in line and "authentication failure" in line:
        m = RE_SU_FAIL_PAM.search(line)
        user = m.group(1) if m else "unknown"
        msg = f"Wrong password on su attempt for user '{user}'"
        print("[SU FAIL]", msg)
        log_event("AUTH_FAIL", "su", msg, "MEDIUM")
        detect_su_failure(user, now)
        return

    # ── su: FAILED SU log line ───────────────────────────────
    if "FAILED SU" in line:
        m = RE_SU_FAIL_LOG.search(line)
        if m:
            target, actor = m.group(1), m.group(2)
            msg = f"Failed su by '{actor}' to '{target}'"
            print("[SU FAIL]", msg)
            log_event("AUTH_FAIL", "su", msg, "MEDIUM")
            detect_su_failure(actor, now)
        return

    # ── su: success ──────────────────────────────────────────
    if "Successful su" in line:
        m = RE_SU_SUCCESS.search(line)
        if m:
            msg = f"Successful su to '{m.group(1)}' by '{m.group(2)}'"
            print("[SU SUCCESS]", msg)
            log_event("AUTH_SUCCESS", "su", msg, "LOW")
        return

    # ── Generic PAM failure (login, screensaver, etc.) ───────
    if "pam_unix" in line and "authentication failure" in line:
        m = RE_PAM_FAIL.search(line)
        if m:
            service, user = m.group(1), m.group(2)
            # Skip sudo — already handled above
            if service.startswith("sudo"):
                return
            msg = f"PAM auth failure for '{user}' via {service}"
            print("[AUTH FAIL]", msg)
            log_event("AUTH_FAIL", "pam", msg, "MEDIUM")


# ══════════════════════════════════════════════════════════
#  SOURCE 1 — journalctl -f
#  Catches: SSH, sudo (PAM), sudo COMMAND lines
# ══════════════════════════════════════════════════════════

def monitor_journal():
    print("[*] JournalMonitor: starting...")
    try:
        proc = subprocess.Popen(
            ["sudo", "journalctl", "-f", "-o", "short-iso", "--no-pager"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
    except Exception as e:
        print(f"[ERROR] journalctl failed: {e}")
        return

    print("[*] JournalMonitor: active.")
    for line in proc.stdout:
        _parse_line(line, time.time(), "journal")


# ══════════════════════════════════════════════════════════
#  SOURCE 2 — /var/log/auth.log
#
#  WHY THIS IS NEEDED:
#  On Kali, `su` wrong password events go to auth.log via
#  rsyslog — they do NOT appear in journalctl at all.
#  This is the ONLY reliable source for su PAM failures.
#
#  Run setup_logging.sh first to enable rsyslog.
# ══════════════════════════════════════════════════════════

def monitor_auth_log():
    AUTH_LOG = "/var/log/auth.log"
    if not os.path.exists(AUTH_LOG):
        print("[WARN] /var/log/auth.log missing — su failures won't be captured.")
        print("[WARN] Run: sudo bash setup_logging.sh")
        return

    print("[*] AuthLogMonitor: tailing /var/log/auth.log...")
    try:
        proc = subprocess.Popen(
            ["sudo", "tail", "-F", "-n", "0", AUTH_LOG],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
    except Exception as e:
        print(f"[ERROR] tail auth.log failed: {e}")
        return

    for line in proc.stdout:
        _parse_line(line, time.time(), "auth.log")


# ══════════════════════════════════════════════════════════
#  SOURCE 3 — /proc watcher for su/sudo
#
#  Detects su/sudo process invocations directly.
#  Acts as a guaranteed fallback when journal/auth.log miss
#  an event. Logs every invocation to DB immediately.
# ══════════════════════════════════════════════════════════

_seen_sudo_pids = set()


def monitor_sudo_proc():
    print("[*] ProcMonitor: watching for su/sudo processes...")

    while True:
        try:
            for pid_dir in glob.glob("/proc/[0-9]*/"):
                try:
                    pid = int(pid_dir.split("/")[2])
                    if pid in _seen_sudo_pids:
                        continue

                    comm_path = f"/proc/{pid}/comm"
                    if not os.path.exists(comm_path):
                        continue

                    with open(comm_path) as f:
                        comm = f.read().strip()

                    if comm not in ("sudo", "su"):
                        continue

                    _seen_sudo_pids.add(pid)

                    # Read cmdline
                    try:
                        with open(f"/proc/{pid}/cmdline", "rb") as f:
                            cmdline = f.read().decode(errors="replace").replace("\x00", " ").strip()
                    except Exception:
                        cmdline = comm

                    # Read username from UID
                    try:
                        uid = None
                        with open(f"/proc/{pid}/status") as f:
                            for line in f:
                                if line.startswith("Uid:"):
                                    uid = int(line.split()[1])
                                    break
                        username = pwd.getpwuid(uid).pw_name if uid is not None else "unknown"
                    except Exception:
                        username = "unknown"

                    msg = f"{comm} invoked by '{username}' | cmd: {cmdline}"
                    print(f"[{comm.upper()} DETECTED]", msg)
                    log_event("PRIV_ESC", comm, msg, "MEDIUM")

                except (ValueError, PermissionError, FileNotFoundError):
                    continue

            if len(_seen_sudo_pids) > 5000:
                _seen_sudo_pids.clear()

        except Exception as e:
            print(f"[WARN] ProcMonitor error: {e}")

        time.sleep(1)


# ══════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":

    threads = [
        threading.Thread(target=monitor_processes,  daemon=True, name="ProcessMonitor"),
        threading.Thread(target=monitor_files,       daemon=True, name="FileMonitor"),
        threading.Thread(target=monitor_journal,     daemon=True, name="JournalMonitor"),
        threading.Thread(target=monitor_auth_log,    daemon=True, name="AuthLogMonitor"),
        threading.Thread(target=monitor_sudo_proc,   daemon=True, name="SudoProcMonitor"),
    ]

    for t in threads:
        t.start()
        print(f"[*] Started: {t.name}")

    print("\n[*] All monitors active. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
