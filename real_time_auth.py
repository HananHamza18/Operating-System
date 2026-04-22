import time
import threading
import subprocess
import re
import os
import glob

from detection_engine import (
    detect_failed_login, detect_failed_ip,
    detect_sudo_failure, detect_su_failure, detect_pam_failure
)
from file_monitor import monitor_files
from process_monitor import monitor_processes
from database import init_db, log_event

print("=== REAL-TIME DEFENSE SYSTEM STARTED ===")
init_db()


# ══════════════════════════════════════════════════════════════
#  SOURCE 1 — journalctl -f
#  Works when systemd-journald is running (always true on Kali)
#  Catches: SSH failures, sudo usage, su failures
# ══════════════════════════════════════════════════════════════

# Regex patterns compiled once for efficiency
RE_FAILED_SSH_USER = re.compile(r"Failed password for (?:invalid user )?(\w+)")
RE_FAILED_SSH_IP   = re.compile(r"from ([\d\.]+)")
RE_ACCEPTED_SSH    = re.compile(r"(?:Accepted password|Accepted publickey) for (\w+) from ([\d\.]+)")
RE_SUDO_FAIL_1     = re.compile(r"pam_unix\(sudo:auth\).*user=(\w+)")   # PAM sudo failure
RE_SUDO_FAIL_2     = re.compile(r"sudo:\s+(\w+)\s+:.*incorrect password")
RE_SUDO_CMD        = re.compile(r"sudo:.*COMMAND=")
RE_SU_FAIL         = re.compile(r"FAILED SU \(to (\w+)\) (\w+)")
RE_SU_SUCCESS      = re.compile(r"Successful su for (\w+) by (\w+)")
RE_PAM_FAIL        = re.compile(r"pam_unix\((\w+):auth\).*authentication failure.*user=(\w+)")


def _parse_journal_line(line, now):
    """Parse a single journal line and fire appropriate events."""

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
        print("[SUCCESS LOGIN]", msg)
        log_event("AUTH_SUCCESS", "ssh", msg, "LOW")
        return

    # ── sudo: wrong password (PAM format) ───────────────────
    if "pam_unix(sudo:auth)" in line and "authentication failure" in line:
        m = RE_SUDO_FAIL_1.search(line)
        user = m.group(1) if m else "unknown"
        msg  = f"Wrong sudo password for user '{user}'"
        print("[SUDO FAIL]", msg)
        log_event("AUTH_FAIL", "sudo", msg, "MEDIUM")
        detect_sudo_failure(user, now)
        return

    # ── sudo: wrong password (alternative format) ────────────
    if "sudo" in line and "incorrect password" in line:
        m = RE_SUDO_FAIL_2.search(line)
        user = m.group(1) if m else "unknown"
        msg  = f"Wrong sudo password for user '{user}'"
        print("[SUDO FAIL]", msg)
        log_event("AUTH_FAIL", "sudo", msg, "MEDIUM")
        detect_sudo_failure(user, now)
        return

    # ── sudo: command executed (privilege use) ───────────────
    if RE_SUDO_CMD.search(line):
        msg = line.strip()
        print("[SUDO USAGE]", msg)
        log_event("PRIV_ESC", "sudo", msg, "MEDIUM")
        return

    # ── su: failed attempt ───────────────────────────────────
    if "FAILED SU" in line:
        m = RE_SU_FAIL.search(line)
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

    # ── Generic PAM failure (not sudo) ───────────────────────
    if "pam_unix" in line and "authentication failure" in line and "sudo" not in line:
        m = RE_PAM_FAIL.search(line)
        if m:
            service, user = m.group(1), m.group(2)
            msg = f"PAM auth failure for '{user}' via {service}"
            print("[AUTH FAIL]", msg)
            log_event("AUTH_FAIL", "pam", msg, "MEDIUM")
            detect_pam_failure(user, now)


def monitor_journal():
    """
    Follow systemd journal in real time.
    This is the PRIMARY auth event source on Kali Linux.
    journalctl -f streams new entries as they arrive.
    """
    print("[*] AuthMonitor: starting journalctl stream...")
    try:
        proc = subprocess.Popen(
            ["sudo", "journalctl", "-f", "-o", "short-iso", "--no-pager"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
    except Exception as e:
        print(f"[ERROR] Could not start journalctl: {e}")
        return

    print("[*] AuthMonitor: journalctl stream active.")
    for line in proc.stdout:
        _parse_journal_line(line, time.time())


# ══════════════════════════════════════════════════════════════
#  SOURCE 2 — /var/log/auth.log tail
#  Works ONLY after setup_logging.sh has been run (rsyslog).
#  Provides a second source and redundancy.
# ══════════════════════════════════════════════════════════════

def monitor_auth_log():
    """
    Tail /var/log/auth.log if it exists (requires rsyslog running).
    Run setup_logging.sh first to enable it.
    Falls back gracefully if not available.
    """
    AUTH_LOG = "/var/log/auth.log"

    if not os.path.exists(AUTH_LOG):
        print("[WARN] /var/log/auth.log not found. Run setup_logging.sh to enable it.")
        print("[WARN] Auth monitoring will rely on journalctl only.")
        return

    print("[*] AuthMonitor: tailing /var/log/auth.log...")
    try:
        proc = subprocess.Popen(
            ["sudo", "tail", "-F", AUTH_LOG],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
    except Exception as e:
        print(f"[ERROR] Could not tail {AUTH_LOG}: {e}")
        return

    for line in proc.stdout:
        _parse_journal_line(line, time.time())


# ══════════════════════════════════════════════════════════════
#  SOURCE 3 — /proc-based sudo/su process watcher
#  Detects sudo/su invocations directly from the process table.
#  Works even when journald misses events (e.g. during startup).
#  Complements journal monitoring — does NOT replace it.
# ══════════════════════════════════════════════════════════════

_seen_sudo_pids = set()

def monitor_sudo_proc():
    """
    Poll /proc every second for new sudo/su processes.
    When found, reads /proc/<pid>/cmdline for context.
    This catches sudo/su invocations regardless of log config.
    """
    print("[*] ProcMonitor: watching for sudo/su processes...")

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

                    with open(comm_path, "r") as f:
                        comm = f.read().strip()

                    if comm not in ("sudo", "su"):
                        continue

                    _seen_sudo_pids.add(pid)

                    # Read command line for context
                    try:
                        with open(f"/proc/{pid}/cmdline", "rb") as f:
                            cmdline = f.read().decode(errors="replace").replace("\x00", " ").strip()
                    except Exception:
                        cmdline = comm

                    # Read the user who ran it
                    try:
                        import pwd
                        stat_path = f"/proc/{pid}/status"
                        uid = None
                        with open(stat_path, "r") as f:
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

            # Clean up old PIDs to keep set small
            if len(_seen_sudo_pids) > 5000:
                _seen_sudo_pids.clear()

        except Exception as e:
            print(f"[WARN] ProcMonitor error: {e}")

        time.sleep(1)


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    threads = [
        threading.Thread(target=monitor_processes, daemon=True, name="ProcessMonitor"),
        threading.Thread(target=monitor_files,     daemon=True, name="FileMonitor"),
        threading.Thread(target=monitor_journal,   daemon=True, name="JournalMonitor"),
        threading.Thread(target=monitor_auth_log,  daemon=True, name="AuthLogMonitor"),
        threading.Thread(target=monitor_sudo_proc, daemon=True, name="SudoProcMonitor"),
    ]

    for t in threads:
        t.start()
        print(f"[*] Started: {t.name}")

    print("\n[*] All monitors running. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
