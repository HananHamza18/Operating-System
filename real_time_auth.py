"""
real_time_auth.py  —  Security Logging & Reporting System
Main entry point — starts all monitors as threads.

Bugs fixed vs original GitHub version:
  1. Ran journalctl in main thread blocking everything — converted to threads
  2. PAM regex looked for "authentication failure" — Kali actually logs
     "conversation failed" and "auth could not identify password" — fixed
  3. No su failure detection at all — added
  4. No PAM failure detection at all — added
  5. IP brute force used a simple counter with no time window — replaced
     with proper time-windowed tracker via detect_failed_ip()
  6. /proc watcher printed [SU DETECTED] to CLI but never called log_event()
     so su events never appeared in the dashboard — fixed
  7. event_type logged as "AUTH" — no matching view query — changed to
     "AUTH_FAIL" / "AUTH_SUCCESS" to match views.py and reporting_engine
  8. No auth.log monitoring — added (catches su failures on Kali)
"""

import time
import threading
import subprocess
import re
import os
import glob
import pwd

from detection_engine import (
    detect_failed_login, detect_failed_ip,
    detect_sudo_failure, detect_su_failure
)
from file_monitor    import monitor_files
from process_monitor import monitor_processes
from database        import init_db, log_event

print("=== REAL-TIME DEFENSE SYSTEM STARTED ===")
init_db()


# ── Compiled regex — matched to ACTUAL Kali journal output ──
#
# Verified format from journalctl on Kali:
#   sudo wrong password:
#     pam_unix(sudo:auth): conversation failed
#     pam_unix(sudo:auth): auth could not identify password for [kali]
#   sudo success:
#     sudo[PID]: kali : TTY=pts/0 ; ... COMMAND=/usr/bin/...
#     pam_unix(sudo:session): session opened for user root by kali(uid=1000)
#   su wrong password → only in /var/log/auth.log (not journalctl)
#     pam_unix(su:auth): authentication failure; ... user=kali
#     su: FAILED SU (to fakeuser) kali on /dev/pts/0

RE_FAILED_SSH_USER  = re.compile(r"Failed password for (?:invalid user )?(\w+)")
RE_FAILED_SSH_IP    = re.compile(r"from ([\d\.]+)")
RE_ACCEPTED_SSH     = re.compile(r"(?:Accepted password|Accepted publickey) for (\w+) from ([\d\.]+)")
RE_SUDO_CONV_FAIL   = re.compile(r"pam_unix\(sudo:auth\):\s+(?:conversation failed|auth could not identify password for \[(\w+)\])")
RE_SUDO_SESSION     = re.compile(r"pam_unix\(sudo:session\): session opened for user \w+ by (\w+)")
RE_SUDO_CMD         = re.compile(r"sudo\[?\d*\]?:.*COMMAND=")
RE_SUDO_USER        = re.compile(r"sudo\[\d+\]:\s+(\w+)\s+:")
RE_SU_FAIL_PAM      = re.compile(r"pam_unix\(su(?:-l)?:auth\): authentication failure.*?user=(\w+)")
RE_SU_FAIL_LOG      = re.compile(r"su: FAILED SU \(to (\w+)\) (\w+)")
RE_SU_SUCCESS       = re.compile(r"Successful su for (\w+) by (\w+)")
RE_PAM_FAIL         = re.compile(r"pam_unix\((\w+):auth\): authentication failure.*?user=(\w+)")
RE_PROC_ID          = re.compile(r"\b(?:sudo|su)\[(\d+)\]")

_auth_dedup_cache = {}
_AUTH_DEDUP_WINDOW = 2.0
_seen_failed_auth_by_pid = {}


def _mark_seen_once(source, event_type, message, now):
    key = (source, event_type, message)
    last = _auth_dedup_cache.get(key, 0.0)
    if now - last < _AUTH_DEDUP_WINDOW:
        return True
    _auth_dedup_cache[key] = now
    if len(_auth_dedup_cache) > 2000:
        stale = [k for k, ts in _auth_dedup_cache.items() if now - ts > 30]
        for k in stale:
            del _auth_dedup_cache[k]
    return False


def _extract_proc_id(line):
    m = RE_PROC_ID.search(line)
    return m.group(1) if m else None


def _parse_line(line, now):
    """
    Parse one line from journalctl or auth.log.
    Calls log_event() AND the appropriate detection function for every match.
    """

    # ── sudo: PAM conversation failed (Kali actual format) ───
    if "pam_unix(sudo:auth)" in line:
        if "conversation failed" in line or "auth could not identify" in line:
            pid = _extract_proc_id(line)
            if pid:
                last = _seen_failed_auth_by_pid.get(("sudo", pid), 0.0)
                if now - last < 5:
                    return
                _seen_failed_auth_by_pid[("sudo", pid)] = now

            # Try extracting username from "for [username]"
            bracket = re.search(r"for \[(\w+)\]", line)
            user    = bracket.group(1) if bracket else "unknown"

            # Fallback: read from /proc using PID in the line
            if user == "unknown":
                pid_m = re.search(r"sudo\[(\d+)\]", line)
                if pid_m:
                    try:
                        with open(f"/proc/{pid_m.group(1)}/status") as f:
                            for l in f:
                                if l.startswith("Uid:"):
                                    user = pwd.getpwuid(int(l.split()[1])).pw_name
                                    break
                    except Exception:
                        pass

            msg = f"Wrong sudo password for user '{user}'"
            print("[SUDO FAIL]", msg)
            if _mark_seen_once("sudo", "AUTH_FAIL", msg, now):
                return
            log_event("AUTH_FAIL", "sudo", msg, "MEDIUM")
            detect_sudo_failure(user, now)
            return

    # ── sudo: session opened = successful sudo ────────────────
    if "pam_unix(sudo:session): session opened" in line:
        m    = RE_SUDO_SESSION.search(line)
        user = m.group(1) if m else "unknown"
        msg  = f"sudo session opened by '{user}'"
        print("[SUDO SUCCESS]", msg)
        if _mark_seen_once("sudo", "AUTH_SUCCESS", msg, now):
            return
        log_event("AUTH_SUCCESS", "sudo", msg, "LOW")
        return

    # ── sudo: COMMAND= line ───────────────────────────────────
    if RE_SUDO_CMD.search(line):
        m    = RE_SUDO_USER.search(line)
        user = m.group(1) if m else "unknown"
        cmd  = re.search(r"COMMAND=(.+)", line)
        cmd  = cmd.group(1).strip() if cmd else line.strip()
        msg  = f"sudo command by '{user}': {cmd}"
        print("[SUDO USAGE]", msg)
        if _mark_seen_once("sudo", "PRIV_ESC", msg, now):
            return
        log_event("PRIV_ESC", "sudo", msg, "MEDIUM")
        return

    # ── SSH: failed password ──────────────────────────────────
    if "Failed password" in line:
        m_user = RE_FAILED_SSH_USER.search(line)
        m_ip   = RE_FAILED_SSH_IP.search(line)
        if m_user:
            user = m_user.group(1)
            msg  = f"Failed SSH login for user '{user}'"
            print("[AUTH FAILED]", msg)
            if not _mark_seen_once("ssh", "AUTH_FAIL", msg, now):
                log_event("AUTH_FAIL", "ssh", msg, "MEDIUM")
            detect_failed_login(user, now)
        if m_ip:
            ip  = m_ip.group(1)
            msg = f"Failed SSH login from IP {ip}"
            if not _mark_seen_once("ssh", "AUTH_FAIL", msg, now):
                log_event("AUTH_FAIL", "ssh", msg, "MEDIUM")
            detect_failed_ip(ip, now)
        return

    # ── SSH: successful login ─────────────────────────────────
    if "Accepted password" in line or "Accepted publickey" in line:
        m = RE_ACCEPTED_SSH.search(line)
        if m:
            msg = f"Successful SSH login — user '{m.group(1)}' from {m.group(2)}"
        else:
            msg = line.strip()
        print("[SSH LOGIN]", msg)
        if _mark_seen_once("ssh", "AUTH_SUCCESS", msg, now):
            return
        log_event("AUTH_SUCCESS", "ssh", msg, "LOW")
        return

    # ── su: PAM auth failure (appears in auth.log on Kali) ───
    if "pam_unix(su" in line and "authentication failure" in line:
        m    = RE_SU_FAIL_PAM.search(line)
        user = m.group(1) if m else "unknown"
        msg  = f"Wrong password on su attempt for user '{user}'"
        print("[SU FAIL]", msg)
        pid = _extract_proc_id(line)
        if pid:
            last = _seen_failed_auth_by_pid.get(("su", pid), 0.0)
            if now - last < 5:
                return
            _seen_failed_auth_by_pid[("su", pid)] = now
        if _mark_seen_once("su", "AUTH_FAIL", msg, now):
            return
        log_event("AUTH_FAIL", "su", msg, "MEDIUM")
        detect_su_failure(user, now)
        return

    # ── su: FAILED SU line ────────────────────────────────────
    if "FAILED SU" in line:
        m = RE_SU_FAIL_LOG.search(line)
        if m:
            target, actor = m.group(1), m.group(2)
            msg = f"Failed su by '{actor}' to '{target}'"
            print("[SU FAIL]", msg)
            if _mark_seen_once("su", "AUTH_FAIL", msg, now):
                return
            log_event("AUTH_FAIL", "su", msg, "MEDIUM")
            detect_su_failure(actor, now)
        return

    # ── su: success ───────────────────────────────────────────
    if "Successful su" in line:
        m = RE_SU_SUCCESS.search(line)
        if m:
            msg = f"Successful su to '{m.group(1)}' by '{m.group(2)}'"
            print("[SU SUCCESS]", msg)
            if _mark_seen_once("su", "AUTH_SUCCESS", msg, now):
                return
            log_event("AUTH_SUCCESS", "su", msg, "LOW")
        return

    # ── Generic PAM failure (not sudo) ────────────────────────
    if "pam_unix" in line and "authentication failure" in line and "sudo" not in line:
        m = RE_PAM_FAIL.search(line)
        if m:
            service, user = m.group(1), m.group(2)
            if not service.startswith("sudo"):
                msg = f"PAM auth failure for '{user}' via {service}"
                print("[AUTH FAIL]", msg)
                if _mark_seen_once("pam", "AUTH_FAIL", msg, now):
                    return
                log_event("AUTH_FAIL", "pam", msg, "MEDIUM")


# ══════════════════════════════════════════════════════════
#  SOURCE 1 — journalctl -f  (SSH + sudo on Kali)
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
        _parse_line(line, time.time())


# ══════════════════════════════════════════════════════════
#  SOURCE 2 — /var/log/auth.log  (su failures on Kali)
#  Requires rsyslog. Run setup_logging.sh first.
# ══════════════════════════════════════════════════════════

def monitor_auth_log():
    AUTH_LOG = "/var/log/auth.log"
    if not os.path.exists(AUTH_LOG):
        print("[WARN] /var/log/auth.log missing — su PAM failures won't be captured.")
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
        _parse_line(line, time.time())


# ══════════════════════════════════════════════════════════
#  SOURCE 3 — /proc watcher  (su/sudo — always works)
#  Detects invocations even when journald misses them.
#  FIX: now calls log_event() so events appear in dashboard.
# ══════════════════════════════════════════════════════════

_seen_sudo_pids = set()


def monitor_sudo_proc():
    print("[*] ProcMonitor: watching /proc for su/sudo...")

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

                    try:
                        with open(f"/proc/{pid}/cmdline", "rb") as f:
                            cmdline = f.read().decode(errors="replace").replace("\x00", " ").strip()
                    except Exception:
                        cmdline = comm

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

                    # FIX: log to DB so it appears in dashboard
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
        threading.Thread(target=monitor_processes, daemon=True, name="ProcessMonitor"),
        threading.Thread(target=monitor_files,     daemon=True, name="FileMonitor"),
        threading.Thread(target=monitor_journal,   daemon=True, name="JournalMonitor"),
        threading.Thread(target=monitor_auth_log,  daemon=True, name="AuthLogMonitor"),
        threading.Thread(target=monitor_sudo_proc, daemon=True, name="SudoProcMonitor"),
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
