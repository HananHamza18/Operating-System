"""
process_monitor.py  —  Security Logging & Reporting System

Bugs fixed vs original GitHub version:
  1. CRASH BUG: detect_suspicious_process(process_name) — variable
     'process_name' was never defined. Should be 'name'. This caused
     every new process detection to silently crash, meaning NO suspicious
     process was ever detected.
  2. No noise filtering — every kernel thread, browser helper, system
     daemon logged as an event. Added comprehensive ignore list.
  3. proc.exe() called without try/except — crashes on permission denied
     for many root processes.
"""

from detection_engine import detect_suspicious_process
import psutil
import time
from database import log_event

print("=== REAL-TIME PROCESS MONITOR STARTED ===")

known_pids = set()

# ── Exact process names to ignore ────────────────────────
IGNORE_PROCESS_NAMES = {
    # Firefox sandbox / renderer
    "bwrap", "glycin-image-rs", "glycin-svg",
    "Web Content", "Chroot Helper", "file:// Content",
    "Privileged Cont", "Socket Process", "Utility Process",
    "WebExtensions", "glxtest", "firefox-esr",

    # GNOME virtual filesystem
    "gvfs-mtp-volume-monitor", "gvfs-gphoto2-volume-monitor",
    "gvfs-afc-volume-monitor", "gvfs-goa-volume-monitor",
    "gvfsd-trash", "fusermount3", "gvfsd-metadata",

    # XDG desktop portals
    "xdg-desktop-portal", "xdg-desktop-portal-gtk",
    "xdg-permission-store", "xdg-document-portal",

    # Audio subsystem
    "pipewire", "pipewire-pulse", "wireplumber", "mpris-proxy",

    # Session / display
    "dbus-daemon", "gpg-agent", "gnome-keyring-daemon",
    "xfce4-session", "xfce4-notifyd", "xfce4-panel",
    "xfce4-mime-helper", "lightdm", "Xorg",

    # systemd workers
    "systemd", "(sd-pam)", "systemd-journald",
    "systemd-timesyncd", "systemd-userdbd",
    "systemd-udevd", "systemd-userwork:", "nm-dispatcher",

    # SSH daemon internals (server-side workers, not the ssh client)
    "sshd-session", "sshd-auth",

    # PAM / auth helpers (internal, actual event captured by auth monitor)
    "unix_chkpwd", "polkit-agent-helper-1",

    # Disk / block queries from desktop automount
    "lsblk",

    # XFCE backend
    "SystemToolsBack",

    # VMware / bluetooth / smartcard
    "vmware-vmblock-fuse", "rtkit-daemon", "obexd", "pcscd",

    # Shell / terminal (normal user activity)
    "zsh", "bash", "sh", "qterminal",

    # Network / system services
    "NetworkManager", "ModemManager", "upowerd",
    "accounts-daemon", "polkitd", "systemd-logind",
    "rsyslogd", "cron",

    # Misc
    "psimon", "wrapper-2.0",
}

# ── Prefix patterns to ignore (kernel threads) ───────────
IGNORE_PREFIXES = (
    "kworker/",    # kernel worker threads
    "irq/",        # interrupt threads
    "jbd2/",       # ext4 journal threads
    "xfce4-",      # all XFCE helpers
)


def should_ignore_process(name):
    if name in IGNORE_PROCESS_NAMES:
        return True
    for prefix in IGNORE_PREFIXES:
        if name.startswith(prefix):
            return True
    if name.startswith("glycin-"):
        return True
    return False


def monitor_processes():
    global known_pids

    while True:
        current_pids = set(psutil.pids())
        new_pids     = current_pids - known_pids

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                user = proc.username()

                if should_ignore_process(name):
                    known_pids.add(pid)
                    continue

                message = f"Process started | PID={pid} | Name={name} | User={user}"
                print("[PROCESS START]", message)
                log_event("PROCESS_START", name, message, "LOW")

                # BUG FIX: original code used undefined variable 'process_name'
                # which caused a silent NameError on every process — fixed to 'name'
                detect_suspicious_process(name)

                # Alert: root process running from /tmp
                if user == "root":
                    try:
                        exe_path = proc.exe()
                        if exe_path.startswith("/tmp"):
                            alert_msg = f"Suspicious root process in /tmp | PID={pid} | Name={name}"
                            print("[ALERT]", alert_msg)
                            log_event("ALERT", name, alert_msg, "HIGH")
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        known_pids = current_pids
        time.sleep(2)
