from detection_engine import detect_suspicious_process
import psutil
import time
from database import log_event

print("=== REAL-TIME PROCESS MONITOR STARTED ===")

known_pids = set()

# ─────────────────────────────────────────────
# EXACT process names to silently ignore
# ─────────────────────────────────────────────
IGNORE_PROCESS_NAMES = {
    # Firefox sandbox / renderer helpers
    "bwrap", "glycin-image-rs", "glycin-svg",
    "Web Content", "Chroot Helper", "file:// Content",
    "Privileged Cont", "Socket Process", "Utility Process",
    "WebExtensions", "glxtest", "firefox-esr",

    # GNOME virtual filesystem
    "gvfs-mtp-volume-monitor", "gvfs-gphoto2-volume-monitor",
    "gvfs-afc-volume-monitor", "gvfs-goa-volume-monitor",
    "gvfsd-trash", "fusermount3",

    # XDG desktop portals
    "xdg-desktop-portal", "xdg-desktop-portal-gtk",
    "xdg-permission-store", "xdg-document-portal",

    # Audio subsystem
    "pipewire", "pipewire-pulse", "wireplumber", "mpris-proxy",

    # Session / display services
    "dbus-daemon", "gpg-agent", "gnome-keyring-daemon",
    "xfce4-session", "xfce4-notifyd", "xfce4-panel",
    "lightdm", "Xorg",

    # systemd workers and services
    "systemd", "(sd-pam)", "systemd-journald",
    "systemd-timesyncd", "systemd-userdbd",
    "systemd-udevd", "systemd-userwork:",
    "nm-dispatcher",

    # VMware tools
    "vmware-vmblock-fuse",

    # Real-time / bluetooth
    "rtkit-daemon", "obexd",

    # Smart card daemon
    "pcscd",

    # Shell / terminal (normal user activity)
    "zsh", "bash", "sh", "qterminal",

    # Misc benign
    "psimon",
}

# ─────────────────────────────────────────────
# PREFIX patterns to ignore (kernel threads)
# ─────────────────────────────────────────────
IGNORE_PREFIXES = (
    "kworker/",   # e.g. kworker/0:2-events
    "irq/",       # e.g. irq/56-vmw_vmci
    "jbd2/",      # e.g. jbd2/sda1-8
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
        new_pids = current_pids - known_pids

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

                # BUG FIX: was undefined `process_name`, corrected to `name`
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
