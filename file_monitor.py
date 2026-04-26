import time
import os
from collections import defaultdict
from detection_engine import detect_mass_file_deletion
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from database import log_event

print("=== REAL-TIME FILE MONITOR STARTED ===")

MONITOR_PATH = "/home/kali"

# ─────────────────────────────────────────────────────────
# Directory segments — any path containing one of these
# strings is silently dropped
# ─────────────────────────────────────────────────────────
IGNORE_DIRS = [
    ".cache/mozilla",
    ".mozilla/firefox",
    ".local/share/gvfs-metadata",
    ".local/share/recently-used",
    "safebrowsing",
    "startupCache",
    "datareporting",
    ".config/xfce4",           # NEW: XFCE config files (panel, settings)
    ".config/qterminal.org",   # NEW: qterminal config lock/temp files
    ".config/Thunar",          # NEW: file manager config
    ".config/pulse",           # NEW: PulseAudio config
]

# ─────────────────────────────────────────────────────────
# File-level patterns — suffix or substring match
# ─────────────────────────────────────────────────────────
IGNORE_PATTERNS = [
    # Editor / temp artifacts
    ".swp", ".tmp",
    # Our own DB
    "security_logs.db", "security_logs.db-journal",
    # SQLite WAL noise
    ".sqlite-wal", ".sqlite-journal",
    # Firefox safe-browsing store files
    ".sbstore", ".vlpset", ".metadata",
    # Firefox misc
    "AlternateServices.bin", "prefs-1.js",
    "session-state.json", "aborted-session-ping",
    "urlCache-new.bin",
    "cache2/entries", "cache2/index", "cache2/ce_",
    # X11 session error log (written constantly by the desktop)
    ".xsession-errors",
    # ZSH history lock (created + deleted instantly)
    ".zsh_history.LOCK",
    # gvfs metadata rotated logs
    ".log.",
    # SSH known_hosts — updated automatically on every new SSH connection
    ".ssh/known_hosts",        # NEW
    # App config temp/lock files
    ".ini.lock", ".ini.MLz",   # NEW: qterminal temp files
    ".xml.new",                # NEW: XFCE config atomic-write temp files
    "#",                       # NEW: editor backup files (e.g. #3035407)
]


def should_ignore(path):
    for d in IGNORE_DIRS:
        if d in path:
            return True
    for pattern in IGNORE_PATTERNS:
        if pattern in path:
            return True
    return False


# ─────────────────────────────────────────────────────────
# DEDUPLICATION
#
# Problem 1: `touch file.txt` fires on_created + on_modified
#   Fix: track recently created files; suppress the modify
#        that arrives within 1 second of creation.
#
# Problem 2: a single file write fires on_modified TWICE
#   Fix: track last-logged timestamp per path; ignore a
#        second modify on the same path within 1 second.
# ─────────────────────────────────────────────────────────
DEDUP_WINDOW = 1.0  # seconds

_recently_created = {}   # path -> timestamp of creation event
_last_modified    = {}   # path -> timestamp of last logged modify


def _cleanup_dedup_caches():
    """Periodically evict old entries to avoid unbounded memory growth."""
    now = time.time()
    stale = [p for p, t in _recently_created.items() if now - t > 5]
    for p in stale:
        del _recently_created[p]
    stale = [p for p, t in _last_modified.items() if now - t > 5]
    for p in stale:
        del _last_modified[p]


class FileMonitorHandler(FileSystemEventHandler):

    def on_created(self, event):
        if event.is_directory or should_ignore(event.src_path):
            return

        now = time.time()
        _recently_created[event.src_path] = now

        message = f"File created: {event.src_path}"
        print("[FILE CREATED]", message)
        log_event("FILE_CREATE", "filesystem", message, "LOW")

        # Alert: unexpected script creation
        if event.src_path.endswith((".sh", ".py")):
            alert_msg = f"Script file created: {event.src_path}"
            print("[ALERT]", alert_msg)
            log_event("ALERT", "filesystem", alert_msg, "HIGH")

        # Alert: sensitive file creation
        sensitive = ["/etc/passwd", "/etc/shadow", "/etc/sudoers",
                     "/etc/hosts", "/etc/crontab"]
        if any(event.src_path == s for s in sensitive):
            alert_msg = f"Sensitive file created: {event.src_path}"
            print("[ALERT]", alert_msg)
            log_event("ALERT", "filesystem", alert_msg, "HIGH")

        _cleanup_dedup_caches()

    def on_modified(self, event):
        if event.is_directory or should_ignore(event.src_path):
            return

        now = time.time()
        path = event.src_path

        # Suppress modify that immediately follows a create (touch, etc.)
        if now - _recently_created.get(path, 0) < DEDUP_WINDOW:
            return

        # Suppress duplicate modify within dedup window (double inotify fire)
        if now - _last_modified.get(path, 0) < DEDUP_WINDOW:
            return

        _last_modified[path] = now

        message = f"File modified: {path}"
        print("[FILE MODIFIED]", message)
        log_event("FILE_MODIFY", "filesystem", message, "LOW")

        # Alert: sensitive file modification
        sensitive = ["/etc/passwd", "/etc/shadow", "/etc/sudoers",
                     "/etc/hosts", "/etc/crontab"]
        if any(path == s for s in sensitive):
            alert_msg = f"Sensitive file modified: {path}"
            print("[ALERT]", alert_msg)
            log_event("ALERT", "filesystem", alert_msg, "HIGH")

    def on_deleted(self, event):
        if event.is_directory or should_ignore(event.src_path):
            return

        message = f"File deleted: {event.src_path}"
        print("[FILE DELETED]", message)
        log_event("FILE_DELETE", "filesystem", message, "MEDIUM")

        detect_mass_file_deletion(event.src_path, time.time())


def monitor_files():
    event_handler = FileMonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_PATH, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
