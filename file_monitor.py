import time
from detection_engine import detect_mass_file_deletion
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from database import log_event

print("=== REAL-TIME FILE MONITOR STARTED ===")

MONITOR_PATH = "/home/kali"

SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/home/kali/important.txt"
]

# ─────────────────────────────────────────────
# Directory segments — any path containing
# one of these strings is silently dropped
# ─────────────────────────────────────────────
IGNORE_DIRS = [
    ".cache/mozilla",
    ".mozilla/firefox",
    ".local/share/gvfs-metadata",
    ".local/share/recently-used",
    "safebrowsing",
    "startupCache",
    "datareporting",
]

# ─────────────────────────────────────────────
# File-level patterns — suffix or substring
# ─────────────────────────────────────────────
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
]


def should_ignore(path):
    for d in IGNORE_DIRS:
        if d in path:
            return True
    for pattern in IGNORE_PATTERNS:
        if pattern in path:
            return True
    return False


class FileMonitorHandler(FileSystemEventHandler):

    def on_created(self, event):
        if event.is_directory or should_ignore(event.src_path):
            return

        message = f"File created: {event.src_path}"
        print("[FILE CREATED]", message)
        log_event("FILE_CREATE", "filesystem", message, "LOW")

        # High-severity: unexpected script creation
        if event.src_path.endswith((".sh", ".py")):
            alert_msg = f"Script file created: {event.src_path}"
            print("[ALERT]", alert_msg)
            log_event("ALERT", "filesystem", alert_msg, "HIGH")

    def on_modified(self, event):
        if event.is_directory or should_ignore(event.src_path):
            return

        message = f"File modified: {event.src_path}"
        print("[FILE MODIFIED]", message)
        log_event("FILE_MODIFY", "filesystem", message, "LOW")

    # 🔴 Sensitive file check
        if event.src_path in SENSITIVE_FILES:
            alert_msg = f"Sensitive file modified: {event.src_path}"
            print("[ALERT]", alert_msg)
            log_event("ALERT", "filesystem", alert_msg, "HIGH")

    def on_deleted(self, event):
        if event.is_directory or should_ignore(event.src_path):
            return

        message = f"File deleted: {event.src_path}"
        print("[FILE DELETED]", message)
        log_event("FILE_DELETE", "filesystem", message, "MEDIUM")

    # 🔴 Sensitive file deletion alert
        if event.src_path in SENSITIVE_FILES:
            alert_msg = f"Sensitive file deleted: {event.src_path}"
            print("[ALERT]", alert_msg)
            log_event("ALERT", "filesystem", alert_msg, "HIGH")

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
