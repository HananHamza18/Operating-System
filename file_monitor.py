"""
file_monitor.py  —  Security Logging & Reporting System

Bugs fixed vs original GitHub version:
  1. No sensitive file protection at all — added alerts for /etc/passwd etc.
  2. Noise filtering was minimal (only .swp .tmp .cache) — massively expanded
  3. touch file.txt generated 2 events (create + modify) — deduplication added
  4. Single file write generated 2 modify events — deduplication added
"""

import time
import os
from detection_engine import detect_mass_file_deletion
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from database import log_event

print("=== REAL-TIME FILE MONITOR STARTED ===")

PATHS_TO_MONITOR = ["/home/kali", "/etc"]

# ── Sensitive files — any access fires HIGH alert ─────────
SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/crontab",
    "/home/kali/projectTesting/file.txt",
]
SENSITIVE_FILE_PATHS = {os.path.abspath(p) for p in SENSITIVE_FILES}

# ── Directory segments to ignore ──────────────────────────
IGNORE_DIRS = [
    ".cache/mozilla",
    ".mozilla/firefox",
    ".local/share/gvfs-metadata",
    ".local/share/recently-used",
    "safebrowsing",
    "startupCache",
    "datareporting",
    ".config/xfce4",
    ".config/qterminal.org",
    ".config/Thunar",
    ".config/pulse",
]

# ── File-level patterns to ignore ────────────────────────
IGNORE_PATTERNS = [
    ".swp", ".tmp",
    "security_logs.db", "security_logs.db-journal",
    ".sqlite-wal", ".sqlite-journal",
    ".sbstore", ".vlpset", ".metadata",
    "AlternateServices.bin", "prefs-1.js",
    "session-state.json", "aborted-session-ping",
    "urlCache-new.bin",
    "cache2/entries", "cache2/index", "cache2/ce_",
    ".xsession-errors",
    ".zsh_history.LOCK",
    ".log.",
    ".ssh/known_hosts",
    ".ini.lock", ".xml.new", "#",
]


def should_ignore(path):
    for d in IGNORE_DIRS:
        if d in path:
            return True
    for p in IGNORE_PATTERNS:
        if p in path:
            return True
    return False


# ── Deduplication ─────────────────────────────────────────
# Prevents: touch file.txt → create + modify (2 events → 1)
# Prevents: single write  → on_modified fires twice (2 → 1)
DEDUP_WINDOW      = 1.0   # seconds
_recently_created = {}    # path -> timestamp
_last_modified    = {}    # path -> timestamp


def _cleanup():
    now = time.time()
    for cache in [_recently_created, _last_modified]:
        stale = [p for p, t in cache.items() if now - t > 5]
        for p in stale:
            del cache[p]


class FileMonitorHandler(FileSystemEventHandler):

    def on_created(self, event):
        if event.is_directory or should_ignore(event.src_path):
            return

        now  = time.time()
        path = event.src_path
        _recently_created[path] = now

        message = f"File created: {path}"
        print("[FILE CREATED]", message)
        log_event("FILE_CREATE", "filesystem", message, "LOW")

        # Alert: script file created
        if path.endswith((".sh", ".py")):
            alert_msg = f"Script file created: {path}"
            print("[ALERT]", alert_msg)
            log_event("ALERT", "filesystem", alert_msg, "HIGH")

        # Alert: sensitive file created
        abs_path = os.path.abspath(path)
        if abs_path in SENSITIVE_FILE_PATHS:
            alert_msg = f"Sensitive file created: {path}"
            print("[ALERT]", alert_msg)
            log_event("ALERT", "filesystem", alert_msg, "HIGH")

        _cleanup()

    def on_modified(self, event):
        if event.is_directory or should_ignore(event.src_path):
            return

        now  = time.time()
        path = event.src_path

        # Suppress modify immediately after create (touch command)
        if now - _recently_created.get(path, 0) < DEDUP_WINDOW:
            return

        # Suppress duplicate modify within dedup window
        if now - _last_modified.get(path, 0) < DEDUP_WINDOW:
            return

        _last_modified[path] = now

        message = f"File modified: {path}"
        print("[FILE MODIFIED]", message)
        log_event("FILE_MODIFY", "filesystem", message, "LOW")

        # Alert: sensitive file modified
        abs_path = os.path.abspath(path)
        if abs_path in SENSITIVE_FILE_PATHS:
            alert_msg = f"Sensitive file modified: {path}"
            print("[ALERT]", alert_msg)
            log_event("ALERT", "filesystem", alert_msg, "HIGH")

    def on_deleted(self, event):
        if event.is_directory or should_ignore(event.src_path):
            return

        path    = event.src_path
        message = f"File deleted: {path}"
        print("[FILE DELETED]", message)
        log_event("FILE_DELETE", "filesystem", message, "MEDIUM")

        # Alert: sensitive file deleted
        abs_path = os.path.abspath(path)
        if abs_path in SENSITIVE_FILE_PATHS:
            alert_msg = f"Sensitive file deleted: {path}"
            print("[ALERT]", alert_msg)
            log_event("ALERT", "filesystem", alert_msg, "HIGH")

        detect_mass_file_deletion(path, time.time())


def monitor_files():
    event_handler = FileMonitorHandler()
    observer      = Observer()
    for path in PATHS_TO_MONITOR:
        observer.schedule(event_handler, path, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
