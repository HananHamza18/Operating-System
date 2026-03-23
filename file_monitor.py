import time
from detection_engine import detect_mass_file_deletion
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from database import log_event
import time
import os

def should_ignore(path):
    ignore_patterns = [
        ".swp",
        ".tmp",
        ".cache",
        "security_logs.db",
        "security_logs.db-journal"
    ]

    for pattern in ignore_patterns:
        if pattern in path:
            return True

    return False


print("=== REAL-TIME FILE MONITOR STARTED ===")

MONITOR_PATH = "/home/kali"

IGNORE_FILES = ["security_logs.db", "security_logs.db-journal"]


class FileMonitorHandler(FileSystemEventHandler):

    def on_created(self, event):
        if not event.is_directory:

            # Ignore database files
            if should_ignore(event.src_path):
              return

            message = f"File created: {event.src_path}"
            print("[FILE CREATED]", message)
            log_event("FILE_CREATE", "filesystem", message, "LOW")

            # Suspicious rule: script created
            if event.src_path.endswith((".sh", ".py")):
                alert_msg = f"Script file created: {event.src_path}"
                print("[ALERT]", alert_msg)
                log_event("ALERT", "filesystem", alert_msg, "HIGH")

    def on_modified(self, event):
        if not event.is_directory:

            # Ignore database files
            if should_ignore(event.src_path):
                return

            message = f"File modified: {event.src_path}"
            print("[FILE MODIFIED]", message)
            log_event("FILE_MODIFY", "filesystem", message, "LOW")

    def on_deleted(self, event):
        if not event.is_directory:

            # Ignore database files
            if any(ignore in event.src_path for ignore in IGNORE_FILES):
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
