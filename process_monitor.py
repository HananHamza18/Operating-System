from detection_engine import detect_suspicious_process
import psutil
import time
from database import log_event

print("=== REAL-TIME PROCESS MONITOR STARTED ===")

known_pids = set()

def monitor_processes():

    global known_pids

    while True:
        current_pids = set(psutil.pids())

        # Detect new processes
        new_pids = current_pids - known_pids

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                user = proc.username()

                message = f"Process started | PID={pid} | Name={name} | User={user}"
                print("[PROCESS START]", message)

                log_event("PROCESS_START", name, message, "LOW")

                detect_suspicious_process(process_name)


                # Suspicious rule: root running from /tmp
                if user == "root":
                    exe_path = proc.exe()
                    if exe_path.startswith("/tmp"):
                        alert_msg = f"Suspicious root process in /tmp | PID={pid}"
                        print("[ALERT]", alert_msg)
                        log_event("ALERT", name, alert_msg, "HIGH")

            except Exception:
                pass

        known_pids = current_pids
        time.sleep(2)
