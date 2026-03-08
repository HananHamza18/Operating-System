import psutil
from datetime import datetime

LOG_FILE = "system_logs.txt"

def log_event(message):
    time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as file:
        file.write(f"{time_now} | {message}\n")

def log_processes():
    log_event("=== Process Snapshot ===")
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            log_event(f"PROCESS | PID={proc.info['pid']} | NAME={proc.info['name']} | USER={proc.info['username']}")
        except:
            pass

def log_users():
    log_event("=== Logged-in Users ===")
    users = psutil.users()
    for user in users:
        log_event(f"USER | NAME={user.name} | TERMINAL={user.terminal} | HOST={user.host}")

if __name__ == "__main__":
    log_event("===== SYSTEM LOGGER STARTED =====")
    log_users()
    log_processes()
    log_event("===== SYSTEM LOGGER FINISHED =====")
