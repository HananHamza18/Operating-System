import sqlite3
from collections import Counter

DB_NAME = "security_logs.db"

def get_connection():
    return sqlite3.connect(DB_NAME)

def total_events():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM events")
    count = cursor.fetchone()[0]
    conn.close()
    return count

def severity_breakdown():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT severity FROM events")
    rows = cursor.fetchall()
    conn.close()

    severities = [row[0] for row in rows]
    return Counter(severities)

def top_failed_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT message FROM events
        WHERE event_type='AUTH' AND message LIKE '%Failed login%'
    """)
    rows = cursor.fetchall()
    conn.close()

    users = []
    for row in rows:
        msg = row[0]
        parts = msg.split()
        if len(parts) >= 6:
            users.append(parts[-1])

    return Counter(users)

def show_report():
    print("\n========= SECURITY INCIDENT REPORT =========")
    print(f"Total Events Logged: {total_events()}")

    print("\n--- Severity Breakdown ---")
    for severity, count in severity_breakdown().items():
        print(f"{severity}: {count}")

    print("\n--- Top Failed Login Users ---")
    for user, count in top_failed_users().items():
        print(f"{user}: {count} attempts")

    print("\n============================================\n")

if __name__ == "__main__":
    show_report()

