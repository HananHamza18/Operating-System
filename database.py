import sqlite3
from datetime import datetime

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

DB_NAME = "security_logs.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            source TEXT,
            message TEXT,
            severity TEXT
        )
    """)

    conn.commit()
    conn.close()


def log_event(event_type, source, message, severity):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO events (timestamp, event_type, source, message, severity)
        VALUES (?, ?, ?, ?, ?)
    """, (timestamp, event_type, source, message, severity))

    conn.commit()
    conn.close()
