"""
Simple SQLite storage layer. No ORM overhead - raw sqlite3 is enough
for a project of this size and keeps things transparent/easy to inspect.
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict

DB_PATH = os.path.join(os.path.dirname(__file__), "hawkeye.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            user TEXT,
            asset TEXT NOT NULL,
            event_type TEXT NOT NULL,
            raw_message TEXT,
            geo_country TEXT
        )
    """)
    conn.commit()
    conn.close()


def insert_logs(logs: List[dict]):
    conn = get_connection()
    cur = conn.cursor()
    cur.executemany("""
        INSERT INTO logs (timestamp, src_ip, user, asset, event_type, raw_message, geo_country)
        VALUES (:timestamp, :src_ip, :user, :asset, :event_type, :raw_message, :geo_country)
    """, logs)
    conn.commit()
    conn.close()


def fetch_all_logs(limit: int = 5000) -> List[Dict]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def clear_logs():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM logs")
    conn.commit()
    conn.close()


def count_logs() -> int:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM logs")
    result = cur.fetchone()["c"]
    conn.close()
    return result
