"""
setup_db.py
Initialises users.db and the orders / logs tables used by app.py.
Run once before starting the vulnerable Flask app.

Usage:
    python setup_db.py
"""

import sqlite3
import hashlib
import os

DB_PATH = "users.db"


def hash_pw(pw: str) -> str:
    return hashlib.md5(pw.encode()).hexdigest()


def setup():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"[setup_db] Removed old {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ── Users table ───────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL UNIQUE,
            password TEXT    NOT NULL,
            email    TEXT,
            role     TEXT    DEFAULT 'user',
            name     TEXT
        )
    """)

    users = [
        ("admin",   hash_pw("secret123"), "admin@corp.internal", "admin", "Admin User"),
        ("alice",   hash_pw("pass456"),   "alice@corp.internal",  "user",  "Alice Smith"),
        ("bob",     hash_pw("hunter2"),   "bob@corp.internal",    "user",  "Bob Jones"),
        ("charlie", hash_pw("ch@rlie!"),  "charlie@corp.internal","user",  "Charlie Brown"),
    ]
    c.executemany(
        "INSERT INTO users (username, password, email, role, name) VALUES (?,?,?,?,?)",
        users,
    )

    # ── Orders table ─────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE orders (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            status  TEXT DEFAULT 'pending',
            total   REAL
        )
    """)
    c.executemany(
        "INSERT INTO orders (user_id, status, total) VALUES (?,?,?)",
        [(1, "pending", 99.99), (2, "shipped", 49.50), (3, "pending", 129.00)],
    )

    # ── Logs table ────────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE logs (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            event   TEXT,
            ts      TEXT DEFAULT (datetime('now'))
        )
    """)

    conn.commit()
    conn.close()

    # Clear request log
    if os.path.exists("request_log.jsonl"):
        os.remove("request_log.jsonl")
        print("[setup_db] Cleared request_log.jsonl")

    os.makedirs("reports", exist_ok=True)
    os.makedirs("alerts",  exist_ok=True)

    print(f"[setup_db] OK  {DB_PATH} ready - 4 users, 3 orders, logs table created.")


if __name__ == "__main__":
    setup()
