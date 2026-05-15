"""
target_codebase/app.py
A deliberately vulnerable Flask app used as the scan target.
Contains multiple SQL injection patterns across different contexts.
All requests are logged to request_log.jsonl for the Sentinel Agent.
"""

import json
import sqlite3
import hashlib
import os
from datetime import datetime, timezone
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH  = "users.db"
LOG_FILE = "request_log.jsonl"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _log_request(endpoint: str, method: str, payload: dict, sql_query: str, response_code: int):
    """Append every request to the JSONL log for sentinel.py to pick up."""
    entry = {
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "source_ip":     request.remote_addr or "127.0.0.1",
        "endpoint":      endpoint,
        "method":        method,
        "payload":       payload,
        "sql_query":     sql_query,
        "response_code": response_code,
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# ── Vulnerability 1: Login — classic string concat ──────────────────────────
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    hashed   = hashlib.md5(password.encode()).hexdigest()

    db = get_db()
    # SQLI-001: direct string interpolation in WHERE clause
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + hashed + "'"
    try:
        user = db.execute(query).fetchone()
        code = 200 if user else 401
    except Exception:
        user = None
        code = 500
    finally:
        db.close()

    _log_request("/login", "POST",
                 {"username": username, "password": password},
                 query, code)

    if user:
        return jsonify({"status": "ok", "user": user["username"]})
    return jsonify({"status": "fail"}), 401


# ── Vulnerability 2: Search — f-string injection ─────────────────────────────
@app.route("/search")
def search():
    term = request.args.get("q", "")
    db   = get_db()
    # SQLI-002: f-string builds raw SQL with user input
    sql  = f"SELECT id, name, email FROM users WHERE name LIKE '%{term}%'"
    try:
        rows = db.execute(sql).fetchall()
        code = 200
    except Exception:
        rows = []
        code = 500
    finally:
        db.close()

    _log_request("/search", "GET", {"q": term}, sql, code)
    return jsonify([dict(r) for r in rows])


# ── Vulnerability 3: User profile — % formatting ─────────────────────────────
@app.route("/user/<user_id>")
def get_user(user_id):
    db  = get_db()
    # SQLI-003: %-format string injection
    sql = "SELECT id, name, email, role FROM users WHERE id = %s" % user_id
    try:
        row  = db.execute(sql).fetchone()
        code = 200 if row else 404
    except Exception:
        row  = None
        code = 500
    finally:
        db.close()

    _log_request(f"/user/{user_id}", "GET", {"user_id": user_id}, sql, code)
    if row:
        return jsonify(dict(row))
    return jsonify({"error": "not found"}), 404


# ── Vulnerability 4: Order filter — format() injection ───────────────────────
@app.route("/orders")
def get_orders():
    status = request.args.get("status", "pending")
    db     = get_db()
    # SQLI-004: .format() injection
    sql    = "SELECT * FROM orders WHERE status = '{}'".format(status)
    try:
        rows = db.execute(sql).fetchall()
        code = 200
    except Exception:
        rows = []
        code = 500
    finally:
        db.close()

    _log_request("/orders", "GET", {"status": status}, sql, code)
    return jsonify([dict(r) for r in rows])


# ── Vulnerability 5: Admin delete — no parameterization ──────────────────────
@app.route("/admin/delete", methods=["POST"])
def admin_delete():
    record_id = request.form.get("id", "0")
    table     = request.form.get("table", "logs")
    db        = get_db()
    # SQLI-005: both table name and id are user-controlled
    sql = "DELETE FROM " + table + " WHERE id = " + record_id
    try:
        db.execute(sql)
        db.commit()
        code = 200
    except Exception:
        code = 500
    finally:
        db.close()

    _log_request("/admin/delete", "POST",
                 {"id": record_id, "table": table}, sql, code)
    return jsonify({"deleted": record_id})


# ── Health check ──────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "db": os.path.exists(DB_PATH)})


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("[app] users.db not found — run setup_db.py first")
    app.run(debug=False, host="0.0.0.0", port=5000)
