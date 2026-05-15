"""
target_codebase/app.py
A deliberately vulnerable Flask app used as the scan target.
Contains multiple SQL injection patterns across different contexts.
"""

import sqlite3
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = "users.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ── Vulnerability 1: Login — classic string concat ──────────────────────────
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    hashed = hashlib.md5(password.encode()).hexdigest()

    db = get_db()
    # SQLI-001: direct string interpolation in WHERE clause
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + hashed + "'"
    user = db.execute(query).fetchone()
    db.close()

    if user:
        return jsonify({"status": "ok", "user": user["username"]})
    return jsonify({"status": "fail"}), 401


# ── Vulnerability 2: Search — f-string injection ─────────────────────────────
@app.route("/search")
def search():
    term = request.args.get("q", "")
    db = get_db()
    # SQLI-002: f-string builds raw SQL with user input
    rows = db.execute(f"SELECT id, name, email FROM users WHERE name LIKE '%{term}%'").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


# ── Vulnerability 3: User profile — % formatting ─────────────────────────────
@app.route("/user/<user_id>")
def get_user(user_id):
    db = get_db()
    # SQLI-003: %-format string injection
    query = "SELECT id, name, email, role FROM users WHERE id = %s" % user_id
    row = db.execute(query).fetchone()
    db.close()
    if row:
        return jsonify(dict(row))
    return jsonify({"error": "not found"}), 404


# ── Vulnerability 4: Order filter — format() injection ───────────────────────
@app.route("/orders")
def get_orders():
    status = request.args.get("status", "pending")
    db = get_db()
    # SQLI-004: .format() injection
    query = "SELECT * FROM orders WHERE status = '{}'".format(status)
    rows = db.execute(query).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


# ── Vulnerability 5: Admin delete — no parameterization ──────────────────────
@app.route("/admin/delete", methods=["POST"])
def admin_delete():
    record_id = request.form.get("id")
    table = request.form.get("table", "logs")
    db = get_db()
    # SQLI-005: both table name and id are user-controlled
    query = "DELETE FROM " + table + " WHERE id = " + record_id
    db.execute(query)
    db.commit()
    db.close()
    return jsonify({"deleted": record_id})


if __name__ == "__main__":
    app.run(debug=True)
