"""
sentinel.py
Stage 1 — Network Sentinel Agent.

Polls request_log.jsonl every 0.5s. Applies 8 regex detection patterns
to each new log entry. Confirmed hits are written to alerts/ as JSON
and queued for the Forensic Agent.

Usage:
    python sentinel.py                  # continuous tail mode
    python sentinel.py --oneshot        # process current log and exit
    python sentinel.py --file <path>    # point at a specific log file
"""

from __future__ import annotations
import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Force UTF-8 output on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

LOG_FILE   = "request_log.jsonl"
ALERT_DIR  = "alerts"

# ── Detection Patterns ────────────────────────────────────────────────────────
# Each entry: (pattern_name, regex, severity, description)
PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    (
        "comment_injection",
        re.compile(r"'[\s]*(-{2}|#|/\*)", re.IGNORECASE),
        "CRITICAL",
        "SQL comment sequence after quote — neutralises WHERE clause",
    ),
    (
        "or_tautology",
        re.compile(r"'\s*(or|OR)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", re.IGNORECASE),
        "CRITICAL",
        "OR tautology injection — always-true condition bypasses auth",
    ),
    (
        "union_extraction",
        re.compile(r"union\s+(all\s+)?select", re.IGNORECASE),
        "CRITICAL",
        "UNION SELECT — attacker is extracting data from other tables",
    ),
    (
        "blind_boolean",
        re.compile(r"'\s*and\s+\d+=\d+", re.IGNORECASE),
        "HIGH",
        "Boolean-based blind SQLi — probing DB structure via true/false responses",
    ),
    (
        "stacked_queries",
        re.compile(r"'.*;", re.IGNORECASE),
        "CRITICAL",
        "Stacked queries — second SQL statement injected after semicolon",
    ),
    (
        "time_based_blind",
        re.compile(r"(sleep|benchmark|pg_sleep|waitfor\s+delay)", re.IGNORECASE),
        "HIGH",
        "Time-based blind SQLi — using sleep functions to infer data",
    ),
    (
        "drop_table",
        re.compile(r"drop\s+table", re.IGNORECASE),
        "CRITICAL",
        "DROP TABLE attempt — destructive DDL injection",
    ),
    (
        "single_quote_escape",
        re.compile(r"'[^']*'[^']*'", re.IGNORECASE),
        "MEDIUM",
        "Multiple unbalanced quotes — generic SQLi probe pattern",
    ),
]


def _extract_payload_string(entry: dict) -> str:
    """Flatten all payload values into a single searchable string."""
    parts = []
    payload = entry.get("payload", {})
    if isinstance(payload, dict):
        parts.extend(str(v) for v in payload.values())
    elif isinstance(payload, str):
        parts.append(payload)
    sql = entry.get("sql_query", "")
    if sql:
        parts.append(sql)
    return " ".join(parts)


def detect(entry: dict) -> list[dict]:
    """
    Run all regex patterns against the payload.
    Returns list of match dicts (one per fired pattern).
    """
    text = _extract_payload_string(entry)
    hits = []
    for name, rx, severity, desc in PATTERNS:
        m = rx.search(text)
        if m:
            hits.append({
                "pattern":     name,
                "severity":    severity,
                "description": desc,
                "matched_text": m.group(0),
            })
    return hits


def build_alert(entry: dict, hits: list[dict]) -> dict:
    return {
        "alert_id":    f"ALERT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "source_ip":   entry.get("source_ip", "unknown"),
        "endpoint":    entry.get("endpoint", ""),
        "method":      entry.get("method", ""),
        "payload":     entry.get("payload", {}),
        "sql_query":   entry.get("sql_query", ""),
        "response_code": entry.get("response_code", 0),
        "detections":  hits,
        "max_severity": max(
            (h["severity"] for h in hits),
            key=lambda s: {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}.get(s, 0),
            default="UNKNOWN",
        ),
        "stage": "sentinel",
        "status": "pending_forensic",  # forensic_agent.py will update this
    }


def save_alert(alert: dict) -> str:
    os.makedirs(ALERT_DIR, exist_ok=True)
    path = os.path.join(ALERT_DIR, f"{alert['alert_id']}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(alert, f, indent=2)
    # Always overwrite 'latest.json' for easy forensic handoff
    latest = os.path.join(ALERT_DIR, "latest.json")
    with open(latest, "w", encoding="utf-8") as f:
        json.dump(alert, f, indent=2)
    return path


def _print_alert(alert: dict):
    sev = alert["max_severity"]
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    icon  = icons.get(sev, "⚪")
    print(f"\n  {icon}  ALERT [{sev}] — {alert['alert_id']}")
    print(f"       Endpoint : {alert['method']} {alert['endpoint']}")
    print(f"       Payload  : {json.dumps(alert['payload'])}")
    for d in alert["detections"]:
        print(f"       Pattern  : {d['pattern']} — {d['description']}")
        print(f"       Matched  : {d['matched_text']!r}")
    print(f"       Saved    : alerts/{alert['alert_id']}.json")


def run_once(log_path: str, seen_ids: set) -> set:
    """Process all unprocessed lines in the log. Returns updated seen set."""
    if not os.path.exists(log_path):
        return seen_ids

    with open(log_path, encoding="utf-8") as f:
        lines = f.readlines()

    for i, raw in enumerate(lines):
        if i in seen_ids:
            continue
        seen_ids.add(i)
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue

        hits = detect(entry)
        if not hits:
            label = entry.get("label", "?")
            ts    = entry.get("timestamp", "")[:19]
            ep    = entry.get("endpoint", "")
            print(f"  ✅  [{ts}] CLEAN  {ep}  label={label}")
            continue

        alert = build_alert(entry, hits)
        path  = save_alert(alert)
        _print_alert(alert)

    return seen_ids


def main():
    parser = argparse.ArgumentParser(description="ZeroDayShield — Sentinel Agent")
    parser.add_argument("--file",    default=LOG_FILE,     help="Path to request_log.jsonl")
    parser.add_argument("--oneshot", action="store_true",  help="Process once and exit")
    parser.add_argument("--interval",type=float, default=0.5, help="Poll interval in seconds")
    args = parser.parse_args()

    print(f"\n{'='*65}")
    print(f"  ZeroDayShield — Sentinel Agent")
    print(f"  Watching : {args.file}")
    print(f"  Patterns : {len(PATTERNS)}")
    print(f"  Mode     : {'oneshot' if args.oneshot else 'continuous'}")
    print(f"{'='*65}\n")

    seen: set[int] = set()

    if args.oneshot:
        run_once(args.file, seen)
        return

    try:
        while True:
            seen = run_once(args.file, seen)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n  Sentinel stopped.")


if __name__ == "__main__":
    main()
