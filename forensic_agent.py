"""
forensic_agent.py
Stage 2 — Forensic Classification Agent.

Reads an alert JSON produced by sentinel.py, calls the fine-tuned
qwen2.5-coder-sqli Ollama model, and produces a structured CWE-89
classification report.

Falls back to the local CNN+GRU classifier if Ollama is unavailable.

Usage:
    python forensic_agent.py                          # process alerts/latest.json
    python forensic_agent.py --alert alerts/foo.json  # specific alert
    python forensic_agent.py --all                    # process all pending alerts
    python forensic_agent.py --test                   # test with synthetic payload
"""

from __future__ import annotations
import argparse
import json
import os
import sys
import re
import time
from datetime import datetime, timezone
from pathlib import Path

# Force UTF-8 output on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ALERT_DIR   = "alerts"
REPORT_DIR  = "reports"
MODEL_NAME  = "qwen2.5-coder-sqli"
FALLBACK    = "qwen2.5-coder:3b"   # used if fine-tuned model not yet created

SYSTEM_PROMPT = (
    "You are a forensic security analyst specialized in CWE-89 SQL Injection detection. "
    "Given an HTTP request log entry (payload and SQL query that was executed), "
    "classify whether it is a SQL injection attack. "
    "Respond ONLY with a valid JSON object containing: "
    "is_sqli (bool), cwe_id (str or null), attack_variant (str or null), "
    "severity (str: Critical/High/Medium/Low/None), cvss_score (float 0-10), "
    "what_attacker_achieved (str), evidence (list of str), confidence (float 0-1). "
    "No text outside the JSON object."
)


# ── Ollama classifier ─────────────────────────────────────────────────────────

def _get_model_to_use() -> str:
    """Return fine-tuned model name if available, else fallback."""
    try:
        import ollama
        client = ollama.Client()
        models = client.list()
        model_list = models.get("models", []) if isinstance(models, dict) else getattr(models, "models", [])
        names = []
        for m in model_list:
            if isinstance(m, dict):
                names.append(m.get("name", m.get("model", "")))
            else:
                names.append(getattr(m, "name", getattr(m, "model", "")))
        if any(MODEL_NAME in n for n in names):
            return MODEL_NAME
        if any(FALLBACK.split(":")[0] in n for n in names):
            print(f"  ⚠  Fine-tuned model '{MODEL_NAME}' not found. Using '{FALLBACK}'.")
            print(f"     Run: python finetune_ollama.py  to create the SQLi-tuned model.")
            return FALLBACK
    except Exception:
        pass
    return MODEL_NAME


def classify_with_ollama(alert: dict) -> dict | None:
    """
    Call Ollama with the alert payload. Returns parsed classification dict or None.
    """
    try:
        import ollama
    except ImportError:
        print("  ✗  ollama Python package not installed. Run: pip install ollama")
        return None

    model = _get_model_to_use()

    # Build the user prompt from the alert
    payload_str = json.dumps(alert.get("payload", {}))
    sql_str     = alert.get("sql_query", "N/A")
    endpoint    = alert.get("endpoint", "")
    method      = alert.get("method", "")
    detections  = alert.get("detections", [])
    detection_summary = ", ".join(d["pattern"] for d in detections) if detections else "none"

    user_content = (
        f"HTTP Request: {method} {endpoint}\n"
        f"Payload: {payload_str}\n"
        f"SQL executed: {sql_str}\n"
        f"Sentinel pre-detection: [{detection_summary}]\n\n"
        f"Classify this request."
    )

    try:
        client = ollama.Client()
        t0 = time.time()
        resp = client.chat(
            model   = model,
            messages = [
                {"role": "system",  "content": SYSTEM_PROMPT},
                {"role": "user",    "content": user_content},
            ],
            options  = {"temperature": 0.05, "top_p": 0.9, "num_predict": 512},
        )
        elapsed = time.time() - t0

        raw = resp["message"]["content"] if isinstance(resp, dict) else resp.message.content
        print(f"     Ollama ({model}) responded in {elapsed:.1f}s")

        # Extract JSON from response (model may wrap in markdown)
        json_match = re.search(r'\{.*\}', raw, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(0))
        return json.loads(raw)

    except json.JSONDecodeError as e:
        print(f"  ⚠  Could not parse JSON from model response: {e}")
        print(f"     Raw response: {raw[:300]}")
        return None
    except Exception as e:
        print(f"  ✗  Ollama error: {e}")
        return None


# ── PyTorch fallback classifier ───────────────────────────────────────────────

def classify_with_local_model(alert: dict) -> dict | None:
    """
    Fallback: use the CNN+GRU classifier from classifier.py.
    Only detects binary (sqli vs safe) — no attack_variant detail.
    """
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from classifier import classify
        sql = alert.get("sql_query", "")
        payload = json.dumps(alert.get("payload", {}))
        text = f"{payload} {sql}"
        result = classify(text)
        is_sqli = result["label"] == "sql_injection"
        return {
            "is_sqli":        is_sqli,
            "cwe_id":         "CWE-89" if is_sqli else None,
            "attack_variant": "unknown" if is_sqli else None,
            "severity":       "High"   if is_sqli else "None",
            "cvss_score":     7.5      if is_sqli else 0.0,
            "what_attacker_achieved": (
                "SQL injection detected by local CNN+GRU classifier" if is_sqli
                else "Clean request — no injection"
            ),
            "evidence":   [],
            "confidence": result["confidence"],
            "_source":    "local_cnn_gru_fallback",
        }
    except Exception as e:
        print(f"  ✗  Local classifier fallback failed: {e}")
        return None


# ── Report builder ────────────────────────────────────────────────────────────

def build_report(alert: dict, classification: dict, elapsed: float, model_used: str) -> dict:
    return {
        "report_id":      f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "stage":          "forensic",
        "model_used":     model_used,
        "inference_time_s": round(elapsed, 2),
        # ── Alert data ──────────────────────────────────────────────────────
        "source_ip":      alert.get("source_ip"),
        "endpoint":       alert.get("endpoint"),
        "method":         alert.get("method"),
        "payload":        alert.get("payload"),
        "sql_query":      alert.get("sql_query"),
        "sentinel_detections": alert.get("detections", []),
        # ── Classification ──────────────────────────────────────────────────
        "classification": classification,
        # ── Handoff data for patch agent ────────────────────────────────────
        "patch_handoff": {
            "cwe_id":              classification.get("cwe_id"),
            "affected_parameter":  _guess_affected_param(alert),
            "attack_variant":      classification.get("attack_variant"),
            "sql_query":           alert.get("sql_query"),
            "ready_for_patch":     classification.get("is_sqli", False),
        },
    }


def _guess_affected_param(alert: dict) -> str | None:
    payload = alert.get("payload", {})
    if isinstance(payload, dict) and payload:
        return list(payload.keys())[0]
    return None


def save_report(report: dict, alert_id: str) -> str:
    os.makedirs(REPORT_DIR, exist_ok=True)
    path = os.path.join(REPORT_DIR, f"forensic_{alert_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Also write Markdown summary
    _write_md_report(report, os.path.join(REPORT_DIR, f"forensic_{alert_id}.md"))
    return path


def _write_md_report(report: dict, path: str):
    c = report["classification"]
    icons = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "None": "✅"}
    sev_icon = icons.get(c.get("severity", "None"), "⚪")

    lines = [
        "# ZeroDayShield — Forensic Classification Report",
        "",
        f"**Report ID:** `{report['report_id']}`  ",
        f"**Generated:** {report['generated_at']}  ",
        f"**Model:** `{report['model_used']}`  ",
        f"**Inference time:** {report['inference_time_s']}s",
        "",
        "---",
        "",
        "## Incident Details",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Source IP | `{report['source_ip']}` |",
        f"| Endpoint  | `{report['method']} {report['endpoint']}` |",
        f"| Payload   | `{json.dumps(report['payload'])}` |",
        f"| SQL Query | `{report['sql_query']}` |",
        "",
        "---",
        "",
        "## Classification Result",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| SQL Injection | {'**YES** ⚠️' if c.get('is_sqli') else 'No ✅'} |",
        f"| CWE ID | `{c.get('cwe_id', 'N/A')}` |",
        f"| Attack Variant | `{c.get('attack_variant', 'N/A')}` |",
        f"| Severity | {sev_icon} **{c.get('severity', 'N/A')}** |",
        f"| CVSS Score | {c.get('cvss_score', 0.0)} |",
        f"| Confidence | {c.get('confidence', 0.0):.0%} |",
        "",
        f"**What attacker achieved:** {c.get('what_attacker_achieved', 'N/A')}",
        "",
    ]

    evidence = c.get("evidence", [])
    if evidence:
        lines += ["**Evidence:**", ""]
        for e in evidence:
            lines.append(f"- {e}")
        lines.append("")

    sentinel = report.get("sentinel_detections", [])
    if sentinel:
        lines += ["## Sentinel Pre-Detections", ""]
        for d in sentinel:
            lines.append(f"- **{d['pattern']}** ({d['severity']}): {d['description']}")
        lines.append("")

    ph = report.get("patch_handoff", {})
    if ph.get("ready_for_patch"):
        lines += [
            "---",
            "",
            "## Patch Agent Handoff",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| CWE | `{ph.get('cwe_id')}` |",
            f"| Affected Parameter | `{ph.get('affected_parameter')}` |",
            f"| Attack Variant | `{ph.get('attack_variant')}` |",
            f"| Ready for patch | ✅ Yes |",
            "",
        ]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ── Main processing ───────────────────────────────────────────────────────────

def process_alert(alert_path: str) -> dict | None:
    print(f"\n  {'='*60}")
    print(f"  Processing alert: {alert_path}")
    print(f"  {'='*60}")

    with open(alert_path, encoding="utf-8") as f:
        alert = json.load(f)

    alert_id = alert.get("alert_id", "unknown")
    print(f"  Alert ID   : {alert_id}")
    print(f"  Endpoint   : {alert.get('method')} {alert.get('endpoint')}")
    print(f"  Payload    : {json.dumps(alert.get('payload', {}))}")
    print(f"  Detections : {', '.join(d['pattern'] for d in alert.get('detections', []))}")

    # Try Ollama first
    t0 = time.time()
    classification = classify_with_ollama(alert)
    model_used = MODEL_NAME

    if classification is None:
        print("  Falling back to local CNN+GRU classifier...")
        classification = classify_with_local_model(alert)
        model_used = "local_cnn_gru"

    if classification is None:
        print("  ✗  All classifiers failed for this alert.")
        return None

    elapsed = time.time() - t0
    report  = build_report(alert, classification, elapsed, model_used)
    path    = save_report(report, alert_id)

    # Print result
    c = classification
    sev_icons = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "None": "✅"}
    icon = sev_icons.get(c.get("severity", "None"), "⚪")

    print(f"\n  Result:")
    print(f"    SQLi detected  : {'YES ⚠️ ' if c.get('is_sqli') else 'No ✅'}")
    print(f"    CWE            : {c.get('cwe_id', 'N/A')}")
    print(f"    Variant        : {c.get('attack_variant', 'N/A')}")
    print(f"    Severity       : {icon} {c.get('severity', 'N/A')}")
    print(f"    CVSS           : {c.get('cvss_score', 0)}")
    print(f"    Confidence     : {c.get('confidence', 0):.0%}")
    print(f"    Report saved   : {path}")

    return report


def process_all_pending():
    alert_files = sorted(Path(ALERT_DIR).glob("ALERT-*.json"))
    if not alert_files:
        print(f"  No alert files found in {ALERT_DIR}/")
        return

    print(f"  Found {len(alert_files)} alert(s) to process.")
    for af in alert_files:
        process_alert(str(af))


def run_test():
    """Quick smoke test with a synthetic alert."""
    synthetic = {
        "alert_id":    "ALERT-TEST-001",
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "source_ip":   "10.0.0.99",
        "endpoint":    "/login",
        "method":      "POST",
        "payload":     {"username": "admin' --", "password": "anything"},
        "sql_query":   "SELECT * FROM users WHERE username = 'admin' --' AND password = '<hash>'",
        "response_code": 200,
        "detections":  [{"pattern": "comment_injection", "severity": "CRITICAL",
                         "description": "SQL comment after quote", "matched_text": "' --"}],
        "max_severity": "CRITICAL",
    }
    # Save synthetic alert
    os.makedirs(ALERT_DIR, exist_ok=True)
    test_path = os.path.join(ALERT_DIR, "ALERT-TEST-001.json")
    with open(test_path, "w") as f:
        json.dump(synthetic, f, indent=2)
    print(f"  Created synthetic alert: {test_path}")
    process_alert(test_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZeroDayShield — Forensic Agent")
    parser.add_argument("--alert", default=None, help="Path to specific alert JSON")
    parser.add_argument("--all",   action="store_true", help="Process all pending alerts")
    parser.add_argument("--test",  action="store_true", help="Smoke test with synthetic payload")
    args = parser.parse_args()

    if args.test:
        run_test()
    elif args.all:
        process_all_pending()
    else:
        alert_path = args.alert or os.path.join(ALERT_DIR, "latest.json")
        if not os.path.exists(alert_path):
            print(f"  No alert file at {alert_path}")
            print(f"  Run attack.py + sentinel.py first, or use --test")
            sys.exit(1)
        process_alert(alert_path)
