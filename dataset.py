"""
data/dataset.py
Builds the SQLi classification dataset AND exports the Ollama fine-tune JSONL.

Labels: 0 = safe,  1 = sql_injection

Usage:
    python data/dataset.py            # builds both datasets
    python data/dataset.py --finetune # only build finetune JSONL
"""

from __future__ import annotations
import argparse
import json
import os
import random
import sys

# Force UTF-8 output on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ── Safe samples (parameterized / escaped) ────────────────────────────────────
SAFE: list[tuple[str, int]] = [
    ('cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))', 0),
    ('cursor.execute("SELECT * FROM users WHERE username = ?", (username,))', 0),
    ('db.execute("INSERT INTO logs (msg) VALUES (?)", (message,))', 0),
    ('cursor.execute("UPDATE users SET email = ? WHERE id = ?", (email, uid))', 0),
    ('cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))', 0),
    ('stmt = db.prepare("SELECT id FROM products WHERE sku = $1"); stmt.execute(sku)', 0),
    ('cursor.execute("SELECT * FROM orders WHERE status = %s AND user_id = %s", (status, uid))', 0),
    ('db.execute("SELECT name FROM categories WHERE id = ?", [cat_id])', 0),
    ('cursor.execute("SELECT * FROM items WHERE price < ?", (max_price,))', 0),
    ('db.execute("SELECT * FROM reviews WHERE product_id = ?", (pid,))', 0),
    ('cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))', 0),
    ('cursor.execute("SELECT role FROM users WHERE token = ?", (session_token,))', 0),
    ('db.execute("SELECT * FROM events WHERE date = ?", (event_date,))', 0),
    ('cursor.execute("SELECT * FROM files WHERE owner_id = ?", (current_user,))', 0),
    ('db.execute("UPDATE orders SET status = ? WHERE id = ?", (new_status, order_id))', 0),
    ('cursor.execute("SELECT * FROM audit WHERE action = ?", (action_type,))', 0),
    ('cursor.execute("SELECT * FROM messages WHERE recipient = ?", (user_id,))', 0),
    ('db.execute("SELECT * FROM configs WHERE key = ?", (config_key,))', 0),
    ('cursor.execute("SELECT * FROM tokens WHERE value = ? AND expired = 0", (tok,))', 0),
    ('db.execute("SELECT * FROM products WHERE category_id = ?", (category,))', 0),
    # Additional safe
    ('cursor.execute("SELECT * FROM payments WHERE txn_id = ?", (txn,))', 0),
    ('db.execute("SELECT id FROM roles WHERE name = ?", (role_name,))', 0),
    ('cursor.execute("SELECT * FROM cache WHERE key = ?", (cache_key,))', 0),
    ('cursor.execute("SELECT * FROM sessions WHERE user_id = ? AND active = 1", (uid,))', 0),
    ('db.execute("INSERT INTO audit (user_id, action) VALUES (?, ?)", (uid, action))', 0),
    ('cursor.execute("SELECT hash FROM api_keys WHERE key = ?", (api_key,))', 0),
    ('db.execute("SELECT * FROM notifications WHERE user_id = ?", (user_id,))', 0),
    ('cursor.execute("DELETE FROM tokens WHERE user_id = ? AND expired = 1", (uid,))', 0),
    ('db.execute("UPDATE profiles SET avatar = ? WHERE id = ?", (avatar_url, uid))', 0),
    ('cursor.execute("SELECT * FROM comments WHERE post_id = ?", (post_id,))', 0),
]

# ── Vulnerable samples (string interpolation of user input) ───────────────────
VULN: list[tuple[str, int]] = [
    # String concatenation
    ("query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"", 1),
    ("db.execute(\"SELECT * FROM users WHERE id = \" + user_id)", 1),
    ("cursor.execute(\"DELETE FROM logs WHERE id = \" + record_id)", 1),
    ("query = \"UPDATE users SET role = '\" + role + \"' WHERE id = \" + uid", 1),
    ("db.execute(\"SELECT * FROM orders WHERE status = '\" + status + \"'\")", 1),
    # f-strings
    ('db.execute(f"SELECT * FROM users WHERE name = \'{username}\'")', 1),
    ('cursor.execute(f"SELECT * FROM products WHERE id = {product_id}")', 1),
    ('db.execute(f"SELECT * FROM orders WHERE user_id = {uid} AND status = \'{status}\'")', 1),
    ('cursor.execute(f"DELETE FROM sessions WHERE user = \'{username}\'")', 1),
    ('db.execute(f"INSERT INTO logs (event) VALUES (\'{event}\')")', 1),
    ('cursor.execute(f"SELECT * FROM reviews WHERE product = {pid} AND rating > {min_rating}")', 1),
    ('db.execute(f"UPDATE accounts SET balance = {amount} WHERE id = {acct_id}")', 1),
    # % formatting
    ("cursor.execute(\"SELECT * FROM users WHERE id = %s\" % user_id)", 1),
    ("db.execute(\"SELECT name FROM items WHERE category = '%s'\" % category)", 1),
    ("cursor.execute(\"SELECT * FROM logs WHERE user = '%s'\" % username)", 1),
    ("query = \"SELECT * FROM products WHERE sku = '%s'\" % sku; db.execute(query)", 1),
    # .format()
    ('db.execute("SELECT * FROM users WHERE role = \'{}\'".format(role))', 1),
    ('cursor.execute("SELECT * FROM orders WHERE id = {}".format(order_id))', 1),
    ('db.execute("DELETE FROM items WHERE name = \'{}\'".format(item_name))', 1),
    ('cursor.execute("SELECT * FROM events WHERE type = \'{}\'".format(event_type))', 1),
    # Raw string building
    ("query = 'SELECT * FROM users WHERE email = \\'' + email + '\\''; db.execute(query)", 1),
    ("sql = 'UPDATE users SET password = \\'' + new_pass + '\\' WHERE id = ' + str(uid)", 1),
    ("db.execute('SELECT * FROM files WHERE name = \\'' + filename + '\\'')", 1),
    # Table/column injection
    ("db.execute('SELECT * FROM ' + table_name + ' WHERE id = ' + record_id)", 1),
    ("cursor.execute('SELECT ' + col + ' FROM users WHERE id = ' + uid)", 1),
    # Additional vulns
    ('db.execute("SELECT * FROM users WHERE token = \'" + token + "\'")', 1),
    ('cursor.execute("SELECT * FROM api_keys WHERE value = \'" + api_key + "\'")', 1),
    ('db.execute(f"SELECT * FROM payments WHERE txn_id = \'{txn_id}\'")', 1),
    ('cursor.execute("SELECT * FROM roles WHERE name = \'%s\'" % role)', 1),
    ('db.execute("SELECT * FROM cache WHERE key = \'{}\'".format(cache_key))', 1),
    ('cursor.execute(f"SELECT * FROM sessions WHERE session_id = \'{sid}\'")', 1),
    ('db.execute("SELECT * FROM audit WHERE user = \'%s\'" % username)', 1),
    ('cursor.execute("UPDATE users SET name = \'" + new_name + "\' WHERE id = \'" + uid + "\'")', 1),
    ('db.execute("INSERT INTO messages (body) VALUES (\'" + msg_body + "\')")', 1),
    ('cursor.execute(f"SELECT * FROM files WHERE path = \'{file_path}\'")', 1),
]


# ── Finetune chat examples (for Ollama / QLoRA training) ─────────────────────
FINETUNE_EXAMPLES: list[dict] = [
    # ── Safe examples ──────────────────────────────────────────────────────
    {
        "input": "username=alice&password=pass456 → SQL: SELECT * FROM users WHERE username = ? AND password = ?",
        "output": json.dumps({
            "is_sqli": False, "cwe_id": None, "attack_variant": None,
            "severity": "None", "cvss_score": 0.0,
            "what_attacker_achieved": "Normal login — no injection",
            "evidence": [], "confidence": 0.99,
        }),
    },
    {
        "input": "q=laptop → SQL: SELECT id, name, email FROM users WHERE name LIKE '%laptop%'",
        "output": json.dumps({
            "is_sqli": False, "cwe_id": None, "attack_variant": None,
            "severity": "None", "cvss_score": 0.0,
            "what_attacker_achieved": "Normal search query",
            "evidence": [], "confidence": 0.98,
        }),
    },
    # ── Comment injection ──────────────────────────────────────────────────
    {
        "input": "username=admin' --&password=anything → SQL: SELECT * FROM users WHERE username = 'admin' --' AND password = '<hash>'",
        "output": json.dumps({
            "is_sqli": True, "cwe_id": "CWE-89", "attack_variant": "comment_injection",
            "severity": "Critical", "cvss_score": 9.8,
            "what_attacker_achieved": "Authentication bypass — password check nullified by SQL comment",
            "evidence": ["Single quote before --", "SQL comment neutralises AND password clause"],
            "confidence": 0.99,
        }),
    },
    {
        "input": "username=admin'#&password=x → SQL: SELECT * FROM users WHERE username = 'admin'#' AND password = '<hash>'",
        "output": json.dumps({
            "is_sqli": True, "cwe_id": "CWE-89", "attack_variant": "comment_injection",
            "severity": "Critical", "cvss_score": 9.8,
            "what_attacker_achieved": "Authentication bypass via MySQL hash comment",
            "evidence": ["Hash (#) comment variant", "Password clause fully skipped"],
            "confidence": 0.99,
        }),
    },
    # ── OR tautology ───────────────────────────────────────────────────────
    {
        "input": "username=' OR '1'='1' --&password=x → SQL: SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = '<hash>'",
        "output": json.dumps({
            "is_sqli": True, "cwe_id": "CWE-89", "attack_variant": "or_tautology",
            "severity": "Critical", "cvss_score": 9.8,
            "what_attacker_achieved": "Full authentication bypass — tautology makes WHERE always TRUE, returns all rows",
            "evidence": ["OR tautology '1'='1'", "Always-true condition", "Comment strips password check"],
            "confidence": 0.99,
        }),
    },
    {
        "input": "username=' OR 1=1 --&password=ignored",
        "output": json.dumps({
            "is_sqli": True, "cwe_id": "CWE-89", "attack_variant": "or_tautology",
            "severity": "Critical", "cvss_score": 9.8,
            "what_attacker_achieved": "Auth bypass via numeric tautology",
            "evidence": ["OR 1=1", "SQL comment"],
            "confidence": 0.97,
        }),
    },
    # ── UNION extraction ───────────────────────────────────────────────────
    {
        "input": "q=' UNION SELECT 1,name,email FROM users -- → SQL: SELECT id, name, email FROM users WHERE name LIKE '%' UNION SELECT 1,name,email FROM users --%'",
        "output": json.dumps({
            "is_sqli": True, "cwe_id": "CWE-89", "attack_variant": "union_extraction",
            "severity": "Critical", "cvss_score": 9.8,
            "what_attacker_achieved": "Data exfiltration — attacker extracted full users table via UNION SELECT",
            "evidence": ["UNION SELECT keyword", "Second SELECT on users table", "Comment terminates original query"],
            "confidence": 0.99,
        }),
    },
    {
        "input": "q=' UNION SELECT null,table_name,null FROM information_schema.tables --",
        "output": json.dumps({
            "is_sqli": True, "cwe_id": "CWE-89", "attack_variant": "union_extraction",
            "severity": "Critical", "cvss_score": 9.8,
            "what_attacker_achieved": "Schema enumeration via UNION SELECT on information_schema",
            "evidence": ["UNION SELECT", "information_schema.tables", "Schema reconnaissance"],
            "confidence": 0.99,
        }),
    },
    # ── Boolean blind ──────────────────────────────────────────────────────
    {
        "input": "q=' AND 1=1 -- → SQL: SELECT ... WHERE name LIKE '%' AND 1=1 --%'",
        "output": json.dumps({
            "is_sqli": True, "cwe_id": "CWE-89", "attack_variant": "blind_boolean",
            "severity": "High", "cvss_score": 7.5,
            "what_attacker_achieved": "Boolean-based blind probe — comparing true vs false responses to infer DB structure",
            "evidence": ["AND 1=1 true condition", "SQL comment", "Blind inference pattern"],
            "confidence": 0.92,
        }),
    },
    {
        "input": "q=' AND 1=2 --",
        "output": json.dumps({
            "is_sqli": True, "cwe_id": "CWE-89", "attack_variant": "blind_boolean",
            "severity": "High", "cvss_score": 7.5,
            "what_attacker_achieved": "Blind boolean false-case test",
            "evidence": ["AND 1=2 false condition", "Paired with true-case to infer data bit-by-bit"],
            "confidence": 0.90,
        }),
    },
    # ── Stacked queries ────────────────────────────────────────────────────
    {
        "input": "username=admin'; INSERT INTO logs (event) VALUES ('pwned'); --&password=x",
        "output": json.dumps({
            "is_sqli": True, "cwe_id": "CWE-89", "attack_variant": "stacked_queries",
            "severity": "Critical", "cvss_score": 9.8,
            "what_attacker_achieved": "Stacked query injection — second SQL statement executed after semicolon",
            "evidence": ["Semicolon terminating first query", "Second INSERT statement", "SQL comment at end"],
            "confidence": 0.98,
        }),
    },
    {
        "input": "username='; DROP TABLE users; --&password=x",
        "output": json.dumps({
            "is_sqli": True, "cwe_id": "CWE-89", "attack_variant": "stacked_queries",
            "severity": "Critical", "cvss_score": 9.8,
            "what_attacker_achieved": "Destructive DDL injection — DROP TABLE would destroy all user data",
            "evidence": ["Stacked query via semicolon", "DROP TABLE DDL statement", "Would result in full data loss"],
            "confidence": 0.99,
        }),
    },
    # ── Time-based blind ───────────────────────────────────────────────────
    {
        "input": "username=admin' AND SLEEP(5) --&password=x",
        "output": json.dumps({
            "is_sqli": True, "cwe_id": "CWE-89", "attack_variant": "time_based_blind",
            "severity": "High", "cvss_score": 7.5,
            "what_attacker_achieved": "Time-based blind SQLi — SLEEP function used to infer true/false via response latency",
            "evidence": ["SLEEP(5) function call", "Conditional time delay", "Used to extract data bit-by-bit"],
            "confidence": 0.95,
        }),
    },
]


# ── Dataset builders ──────────────────────────────────────────────────────────

def build_dataset(out_path: str, val_split: float = 0.2, seed: int = 42):
    """Build train/val JSONL for the CNN+GRU classifier."""
    random.seed(seed)
    all_samples = SAFE + VULN
    random.shuffle(all_samples)

    split = int(len(all_samples) * (1 - val_split))
    train = all_samples[:split]
    val   = all_samples[split:]

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    base = os.path.splitext(out_path)[0]

    for name, subset in [("train", train), ("val", val)]:
        path = f"{base}_{name}.jsonl"
        with open(path, "w") as f:
            for text, label in subset:
                f.write(json.dumps({"text": text, "label": label}) + "\n")
        print(f"Saved {len(subset)} samples -> {path}")


def build_finetune_jsonl(out_path: str = "data/sqli_finetune.jsonl"):
    """
    Build Ollama chat-format JSONL for fine-tuning qwen2.5-coder:3b.
    Each record has 'messages' with system / user / assistant roles.
    """
    SYSTEM_PROMPT = (
        "You are a forensic security analyst specialized in CWE-89 SQL Injection detection. "
        "Given an HTTP request log entry (payload and SQL query that was executed), "
        "classify whether it is a SQL injection attack. "
        "Respond ONLY with a valid JSON object containing: "
        "is_sqli (bool), cwe_id (str or null), attack_variant (str or null), "
        "severity (str), cvss_score (float), what_attacker_achieved (str), "
        "evidence (list of str), confidence (float 0-1). "
        "No explanation outside the JSON."
    )

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    records = []
    for ex in FINETUNE_EXAMPLES:
        records.append({
            "messages": [
                {"role": "system",    "content": SYSTEM_PROMPT},
                {"role": "user",      "content": ex["input"]},
                {"role": "assistant", "content": ex["output"]},
            ]
        })

    with open(out_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print(f"Saved {len(records)} finetune records -> {out_path}")
    return out_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--finetune-only", action="store_true")
    args = parser.parse_args()

    if not args.finetune_only:
        build_dataset("data/sqli_dataset")
    build_finetune_jsonl("data/sqli_finetune.jsonl")
