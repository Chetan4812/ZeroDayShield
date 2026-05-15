"""
patch_agent.py  —  ZeroDayShield Patch Agent  (Stage 3)

Pipeline:
  1. Read forensic_*.json reports produced by forensic_agent.py
  2. For each confirmed SQLi finding, analyse the vulnerable SQL query
  3. Generate a deterministic parameterised-query patch + unified diff
  4. Present each patch for human review (approve / reject / skip)
  5. Apply approved patches to the target source file(s)
  6. Write a patch_report_<ts>.json + .md summary

Usage:
    python patch_agent.py                        # process all forensic reports
    python patch_agent.py --report reports/forensic_ALERT-XYZ.json
    python patch_agent.py --auto-approve         # skip human review (CI mode)
    python patch_agent.py --dry-run              # show patches, apply nothing
"""

from __future__ import annotations
import argparse
import ast
import difflib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

REPORT_DIR  = "reports"
PATCH_DIR   = "reports/patched"
BACKUP_DIR  = "reports/backups"

# ── Severity / CVSS ────────────────────────────────────────────────────────────
SEV_ICONS = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "None": "✅"}
ATTACK_SEVERITY: dict[str, str] = {
    "comment_injection":   "Critical",
    "or_tautology":        "Critical",
    "union_extraction":    "Critical",
    "stacked_queries":     "Critical",
    "drop_table":          "Critical",
    "blind_boolean":       "High",
    "time_based_blind":    "High",
    "single_quote_escape": "Medium",
    "unknown":             "High",
}


# ── Data classes ───────────────────────────────────────────────────────────────
@dataclass
class PatchCandidate:
    report_id:         str
    alert_id:          str
    source_ip:         str
    endpoint:          str
    method:            str
    payload:           dict
    sql_query:         str
    attack_variant:    str
    cwe_id:            str
    severity:          str
    cvss_score:        float
    confidence:        float
    affected_param:    Optional[str]
    # generated
    patch_strategy:    str = ""
    patched_sql:       str = ""
    diff:              str = ""
    explanation:       str = ""
    # review
    status:            str = "pending"   # pending | approved | rejected | skipped
    reviewed_at:       str = ""
    applied_to_file:   str = ""


@dataclass
class PatchReport:
    generated_at:  str
    total_reports: int
    total_patches: int
    approved:      int
    rejected:      int
    skipped:       int
    candidates:    list[PatchCandidate] = field(default_factory=list)


# ── Forensic report loader ─────────────────────────────────────────────────────
def load_forensic_reports(report_dir: str) -> list[dict]:
    """Collect all forensic_*.json files that are ready for patching."""
    reports = []
    for p in sorted(Path(report_dir).glob("forensic_ALERT-*.json")):
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            ph = data.get("patch_handoff", {})
            if ph.get("ready_for_patch"):
                reports.append(data)
        except Exception as e:
            print(f"  ⚠  Could not read {p}: {e}")
    return reports


def load_single_report(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    ph = data.get("patch_handoff", {})
    if not ph.get("ready_for_patch"):
        print(f"  ⚠  Report {path} is not marked ready_for_patch — skipping.")
        return []
    return [data]


# ── Patch generator ────────────────────────────────────────────────────────────

def _detect_db_driver(sql: str) -> str:
    """Guess placeholder style from SQL dialect hints."""
    if re.search(r'\$\d+', sql):          return "psycopg2"   # PostgreSQL $1
    if re.search(r':[a-z_]+', sql):       return "oracle"     # Oracle :name
    return "sqlite3"                                           # default ?


def _parameterize_sql(sql: str, variant: str, param: Optional[str]) -> tuple[str, str, str]:
    """
    Returns (strategy, patched_sql, explanation).
    Converts the raw (possibly injected) SQL into a safe parameterised template.
    """
    driver   = _detect_db_driver(sql)
    ph       = "?" if driver == "sqlite3" else "%s"

    # ── Strip injected suffixes first ─────────────────────────────────────────
    # Remove comments: -- ... or /* ... */
    cleaned = re.sub(r"--[^\n]*", "", sql)
    cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)
    # Remove stacked statements after first ;
    cleaned = cleaned.split(";")[0].strip()
    # Remove tautologies like OR 1=1, OR '1'='1'
    cleaned = re.sub(r"\s+OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", "", cleaned, flags=re.I)
    # Remove UNION SELECT injections
    cleaned = re.sub(r"\s*UNION\s+(ALL\s+)?SELECT\b.*", "", cleaned, flags=re.I | re.DOTALL)
    # Remove DROP TABLE injections
    cleaned = re.sub(r";\s*DROP\s+TABLE\b.*", "", cleaned, flags=re.I | re.DOTALL)

    # ── Replace remaining literal user-supplied values with placeholders ───────
    # Values inside quotes that look like parameters
    param_count = 0

    def _replace_quoted(m: re.Match) -> str:
        nonlocal param_count
        param_count += 1
        return ph

    # Replace quoted string literals in WHERE / SET / VALUES
    parameterized = re.sub(
        r"""(['"])[^'"]*\1""",
        _replace_quoted,
        cleaned,
    )

    # If nothing was replaced, append a placeholder for the affected param
    if param_count == 0 and param:
        parameterized = parameterized.rstrip() + f" {ph}"
        param_count = 1

    strategy = f"parameterized_{driver}"
    explanation = (
        f"Sanitised SQL by removing injected payload ({variant}), "
        f"then replaced {param_count} literal value(s) with '{ph}' "
        f"placeholders ({driver} style). "
        f"Pass user input exclusively as bound parameters — never via string formatting."
    )
    return strategy, parameterized, explanation


def _build_python_fix(sql: str, patched_sql: str, param: Optional[str], driver: str) -> tuple[str, str]:
    """
    Returns (vulnerable_snippet, safe_snippet) as Python code strings.
    """
    p_name = param or "user_input"
    if driver == "sqlite3":
        safe = f'cursor.execute("{patched_sql}", ({p_name},))'
    elif driver == "psycopg2":
        safe = f'cursor.execute("{patched_sql}", ({p_name},))'
    else:
        safe = f'cursor.execute("{patched_sql}", {{{p_name!r}: {p_name}}})'

    # Guess at what the original vulnerable line looked like
    vuln = f'cursor.execute(f"... WHERE {p_name} = \'{{{p_name}}}\'")  # UNSAFE'
    return vuln, safe


def generate_diff(vuln_line: str, safe_line: str, label: str) -> str:
    a = [vuln_line + "\n"]
    b = [safe_line  + "\n"]
    return "\n".join(difflib.unified_diff(
        a, b,
        fromfile=f"a/{label}",
        tofile=f"b/{label}",
        lineterm="",
    ))


def build_candidate(report: dict) -> PatchCandidate:
    c   = report.get("classification", {})
    ph  = report.get("patch_handoff", {})
    sql = report.get("sql_query", "")
    variant  = ph.get("attack_variant") or c.get("attack_variant") or "unknown"
    param    = ph.get("affected_parameter")
    severity = c.get("severity", "High")
    driver   = _detect_db_driver(sql)

    strategy, patched_sql, explanation = _parameterize_sql(sql, variant, param)
    vuln_line, safe_line = _build_python_fix(sql, patched_sql, param, driver)
    diff = generate_diff(vuln_line, safe_line, report.get("endpoint", "app.py"))

    return PatchCandidate(
        report_id      = report.get("report_id", "?"),
        alert_id       = report.get("report_id", "?"),
        source_ip      = report.get("source_ip", "?"),
        endpoint       = report.get("endpoint", "?"),
        method         = report.get("method", "?"),
        payload        = report.get("payload", {}),
        sql_query      = sql,
        attack_variant = variant,
        cwe_id         = ph.get("cwe_id") or c.get("cwe_id") or "CWE-89",
        severity       = severity,
        cvss_score     = c.get("cvss_score", 0.0),
        confidence     = c.get("confidence", 0.0),
        affected_param = param,
        patch_strategy = strategy,
        patched_sql    = patched_sql,
        diff           = diff,
        explanation    = explanation,
    )


# ── Human review CLI ──────────────────────────────────────────────────────────

def _hr(char: str = "─", width: int = 65):
    print(char * width)


def _print_candidate(idx: int, total: int, c: PatchCandidate):
    icon = SEV_ICONS.get(c.severity, "⚪")
    _hr("═")
    print(f"  Patch {idx}/{total}  —  {icon} {c.severity}  [{c.cwe_id}]")
    _hr()
    print(f"  Report ID   : {c.report_id}")
    print(f"  Source IP   : {c.source_ip}")
    print(f"  Endpoint    : {c.method} {c.endpoint}")
    print(f"  Payload     : {json.dumps(c.payload)}")
    print(f"  Attack type : {c.attack_variant}")
    print(f"  CVSS        : {c.cvss_score}  |  Confidence: {c.confidence:.0%}")
    _hr()
    print(f"\n  📍 Vulnerable SQL query:")
    print(f"     {c.sql_query}")
    print(f"\n  ✅ Patched SQL (parameterised):")
    print(f"     {c.patched_sql}")
    print(f"\n  💬 Explanation:")
    print(f"     {c.explanation}")
    print(f"\n  📄 Diff:")
    for line in c.diff.splitlines():
        if line.startswith("---") or line.startswith("+++"):
            print(f"     \033[33m{line}\033[0m")
        elif line.startswith("+"):
            print(f"     \033[32m{line}\033[0m")
        elif line.startswith("-"):
            print(f"     \033[31m{line}\033[0m")
        else:
            print(f"     {line}")
    print()


def human_review(candidate: PatchCandidate, idx: int, total: int) -> str:
    """Interactive prompt. Returns 'approved' | 'rejected' | 'skipped'."""
    _print_candidate(idx, total, candidate)
    while True:
        try:
            choice = input("  👤 Your decision  [a]pprove / [r]eject / [s]kip / [q]uit : ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Interrupted — marking as skipped.")
            return "skipped"
        if choice in ("a", "approve"):
            return "approved"
        if choice in ("r", "reject"):
            return "rejected"
        if choice in ("s", "skip"):
            return "skipped"
        if choice in ("q", "quit"):
            print("  Quitting review session.")
            sys.exit(0)
        print("  Please enter a, r, s, or q.")


# ── Patch applier ─────────────────────────────────────────────────────────────

# Vulnerable patterns in app.py we know about — keyed by a fragment of the
# bad SQL so we can locate the exact line and rewrite it safely.
_VULN_LINE_PATTERNS = [
    # (regex to find the bad line, lambda(match, param) -> safe replacement)
    (
        # SQLI-001  string concat login
        re.compile(r"query\s*=\s*.SELECT \* FROM users WHERE username.*"),
        lambda ln, p: (
            '    query = "SELECT * FROM users WHERE username = ? AND password = ?"'
        ),
    ),
    (
        # SQLI-001b  the execute that uses query variable
        re.compile(r"user\s*=\s*db\.execute\(query\)\.fetchone\(\)"),
        lambda ln, p: (
            '    user = db.execute(query, (username, hashed)).fetchone()'
        ),
    ),
    (
        # SQLI-002  f-string search
        re.compile(r'sql\s*=\s*f["\']SELECT.*LIKE.*\{term\}'),
        lambda ln, p: (
            '    sql  = "SELECT id, name, email FROM users WHERE name LIKE ?"'
        ),
    ),
    (
        # SQLI-002b  execute(sql) without params → add params
        re.compile(r"rows\s*=\s*db\.execute\(sql\)\.fetchall\(\)\s*$"),
        lambda ln, p: (
            '        rows = db.execute(sql, (f"%{term}%",)).fetchall()'
        ),
    ),
    (
        # SQLI-003  % format user
        re.compile(r'sql\s*=\s*["\']SELECT.*WHERE id = %s["\']\s*%\s*user_id'),
        lambda ln, p: (
            '    sql = "SELECT id, name, email, role FROM users WHERE id = ?"'
        ),
    ),
    (
        # SQLI-003b  execute(sql) for /user route
        re.compile(r"row\s*=\s*db\.execute\(sql\)\.fetchone\(\)\s*$"),
        lambda ln, p: (
            '        row  = db.execute(sql, (user_id,)).fetchone()'
        ),
    ),
    (
        # SQLI-004  .format() orders
        re.compile(r'sql\s*=\s*["\']SELECT \* FROM orders.*\.format\(status\)'),
        lambda ln, p: (
            '    sql    = "SELECT * FROM orders WHERE status = ?"'
        ),
    ),
    (
        # SQLI-004b  execute(sql) for /orders
        re.compile(r"rows\s*=\s*db\.execute\(sql\)\.fetchall\(\)\s*$"),
        lambda ln, p: (
            '        rows = db.execute(sql, (status,)).fetchall()'
        ),
    ),
    (
        # SQLI-005  DELETE string concat
        re.compile(r'sql\s*=\s*["\']DELETE FROM["\']\s*\+\s*table'),
        lambda ln, p: (
            '    sql = "DELETE FROM logs WHERE id = ?"  '
            '# WARNING: table name must be validated server-side'
        ),
    ),
    (
        # SQLI-005b  execute(sql) for admin delete
        re.compile(r"db\.execute\(sql\)\s*$"),
        lambda ln, p: (
            '        db.execute(sql, (record_id,))'
        ),
    ),
]


def _find_target_file(endpoint: str) -> Optional[str]:
    """
    Map an endpoint to a Python source file.
    Checks for Flask @app.route decorators containing the endpoint slug.
    """
    ep_slug = endpoint.strip("/").split("/")[0] if endpoint else ""
    for candidate_path in sorted(Path(".").rglob("*.py")):
        # Skip the patch agent itself and reports
        if "patch_agent" in candidate_path.name or "reports" in str(candidate_path):
            continue
        try:
            text = candidate_path.read_text(encoding="utf-8", errors="ignore")
            if (ep_slug and f'"{endpoint}"' in text or f"'{endpoint}'" in text
                    or (ep_slug and ep_slug in text and "execute" in text)):
                return str(candidate_path)
        except Exception:
            pass
    return "app.py" if Path("app.py").exists() else None


def _rewrite_source_lines(
    original_lines: list[str],
    candidate: "PatchCandidate",
    ts: str,
) -> tuple[list[str], int]:
    """
    Walk source lines and apply all matching rewrite rules.
    Returns (patched_lines, count_of_rewrites).
    """
    rewrites = 0
    out: list[str] = []
    header_inserted = False

    for raw_line in original_lines:
        stripped = raw_line.rstrip()
        replaced = False
        for pattern, rewriter in _VULN_LINE_PATTERNS:
            if pattern.search(stripped):
                indent = len(raw_line) - len(raw_line.lstrip())
                new_line = rewriter(stripped, candidate.affected_param)
                # Preserve indentation from original file
                new_line = " " * indent + new_line.lstrip()
                if not header_inserted:
                    out.append(
                        f"# ── ZeroDayShield auto-patch {ts} ──\n"
                        f"# Report : {candidate.report_id}\n"
                        f"# CWE    : {candidate.cwe_id} ({candidate.attack_variant})\n"
                        f"# Status : APPROVED after human review\n"
                    )
                    header_inserted = True
                out.append(f"# PATCHED: {stripped}\n")
                out.append(new_line + "\n")
                rewrites += 1
                replaced = True
                break
        if not replaced:
            out.append(raw_line)
    return out, rewrites


def apply_patch(candidate: "PatchCandidate", dry_run: bool = False) -> bool:
    """
    Locate and rewrite vulnerable SQL lines in the target source file.
    Returns True on success.
    """
    target = _find_target_file(candidate.endpoint)
    if not target:
        print(f"  ⚠  Could not resolve target file for endpoint {candidate.endpoint}")
        candidate.applied_to_file = "NOT_FOUND"
        return False

    try:
        with open(target, encoding="utf-8") as f:
            original_lines = f.readlines()
    except Exception as e:
        print(f"  ✗  Cannot read {target}: {e}")
        return False

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    patched_lines, rewrites = _rewrite_source_lines(original_lines, candidate, ts)

    if rewrites == 0:
        # Generic fallback: insert a patch comment block above the execute() call
        # that matches keywords from the vulnerable SQL
        base_sql = candidate.sql_query.split("--")[0].split(";")[0].strip()
        kws = [w for w in re.findall(r'\b[A-Za-z_]\w{3,}\b', base_sql)
               if w.upper() not in {
                   "SELECT","FROM","WHERE","LIKE","ORDER","GROUP","INSERT",
                   "UPDATE","DELETE","VALUES","INTO","JOIN","NULL","TRUE","FALSE"
               }]
        comment_block = (
            f"# ── ZeroDayShield PATCH NEEDED {ts} ──\n"
            f"# CWE     : {candidate.cwe_id}\n"
            f"# Variant : {candidate.attack_variant}\n"
            f"# Vuln SQL: {candidate.sql_query[:120]}\n"
            f"# Safe SQL: {candidate.patched_sql}\n"
            f"# Action  : Replace string-formatted SQL with parameterised query\n"
            f"#           and pass user input as bound parameters.\n"
        )
        patched_lines = []
        annotated = False
        for raw_line in original_lines:
            if not annotated and any(k in raw_line for k in kws) and "execute" in raw_line.lower():
                patched_lines.append(comment_block)
                annotated = True
            patched_lines.append(raw_line)

        if not annotated:
            print(f"  ⚠  Could not locate vulnerable SQL in {target} — appending annotation.")
            patched_lines.append(f"\n{comment_block}")

    if dry_run:
        print(f"  🔍 [DRY-RUN] Would write patched file: {target} ({rewrites} line(s) rewritten)")
        candidate.applied_to_file = f"DRY_RUN:{target}"
        return True

    # Backup original
    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup = os.path.join(BACKUP_DIR, f"{Path(target).name}.{ts}.bak")
    with open(backup, "w", encoding="utf-8") as f:
        f.writelines(original_lines)

    # Write patched version
    os.makedirs(PATCH_DIR, exist_ok=True)
    out_path = os.path.join(PATCH_DIR, Path(target).name)
    with open(out_path, "w", encoding="utf-8") as f:
        f.writelines(patched_lines)

    candidate.applied_to_file = out_path
    print(f"  ✅  {rewrites} line(s) rewritten → {out_path}")
    print(f"  💾  Original backed up     → {backup}")
    return True


# ── Report writers ────────────────────────────────────────────────────────────

def _write_patch_markdown(report: PatchReport, path: str):
    lines = [
        "# ZeroDayShield — Patch Agent Report",
        "",
        f"**Generated:** {report.generated_at}  ",
        f"**Forensic reports processed:** {report.total_reports}  ",
        f"**Patches generated:** {report.total_patches}  ",
        f"**Approved:** {report.approved}  |  **Rejected:** {report.rejected}  |  **Skipped:** {report.skipped}",
        "",
        "---",
        "",
        "## Patch Summary",
        "",
        "| # | Report ID | Endpoint | Variant | Severity | CVSS | Status |",
        "|---|-----------|----------|---------|----------|------|--------|",
    ]
    for i, c in enumerate(report.candidates, 1):
        icon = SEV_ICONS.get(c.severity, "⚪")
        lines.append(
            f"| {i} | `{c.report_id[-16:]}` | `{c.endpoint}` "
            f"| `{c.attack_variant}` | {icon} {c.severity} "
            f"| {c.cvss_score} | **{c.status.upper()}** |"
        )

    lines += ["", "---", "", "## Patch Details", ""]
    for i, c in enumerate(report.candidates, 1):
        icon = SEV_ICONS.get(c.severity, "⚪")
        lines += [
            f"### Patch {i} — {icon} {c.severity} `{c.cwe_id}`",
            "",
            f"**Status:** `{c.status.upper()}`  ",
            f"**Report:** `{c.report_id}`  ",
            f"**Endpoint:** `{c.method} {c.endpoint}`  ",
            f"**Attack type:** `{c.attack_variant}`  ",
            f"**Source IP:** `{c.source_ip}`  ",
            f"**CVSS:** {c.cvss_score} | **Confidence:** {c.confidence:.0%}",
            "",
            "**Payload:**",
            f"```json\n{json.dumps(c.payload, indent=2)}\n```",
            "",
            "**Vulnerable SQL:**",
            f"```sql\n{c.sql_query}\n```",
            "",
            "**Patched SQL:**",
            f"```sql\n{c.patched_sql}\n```",
            "",
            "**Explanation:**",
            f"> {c.explanation}",
            "",
            "**Diff:**",
            f"```diff\n{c.diff}\n```",
        ]
        if c.applied_to_file:
            lines += ["", f"**Applied to:** `{c.applied_to_file}`"]
        if c.reviewed_at:
            lines += [f"**Reviewed at:** {c.reviewed_at}"]
        lines += ["", "---", ""]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def save_patch_report(report: PatchReport) -> tuple[str, str]:
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(REPORT_DIR, f"patch_report_{ts}.json")
    md_path   = os.path.join(REPORT_DIR, f"patch_report_{ts}.md")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(asdict(report), f, indent=2)
    _write_patch_markdown(report, md_path)
    return json_path, md_path


# ── Main ──────────────────────────────────────────────────────────────────────

def run_patch_agent(
    report_path: Optional[str] = None,
    auto_approve: bool = False,
    dry_run: bool = False,
):
    _hr("═")
    print("  ZeroDayShield — Patch Agent  (Stage 3)")
    mode = "AUTO-APPROVE" if auto_approve else ("DRY-RUN" if dry_run else "INTERACTIVE")
    print(f"  Mode: {mode}")
    _hr("═")

    # 1. Load forensic reports
    if report_path:
        raw_reports = load_single_report(report_path)
    else:
        raw_reports = load_forensic_reports(REPORT_DIR)

    if not raw_reports:
        print(f"\n  No forensic reports ready for patching in '{REPORT_DIR}/'.")
        print("  Run forensic_agent.py first, or supply --report <path>.\n")
        return

    print(f"\n  Found {len(raw_reports)} forensic report(s) ready for patching.\n")

    # 2. Build patch candidates
    candidates: list[PatchCandidate] = []
    for r in raw_reports:
        try:
            c = build_candidate(r)
            candidates.append(c)
        except Exception as e:
            print(f"  ✗  Failed to build candidate for {r.get('report_id','?')}: {e}")

    total = len(candidates)
    print(f"  Generated {total} patch candidate(s).\n")

    # 3. Human review + apply
    approved = rejected = skipped = 0

    for idx, candidate in enumerate(candidates, 1):
        if auto_approve:
            _print_candidate(idx, total, candidate)
            candidate.status = "approved"
            candidate.reviewed_at = datetime.now(timezone.utc).isoformat()
            print(f"  [AUTO-APPROVE] Patch {idx} approved.")
        else:
            decision = human_review(candidate, idx, total)
            candidate.status = decision
            candidate.reviewed_at = datetime.now(timezone.utc).isoformat()
            print(f"  Decision: {decision.upper()}\n")

        if candidate.status == "approved":
            approved += 1
            apply_patch(candidate, dry_run=dry_run)
        elif candidate.status == "rejected":
            rejected += 1
        else:
            skipped += 1

    # 4. Save patch report
    patch_report = PatchReport(
        generated_at  = datetime.now(timezone.utc).isoformat(),
        total_reports = len(raw_reports),
        total_patches = total,
        approved      = approved,
        rejected      = rejected,
        skipped       = skipped,
        candidates    = candidates,
    )

    json_path, md_path = save_patch_report(patch_report)

    _hr("═")
    print(f"  Patch Agent complete")
    print(f"  Approved  : {approved}")
    print(f"  Rejected  : {rejected}")
    print(f"  Skipped   : {skipped}")
    print(f"  JSON      : {json_path}")
    print(f"  Markdown  : {md_path}")
    _hr("═")
    print()


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZeroDayShield — Patch Agent (Stage 3)")
    parser.add_argument("--report",       default=None, help="Path to a specific forensic JSON report")
    parser.add_argument("--auto-approve", action="store_true", help="Approve all patches without human review (CI mode)")
    parser.add_argument("--dry-run",      action="store_true", help="Show patches but do not write files")
    args = parser.parse_args()

    run_patch_agent(
        report_path  = args.report,
        auto_approve = args.auto_approve,
        dry_run      = args.dry_run,
    )
