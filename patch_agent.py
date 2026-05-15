"""
agent/patch_agent.py
The SQL injection patch agent.

Pipeline:
  1. Walk target codebase (.py files)
  2. For each file, extract candidate code lines via regex patterns
  3. Run each candidate through the GPT-2 classifier
  4. For confirmed injections, call the LLM patcher to generate a fix
  5. Produce a unified diff and a full JSON + Markdown report

Usage:
    python agent/patch_agent.py --target target_codebase/ --report reports/
"""

from __future__ import annotations
import argparse
import ast
import difflib
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

# ── Add project root to path ──────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))
from model.classifier import classify

# ── Severity mapping ──────────────────────────────────────────────────────────
SEVERITY_MAP = {
    "string_concat": "CRITICAL",
    "fstring":       "HIGH",
    "percent_fmt":   "HIGH",
    "format_call":   "MEDIUM",
    "unknown":       "MEDIUM",
}

SQLI_PATTERNS = [
    # name, regex
    ("string_concat", re.compile(
        r'(execute|query)\s*\(\s*["\'].*["\']'
        r'\s*\+\s*\w+|'
        r'["\'].*WHERE.*["\'\s]\s*\+\s*\w+',
        re.IGNORECASE
    )),
    ("fstring", re.compile(
        r'(execute|query)\s*\(\s*f["\'].*\{.*\}',
        re.IGNORECASE
    )),
    ("percent_fmt", re.compile(
        r'(execute|query)\s*\(\s*["\'].*%s.*["\']'
        r'\s*%\s*\w+',
        re.IGNORECASE
    )),
    ("format_call", re.compile(
        r'(execute|query)\s*\(\s*["\'].*\{\}.*["\']'
        r'\.format\s*\(',
        re.IGNORECASE
    )),
]


# ── Data classes ──────────────────────────────────────────────────────────────
@dataclass
class Finding:
    file:       str
    line_no:    int
    vuln_id:    str
    pattern:    str
    severity:   str
    code_line:  str
    confidence: float
    explanation: str = ""
    patch_line:  str = ""
    diff:        str = ""


@dataclass
class Report:
    scan_target:  str
    scan_time:    str
    total_files:  int
    total_vulns:  int
    findings:     list[Finding] = field(default_factory=list)


# ── Pattern-based scanner ─────────────────────────────────────────────────────
def scan_file(filepath: str) -> list[tuple[int, str, str]]:
    """
    Returns list of (line_no, pattern_name, raw_line) candidates.
    Only lines that match at least one SQLI_PATTERNS regex are returned.
    """
    candidates = []
    with open(filepath, encoding="utf-8", errors="ignore") as fh:
        for lineno, line in enumerate(fh, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for pname, rx in SQLI_PATTERNS:
                if rx.search(stripped):
                    candidates.append((lineno, pname, stripped))
                    break  # one match per line is enough
    return candidates


# ── Patch generator ───────────────────────────────────────────────────────────
# Deterministic rule-based patcher (no external API required).
# In production, swap _rule_patch() with an LLM call.

def _extract_vars(line: str) -> list[str]:
    """Best-effort: find identifiers after the last quote."""
    m = re.findall(r'\b([a-zA-Z_]\w*)\b', line)
    # exclude common SQL keywords and string markers
    exclude = {"SELECT","FROM","WHERE","AND","OR","INSERT","INTO",
               "UPDATE","SET","DELETE","VALUES","LIKE","ORDER","BY",
               "execute","query","db","cursor","conn","f","s","r",
               "None","True","False","str","int"}
    return [v for v in m if v not in exclude]


def _rule_patch(line: str, pattern: str) -> tuple[str, str]:
    """
    Returns (patched_line, explanation).
    Converts vulnerable SQL construction to parameterized form.
    """
    indent = len(line) - len(line.lstrip())
    pad = " " * indent

    # ── f-string ──────────────────────────────────────────────────────────────
    if pattern == "fstring":
        m = re.search(r'f["\'](.+?)["\']', line)
        if m:
            template = m.group(1)
            params = re.findall(r'\{(\w+)\}', template)
            # For LIKE '%{var}%' patterns, use ? with Python-side wildcard
            def _replace_var(match):
                return "?"
            clean_sql = re.sub(r"'?%?\{(\w+)\}%?'?", lambda m2: "?", template)
            clean_sql = re.sub(r'\{(\w+)\}', '?', clean_sql)
            # Build param tuple, wrapping LIKE vars with wildcards
            param_parts = []
            for p in params:
                if f"%{{{p}}}%" in template or f"LIKE" in template.upper():
                    param_parts.append(f"f'%{{{p}}}%'")
                else:
                    param_parts.append(p)
            param_str = "(" + ", ".join(param_parts) + (",)" if len(param_parts) == 1 else ")")
            # Recover the full call (e.g. db.execute(...).fetchall())
            suffix_m = re.search(r'\)\s*(\.\w+\(\))', line)
            suffix = suffix_m.group(1) if suffix_m else ""
            call_m = re.match(r'\s*(\w[\w.]*)\s*\(', line)
            caller = call_m.group(1) if call_m else "db.execute"
            # Recover leading assignment if any (e.g. "rows = ")
            assign_m = re.match(r'(\s*\w+\s*=\s*)', line)
            assign = assign_m.group(1) if assign_m and "execute" not in assign_m.group(1) else pad
            patched = f'{assign}{caller}("{clean_sql}", {param_str}){suffix}'
            explanation = (
                f"Replaced f-string interpolation with parameterized query. "
                f"Variables {params} are now passed as bind parameters, "
                f"with LIKE wildcards moved to the Python parameter."
            )
            return patched, explanation

    # ── string concatenation ──────────────────────────────────────────────────
    if pattern == "string_concat":
        # Extract full SQL template from first quoted string
        m_sql = re.search(r'["\']([^"\']+)["\']', line)
        base_sql = m_sql.group(1) if m_sql else "SELECT * FROM table WHERE id = ?"
        # Find all identifiers that appear after + signs (the injected vars)
        injected = re.findall(r'\+\s*(\w+)', line)
        injected = [v for v in injected if v not in
                    {"query","sql","db","cursor","conn","execute","fetchone","fetchall","str"}]
        # Rebuild SQL — add ? placeholders for WHERE conditions
        if "?" not in base_sql:
            # Replace trailing partial quote fragments with ?
            clean_sql = re.sub(r"'\s*$", " ?", base_sql.rstrip())
            if "?" not in clean_sql:
                clean_sql = base_sql + " ?"
        else:
            clean_sql = base_sql
        param_str = "(" + ", ".join(injected) + (",)" if len(injected) == 1 else ")")\
                    if injected else "(value,)"
        call_m = re.match(r'\s*(\w[\w.]*)\s*\(', line)
        # Detect if line is an assignment (query = ...) or a direct call
        is_assign = bool(re.match(r'\s*\w+\s*=\s*["\']', line))
        if is_assign:
            # Keep as query variable with the call on next logical step;
            # simplify: replace with parameterized call directly
            caller = "db.execute"
        else:
            caller = call_m.group(1) if call_m else "db.execute"
        patched = f'{pad}{caller}("{clean_sql}", {param_str})'
        explanation = (
            f"Replaced string concatenation SQL with parameterized query. "
            f"User-supplied variables {injected} are now bound safely via '?' placeholders."
        )
        return patched, explanation

    # ── % formatting ──────────────────────────────────────────────────────────
    if pattern == "percent_fmt":
        m = re.search(r'["\'](.+?)["\']', line)
        base_sql = m.group(1) if m else ""
        clean_sql = base_sql.replace("%s", "?")
        m_var = re.search(r'%\s*(\w+)', line)
        var = m_var.group(1) if m_var else "value"
        call_m = re.match(r'\s*(\w[\w.]*)\s*\(', line)
        caller = call_m.group(1) if call_m else "db.execute"
        patched = f'{pad}{caller}("{clean_sql}", ({var},))'
        explanation = (
            f"Replaced %-format SQL string with parameterized query. "
            f"'{var}' is now safely bound via placeholder."
        )
        return patched, explanation

    # ── .format() ─────────────────────────────────────────────────────────────
    if pattern == "format_call":
        m = re.search(r'["\'](.+?)["\']', line)
        base_sql = m.group(1) if m else ""
        clean_sql = base_sql.replace("{}", "?")
        m_var = re.search(r'\.format\s*\(\s*(\w+)', line)
        var = m_var.group(1) if m_var else "value"
        call_m = re.match(r'\s*(\w[\w.]*)\s*\(', line)
        caller = call_m.group(1) if call_m else "db.execute"
        patched = f'{pad}{caller}("{clean_sql}", ({var},))'
        explanation = (
            f"Replaced .format() SQL string with parameterized query. "
            f"'{var}' is now safely bound via placeholder."
        )
        return patched, explanation

    # fallback
    return line, "Manual review required — could not auto-patch this pattern."


# ── Diff builder ──────────────────────────────────────────────────────────────
def make_diff(original: str, patched: str, filepath: str, line_no: int) -> str:
    a = [original + "\n"]
    b = [patched  + "\n"]
    diff = difflib.unified_diff(
        a, b,
        fromfile=f"a/{filepath}:{line_no}",
        tofile=f"b/{filepath}:{line_no}",
        lineterm="",
    )
    return "\n".join(diff)


# ── Main agent ────────────────────────────────────────────────────────────────
def run_agent(target_dir: str, report_dir: str) -> Report:
    target_path = Path(target_dir)
    py_files = sorted(target_path.rglob("*.py"))

    report = Report(
        scan_target=str(target_path.resolve()),
        scan_time=datetime.now().isoformat(timespec="seconds"),
        total_files=len(py_files),
        total_vulns=0,
    )

    vuln_counter = 1

    for py_file in py_files:
        rel = str(py_file.relative_to(target_path))
        candidates = scan_file(str(py_file))
        if not candidates:
            continue

        for lineno, pname, raw_line in candidates:
            # ── Classifier gate ───────────────────────────────────────────────
            result = classify(raw_line)
            if result["label"] != "sql_injection":
                continue

            vuln_id = f"SQLI-{vuln_counter:03d}"
            vuln_counter += 1

            severity = SEVERITY_MAP.get(pname, "MEDIUM")
            patch_line, explanation = _rule_patch(raw_line, pname)
            diff = make_diff(raw_line, patch_line, rel, lineno)

            finding = Finding(
                file=rel,
                line_no=lineno,
                vuln_id=vuln_id,
                pattern=pname,
                severity=severity,
                code_line=raw_line,
                confidence=result["confidence"],
                explanation=explanation,
                patch_line=patch_line,
                diff=diff,
            )
            report.findings.append(finding)

    report.total_vulns = len(report.findings)

    # ── Save outputs ──────────────────────────────────────────────────────────
    os.makedirs(report_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # JSON report
    json_path = os.path.join(report_dir, f"sqli_report_{ts}.json")
    with open(json_path, "w") as f:
        json.dump(asdict(report), f, indent=2)

    # Markdown report
    md_path = os.path.join(report_dir, f"sqli_report_{ts}.md")
    _write_markdown(report, md_path)

    # Patched file(s)
    _write_patched_files(report, target_dir, report_dir)

    print(f"\n{'='*60}")
    print(f"  Scan complete")
    print(f"  Files scanned : {report.total_files}")
    print(f"  Vulnerabilities: {report.total_vulns}")
    print(f"  JSON report   : {json_path}")
    print(f"  MD report     : {md_path}")
    print(f"{'='*60}\n")

    return report


# ── Report writers ────────────────────────────────────────────────────────────
SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

def _write_markdown(report: Report, path: str):
    lines = [
        "# SQL Injection Vulnerability Report",
        "",
        f"**Scan target:** `{report.scan_target}`  ",
        f"**Scan time:** {report.scan_time}  ",
        f"**Files scanned:** {report.total_files}  ",
        f"**Vulnerabilities found:** {report.total_vulns}",
        "",
        "---",
        "",
    ]

    if not report.findings:
        lines.append("No SQL injection vulnerabilities detected.")
    else:
        # Summary table
        lines += [
            "## Summary",
            "",
            "| ID | File | Line | Pattern | Severity | Confidence |",
            "|----|------|------|---------|----------|------------|",
        ]
        for f in report.findings:
            icon = SEV_ICON.get(f.severity, "")
            lines.append(
                f"| {f.vuln_id} | `{f.file}` | {f.line_no} "
                f"| `{f.pattern}` | {icon} {f.severity} | {f.confidence:.0%} |"
            )

        lines += ["", "---", "", "## Findings"]

        for f in report.findings:
            icon = SEV_ICON.get(f.severity, "")
            lines += [
                "",
                f"### {f.vuln_id} — {icon} {f.severity}",
                "",
                f"**File:** `{f.file}` · **Line:** {f.line_no}  ",
                f"**Pattern:** `{f.pattern}` · **Classifier confidence:** {f.confidence:.0%}",
                "",
                "**Vulnerable code:**",
                "```python",
                f.code_line,
                "```",
                "",
                "**Explanation:**",
                f"> {f.explanation}",
                "",
                "**Patched code:**",
                "```python",
                f.patch_line,
                "```",
                "",
                "**Diff:**",
                "```diff",
                f.diff,
                "```",
                "",
                "---",
            ]

    with open(path, "w") as fh:
        fh.write("\n".join(lines))


def _write_patched_files(report: Report, target_dir: str, report_dir: str):
    """Write patched versions of all affected files into reports/patched/."""
    patched_dir = os.path.join(report_dir, "patched")
    os.makedirs(patched_dir, exist_ok=True)

    # Group findings by file
    file_findings: dict[str, list[Finding]] = {}
    for f in report.findings:
        file_findings.setdefault(f.file, []).append(f)

    for rel_path, findings in file_findings.items():
        src = os.path.join(target_dir, rel_path)
        with open(src, encoding="utf-8") as fh:
            original_lines = fh.readlines()

        patched_lines = original_lines[:]
        for f in findings:
            idx = f.line_no - 1
            # preserve original indentation from file (raw_line may be stripped)
            orig = patched_lines[idx]
            indent = len(orig) - len(orig.lstrip())
            patched_lines[idx] = " " * indent + f.patch_line.lstrip() + "\n"

        out_path = os.path.join(patched_dir, rel_path)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.writelines(patched_lines)

    print(f"  Patched files : {patched_dir}/")


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQLi zero-day patch agent")
    parser.add_argument("--target", default="target_codebase/",
                        help="Directory to scan")
    parser.add_argument("--report", default="reports/",
                        help="Directory to write reports")
    args = parser.parse_args()
    run_agent(args.target, args.report)
