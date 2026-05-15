"""
pipeline.py
End-to-end ZeroDayShield pipeline orchestrator.

Stages:
  0. setup_db      — initialise the vulnerable target database
  1. app server    — start Flask target in background
  2. sentinel      — start sentinel monitor in background
  3. attack        — fire SQLi payloads
  4. forensic      — classify all raised alerts
  5. patch         — generate + human-review + apply patches
  6. summary       — print final report table

Usage:
    python pipeline.py                       # full interactive run
    python pipeline.py --skip-db
    python pipeline.py --skip-attack
    python pipeline.py --no-server
    python pipeline.py --forensic-only
    python pipeline.py --patch-auto-approve  # skip human review in patch stage
    python pipeline.py --skip-patch          # forensic only, no patching
    python pipeline.py --dry-run-patch       # show patches but don't write files
"""

from __future__ import annotations
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Force UTF-8 output on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = Path(__file__).parent

# ── Colour helpers ────────────────────────────────────────────────────────────
SEV_ICONS = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "None": "✅"}


def _banner(title: str):
    print(f"\n{'='*65}")
    print(f"  {title}")
    print(f"{'='*65}")


def _step(n: int, label: str):
    print(f"\n  ──── Stage {n}: {label} ────")


# ── Stage runners ─────────────────────────────────────────────────────────────

def stage_setup_db():
    _step(0, "Setup database")
    r = subprocess.run([sys.executable, str(ROOT / "setup_db.py")], cwd=ROOT)
    if r.returncode != 0:
        print("  ✗  setup_db.py failed")
        sys.exit(1)


def stage_start_server() -> subprocess.Popen:
    _step(1, "Start Flask target server")
    # Patch app.py to also log requests to request_log.jsonl
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "app.py")],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"  Flask PID: {proc.pid}")
    print("  Waiting for server to be ready...")
    time.sleep(2)

    # Verify server is up
    import urllib.request
    for attempt in range(10):
        try:
            urllib.request.urlopen("http://127.0.0.1:5000/search?q=test", timeout=2)
            print(f"  ✅  Flask server ready on http://127.0.0.1:5000")
            return proc
        except Exception:
            time.sleep(0.5)

    print("  ⚠  Flask server didn't respond — continuing anyway.")
    return proc


def stage_start_sentinel() -> subprocess.Popen:
    _step(2, "Start Sentinel monitor")
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "sentinel.py")],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    print(f"  Sentinel PID: {proc.pid}")
    time.sleep(0.5)
    return proc


def stage_attack():
    _step(3, "Run SQLi attack script")
    r = subprocess.run(
        [sys.executable, str(ROOT / "attack.py"), "--delay", "0.8"],
        cwd=ROOT,
    )
    if r.returncode != 0:
        print("  ✗  attack.py failed")
        sys.exit(1)
    # Give sentinel time to process
    print("  Waiting for sentinel to process log...")
    time.sleep(3)


def stage_forensic() -> list[dict]:
    _step(4, "Forensic classification (Ollama qwen2.5-coder-sqli)")
    from forensic_agent import process_all_pending
    process_all_pending()

    # Collect all reports
    reports = []
    for p in sorted(Path("reports").glob("forensic_ALERT-*.json")):
        with open(p) as f:
            reports.append(json.load(f))
    return reports


def stage_patch(
    auto_approve: bool = False,
    dry_run: bool = False,
) -> None:
    _step(5, "Patch Agent — generate, review & apply fixes")
    from patch_agent import run_patch_agent
    run_patch_agent(
        report_path  = None,
        auto_approve = auto_approve,
        dry_run      = dry_run,
    )


def stage_summary(reports: list[dict]):
    _step(6, "Summary")
    _banner("ZeroDayShield — Pipeline Complete")

    if not reports:
        print("  No reports generated.")
        return

    print(f"\n  {'ID':<20} {'Endpoint':<12} {'Variant':<22} {'Severity':<10} {'CVSS':<6} {'Conf'}")
    print(f"  {'-'*85}")

    for r in reports:
        c   = r.get("classification", {})
        rid = r.get("report_id", "?")[-16:]
        ep  = r.get("endpoint", "?")
        var = c.get("attack_variant") or "safe"
        sev = c.get("severity", "None")
        cvs = c.get("cvss_score", 0.0)
        con = c.get("confidence", 0.0)
        icon = SEV_ICONS.get(sev, "⚪")

        print(f"  {rid:<20} {ep:<12} {var:<22} {icon} {sev:<8} {cvs:<6} {con:.0%}")

    # Count by severity
    sev_counts: dict[str, int] = {}
    for r in reports:
        sev = r.get("classification", {}).get("severity", "None")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    print(f"\n  Severity breakdown:")
    for sev, cnt in sorted(sev_counts.items(), key=lambda x: -{"Critical":4,"High":3,"Medium":2,"Low":1}.get(x[0],0)):
        print(f"    {SEV_ICONS.get(sev,'⚪')} {sev}: {cnt}")

    print(f"\n  Reports saved to : reports/")
    print(f"  Patched files    : reports/patched/  (if patch stage ran)")
    print(f"  Backups          : reports/backups/")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ZeroDayShield end-to-end pipeline")
    parser.add_argument("--skip-db",          action="store_true")
    parser.add_argument("--no-server",        action="store_true")
    parser.add_argument("--skip-attack",      action="store_true")
    parser.add_argument("--forensic-only",    action="store_true")
    parser.add_argument("--skip-patch",       action="store_true",
                        help="Skip patch agent stage (forensic + summary only)")
    parser.add_argument("--patch-auto-approve", action="store_true",
                        help="Auto-approve all patches without human review")
    parser.add_argument("--dry-run-patch",    action="store_true",
                        help="Show patches but do not write patched files")
    args = parser.parse_args()

    _banner(f"ZeroDayShield — Classification Pipeline  [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]")

    server_proc  = None
    sentinel_proc = None

    try:
        if args.forensic_only:
            reports = stage_forensic()
            if not args.skip_patch:
                stage_patch(
                    auto_approve = args.patch_auto_approve,
                    dry_run      = args.dry_run_patch,
                )
            stage_summary(reports)
            return

        if not args.skip_db:
            stage_setup_db()

        if not args.no_server:
            server_proc = stage_start_server()

        sentinel_proc = stage_start_sentinel()

        if not args.skip_attack:
            stage_attack()
        else:
            print("\n  [skip-attack] Using existing request_log.jsonl")
            # Give sentinel a moment to process existing log
            time.sleep(2)

        # Stop sentinel (we have what we need)
        if sentinel_proc:
            sentinel_proc.terminate()
            # Drain stdout
            try:
                out, _ = sentinel_proc.communicate(timeout=3)
                if out:
                    print(out)
            except Exception:
                pass

        reports = stage_forensic()

        if not args.skip_patch:
            stage_patch(
                auto_approve = args.patch_auto_approve,
                dry_run      = args.dry_run_patch,
            )

        stage_summary(reports)

    finally:
        if sentinel_proc and sentinel_proc.poll() is None:
            sentinel_proc.terminate()
        if server_proc and server_proc.poll() is None:
            print("\n  Stopping Flask server...")
            server_proc.terminate()


if __name__ == "__main__":
    main()
