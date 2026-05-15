"""
run_pipeline.py
One-command entry point. Runs all three stages in order:
  1. Build dataset
  2. Fine-tune GPT-2 classifier
  3. Run patch agent on target codebase

Usage:
    python run_pipeline.py [--skip-train]
"""

import argparse
import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.abspath(__file__))


def run(cmd: list[str], label: str):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        print(f"\n[ERROR] '{label}' failed with code {result.returncode}")
        sys.exit(result.returncode)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-train", action="store_true",
                        help="Skip dataset build + training (use existing model)")
    args = parser.parse_args()

    if not args.skip_train:
        run([sys.executable, "data/dataset.py"],   "Stage 0 — build dataset")
        run([sys.executable, "model/train.py"],     "Stage 1 — fine-tune GPT-2 classifier")

    run([sys.executable, "agent/patch_agent.py",
         "--target", "target_codebase/",
         "--report", "reports/"],                  "Stage 2 — agentic patch scan")

    print("\nPipeline complete. Check reports/ for output.\n")


if __name__ == "__main__":
    main()
