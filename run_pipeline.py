"""
run_pipeline.py
One-command entry point for the full ZeroDayShield pipeline.

Stages:
  0. Build dataset (JSONL for classifier + Ollama finetune data)
  1. Create Ollama model  (qwen2.5-coder-sqli via Modelfile)
  2. Train local CNN+GRU  (fallback classifier)
  3. Run full pipeline    (DB → Flask → sentinel → attack → forensic → report)

Usage:
    python run_pipeline.py                  # full run from scratch
    python run_pipeline.py --skip-train     # skip dataset build + training
    python run_pipeline.py --skip-finetune  # skip Ollama model creation
    python run_pipeline.py --skip-all-train # jump straight to pipeline
"""

import argparse
import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.abspath(__file__))


def run(cmd: list[str], label: str):
    print(f"\n{'='*65}")
    print(f"  {label}")
    print(f"{'='*65}")
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        print(f"\n[ERROR] '{label}' failed with exit code {result.returncode}")
        sys.exit(result.returncode)


def main():
    parser = argparse.ArgumentParser(description="ZeroDayShield full pipeline runner")
    parser.add_argument("--skip-train",      action="store_true",
                        help="Skip dataset build + CNN+GRU training")
    parser.add_argument("--skip-finetune",   action="store_true",
                        help="Skip Ollama Modelfile creation")
    parser.add_argument("--skip-all-train",  action="store_true",
                        help="Skip all training, run pipeline directly")
    parser.add_argument("--forensic-only",   action="store_true",
                        help="Only run forensic on existing alerts")
    args = parser.parse_args()

    skip_train    = args.skip_train    or args.skip_all_train
    skip_finetune = args.skip_finetune or args.skip_all_train

    # Stage 0 — Build datasets
    if not skip_train:
        run(
            [sys.executable, "dataset.py"],
            "Stage 0 — Build dataset (classifier JSONL + Ollama finetune JSONL)",
        )

    # Stage 1 — Ollama model creation (Path A: Modelfile)
    if not skip_finetune:
        run(
            [sys.executable, "finetune_ollama.py"],
            "Stage 1 — Create Ollama model (qwen2.5-coder-sqli via Modelfile)",
        )

    # Stage 2 — Train local CNN+GRU fallback
    if not skip_train:
        run(
            [sys.executable, "train.py"],
            "Stage 2 — Train local CNN+GRU fallback classifier",
        )

    # Stage 3 — End-to-end detection pipeline
    pipeline_args = [sys.executable, "pipeline.py"]
    if args.forensic_only:
        pipeline_args.append("--forensic-only")

    run(pipeline_args, "Stage 3 — Run end-to-end detection pipeline")

    print("\n" + "="*65)
    print("  ✅  Pipeline complete!")
    print("  Check reports/ for JSON + Markdown forensic reports.")
    print("  Next stage: python patch_agent.py --target . --report reports/")
    print("="*65 + "\n")


if __name__ == "__main__":
    main()
