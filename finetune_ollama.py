"""
finetune_ollama.py
Creates the qwen2.5-coder-sqli Ollama model from the Modelfile.

Path A (default): Uses Modelfile with baked-in system prompt + few-shot examples.
                  No GPU training required. Works immediately.

Path B (--qlora): Actually fine-tunes qwen2.5-coder:3b weights on the JSONL dataset
                  using unsloth + trl. Requires ~4GB VRAM and ~20-30 min.
                  After training, exports to GGUF and registers with Ollama.

Usage:
    python finetune_ollama.py              # Path A: Modelfile customisation
    python finetune_ollama.py --check      # Check if Ollama + model is available
    python finetune_ollama.py --qlora      # Path B: full QLoRA fine-tune (advanced)
    python finetune_ollama.py --pull-base  # Pull qwen2.5-coder:3b base if not present
"""

from __future__ import annotations
import argparse
import json
import os
import subprocess
import sys

# Force UTF-8 output on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


MODEL_NAME    = "qwen2.5-coder-sqli"
BASE_MODEL    = "qwen2.5-coder:3b"
MODELFILE     = "Modelfile"
FINETUNE_DATA = "data/sqli_finetune.jsonl"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(cmd: list[str], label: str, capture: bool = False):
    print(f"\n  ▶  {label}")
    print(f"     $ {' '.join(cmd)}")
    if capture:
        r = subprocess.run(cmd, capture_output=True, text=True)
        return r.stdout + r.stderr
    r = subprocess.run(cmd)
    if r.returncode != 0:
        print(f"  ✗  '{label}' failed (exit {r.returncode})")
        sys.exit(r.returncode)
    return ""


def check_ollama() -> bool:
    try:
        import ollama
        client = ollama.Client()
        client.list()
        return True
    except Exception as e:
        print(f"  ✗  Ollama not reachable: {e}")
        print("     Install from https://ollama.com and run 'ollama serve'")
        return False


def list_models() -> list[str]:
    try:
        import ollama
        client = ollama.Client()
        models = client.list()
        # Handle both dict and object response formats
        model_list = models.get("models", []) if isinstance(models, dict) else getattr(models, "models", [])
        names = []
        for m in model_list:
            if isinstance(m, dict):
                names.append(m.get("name", m.get("model", "")))
            else:
                names.append(getattr(m, "name", getattr(m, "model", "")))
        return names
    except Exception as e:
        print(f"  ✗  Could not list models: {e}")
        return []


def pull_base():
    """Pull the base qwen2.5-coder:3b model if not already present."""
    print(f"\n  Checking for base model '{BASE_MODEL}'...")
    names = list_models()
    if any(BASE_MODEL in n for n in names):
        print(f"  ✅  Base model '{BASE_MODEL}' already present.")
        return
    print(f"  Pulling '{BASE_MODEL}' — this may take a few minutes...")
    _run(["ollama", "pull", BASE_MODEL], f"Pull {BASE_MODEL}")
    print(f"  ✅  '{BASE_MODEL}' pulled successfully.")


# ── Path A: Modelfile customisation ──────────────────────────────────────────

def create_from_modelfile():
    print(f"\n{'='*65}")
    print(f"  Path A — Ollama Modelfile Customisation")
    print(f"  Creates : {MODEL_NAME}")
    print(f"  Base    : {BASE_MODEL}")
    print(f"  File    : {MODELFILE}")
    print(f"{'='*65}")

    if not os.path.exists(MODELFILE):
        print(f"  ✗  {MODELFILE} not found. Run from project root.")
        sys.exit(1)

    # Ensure finetune data also exists (generate if missing)
    if not os.path.exists(FINETUNE_DATA):
        print(f"  Generating {FINETUNE_DATA}...")
        from dataset import build_finetune_jsonl
        build_finetune_jsonl(FINETUNE_DATA)

    pull_base()

    # Remove old model if exists
    names = list_models()
    if any(MODEL_NAME in n for n in names):
        print(f"\n  Removing existing '{MODEL_NAME}' model...")
        _run(["ollama", "rm", MODEL_NAME], f"Remove old {MODEL_NAME}")

    # Create new model
    _run(
        ["ollama", "create", MODEL_NAME, "-f", MODELFILE],
        f"Create {MODEL_NAME} from Modelfile",
    )

    # Verify
    names = list_models()
    if any(MODEL_NAME in n for n in names):
        print(f"\n  ✅  Model '{MODEL_NAME}' is ready.")
        print(f"     Test it: ollama run {MODEL_NAME}")
    else:
        print(f"  ✗  Model creation failed — '{MODEL_NAME}' not in model list.")
        sys.exit(1)


# ── Path B: QLoRA fine-tuning (advanced) ─────────────────────────────────────

def qlora_finetune():
    print(f"\n{'='*65}")
    print(f"  Path B — QLoRA Fine-tuning (unsloth + trl)")
    print(f"{'='*65}")

    # Check dependencies
    try:
        import torch
        vram = 0.0
        if torch.cuda.is_available():
            vram = torch.cuda.get_device_properties(0).total_memory / 1e9
            print(f"  GPU: {torch.cuda.get_device_name(0)} — {vram:.1f} GB VRAM")
        else:
            print("  ⚠  No CUDA GPU detected — QLoRA training will be very slow on CPU.")
    except ImportError:
        print("  ✗  PyTorch not installed.")
        sys.exit(1)

    try:
        from unsloth import FastLanguageModel
    except ImportError:
        print("  Installing unsloth...")
        _run(
            [sys.executable, "-m", "pip", "install",
             "unsloth[colab-new]", "trl", "peft", "accelerate", "bitsandbytes"],
            "Install unsloth",
        )
        from unsloth import FastLanguageModel

    import torch
    from datasets import Dataset
    from trl import SFTTrainer
    from transformers import TrainingArguments

    print("\n  Loading base model with 4-bit quantization...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name  = "Qwen/Qwen2.5-Coder-3B-Instruct",
        max_seq_length = 2048,
        dtype       = None,   # auto-detect
        load_in_4bit = True,
    )

    model = FastLanguageModel.get_peft_model(
        model,
        r              = 16,
        target_modules = ["q_proj", "k_proj", "v_proj", "o_proj",
                          "gate_proj", "up_proj", "down_proj"],
        lora_alpha     = 32,
        lora_dropout   = 0.05,
        bias           = "none",
        use_gradient_checkpointing = True,
    )

    # Load data
    if not os.path.exists(FINETUNE_DATA):
        from dataset import build_finetune_jsonl
        build_finetune_jsonl(FINETUNE_DATA)

    records = []
    with open(FINETUNE_DATA) as f:
        for line in f:
            records.append(json.loads(line))

    def format_chat(record):
        msgs = record["messages"]
        return tokenizer.apply_chat_template(msgs, tokenize=False, add_generation_prompt=False)

    texts = [format_chat(r) for r in records]
    ds = Dataset.from_dict({"text": texts})

    trainer = SFTTrainer(
        model     = model,
        tokenizer = tokenizer,
        train_dataset = ds,
        dataset_text_field = "text",
        max_seq_length = 2048,
        args = TrainingArguments(
            output_dir             = "model/qlora_output",
            per_device_train_batch_size = 2,
            gradient_accumulation_steps = 4,
            num_train_epochs        = 3,
            learning_rate          = 2e-4,
            fp16                   = not torch.cuda.is_bf16_supported(),
            bf16                   = torch.cuda.is_bf16_supported(),
            logging_steps          = 5,
            save_steps             = 50,
            warmup_ratio           = 0.1,
            lr_scheduler_type      = "cosine",
            report_to              = "none",
        ),
    )

    print("\n  Starting QLoRA training...")
    trainer.train()

    # Export to GGUF
    gguf_dir = "model/qlora_gguf"
    os.makedirs(gguf_dir, exist_ok=True)
    print(f"\n  Exporting to GGUF → {gguf_dir}/")
    model.save_pretrained_gguf(gguf_dir, tokenizer, quantization_method="q4_k_m")

    # Write Modelfile pointing at GGUF
    gguf_files = [f for f in os.listdir(gguf_dir) if f.endswith(".gguf")]
    if gguf_files:
        gguf_path = os.path.join(gguf_dir, gguf_files[0])
        qlora_modelfile = "Modelfile.qlora"
        with open(qlora_modelfile, "w") as mf:
            mf.write(f"FROM {gguf_path}\n")
            mf.write(open(MODELFILE).read().replace(f"FROM {BASE_MODEL}\n", ""))
        _run(
            ["ollama", "create", f"{MODEL_NAME}-qlora", "-f", qlora_modelfile],
            f"Register {MODEL_NAME}-qlora with Ollama",
        )
        print(f"\n  ✅  QLoRA fine-tuned model registered as '{MODEL_NAME}-qlora'")
    else:
        print(f"  ✗  No GGUF file found in {gguf_dir}")


# ── Check mode ────────────────────────────────────────────────────────────────

def check():
    print(f"\n{'='*65}")
    print(f"  ZeroDayShield — Ollama Status Check")
    print(f"{'='*65}")

    ok = check_ollama()
    if not ok:
        return

    names = list_models()
    print(f"\n  Installed models ({len(names)}):")
    for n in names:
        tag = ""
        if MODEL_NAME in n:
            tag = "  ← fine-tuned SQLi model ✅"
        elif BASE_MODEL in n:
            tag = "  ← base model ✅"
        print(f"    {n}{tag}")

    if not any(MODEL_NAME in n for n in names):
        print(f"\n  ⚠  '{MODEL_NAME}' not found. Run: python finetune_ollama.py")
    else:
        print(f"\n  ✅  Ready. Run the pipeline: python pipeline.py")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZeroDayShield — Ollama fine-tune setup")
    parser.add_argument("--check",     action="store_true", help="Check Ollama status")
    parser.add_argument("--pull-base", action="store_true", help="Pull base model only")
    parser.add_argument("--qlora",     action="store_true", help="Path B: QLoRA fine-tune")
    args = parser.parse_args()

    if args.check:
        check()
    elif args.pull_base:
        if check_ollama():
            pull_base()
    elif args.qlora:
        if check_ollama():
            qlora_finetune()
    else:
        if check_ollama():
            create_from_modelfile()
