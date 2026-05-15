# ZeroDayShield 🛡️

**Zero-Day Threat Patching Agent — Classification Prototype (CWE-89 SQL Injection)**

A local, air-gapped pipeline that automatically detects and classifies SQL injection attacks using a fine-tuned Ollama LLM (`qwen2.5-coder:3b`) with a CNN+GRU neural network as fallback. Built for RTX 3060 / 16 GB RAM hardware.

---

## Architecture Overview

```
[Vulnerable Flask App] ──► [request_log.jsonl]
                                    │
                            [Sentinel Agent]       ← 8 regex patterns
                                    │
                             [alerts/*.json]
                                    │
                          [Forensic Agent]          ← Ollama qwen2.5-coder-sqli
                                    │
                           [reports/*.json/.md]
```

**Stage scope:** Detection + Classification only (patching is the next stage).

---

## Quick Start

### 1. Create venv and install dependencies
```powershell
python -m venv venv
venv\Scripts\pip install flask requests torch scikit-learn numpy ollama
```

### 2. Set up the Ollama model
```powershell
# Pull base model (if not already present)
ollama pull qwen2.5-coder:3b

# Create the fine-tuned SQLi model from Modelfile
venv\Scripts\python finetune_ollama.py
```

### 3. Train the fallback CNN+GRU classifier
```powershell
venv\Scripts\python dataset.py
venv\Scripts\python train.py
```

### 4. Run end-to-end (three terminals)
```powershell
# Terminal 1 — start vulnerable target
venv\Scripts\python setup_db.py
venv\Scripts\python app.py

# Terminal 2 — start sentinel monitor
venv\Scripts\python sentinel.py

# Terminal 3 — fire attack then classify
venv\Scripts\python attack.py
venv\Scripts\python forensic_agent.py --all
```

### OR: One-command run (after model is trained)
```powershell
venv\Scripts\python run_pipeline.py --skip-all-train
```

---

## File Reference

| File | Role |
|------|------|
| `app.py` | Deliberately vulnerable Flask app (5 SQLi patterns, logs all requests) |
| `setup_db.py` | Initialises `users.db` with seed users/orders/logs tables |
| `attack.py` | Fires 7 HTTP requests: 2 clean + 5 SQLi (comment, OR, UNION, blind, stacked) |
| `sentinel.py` | Stage 1 detection: 8 regex patterns, writes alerts to `alerts/` |
| `forensic_agent.py` | Stage 2 classification: Ollama LLM → structured CWE-89 JSON report |
| `classifier.py` | Unified classifier: Ollama primary, CNN+GRU fallback |
| `dataset.py` | Builds 65-sample train/val JSONL + Ollama finetune JSONL |
| `train.py` | Trains the character-level CNN+GRU classifier (F1=0.84) |
| `Modelfile` | Ollama Modelfile for `qwen2.5-coder-sqli` (system prompt baked in) |
| `finetune_ollama.py` | Creates Ollama model (Path A) or QLoRA fine-tune (Path B `--qlora`) |
| `pipeline.py` | Full orchestrator: DB → Flask → sentinel → attack → forensic → summary |
| `run_pipeline.py` | One-command entry point |

---

## Output

- `alerts/ALERT-*.json` — Sentinel detection alerts
- `reports/forensic_*.json` — Full CWE-89 classification (Ollama)
- `reports/forensic_*.md` — Human-readable Markdown reports
- `model/sqli_classifier/` — Trained CNN+GRU weights + config

---

## Hardware Tested

- CPU: Ryzen 7 7840HS
- GPU: RTX 3060 6GB
- RAM: 16 GB
- Model: `qwen2.5-coder:3b` Q4 (~2 GB VRAM)

---

## Fine-tuning Details

**Path A (default)** — Ollama Modelfile customisation:
- Bakes a security-forensics system prompt into `qwen2.5-coder:3b`
- Zero GPU training required, ready in ~30 seconds

**Path B (advanced)** — QLoRA gradient fine-tune:
```powershell
venv\Scripts\python finetune_ollama.py --qlora
```
- Uses `unsloth` + `trl`, ~4 GB VRAM, ~20 min
- Exports GGUF, registers as `qwen2.5-coder-sqli-qlora`

---

## Next Stage

The patch agent (`patch_agent.py`) consumes the `patch_handoff` field from forensic reports to generate parameterised SQL fixes. Run:
```powershell
venv\Scripts\python patch_agent.py --target . --report reports/
```
