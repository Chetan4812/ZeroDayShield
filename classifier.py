"""
classifier.py
Unified SQLi classifier with two backends:
  1. Ollama (qwen2.5-coder-sqli) — primary, detailed classification
  2. Local CNN+GRU (PyTorch)     — fallback, binary only

Usage:
    from classifier import classify
    result = classify("db.execute(f\"SELECT * FROM users WHERE id = {uid}\")")
"""

from __future__ import annotations
import json
import re
import sys
from pathlib import Path
import torch
import torch.nn as nn

MODEL_DIR  = "model/sqli_classifier"
OLLAMA_MODEL = "qwen2.5-coder-sqli"
OLLAMA_FALLBACK = "qwen2.5-coder:3b"


# ── Local CNN+GRU model definition ────────────────────────────────────────────

def _load_config():
    with open(f"{MODEL_DIR}/config.json") as f:
        return json.load(f)


class SQLiClassifier(nn.Module):
    def __init__(self, vocab_size, embed_dim, hidden_dim, num_labels):
        super().__init__()
        self.embed = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.conv1 = nn.Conv1d(embed_dim,  hidden_dim, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(hidden_dim, hidden_dim, kernel_size=5, padding=2)
        self.gru   = nn.GRU(hidden_dim, hidden_dim, batch_first=True, bidirectional=True)
        self.drop  = nn.Dropout(0.3)
        self.head  = nn.Linear(hidden_dim * 2, num_labels)

    def forward(self, input_ids):
        x = self.embed(input_ids).permute(0, 2, 1)
        x = torch.relu(self.conv1(x))
        x = torch.relu(self.conv2(x))
        x = x.permute(0, 2, 1)
        _, h = self.gru(x)
        h = self.drop(torch.cat([h[0], h[1]], dim=-1))
        return self.head(h)


_local_model  = None
_local_config = None


def _load_local():
    global _local_model, _local_config
    if _local_model is not None:
        return True
    try:
        _local_config = _load_config()
        _local_model  = SQLiClassifier(
            vocab_size=_local_config["vocab_size"],
            embed_dim=_local_config["embed_dim"],
            hidden_dim=_local_config["hidden_dim"],
            num_labels=_local_config["num_labels"],
        )
        _local_model.load_state_dict(
            torch.load(f"{MODEL_DIR}/model.pt", weights_only=True)
        )
        _local_model.eval()
        return True
    except Exception:
        return False


def _char_tokenize(text: str, max_len: int) -> list[int]:
    ids = [min(max(ord(c) - 32, 0), _local_config["vocab_size"] - 1) for c in text[:max_len]]
    ids += [0] * (max_len - len(ids))
    return ids


def classify_local(code_snippet: str) -> dict:
    """
    Local CNN+GRU binary classifier.
    Returns: {label, confidence, raw_logits, source}
    """
    if not _load_local():
        raise RuntimeError("Local model not loaded. Run train.py first.")
    ids    = torch.tensor([_char_tokenize(code_snippet, _local_config["max_len"])], dtype=torch.long)
    with torch.no_grad():
        logits = _local_model(ids)
    probs  = torch.softmax(logits, dim=-1).squeeze().tolist()
    pred   = int(torch.argmax(logits, dim=-1).item())
    return {
        "label":      _local_config["id2label"][str(pred)],
        "confidence": round(probs[pred], 4),
        "raw_logits": [round(x, 4) for x in logits.squeeze().tolist()],
        "source":     "local_cnn_gru",
    }


# ── Ollama classifier ─────────────────────────────────────────────────────────

_SYSTEM = (
    "You are a SQL injection detector. Given a code snippet or SQL query string, "
    "respond ONLY with a JSON object: "
    "{\"label\": \"sql_injection\" or \"safe\", \"confidence\": float 0-1, "
    "\"attack_variant\": str or null, \"reason\": str}"
)


def _available_ollama_model() -> str | None:
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
        if any(OLLAMA_MODEL in n for n in names):
            return OLLAMA_MODEL
        if any(OLLAMA_FALLBACK.split(":")[0] in n for n in names):
            return OLLAMA_FALLBACK
    except Exception:
        pass
    return None


def classify_ollama(code_snippet: str) -> dict | None:
    """
    Ollama-based classifier using qwen2.5-coder-sqli.
    Returns rich dict or None if Ollama is unreachable.
    """
    try:
        import ollama
    except ImportError:
        return None

    model = _available_ollama_model()
    if model is None:
        return None

    try:
        client = ollama.Client()
        resp = client.chat(
            model    = model,
            messages = [
                {"role": "system", "content": _SYSTEM},
                {"role": "user",   "content": f"Classify this snippet:\n\n{code_snippet}"},
            ],
            options  = {"temperature": 0.05, "num_predict": 256},
        )
        raw = resp["message"]["content"] if isinstance(resp, dict) else resp.message.content
        m   = re.search(r'\{.*\}', raw, re.DOTALL)
        parsed = json.loads(m.group(0) if m else raw)
        parsed["source"] = f"ollama:{model}"
        return parsed
    except Exception:
        return None


# ── Unified entry point ───────────────────────────────────────────────────────

def classify(code_snippet: str, prefer_ollama: bool = True) -> dict:
    """
    Unified classifier.
    1. Try Ollama (qwen2.5-coder-sqli) if prefer_ollama=True
    2. Fall back to local CNN+GRU
    Returns a dict with at minimum: {label, confidence, source}
    """
    if prefer_ollama:
        result = classify_ollama(code_snippet)
        if result is not None:
            # Normalise label key
            if "label" not in result and "is_sqli" in result:
                result["label"] = "sql_injection" if result["is_sqli"] else "safe"
            return result

    # Fallback
    try:
        return classify_local(code_snippet)
    except RuntimeError:
        # Local model not trained yet — return a default
        return {
            "label": "unknown",
            "confidence": 0.0,
            "source": "none",
            "error": "No classifier available. Run finetune_ollama.py or train.py.",
        }


if __name__ == "__main__":
    samples = [
        'cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))',
        'db.execute(f"SELECT * FROM users WHERE name = \'{username}\'")',
        "query = \"SELECT * FROM users WHERE user = '\" + username + \"'\"",
        'cursor.execute("SELECT * FROM orders WHERE status = %s" % status)',
        'db.execute("SELECT * FROM items WHERE id = {}".format(item_id))',
    ]
    print(f"\n{'='*70}")
    print(f"  Classifier test ({5} samples)")
    print(f"{'='*70}")
    for s in samples:
        r = classify(s)
        src  = r.get("source", "?")
        lbl  = r.get("label", "?")
        conf = r.get("confidence", 0.0)
        print(f"  [{lbl:15s}] {conf:.0%} ({src:25s})  {s[:60]}")
