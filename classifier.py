"""
model/classifier.py
Loads the locally trained SQLi classifier and exposes classify().
"""
from __future__ import annotations
import json, sys
from pathlib import Path
import torch
import torch.nn as nn

MODEL_DIR = "model/sqli_classifier"

# ── Load config ───────────────────────────────────────────────────────────────
def _load_config():
    with open(f"{MODEL_DIR}/config.json") as f:
        return json.load(f)

# ── Model definition (must match train.py) ────────────────────────────────────
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


_model  = None
_config = None

def _load():
    global _model, _config
    if _model is not None:
        return
    _config = _load_config()
    _model  = SQLiClassifier(
        vocab_size=_config["vocab_size"],
        embed_dim=_config["embed_dim"],
        hidden_dim=_config["hidden_dim"],
        num_labels=_config["num_labels"],
    )
    _model.load_state_dict(torch.load(f"{MODEL_DIR}/model.pt", weights_only=True))
    _model.eval()


def _char_tokenize(text: str, max_len: int) -> list[int]:
    ids = [min(max(ord(c) - 32, 0), _config["vocab_size"] - 1) for c in text[:max_len]]
    ids += [0] * (max_len - len(ids))
    return ids


def classify(code_snippet: str) -> dict:
    """
    Returns:
        {"label": "sql_injection"|"safe", "confidence": float, "raw_logits": [...]}
    """
    _load()
    ids    = torch.tensor([_char_tokenize(code_snippet, _config["max_len"])], dtype=torch.long)
    with torch.no_grad():
        logits = _model(ids)
    probs  = torch.softmax(logits, dim=-1).squeeze().tolist()
    pred   = int(torch.argmax(logits, dim=-1).item())
    return {
        "label":      _config["id2label"][str(pred)],
        "confidence": round(probs[pred], 4),
        "raw_logits": [round(x, 4) for x in logits.squeeze().tolist()],
    }


if __name__ == "__main__":
    samples = [
        'cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))',
        'db.execute(f"SELECT * FROM users WHERE name = \'{username}\'")',
        "query = \"SELECT * FROM users WHERE user = '\" + username + \"'\"",
        'cursor.execute("SELECT * FROM orders WHERE status = %s" % status)',
        'db.execute("SELECT * FROM items WHERE id = {}".format(item_id))',
    ]
    for s in samples:
        r = classify(s)
        print(f"{r['label']:15s} ({r['confidence']:.0%})  {s[:70]}")

