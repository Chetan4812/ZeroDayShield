"""
model/train.py
Fine-tunes GPT-2 as a sequence classifier for SQL injection detection.

Usage:
    python model/train.py

Outputs:
    model/sqli_classifier/   — saved model + tokenizer
"""

import json
import os
import re
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.metrics import classification_report, f1_score


# ── Config ────────────────────────────────────────────────────────────────────
TRAIN_FILE   = "data/sqli_dataset_train.jsonl"
VAL_FILE     = "data/sqli_dataset_val.jsonl"
OUTPUT_DIR   = "model/sqli_classifier"
MAX_LEN      = 64
NUM_LABELS   = 2
EPOCHS       = 10
BATCH_SIZE   = 8
LR           = 1e-3
SEED         = 42
VOCAB_SIZE   = 512   # character-level vocab (ASCII printable)
EMBED_DIM    = 64
HIDDEN_DIM   = 128

LABEL2ID = {"safe": 0, "sql_injection": 1}
ID2LABEL = {0: "safe", 1: "sql_injection"}


# ── Dataset ───────────────────────────────────────────────────────────────────
def char_tokenize(text: str, max_len: int) -> list[int]:
    """Character-level tokenizer using ASCII ordinals (32-127 → 0-95)."""
    ids = [min(max(ord(c) - 32, 0), VOCAB_SIZE - 1) for c in text[:max_len]]
    ids += [0] * (max_len - len(ids))
    return ids


# ── Dataset ───────────────────────────────────────────────────────────────────
class SQLiDataset(Dataset):
    def __init__(self, path: str, max_len: int):
        self.samples = []
        with open(path) as f:
            for line in f:
                item = json.loads(line)
                ids = char_tokenize(item["text"], max_len)
                self.samples.append({
                    "input_ids": torch.tensor(ids, dtype=torch.long),
                    "label":     torch.tensor(item["label"], dtype=torch.long),
                })

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        return self.samples[idx]


# ── Model: char-level CNN + GRU classifier (GPT-2 inspired architecture) ─────
class SQLiClassifier(nn.Module):
    """
    Lightweight character-level sequence classifier.
    Mirrors GPT-2's philosophy (embedding → context → classification head)
    without requiring a pretrained download.
    """
    def __init__(self):
        super().__init__()
        self.embed = nn.Embedding(VOCAB_SIZE, EMBED_DIM, padding_idx=0)
        # 1D convolutions to capture n-gram patterns (like SQL keywords)
        self.conv1 = nn.Conv1d(EMBED_DIM, HIDDEN_DIM, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(HIDDEN_DIM, HIDDEN_DIM, kernel_size=5, padding=2)
        self.gru   = nn.GRU(HIDDEN_DIM, HIDDEN_DIM, batch_first=True, bidirectional=True)
        self.drop  = nn.Dropout(0.3)
        self.head  = nn.Linear(HIDDEN_DIM * 2, NUM_LABELS)

    def forward(self, input_ids):
        x = self.embed(input_ids)           # (B, L, E)
        x = x.permute(0, 2, 1)             # (B, E, L) for Conv1d
        x = torch.relu(self.conv1(x))
        x = torch.relu(self.conv2(x))
        x = x.permute(0, 2, 1)             # (B, L, H)
        _, h = self.gru(x)                  # h: (2, B, H)
        h = torch.cat([h[0], h[1]], dim=-1) # (B, 2H)
        h = self.drop(h)
        return self.head(h)                 # (B, num_labels)


# ── Main ──────────────────────────────────────────────────────────────────────
def train():
    torch.manual_seed(SEED)

    train_ds = SQLiDataset(TRAIN_FILE, MAX_LEN)
    val_ds   = SQLiDataset(VAL_FILE,   MAX_LEN)
    print(f"Train: {len(train_ds)} samples | Val: {len(val_ds)} samples")

    train_dl = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
    val_dl   = DataLoader(val_ds,   batch_size=BATCH_SIZE)

    model    = SQLiClassifier()
    optimizer = torch.optim.AdamW(model.parameters(), lr=LR)
    criterion = nn.CrossEntropyLoss()

    best_f1 = 0.0
    for epoch in range(1, EPOCHS + 1):
        model.train()
        total_loss = 0.0
        for batch in train_dl:
            optimizer.zero_grad()
            logits = model(batch["input_ids"])
            loss   = criterion(logits, batch["label"])
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        # Validation
        model.eval()
        all_preds, all_labels = [], []
        with torch.no_grad():
            for batch in val_dl:
                logits = model(batch["input_ids"])
                preds  = torch.argmax(logits, dim=-1)
                all_preds.extend(preds.tolist())
                all_labels.extend(batch["label"].tolist())

        f1  = f1_score(all_labels, all_preds, average="weighted", zero_division=0)
        acc = sum(p == l for p, l in zip(all_preds, all_labels)) / len(all_labels)
        print(f"Epoch {epoch:2d}/{EPOCHS} | loss={total_loss/len(train_dl):.4f} "
              f"| val_f1={f1:.4f} | val_acc={acc:.4f}")

        if f1 >= best_f1:
            best_f1 = f1
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            torch.save(model.state_dict(), f"{OUTPUT_DIR}/model.pt")

    # Save config + tokenizer info alongside the weights
    config = {
        "vocab_size": VOCAB_SIZE, "embed_dim": EMBED_DIM,
        "hidden_dim": HIDDEN_DIM, "max_len": MAX_LEN,
        "num_labels": NUM_LABELS, "id2label": ID2LABEL,
        "label2id": LABEL2ID,
    }
    with open(f"{OUTPUT_DIR}/config.json", "w") as f:
        json.dump(config, f, indent=2)
    print(f"\nBest val F1: {best_f1:.4f} — model saved to {OUTPUT_DIR}/")

    # Final classification report on val set
    model.load_state_dict(torch.load(f"{OUTPUT_DIR}/model.pt", weights_only=True))
    model.eval()
    all_preds, all_labels = [], []
    with torch.no_grad():
        for batch in val_dl:
            logits = model(batch["input_ids"])
            all_preds.extend(torch.argmax(logits, dim=-1).tolist())
            all_labels.extend(batch["label"].tolist())
    print("\n── Evaluation report ──")
    print(classification_report(all_labels, all_preds,
                                 target_names=list(LABEL2ID.keys())))


if __name__ == "__main__":
    train()
