"""
verify_model.py — independent checks on a trained model
======================================================
Run from the repo root or from training/:

    python training/verify_model.py            # checks model_v1
    python training/verify_model.py v2         # checks model_v2

Checks:
  1. The model file loads, and its features and classes match features.json.
  2. False-alarm rate on every benign flow the model did NOT see in training or testing.
  3. Recall on the attack labels that were excluded from training (expected to be poor).

Uses the same cleaning steps and seed as train_cicids2017.ipynb.
"""

import glob
import hashlib
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn

VERSION = sys.argv[1] if len(sys.argv) > 1 else "v1"
SEED = 42
BENIGN_SAMPLE = 500_000

TRAIN_DIR = Path(__file__).resolve().parent
MODEL_PATH = TRAIN_DIR.parent / "python-engine" / "models" / f"model_{VERSION}.pkl"
DATA_DIR = TRAIN_DIR / "data" / "MachineLearningCVE"

# Must match the candidate columns used for de-duplication in the notebook
FLAGS = ["SYN Flag Count", "FIN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count"]
WIN = ["Init_Win_bytes_forward", "Init_Win_bytes_backward"]
PORT = ["Destination Port"]
KEPT = {"BENIGN", "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest",
        "DDoS", "PortScan", "FTP-Patator", "SSH-Patator", "Bot"}

# ── 1. Load check ─────────────────────────────────────────────────────────────
spec = json.loads((TRAIN_DIR / "features.json").read_text(encoding="utf-8"))
model = joblib.load(MODEL_PATH)
features = list(model.feature_names_in_)
sha = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
print(f"[1] loaded {MODEL_PATH.name} with scikit-learn {sklearn.__version__}, joblib {joblib.__version__}, numpy {np.__version__}")
print(f"    sha256 {sha}")
print(f"    features match features.json: {features == spec['features']}")
print(f"    classes match features.json:  {list(model.classes_) == spec['classes']}")

# ── Rebuild the cleaned table exactly as the notebook does ────────────────────
all_candidates = features + FLAGS + WIN + PORT
parts = []
for f in sorted(glob.glob(str(DATA_DIR / "*.csv"))):
    d = pd.read_csv(f, encoding="latin-1", usecols=lambda c: c.strip() in all_candidates + ["Label"])
    d.columns = [c.strip() for c in d.columns]
    parts.append(d)
raw = pd.concat(parts, ignore_index=True)
raw[all_candidates] = raw[all_candidates].replace([np.inf, -np.inf], np.nan)
raw = raw.dropna(subset=all_candidates)
raw = raw[raw["Flow Duration"] >= 0]

# ── 2. Benign flows never used for training or testing ────────────────────────
kept = raw[raw["Label"].isin(KEPT)].drop_duplicates()
benign = kept[kept["Label"] == "BENIGN"]
used = benign.sample(n=BENIGN_SAMPLE, random_state=SEED).index
unseen = benign.drop(index=used)

proba = model.predict_proba(unseen[features])
top = model.classes_[proba.argmax(axis=1)]
conf = proba.max(axis=1)
flagged = top != "Benign"
print(f"\n[2] unseen benign flows: {len(unseen):,}")
print(f"    flagged as any attack: {flagged.sum():,} ({flagged.mean():.3%})")
for c in model.classes_:
    if c != "Benign":
        print(f"      as {c:<11s} {(top == c).sum():,}")
for t in (0.70, 0.90, 0.95, 0.99):
    b = flagged & (conf >= t)
    print(f"    would be auto-blocked at confidence >= {t:.2f}: {b.sum():,} ({b.mean():.3%})")

# ── 3. Attack labels the model was never trained on ───────────────────────────
print("\n[3] attack labels excluded from training (the model has no class for these)")
excluded = raw[~raw["Label"].isin(KEPT)]
for label, grp in excluded.groupby("Label"):
    p = model.predict(grp[features])
    name = "".join(ch if 32 <= ord(ch) < 127 else "-" for ch in label)
    counts = pd.Series(p).value_counts().to_dict()
    print(f"    {name:<28s} {len(grp):>5,} flows | flagged as some attack: {(p != 'Benign').mean():.1%} | {counts}")
