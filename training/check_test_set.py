"""
check_test_set.py — re-score model_v1 on its held-out test set
=============================================================
    python training/check_test_set.py

Rebuilds the exact 184,679-flow test set of train_cicids2017.ipynb (same cleaning,
same Benign sample, same stratified 80/20 split, seed 42) and scores the saved model
on it, without retraining. Then shows what the engine's 0.70 alert threshold
(ALERT_CONFIDENCE) does to those results. Needs the CICIDS2017 CSVs in
training/data/MachineLearningCVE/ (MachineLearningCSV.zip from
https://www.unb.ca/cic/datasets/ids-2017.html). Takes about a minute.
"""

import glob
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

VERSION = sys.argv[1] if len(sys.argv) > 1 else "v1"
SEED = 42
BENIGN_SAMPLE = 500_000
TEST_SIZE = 0.20
ALERT_CONFIDENCE = 0.70

TRAIN_DIR = Path(__file__).resolve().parent
MODEL_PATH = TRAIN_DIR.parent / "python-engine" / "models" / f"model_{VERSION}.pkl"
DATA_DIR = TRAIN_DIR / "data" / "MachineLearningCVE"

# Must match train_cicids2017.ipynb (cell "candidate columns and class map")
CORE = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Fwd Packet Length Max", "Fwd Packet Length Mean",
        "Bwd Packet Length Max", "Bwd Packet Length Mean",
        "Packet Length Mean", "Packet Length Std",
        "Flow Bytes/s", "Flow Packets/s",
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
        "Fwd IAT Mean", "Bwd IAT Mean", "Down/Up Ratio"]
FLAGS = ["SYN Flag Count", "FIN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count"]
WIN = ["Init_Win_bytes_forward", "Init_Win_bytes_backward"]
PORT = ["Destination Port"]
ALL_CANDIDATES = CORE + FLAGS + WIN + PORT
CLASS_MAP = {
    "BENIGN": "Benign",
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS", "DoS slowloris": "DoS", "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
    "Bot": "Botnet",
}

files = sorted(glob.glob(str(DATA_DIR / "*.csv")))
if len(files) != 8:
    sys.exit(f"Expected 8 CSV files in {DATA_DIR}, found {len(files)}. "
             "Download MachineLearningCSV.zip from https://www.unb.ca/cic/datasets/ids-2017.html.")

# ── Same cleaning as the notebook ─────────────────────────────────────────────
parts = []
for f in files:
    d = pd.read_csv(f, encoding="latin-1", usecols=lambda c: c.strip() in ALL_CANDIDATES + ["Label"])
    d.columns = [c.strip() for c in d.columns]
    parts.append(d)
df = pd.concat(parts, ignore_index=True)
raw_rows = len(df)
df["label"] = df["Label"].map(CLASS_MAP)
df = df[df["label"].notna()].drop(columns="Label")
df[ALL_CANDIDATES] = df[ALL_CANDIDATES].replace([np.inf, -np.inf], np.nan)
df = df.dropna(subset=ALL_CANDIDATES)
df = df[df["Flow Duration"] >= 0]
df = df.drop_duplicates()

# ── Same Benign sample and split ──────────────────────────────────────────────
benign = df[df["label"] == "Benign"].sample(n=BENIGN_SAMPLE, random_state=SEED)
data = pd.concat([benign, df[df["label"] != "Benign"]], ignore_index=True)
train, test = train_test_split(data, test_size=TEST_SIZE, stratify=data["label"], random_state=SEED)

model = joblib.load(MODEL_PATH)
features = list(model.feature_names_in_)
print(f"{raw_rows:,} raw flows -> {len(df):,} after cleaning -> {len(train):,} train, {len(test):,} test")
print(f"Scoring {MODEL_PATH.name} (not retrained)\n")

# ── 1. The results reported in the notebook ───────────────────────────────────
proba = model.predict_proba(test[features])
top = model.classes_[proba.argmax(axis=1)]
conf = proba.max(axis=1)
y = test["label"].to_numpy()
print(classification_report(y, top, digits=4))

# ── 2. Effect of the engine's alert threshold ─────────────────────────────────
attack = y != "Benign"
print(f"Effect of ignoring model verdicts under {ALERT_CONFIDENCE:.0%} confidence (test set):")
print(f"{'':28s}{'all verdicts':>14s}{f'>= {ALERT_CONFIDENCE:.2f}':>14s}")
reported = {t: (top != "Benign") & (conf >= t) for t in (0.0, ALERT_CONFIDENCE)}
rows = [("attack flows reported", attack)]
rows += [(f"  {c}", y == c) for c in sorted(set(y)) if c != "Benign"]
for name, mask in rows:
    print(f"{name:28s}" + "".join(f"{reported[t][mask].mean():>14.2%}" for t in reported))
benign_mask = ~attack
print(f"{'benign flows flagged':28s}" + "".join(
    f"{reported[t][benign_mask].mean():>14.3%}" for t in reported))
