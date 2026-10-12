"""
classifier.py — ML Inference for CyberSentinel
============================================
Loads the active CICIDS2017 model (models/model_<ACTIVE_MODEL>.pkl), a scikit-learn
Pipeline of a median imputer and a Random Forest. One closed flow gives one prediction.
"""

import json
import logging
import math
import os

import joblib
import pandas as pd

from config import MODEL_PATH, FEATURES_PATH, ACTIVE_MODEL, BENIGN_LABEL

logger = logging.getLogger("cybersentinel.classifier")

# 99th percentile of each feature over 2.27 million benign CICIDS2017 flows
# (PART_A_DETECTION_ENGINE.md section 4.3). Used to explain detections.
BENIGN_P99 = {
    "Flow Duration":               118_007_000,
    "Total Fwd Packets":           55,
    "Total Backward Packets":      68,
    "Total Length of Fwd Packets": 11_607,
    "Total Length of Bwd Packets": 90_111,
    "Fwd Packet Length Max":       4_333,
    "Fwd Packet Length Mean":      1_375,
    "Bwd Packet Length Max":       4_290,
    "Bwd Packet Length Mean":      1_500,
    "Packet Length Mean":          983,
    "Packet Length Std":           1_228,
    "Flow Bytes/s":                16_250_000,
    "Flow Packets/s":              1_000_000,
    "Flow IAT Mean":               22_000_000,
    "Flow IAT Std":                34_300_000,
    "Flow IAT Max":                78_600_000,
    "Fwd IAT Mean":                63_000_000,
    "Bwd IAT Mean":                58_800_000,
    "Down/Up Ratio":               3,
}


class ThreatClassifier:
    """
    Wraps the trained pipeline. Feature vectors are lists of 19 numbers in
    features.json order; NaN is allowed (the pipeline's imputer handles it).
    """

    def __init__(self, model_path: str = MODEL_PATH, features_path: str = FEATURES_PATH):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        if not os.path.exists(features_path):
            raise FileNotFoundError(f"Feature list not found: {features_path}")

        with open(features_path, encoding="utf-8") as f:
            spec = json.load(f)
        self.features = list(spec["features"])
        if spec.get("model_version") not in (None, ACTIVE_MODEL):
            logger.warning(f"[MODEL] features.json is for model {spec['model_version']}, "
                           f"active model is {ACTIVE_MODEL}")

        self.model = joblib.load(model_path)
        if list(self.model.feature_names_in_) != self.features:
            raise ValueError(
                f"{os.path.basename(model_path)} expects features {list(self.model.feature_names_in_)}, "
                f"but features.json lists {self.features}"
            )
        missing = set(self.features) - set(BENIGN_P99)
        if missing:
            raise ValueError(f"No benign reference percentile for: {sorted(missing)}")

        # Single-flow predictions are ~7x faster without the thread pool. In memory only;
        # predictions are identical and the model file is never written.
        if "forest" in self.model.named_steps:
            self.model.set_params(forest__n_jobs=1)

        self.classes = [str(c) for c in self.model.classes_]
        logger.info(f"[MODEL] Loaded {os.path.basename(model_path)}: classes {self.classes}")

    @staticmethod
    def is_attack(label: str) -> bool:
        return label != BENIGN_LABEL

    def classify(self, vector: list) -> tuple[str, float]:
        """One flow's feature vector → (label, confidence)."""
        return self.classify_many([vector])[0]

    def classify_many(self, vectors: list) -> list:
        """Several feature vectors in one model call → [(label, confidence), ...]."""
        if not vectors:
            return []
        for v in vectors:
            if len(v) != len(self.features):
                raise ValueError(f"Expected {len(self.features)} features, got {len(v)}")
        rows = pd.DataFrame(vectors, columns=self.features, dtype=float)
        proba = self.model.predict_proba(rows)
        best = proba.argmax(axis=1)
        return [(self.classes[i], float(p[i])) for i, p in zip(best, proba)]

    def evidence(self, vector: list, top: int = 3) -> list:
        """
        The features furthest above their benign 99th percentile (at most `top`),
        as [{"feature": name, "value": value}]. Distance is value ÷ percentile.
        Features at or below their percentile are never listed.
        """
        above = []
        for name, value in zip(self.features, vector):
            if value is None or math.isnan(value):
                continue
            ratio = value / BENIGN_P99[name]
            if ratio > 1:
                above.append((ratio, name, value))
        above.sort(reverse=True)
        return [{"feature": name, "value": _tidy(value)} for _, name, value in above[:top]]


def _tidy(value: float):
    """Rounded to 2 decimals, and whole numbers as int, for readable JSON."""
    value = round(float(value), 2)
    return int(value) if value.is_integer() else value
