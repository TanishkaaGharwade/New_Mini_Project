"""
classifier.py — ML Inference for CyberSentinel
============================================
Loads the pretrained Random Forest + preprocessor from Repo 1 (21Sandesh/CyberSentinel).

Key finding from diagnostic test:
  - Model labels end with a dot: "neptune.", "normal.", "nmap." etc.
  - Model has 20 attack classes including "nmap." specifically
  - Works reliably with flow-level feature vectors (20+ packets aggregated)
"""

import joblib
import numpy as np
import pandas as pd
import warnings
import os

from config import MODEL_PATH, PREPROCESSOR_PATH, NORMAL_LABELS

# Suppress sklearn version mismatch warnings (model was trained on 1.4.1)
warnings.filterwarnings("ignore", category=UserWarning)

# NSL-KDD column names — must match preprocessor's expected input exactly
FEATURE_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes',
    'count', 'srv_count',
    'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
]


class ThreatClassifier:
    """
    Wraps the pretrained Random Forest model + preprocessor pipeline.
    Thread-safe for concurrent calls (model.predict is read-only).
    """

    def __init__(self):
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model not found: {MODEL_PATH}")
        if not os.path.exists(PREPROCESSOR_PATH):
            raise FileNotFoundError(f"Preprocessor not found: {PREPROCESSOR_PATH}")

        self.preprocessor = joblib.load(PREPROCESSOR_PATH)
        self.model        = joblib.load(MODEL_PATH)

        print(f"[+] Model loaded: {type(self.model).__name__}")
        if hasattr(self.model, "classes_"):
            print(f"[+] Known classes: {list(self.model.classes_)}")

    def predict(self, feature_vector: list) -> tuple[str, bool]:
        """
        Run ML inference on a 21-dimensional feature vector.
        
        Returns:
            (label: str, is_attack: bool)
            label    — raw model output e.g. "neptune.", "normal.", "nmap."
            is_attack— True if label is NOT in NORMAL_LABELS
        """
        if len(feature_vector) != 21:
            raise ValueError(f"Expected 21 features, got {len(feature_vector)}")

        df = pd.DataFrame([feature_vector], columns=FEATURE_COLUMNS)

        try:
            X_scaled = self.preprocessor.transform(df)
        except Exception as e:
            raise RuntimeError(f"Preprocessor failed: {e}")

        # Suppress feature-name warning from sklearn version mismatch
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            label = str(self.model.predict(X_scaled)[0])

        is_attack = label.strip().lower() not in NORMAL_LABELS
        return label, is_attack

    def predict_flow(self, feature_vectors: list[list]) -> tuple[str, bool]:
        """
        Run inference on multiple feature vectors from the same flow.
        Returns the most common non-normal prediction (majority vote).
        If all are normal, returns ("normal.", False).
        """
        if not feature_vectors:
            return "normal.", False

        results = []
        for vec in feature_vectors:
            try:
                label, is_attack = self.predict(vec)
                results.append((label, is_attack))
            except Exception:
                continue

        if not results:
            return "normal.", False

        # Majority vote — if ANY packet in the flow is an attack, flag it
        attack_results = [(lbl, atk) for lbl, atk in results if atk]
        if attack_results:
            # Return most common attack label
            from collections import Counter
            labels = [lbl for lbl, _ in attack_results]
            most_common = Counter(labels).most_common(1)[0][0]
            return most_common, True

        return "normal.", False
