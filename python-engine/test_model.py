"""
NetSentinel — Model Diagnostic Test
====================================
Run this BEFORE building anything else.
It tests whether best_model.pkl correctly classifies
attack-like feature vectors without needing live Nmap traffic.

Usage (run from repo root):
    python python/test_model.py

Takes ~5 seconds. No network needed. No admin needed.
"""

import joblib
import numpy as np
import pandas as pd
import os

MODEL_PATH       = './python/models/best_model.pkl'
PREPROC_PATH     = './python/models/preprocessor.pkl'

FEATURE_COLS = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes',
    'count', 'srv_count',
    'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate'
]

# ─────────────────────────────────────────────────────────────────
# Test Vectors
# Each row is one "connection" as NSL-KDD would describe it.
# We manually construct what Nmap / SYN flood / normal traffic
# would look like if perfectly extracted.
# ─────────────────────────────────────────────────────────────────
test_cases = [
    {
        "name": "[PASS?] NORMAL -- Plain HTTP browsing (you open Google)",
        "expected": "normal",
        "features": {
            'duration': 5, 'protocol_type': 'tcp', 'service': 'http',
            'flag': 'SF',                   # SF = connection completed normally
            'src_bytes': 1200, 'dst_bytes': 8000,
            'count': 2, 'srv_count': 2,
            'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
            'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
            'dst_host_count': 5, 'dst_host_srv_count': 5,
            'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.2, 'dst_host_srv_diff_host_rate': 0.0
        }
    },
    {
        "name": "[ATTACK] NMAP SYN SCAN -- Sent SYN, no response (S0 flag)",
        "expected": "portsweep or neptune",
        "features": {
            'duration': 0, 'protocol_type': 'tcp', 'service': 'private',
            'flag': 'S0',                   # S0 = SYN sent but no reply → classic Nmap
            'src_bytes': 0, 'dst_bytes': 0, # no data exchanged
            'count': 511, 'srv_count': 1,   # 511 connections to same host (port scan)
            'serror_rate': 1.0, 'srv_serror_rate': 1.0,  # all are SYN errors
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
            'same_srv_rate': 0.0, 'diff_srv_rate': 1.0, 'srv_diff_host_rate': 0.0,
            'dst_host_count': 255, 'dst_host_srv_count': 1,
            'dst_host_same_srv_rate': 0.0, 'dst_host_diff_srv_rate': 1.0,
            'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0
        }
    },
    {
        "name": "[ATTACK] SYN FLOOD (Neptune DoS) -- Hundreds of SYNs to port 80",
        "expected": "neptune",
        "features": {
            'duration': 0, 'protocol_type': 'tcp', 'service': 'http',
            'flag': 'S0',
            'src_bytes': 0, 'dst_bytes': 0,
            'count': 511, 'srv_count': 511, # all to same service (port 80)
            'serror_rate': 1.0, 'srv_serror_rate': 1.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
            'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
            'dst_host_count': 255, 'dst_host_srv_count': 255,
            'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 1.0
        }
    },
    {
        "name": "[ATTACK] PORT SWEEP -- One attacker scanning many hosts",
        "expected": "portsweep",
        "features": {
            'duration': 0, 'protocol_type': 'tcp', 'service': 'private',
            'flag': 'REJ',
            'src_bytes': 0, 'dst_bytes': 0,
            'count': 1, 'srv_count': 511,
            'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 1.0, 'srv_rerror_rate': 1.0,
            'same_srv_rate': 0.5, 'diff_srv_rate': 0.5, 'srv_diff_host_rate': 1.0,
            'dst_host_count': 255, 'dst_host_srv_count': 1,
            'dst_host_same_srv_rate': 0.0, 'dst_host_diff_srv_rate': 1.0,
            'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.95
        }
    },
    {
        "name": "[ATTACK] REALISTIC Nmap -- What you'll actually see in your demo",
        "expected": "attack (anything except normal)",
        "features": {
            # This is what your feature extractor will actually produce
            # when it sees partial/incomplete packets from Nmap:
            'duration': 0, 'protocol_type': 'tcp', 'service': 'http',
            'flag': 'S0',
            'src_bytes': 44, 'dst_bytes': 0,   # just the SYN packet size
            'count': 25, 'srv_count': 1,
            'serror_rate': 1.0, 'srv_serror_rate': 1.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
            'same_srv_rate': 0.04, 'diff_srv_rate': 0.96, 'srv_diff_host_rate': 0.0,
            'dst_host_count': 25, 'dst_host_srv_count': 1,
            'dst_host_same_srv_rate': 0.04, 'dst_host_diff_srv_rate': 0.96,
            'dst_host_same_src_port_rate': 0.04, 'dst_host_srv_diff_host_rate': 0.0
        }
    },
]

# ─────────────────────────────────────────────────────────────────
# Run Tests
# ─────────────────────────────────────────────────────────────────
def run_tests():
    print("\n" + "="*65)
    print("  NetSentinel — Model Diagnostic Test")
    print("="*65)

    # Check files exist
    for path in [MODEL_PATH, PREPROC_PATH]:
        if not os.path.exists(path):
            print(f"\n[ERROR] FILE NOT FOUND: {path}")
            print("   Run this script from the repo root directory.")
            return

    print(f"\n[OK] Model found:       {MODEL_PATH}")
    print(f"[OK] Preprocessor found: {PREPROC_PATH}\n")

    preprocessor = joblib.load(PREPROC_PATH)
    model        = joblib.load(MODEL_PATH)

    print(f"Model type: {type(model).__name__}")
    if hasattr(model, 'classes_'):
        print(f"Attack classes known to model: {list(model.classes_)}\n")

    print("-"*65)

    pass_count = 0
    fail_count = 0

    for i, tc in enumerate(test_cases):
        df = pd.DataFrame([tc["features"]], columns=FEATURE_COLS)

        try:
            X = preprocessor.transform(df)
            prediction = model.predict(X)[0]

            is_attack = (prediction != 'normal' and prediction != '0' and prediction != 0)
            is_normal = not is_attack

            expected_attack = 'normal' not in tc["expected"].lower()

            if expected_attack and is_attack:
                status = ">> PASS"
                pass_count += 1
            elif not expected_attack and is_normal:
                status = ">> PASS"
                pass_count += 1
            else:
                status = "!! FAIL"
                fail_count += 1

            print(f"Test {i+1}: {tc['name']}")
            print(f"  Expected : {tc['expected']}")
            print(f"  Got      : {prediction}")
            print(f"  Result   : {status}")
            print()

        except Exception as e:
            print(f"Test {i+1}: {tc['name']}")
            print(f"  [ERROR]: {e}")
            print(f"  This means your feature columns don't match what the preprocessor expects.")
            print()
            fail_count += 1

    print("="*65)
    print(f"  Results: {pass_count} passed, {fail_count} failed out of {len(test_cases)} tests")
    print("="*65)

    if fail_count == 0:
        print("""
ALL TESTS PASSED!
   Your model correctly classifies Nmap-like traffic as attacks.
   You can proceed with the full implementation.
""")
    elif pass_count == 0:
        print("""
ALL TESTS FAILED -- The model classifies everything as NORMAL.
   Options:
   1. The preprocessor expects different column names -- check errors above
   2. The model was trained on different feature ranges
   3. You may need to use a hardcoded demo mode for the presentation
      (simulate attack labels instead of real ML prediction)
""")
    else:
        print("""
PARTIAL RESULTS -- Model works for some cases but not all.
   The normal traffic test is the most important one.
   If at least the SYN flood and Nmap cases pass, your demo will work.
""")

if __name__ == "__main__":
    run_tests()
