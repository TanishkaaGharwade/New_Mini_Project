"""
config.py — Central configuration for NetSentinel Python Engine
All tunable parameters live here.
"""

import os

# ─── Network Interface ────────────────────────────────────────────────────────
# Set to None to let Scapy auto-detect, or set explicitly e.g. "Wi-Fi", "Ethernet"
NET_INTERFACE = os.getenv("NET_INTERFACE", None)

# ─── Model Paths ──────────────────────────────────────────────────────────────
MODEL_PATH        = os.path.join(os.path.dirname(__file__), "models", "model.pkl")
PREPROCESSOR_PATH = os.path.join(os.path.dirname(__file__), "models", "preprocessor.pkl")

# ─── Firebase ─────────────────────────────────────────────────────────────────
FIREBASE_CRED        = os.getenv("FIREBASE_CRED", "serviceAccountKey.json")
FIRESTORE_COLLECTION = "threats"
STATS_DOCUMENT       = "live"

# ─── Flow Aggregation ─────────────────────────────────────────────────────────
# How many packets to accumulate per source IP before running ML inference.
FLOW_WINDOW_PACKETS = 30   # classify after seeing 30 packets from same src IP
FLOW_WINDOW_SECONDS = 3    # OR after 3 seconds, whichever comes first

# ─── Queue ────────────────────────────────────────────────────────────────────
QUEUE_MAXSIZE = 2000        # max packets buffered between capture and processing

# ─── Blocking ─────────────────────────────────────────────────────────────────
# IPs that should NEVER be blocked (your own machine + default router gateway)
NEVER_BLOCK_IPS = {
    "127.0.0.1",
    "::1",
    "localhost",
    "192.168.1.1",
    "192.168.0.1",
}

# ─── NSL-KDD Labels that are considered attacks ────────────────────────────────
# The model labels end with a dot (e.g. "neptune.") — this is NSL-KDD quirk
NORMAL_LABELS = {"normal.", "normal"}
