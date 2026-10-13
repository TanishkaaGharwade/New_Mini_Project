"""
config.py — Central configuration for CyberSentinel Python Engine
All tunable parameters live here.
"""

import os

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT  = os.path.dirname(ENGINE_DIR)

# ─── Network Interface ────────────────────────────────────────────────────────
# Set to None to let Scapy auto-detect, or set explicitly e.g. "Wi-Fi", "Ethernet"
NET_INTERFACE = os.getenv("NET_INTERFACE", None)

# ─── Safety ───────────────────────────────────────────────────────────────────
DETECT_ONLY       = True      # never touch the firewall while True
BLOCK_CONFIDENCE  = 0.90      # model-only detections block at or above this confidence

# ─── Model ────────────────────────────────────────────────────────────────────
ACTIVE_MODEL    = "v1"        # loads models/model_v1.pkl
MODEL_PATH      = os.path.join(ENGINE_DIR, "models", f"model_{ACTIVE_MODEL}.pkl")
MODEL_META_PATH = os.path.join(ENGINE_DIR, "models", f"model_{ACTIVE_MODEL}.meta.json")
FEATURES_PATH   = os.path.join(REPO_ROOT, "training", "features.json")
BENIGN_LABEL    = "Benign"

# ─── Firebase (read by firebase_client.py) ────────────────────────────────────
FIREBASE_CRED        = os.getenv("FIREBASE_CRED", os.path.join(ENGINE_DIR, "serviceAccountKey.json"))
FIRESTORE_COLLECTION = "threats"
STATS_DOCUMENT       = "live"
STATS_CLOUD_INTERVAL = 60      # seconds between stats/live writes; also the engine's heartbeat
COMMAND_MAX_AGE      = 300     # seconds; older unblock requests are refused, not replayed
CLOUD_QUEUE_MAXSIZE  = 1000    # Firestore writes waiting for the background writer

# ─── AI explanations (Groq) ───────────────────────────────────────────────────
# The key and model name come from python-engine/.env (GROQ_API_KEY, GROQ_MODEL)
AI_TIMEOUT        = 15     # seconds to wait for one explanation
AI_MAX_PER_MINUTE = 10     # API calls per minute; beyond this the offline text is used
AI_REUSE_SECONDS  = 120    # reuse an explanation for the same label and source within this time
AI_QUEUE_MAXSIZE  = 200    # explanations waiting for the background worker

# ─── Flows ────────────────────────────────────────────────────────────────────
FLOW_IDLE_TIMEOUT   = 15      # seconds without packets before a flow is closed
FLOW_MAX_DURATION   = 120     # seconds; matches the dataset
FLOW_SWEEP_INTERVAL = 1.0     # seconds between idle-flow sweeps
MAX_OPEN_FLOWS      = 50_000  # least recently active flow is closed early beyond this

# ─── Queues ───────────────────────────────────────────────────────────────────
QUEUE_MAXSIZE           = 20_000   # parsed packets buffered between capture and the flow worker
DETECTION_QUEUE_MAXSIZE = 20_000   # closed flows and rule hits waiting for classification
CLASSIFY_BATCH_SIZE     = 256      # closed flows classified in one model call

# ─── Rules (per remote source IP) ─────────────────────────────────────────────
SYN_FLOOD_THRESHOLD  = 100    # more than this many SYNs without ACK ...
SYN_FLOOD_WINDOW     = 2.0    # ... within this many seconds
PORT_SCAN_THRESHOLD  = 20     # more than this many distinct destination ports ...
PORT_SCAN_WINDOW     = 5.0    # ... within this many seconds
ICMP_FLOOD_THRESHOLD = 100    # more than this many ICMP packets ...
ICMP_FLOOD_WINDOW    = 2.0    # ... within this many seconds
RULE_COOLDOWN        = 5.0    # seconds before the same rule can fire again for the same source
MAX_TRACKED_SOURCES  = 10_000 # least recently seen source is forgotten beyond this
MAX_EVENTS_PER_SOURCE = 5_000 # cap on remembered packets per source and rule window

# ─── Decisions and output ─────────────────────────────────────────────────────
CORRELATION_WINDOW     = 10.0  # seconds a rule hit or model verdict counts as "recent" for trigger "both"
MODEL_BLOCK_MIN_FLOWS  = 3     # attack flows from one source within CORRELATION_WINDOW before the model alone may block
ALERT_THROTTLE_SECONDS = 5.0   # at most one record per (source, label) in this many seconds
STATS_INTERVAL         = 3.0   # seconds between stats broadcasts

# ─── SSE server ───────────────────────────────────────────────────────────────
SSE_HOST = "127.0.0.1"
SSE_PORT = 5000

# ─── Blocking ─────────────────────────────────────────────────────────────────
# Networks that are never blocked. This machine's own IPs, the default gateway
# and the DNS servers are detected at startup and added on top of these.
NEVER_BLOCK_NETWORKS = [
    "127.0.0.0/8",      # IPv4 loopback
    "::1/128",          # IPv6 loopback
    "192.168.1.1/32",   # common home router addresses
    "192.168.0.1/32",
    "13.107.0.0/16",    # Microsoft Teams / Windows Update
    "34.54.0.0/16",     # Google Cloud CDN
    "172.188.0.0/16",   # Microsoft Azure
]

# DNS servers to never block, in addition to the ones detected from Windows
DNS_SERVERS: list[str] = []
