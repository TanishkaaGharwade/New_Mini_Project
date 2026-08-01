"""
firebase_client.py — Firestore Writer for NetSentinel
=====================================================
Writes threat events and live stats to Firebase Firestore.
React dashboard reads these via onSnapshot() in real-time.

Setup:
  1. Create Firebase project at console.firebase.google.com
  2. Enable Firestore Database (test mode initially)
  3. Generate Service Account key → save as serviceAccountKey.json
     in the python-engine/ folder (gitignored)
  4. Set FIREBASE_CRED env var if using a different path

Collections written:
  - "threats"      : one document per detected attack event
  - "stats/live"   : single document with running counters
"""

import os
import logging
from datetime import datetime, timezone

logger = logging.getLogger("netsentinel.firebase")

# Lazy initialization — Firebase only imported if cred file exists
_db         = None
_initialized = False


def _init_firebase():
    """Initialize Firebase Admin SDK. Called once on first use."""
    global _db, _initialized
    if _initialized:
        return _db is not None

    cred_path = os.getenv("FIREBASE_CRED", "serviceAccountKey.json")

    if not os.path.exists(cred_path):
        logger.warning(
            f"[FIREBASE] serviceAccountKey.json not found at '{cred_path}'. "
            "Threat events will be printed to console only."
        )
        _initialized = True
        return False

    try:
        import firebase_admin
        from firebase_admin import credentials, firestore

        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        _db = firestore.client()
        _initialized = True
        logger.info("[FIREBASE] Connected to Firestore successfully")
        print("[+] Firebase connected")
        return True

    except Exception as e:
        logger.error(f"[FIREBASE] Initialization failed: {e}")
        _initialized = True
        return False


def log_threat(src_ip: str, dst_ip: str, src_port, dst_port,
               protocol: str, attack_label: str, was_blocked: bool,
               packet_count: int = 1):
    """
    Write a threat event to Firestore threats collection.
    If Firebase is not configured, prints to console instead.
    """
    _init_firebase()

    now = datetime.now(timezone.utc).isoformat()

    doc = {
        "timestamp":     now,
        "src_ip":        src_ip,
        "src_port":      str(src_port) if src_port else "N/A",
        "dst_ip":        dst_ip,
        "dst_port":      str(dst_port) if dst_port else "N/A",
        "protocol":      protocol.upper(),
        "attack_type":   attack_label.rstrip("."),   # strip NSL-KDD trailing dot
        "blocked":       was_blocked,
        "packet_count":  packet_count,
        "logged_at":     now,
    }

    # Always print to console
    print(
        f"[THREAT] {now[:19]}  {src_ip} → {dst_ip}  "
        f"| {attack_label.upper()}  | blocked={was_blocked}"
    )

    if _db:
        try:
            from config import FIRESTORE_COLLECTION
            _db.collection(FIRESTORE_COLLECTION).add(doc)
        except Exception as e:
            logger.error(f"[FIREBASE] Failed to write threat: {e}")


def update_stats(total_packets: int, total_attacks: int, blocked_count: int):
    """
    Update the live stats document in Firestore.
    React StatCards read this via onSnapshot.
    """
    _init_firebase()

    if not _db:
        return

    try:
        from config import STATS_DOCUMENT
        _db.collection("stats").document(STATS_DOCUMENT).set({
            "total_packets": total_packets,
            "total_attacks": total_attacks,
            "blocked_ips":   blocked_count,
            "threat_level":  round((total_attacks / max(total_packets, 1)) * 100, 1),
            "updated_at":    datetime.now(timezone.utc).isoformat(),
        })
    except Exception as e:
        logger.error(f"[FIREBASE] Failed to update stats: {e}")
