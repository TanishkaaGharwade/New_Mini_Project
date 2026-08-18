"""
main.py — CyberSentinel Python Engine Entry Point
===============================================
Wires together: sniffer → feature_extractor → classifier → blocker → firebase + real-time SSE stream

Run as Administrator:
    python main.py

Optional env vars:
    NET_INTERFACE=Wi-Fi     (default: auto-detect)
    FIREBASE_CRED=path/to/serviceAccountKey.json
"""

import threading
import logging
import signal
import sys
from datetime import datetime, timezone

from sniffer import start_capture, packet_queue
from feature_extractor import build_feature_vector, init_state_dicts
from classifier import ThreatClassifier
from blocker import block_ip, get_blocked_ips
from firebase_client import log_threat, update_stats
from server import start_sse_server, broadcast_event

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("cybersentinel.log", encoding="utf-8"),
    ]
)
logger = logging.getLogger("cybersentinel.main")

# ─── Global counters ──────────────────────────────────────────────────────────
total_packets = 0
total_attacks = 0


def processing_loop(classifier: ThreatClassifier, state: dict):
    """
    Consumer thread: reads aggregated flows from packet_queue,
    extracts features, classifies, blocks, and broadcasts to React UI + Firebase.
    """
    global total_packets, total_attacks

    logger.info("[PROCESSING] Worker thread started")

    while True:
        try:
            # Get next aggregated flow from sniffer
            flow = packet_queue.get(timeout=1)
        except Exception:
            continue  # timeout — keep looping

        src_ip   = flow["src_ip"]
        packets  = flow["packets"]
        pkt_cnt  = flow["count"]

        total_packets += pkt_cnt

        # Build feature vector for each packet in the flow
        feature_vectors = []
        last_parsed     = None

        for parsed in packets:
            vec = build_feature_vector(parsed, state)
            if vec is not None:
                feature_vectors.append(vec)
                last_parsed = parsed

        if not feature_vectors or last_parsed is None:
            packet_queue.task_done()
            continue

        # Run ML inference — majority vote across all vectors in flow
        try:
            attack_label, is_attack = classifier.predict_flow(feature_vectors)
        except Exception as e:
            logger.error(f"[ML ERROR] {e}")
            packet_queue.task_done()
            continue

        dst_ip   = last_parsed.get("dst_ip", "?")
        src_port = last_parsed.get("src_port")
        dst_port = last_parsed.get("dst_port")
        protocol = last_parsed.get("protocol", "?").upper()
        clean_label = attack_label.rstrip(".")

        was_blocked = False

        if not is_attack:
            logger.debug(f"[NORMAL] {src_ip} -> {dst_ip} | {protocol} | {pkt_cnt} pkts")
        else:
            total_attacks += 1
            logger.info(
                f"[ATTACK] {src_ip} -> {dst_ip} | {clean_label.upper()} "
                f"| {pkt_cnt} pkts | {protocol}"
            )

            # ── Block the attacker IP (only if flow packet count >= 5 to avoid background noise) ──
            if pkt_cnt >= 5:
                was_blocked = block_ip(src_ip)
            else:
                logger.info(f"[NOISE SKIPPED] {src_ip} flagged as {clean_label} but only {pkt_cnt} pkts (ignored)")

            # ── Log to Firebase ───────────────────────────────────────────
            log_threat(
                src_ip       = src_ip,
                dst_ip       = dst_ip,
                src_port     = src_port,
                dst_port     = dst_port,
                protocol     = protocol,
                attack_label = attack_label,
                was_blocked  = was_blocked,
                packet_count = pkt_cnt,
            )

        # ── Always broadcast event & stats to React Dashboard via SSE ────
        now_iso = datetime.now(timezone.utc).isoformat()

        event_doc = {
            "id": f"event-{total_packets}-{src_ip}",
            "timestamp": now_iso,
            "src_ip": src_ip,
            "src_port": str(src_port) if src_port else "N/A",
            "dst_ip": dst_ip,
            "dst_port": str(dst_port) if dst_port else "N/A",
            "protocol": protocol,
            "attack_type": clean_label,
            "blocked": was_blocked,
            "packet_count": pkt_cnt,
        }

        stats_doc = {
            "totalPackets": total_packets,
            "totalAttacks": total_attacks,
            "blockedIPs": len(get_blocked_ips()),
            "threatLevel": round((total_attacks / max(total_packets, 1)) * 100, 1),
            "updatedAt": now_iso,
        }

        # Broadcast real-time update to any connected React dashboard browser
        broadcast_event("THREAT_EVENT", {"threat": event_doc, "stats": stats_doc})

        packet_queue.task_done()


def _handle_shutdown(sig, frame):
    """Graceful shutdown on Ctrl+C."""
    print("\n[*] Shutting down CyberSentinel...")
    sys.exit(0)


if __name__ == "__main__":
    print("=" * 60)
    print("  CyberSentinel — ML-Based Intrusion Prevention System")
    print("=" * 60)
    print("[!] Make sure you are running this as Administrator")
    print()

    # Register Ctrl+C handler
    signal.signal(signal.SIGINT, _handle_shutdown)

    # Start Real-Time Server on port 5000 for React UI
    start_sse_server(port=5000)

    # Load ML model
    try:
        clf = ThreatClassifier()
    except FileNotFoundError as e:
        print(f"[ERROR] {e}")
        print("  Make sure model.pkl and preprocessor.pkl are in python-engine/models/")
        sys.exit(1)

    # Initialize connection state tracking
    state = init_state_dicts()

    # Start processing worker thread (daemon — dies when main exits)
    worker = threading.Thread(
        target=processing_loop,
        args=(clf, state),
        daemon=True,
        name="ProcessingWorker"
    )
    worker.start()
    logger.info("[MAIN] Processing worker started")

    # Start Scapy capture — this blocks the main thread
    logger.info("[MAIN] Starting packet capture...")
    start_capture()
