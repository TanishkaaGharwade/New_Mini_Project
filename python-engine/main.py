"""
main.py — CyberSentinel Python Engine Entry Point
===============================================
Wires together:

  sniffer (capture thread)
     │  PacketInfo
     ▼
  flow worker ── FlowTracker (bi-directional flows) + RuleEngine (per-source rates)
     │  closed flows, rule hits                 ▲
     ▼                                          │ idle flows
  detection worker ── classifier + DetectionEngine ◄── sweeper (every second)
     │  threat records
     ▼
  sinks.handle_detection()  (print + SSE + Firestore + explanation)

Run as Administrator:
    python main.py

Optional env vars:
    NET_INTERFACE=Wi-Fi     (default: auto-detect)
"""

import logging
import os
import queue
import sys
import threading
import time

import blocker
import netinfo
import sinks
import sniffer
from classifier import ThreatClassifier
from config import (
    ENGINE_DIR, ACTIVE_MODEL, DETECT_ONLY, BLOCK_CONFIDENCE,
    FLOW_SWEEP_INTERVAL, STATS_INTERVAL, DETECTION_QUEUE_MAXSIZE, CLASSIFY_BATCH_SIZE,
    SSE_HOST, SSE_PORT,
)
from detector import DetectionEngine, Stats
from feature_extractor import FlowTracker
from rules import RuleEngine, RuleHit
from server import start_sse_server

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(ENGINE_DIR, "cybersentinel.log"), encoding="utf-8"),
    ]
)
logger = logging.getLogger("cybersentinel.main")

_TICK = object()   # tells the detection worker to flush throttled records and publish stats

# Closed flows (lists), RuleHits and _TICK, in the order they happened
detection_queue: queue.Queue = queue.Queue(maxsize=DETECTION_QUEUE_MAXSIZE)
dropped_detections = 0


def _enqueue(item) -> None:
    global dropped_detections
    try:
        detection_queue.put_nowait(item)
    except queue.Full:
        dropped_detections += 1


def flow_worker(tracker: FlowTracker, rules: RuleEngine, stats: Stats) -> None:
    """Feeds every captured packet to the flow tracker and the rules."""
    logger.info("[FLOW WORKER] started")
    while True:
        pkt = sniffer.packet_queue.get()
        try:
            stats.packets += 1
            new_flow, closed = tracker.add_packet(pkt)
            for hit in rules.observe(pkt, new_flow):
                _enqueue(hit)
            if closed:
                _enqueue(closed)
        except Exception:
            logger.exception("[FLOW WORKER] failed on a packet")


def sweeper(tracker: FlowTracker, rules: RuleEngine) -> None:
    """Closes idle flows, forgets quiet sources, and requests a stats tick."""
    last_tick = 0.0
    while True:
        time.sleep(FLOW_SWEEP_INTERVAL)
        now = time.time()
        try:
            closed = tracker.sweep(now)
            if closed:
                _enqueue(closed)
            rules.prune(now)
        except Exception:
            logger.exception("[SWEEPER] sweep failed")
        if now - last_tick >= STATS_INTERVAL:
            last_tick = now
            _enqueue(_TICK)


def detection_worker(engine: DetectionEngine, tracker: FlowTracker) -> None:
    """Classifies closed flows in batches and acts on rule hits, in arrival order."""
    logger.info("[DETECTION WORKER] started")
    reported_drops = (0, 0)
    batch: list = []

    def run_batch():
        if batch:
            try:
                engine.handle_flows(batch)
            except Exception:
                logger.exception("[DETECTION WORKER] classification failed")
            batch.clear()

    while True:
        items = [detection_queue.get()]
        while len(items) < CLASSIFY_BATCH_SIZE:
            try:
                items.append(detection_queue.get_nowait())
            except queue.Empty:
                break

        for item in items:
            if isinstance(item, list):
                batch.extend(item)
                if len(batch) >= CLASSIFY_BATCH_SIZE:
                    run_batch()
                continue

            run_batch()   # keep flows and rule hits in order
            try:
                if isinstance(item, RuleHit):
                    engine.handle_rule_hit(item)
                elif item is _TICK:
                    engine.tick()
                    sinks.publish_stats()
                    drops = (sniffer.dropped_packets, dropped_detections)
                    if drops != reported_drops:
                        logger.warning(f"[ENGINE] falling behind: {drops[0]} packets and "
                                       f"{drops[1]} detection items dropped so far")
                        reported_drops = drops
                    logger.debug(f"[ENGINE] open flows: {len(tracker)}")
            except Exception:
                logger.exception("[DETECTION WORKER] failed on an item")
        run_batch()


def main() -> None:
    print("=" * 60)
    print("  CyberSentinel — ML-Based Intrusion Prevention System")
    print("=" * 60)
    print("[!] Make sure you are running this as Administrator")
    print()

    try:
        classifier = ThreatClassifier()
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"[MODEL] {e}")
        print(f"  Make sure models/model_{ACTIVE_MODEL}.pkl and training/features.json exist")
        sys.exit(1)

    local_ips = netinfo.local_ips()
    blocker.init_whitelist()
    blocker.load_existing_rules()
    mode = "DETECT-ONLY (firewall untouched)" if DETECT_ONLY else f"BLOCKING (model confidence >= {BLOCK_CONFIDENCE})"
    logger.info(f"[MAIN] Mode: {mode}")

    stats = Stats(blocked_ips=blocker.get_blocked_ips)
    sinks.set_stats_provider(stats.snapshot)
    start_sse_server(host=SSE_HOST, port=SSE_PORT)
    sinks.start_cloud(unblock=blocker.unblock_ip)

    engine = DetectionEngine(
        classifier, sinks.handle_detection,
        local_ips=local_ips, stats=stats,
        detect_only=DETECT_ONLY, block_confidence=BLOCK_CONFIDENCE,
        is_whitelisted=blocker.is_whitelisted, block_ip=blocker.block_ip,
    )
    tracker = FlowTracker()
    rules = RuleEngine(local_ips=local_ips)

    for target, args, name in (
        (flow_worker, (tracker, rules, stats), "FlowWorker"),
        (sweeper, (tracker, rules), "FlowSweeper"),
        (detection_worker, (engine, tracker), "DetectionWorker"),
    ):
        threading.Thread(target=target, args=args, daemon=True, name=name).start()

    # Scapy capture blocks the main thread until Ctrl+C
    logger.info("[MAIN] Starting packet capture...")
    try:
        sniffer.start_capture(local_ips)
    except KeyboardInterrupt:
        pass
    print("\n[*] Shutting down CyberSentinel...")
    sinks.stop_cloud()


if __name__ == "__main__":
    main()
