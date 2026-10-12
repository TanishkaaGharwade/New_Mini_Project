"""
sinks.py — Where CyberSentinel's detections go
=============================================
handle_detection() is the hand-over point between Part A (detection) and Part B
(storage and explanations). main.py calls it once per threat record and sends
no other detection output anywhere else.

Part A's version prints the record and broadcasts it to the dashboard over SSE.
Part B extends handle_detection() to also store it in Firestore.
"""

import json
import logging
import uuid

from server import broadcast_event

logger = logging.getLogger("cybersentinel.sinks")

_stats_provider = None


def set_stats_provider(provider) -> None:
    """Register a function returning the current stats dict sent with every SSE event."""
    global _stats_provider
    _stats_provider = provider


def _stats() -> dict | None:
    return _stats_provider() if _stats_provider else None


def handle_detection(threat: dict) -> None:
    """Called by main.py once per detection."""
    print(f"[THREAT] {json.dumps(threat)}", flush=True)
    logger.info(
        f"[THREAT] {threat['src_ip']} -> {threat['dst_ip']} | {threat['label']} | "
        f"trigger={threat['trigger']} action={threat['action']} conf={threat['confidence']}"
    )

    # The current dashboard reads attack_type/blocked and de-duplicates on id.
    # These exist only in the SSE copy, never in the record itself.
    sse_threat = {
        **threat,
        "id": f"live-{uuid.uuid4().hex[:12]}",
        "attack_type": threat["label"],
        "blocked": threat["action"] == "blocked",
    }
    broadcast_event("THREAT_EVENT", {"threat": sse_threat, "stats": _stats()})


def publish_stats() -> None:
    """Broadcast the current stats alone, so the dashboard counters stay live between detections."""
    stats = _stats()
    if stats is not None:
        broadcast_event("THREAT_EVENT", {"stats": stats})
