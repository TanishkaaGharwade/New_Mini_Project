"""
sinks.py — Where CyberSentinel's detections go
=============================================
handle_detection() is the hand-over point between Part A (detection) and Part B
(storage and explanations). main.py calls it once per threat record and sends
no other detection output anywhere else.

It prints the record, broadcasts it to the local dashboard over SSE, stores it in
Firestore, writes an audit entry for blocks, and asks for an explanation. The
cloud steps are skipped when Firestore is not available.
"""

import json
import logging
import uuid

from server import broadcast_event

logger = logging.getLogger("cybersentinel.sinks")

_stats_provider = None
_cloud = None        # firebase_client.CloudStore, or None when Firestore is unavailable
_explainer = None    # ai.Explainer, or None


def start_cloud(unblock) -> None:
    """Connect to Firestore and start the explanation worker. Safe to call without a key file."""
    global _cloud, _explainer
    import ai
    import firebase_client

    _cloud = firebase_client.connect(unblock=unblock)
    if _cloud is None:
        return
    _cloud.start()
    _cloud.listen_for_commands()
    _cloud.write_audit("engine_start", detail=f"model {_cloud.model_version}, "
                                              f"{'detect-only' if _cloud.detect_only else 'blocking'}")
    _explainer = ai.Explainer.from_env(store=_cloud.update_explanation)
    _explainer.start()
    publish_stats(force=True)


def stop_cloud() -> None:
    """Send a last stats update and let queued writes finish."""
    global _cloud, _explainer
    if _explainer is not None:
        _explainer.stop()
    if _cloud is not None:
        publish_stats(force=True)
        _cloud.stop()
    _cloud = _explainer = None


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

    if _cloud is None:
        return
    doc_id = _cloud.store_threat(threat)
    if threat["action"] == "blocked":
        _cloud.write_audit("block", threat["src_ip"],
                           detail=f"{threat['label']} (trigger: {threat['trigger']})")
    if doc_id is not None and _explainer is not None:
        _explainer.request(doc_id, threat)


def publish_stats(force: bool = False) -> None:
    """
    Broadcast the current stats alone, so the dashboard counters stay live between
    detections. Firestore gets them too, but only about once a minute.
    """
    stats = _stats()
    if stats is None:
        return
    broadcast_event("THREAT_EVENT", {"stats": stats})
    if _cloud is not None:
        _cloud.update_stats(stats, force=force)
