"""
detector.py — Decisions for CyberSentinel
========================================
Turns closed flows (classified by the model) and rule hits into threat records
(PART_A_DETECTION_ENGINE.md section 5) and hands them to a sink.

Decision table (section 6, step A11):

  rule fired | model says attack | confidence         | trigger | action
  -----------+-------------------+--------------------+---------+-----------
  yes        | yes               | any                | both    | blocked
  yes        | no                | —                  | rule    | blocked
  no         | yes               | >= BLOCK_CONFIDENCE| model   | blocked
  no         | yes               | below              | model   | alert_only
  no         | no                | —                  | (no record)

A "blocked" decision then goes through the overrides, in order:
  1. source whitelisted  → "whitelisted", not blocked
  2. DETECT_ONLY         → "detect_only", not blocked
  3. block_ip() fails    → "alert_only"

A rule hit and a model verdict are combined into trigger "both" when they concern
the same remote IP within CORRELATION_WINDOW seconds of each other. A "both" record
carries the model's class as its label and the evidence of both; a "rule" record
carries the rule's name (SynFlood, PortScan, IcmpFlood) and a null confidence.
"""

import logging
import time
from datetime import datetime, timezone

from config import (
    BLOCK_CONFIDENCE, DETECT_ONLY, CORRELATION_WINDOW, ALERT_THROTTLE_SECONDS,
)
from feature_extractor import feature_vector

logger = logging.getLogger("cybersentinel.detector")

TRIGGER_MODEL, TRIGGER_RULE, TRIGGER_BOTH = "model", "rule", "both"
BLOCKED, ALERT_ONLY, DETECT_ONLY_ACTION, WHITELISTED = "blocked", "alert_only", "detect_only", "whitelisted"


def decide(rule_fired: bool, model_attack: bool, confidence: float | None,
           block_confidence: float = BLOCK_CONFIDENCE):
    """The decision table. Returns (trigger, action), or None when nothing is detected."""
    if rule_fired and model_attack:
        return TRIGGER_BOTH, BLOCKED
    if rule_fired:
        return TRIGGER_RULE, BLOCKED
    if model_attack:
        if confidence is not None and confidence >= block_confidence:
            return TRIGGER_MODEL, BLOCKED
        return TRIGGER_MODEL, ALERT_ONLY
    return None


def resolve_action(action: str, src_ip: str, *, detect_only: bool, is_whitelisted, block_ip) -> str:
    """Apply the overrides to a "blocked" decision; other actions pass through unchanged."""
    if action != BLOCKED:
        return action
    if is_whitelisted(src_ip):
        return WHITELISTED
    if detect_only:
        return DETECT_ONLY_ACTION
    status = block_ip(src_ip)
    if status in ("blocked", "already_blocked"):
        return BLOCKED
    if status == "whitelisted":
        return WHITELISTED
    return ALERT_ONLY


def iso_utc(ts: float) -> str:
    """Epoch seconds → "2026-10-12T14:03:22Z"."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_threat(*, ts: float, src_ip: str, src_port, dst_ip: str, dst_port, protocol: str,
                label: str, confidence, trigger: str, action: str, packet_count: int,
                evidence: list) -> dict:
    """A threat record with exactly the fields of the shared contract (no "id")."""
    return {
        "timestamp":    iso_utc(ts),
        "src_ip":       src_ip,
        "src_port":     src_port,
        "dst_ip":       dst_ip,
        "dst_port":     dst_port,
        "protocol":     protocol,
        "label":        label,
        "confidence":   None if confidence is None else round(float(confidence), 4),
        "trigger":      trigger,
        "action":       action,
        "packet_count": int(packet_count),
        "evidence":     list(evidence),
    }


def orient(flow, local_ips) -> tuple:
    """(remote_ip, remote_port, local_ip, local_port) for a flow. Remote is the side to block."""
    if flow.src_ip in local_ips and flow.dst_ip not in local_ips:
        return flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port
    return flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port


class AlertThrottle:
    """
    At most one record per (src_ip, label) every `window` seconds. Records that arrive
    sooner are held back; their packet_count is added to the next record for that key.
    flush() releases held records whose window has passed.
    """

    def __init__(self, window: float = ALERT_THROTTLE_SECONDS):
        self.window = window
        self._last_emit: dict = {}   # key → time of last emitted record
        self._pending: dict = {}     # key → held-back record (counts already summed)

    def offer(self, threat: dict, now: float) -> list:
        key = (threat["src_ip"], threat["label"])
        last = self._last_emit.get(key)
        held = self._pending.pop(key, None)
        if held is not None:
            threat = {**threat, "packet_count": threat["packet_count"] + held["packet_count"]}

        if last is None or now - last >= self.window:
            self._last_emit[key] = now
            return [threat]
        self._pending[key] = threat
        return []

    def flush(self, now: float) -> list:
        out = []
        for key in list(self._pending):
            if now - self._last_emit[key] >= self.window:
                out.append(self._pending.pop(key))
                self._last_emit[key] = now
        for key in [k for k, t in self._last_emit.items() if k not in self._pending and now - t >= self.window]:
            del self._last_emit[key]
        return out


class Stats:
    """Counters shown on the dashboard. Each counter has a single writer thread."""

    def __init__(self, blocked_ips=lambda: set()):
        self.packets = 0
        self.flows = 0
        self.attacks = 0
        self._blocked_ips = blocked_ips

    def snapshot(self) -> dict:
        return {
            "totalPackets": self.packets,
            "totalFlows":   self.flows,
            "totalAttacks": self.attacks,
            "blockedIPs":   len(self._blocked_ips()),
            "threatLevel":  round(min(100.0, self.attacks / max(self.flows, 1) * 100), 1),
            "updatedAt":    datetime.now(timezone.utc).isoformat(),
        }


class DetectionEngine:
    """
    Combines model verdicts and rule hits, applies the decision table and the
    overrides, throttles, and calls `sink(threat)` once per record.
    Not thread-safe: call it from a single thread.
    """

    def __init__(self, classifier, sink, *, local_ips=(), stats: Stats | None = None,
                 detect_only: bool = DETECT_ONLY, block_confidence: float = BLOCK_CONFIDENCE,
                 is_whitelisted=lambda ip: False, block_ip=lambda ip: "failed",
                 correlation_window: float = CORRELATION_WINDOW,
                 throttle: AlertThrottle | None = None, clock=time.time):
        self.classifier = classifier
        self.sink = sink
        self.local_ips = set(local_ips)
        self.stats = stats or Stats()
        self.detect_only = detect_only
        self.block_confidence = block_confidence
        self.is_whitelisted = is_whitelisted
        self.block_ip = block_ip
        self.correlation_window = correlation_window
        self.throttle = throttle or AlertThrottle()
        self.clock = clock
        self._recent_rule: dict = {}    # remote ip → latest RuleHit
        self._recent_model: dict = {}   # remote ip → (ts, label, confidence, evidence)

    # ── inputs ────────────────────────────────────────────────────────────────

    def handle_flows(self, flows: list) -> list:
        """Classify closed flows and act on attacks. Returns the records emitted."""
        if not flows:
            return []
        vectors = [feature_vector(f, self.classifier.features) for f in flows]
        verdicts = self.classifier.classify_many(vectors)
        emitted = []
        for flow, vector, (label, confidence) in zip(flows, vectors, verdicts):
            self.stats.flows += 1
            if not self.classifier.is_attack(label):
                continue
            self.stats.attacks += 1

            ts = flow.last_ts / 1_000_000
            src_ip, src_port, dst_ip, dst_port = orient(flow, self.local_ips)
            model_evidence = self.classifier.evidence(vector)
            self._recent_model[src_ip] = (ts, label, confidence, model_evidence)

            hit = self._recent_rule.get(src_ip)
            rule_fired = hit is not None and abs(ts - hit.ts) <= self.correlation_window
            trigger, action = decide(rule_fired, True, confidence, self.block_confidence)
            evidence = (hit.evidence if rule_fired else []) + model_evidence

            emitted += self._emit(ts, src_ip, src_port, dst_ip, dst_port, flow.protocol,
                                  label, confidence, trigger, action, flow.packet_count, evidence)
        return emitted

    def handle_rule_hit(self, hit) -> list:
        """Act on one rule hit. Returns the records emitted."""
        self.stats.attacks += 1
        self._recent_rule[hit.src_ip] = hit

        recent = self._recent_model.get(hit.src_ip)
        model_attack = recent is not None and abs(hit.ts - recent[0]) <= self.correlation_window
        if model_attack:
            _, label, confidence, model_evidence = recent
        else:
            label, confidence, model_evidence = hit.label, None, []
        trigger, action = decide(True, model_attack, confidence, self.block_confidence)

        pkt = hit.packet
        local_ip = pkt.dst_ip
        return self._emit(hit.ts, hit.src_ip, pkt.src_port, local_ip, pkt.dst_port, pkt.protocol,
                          label, confidence, trigger, action, hit.packet_count,
                          hit.evidence + model_evidence)

    def tick(self) -> list:
        """Release throttled records and forget stale correlations. Call every few seconds."""
        now = self.clock()
        emitted = self.throttle.flush(now)
        for threat in emitted:
            self.sink(threat)

        horizon = now - 2 * self.correlation_window
        self._recent_rule = {ip: h for ip, h in self._recent_rule.items() if h.ts >= horizon}
        self._recent_model = {ip: m for ip, m in self._recent_model.items() if m[0] >= horizon}
        return emitted

    # ── output ────────────────────────────────────────────────────────────────

    def _emit(self, ts, src_ip, src_port, dst_ip, dst_port, protocol, label, confidence,
              trigger, action, packet_count, evidence) -> list:
        action = resolve_action(action, src_ip, detect_only=self.detect_only,
                                is_whitelisted=self.is_whitelisted, block_ip=self.block_ip)
        threat = make_threat(
            ts=ts, src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port,
            protocol=protocol, label=label, confidence=confidence, trigger=trigger,
            action=action, packet_count=packet_count, evidence=evidence,
        )
        emitted = self.throttle.offer(threat, self.clock())
        for t in emitted:
            self.sink(t)
        return emitted
