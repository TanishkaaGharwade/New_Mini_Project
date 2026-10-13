"""Decision table, overrides, record contract, throttle and the detection engine."""

import json

import pytest

from detector import (
    AlertThrottle, DetectionEngine, Stats, decide, iso_utc, make_threat, resolve_action,
)
from feature_extractor import FlowTracker, PacketInfo
from rules import RuleEngine

T0 = 1_760_000_000.0
ME = "192.168.1.4"
ATTACKER = "198.51.100.42"

CONTRACT_FIELDS = ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "label",
                   "confidence", "trigger", "action", "packet_count", "evidence"]


# ── Decision table ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("rule,attack,conf,expected", [
    (True,  True,  0.30, ("both", "blocked")),
    (True,  True,  0.99, ("both", "blocked")),
    (True,  False, None, ("rule", "blocked")),
    (False, True,  0.90, ("model", "blocked")),
    (False, True,  0.95, ("model", "blocked")),
    (False, True,  0.8999, ("model", "alert_only")),
    (False, False, 0.99, None),
])
def test_decision_table(rule, attack, conf, expected):
    assert decide(rule, attack, conf, block_confidence=0.90) == expected


# ── Overrides ─────────────────────────────────────────────────────────────────

class FakeFirewall:
    def __init__(self, status="blocked"):
        self.status = status
        self.calls = []

    def __call__(self, ip):
        self.calls.append(ip)
        return self.status


def test_whitelist_override_comes_first():
    fw = FakeFirewall()
    action = resolve_action("blocked", "192.168.1.1", detect_only=True,
                            is_whitelisted=lambda ip: True, block_ip=fw)
    assert action == "whitelisted" and fw.calls == []


def test_detect_only_never_calls_the_firewall():
    fw = FakeFirewall()
    action = resolve_action("blocked", ATTACKER, detect_only=True,
                            is_whitelisted=lambda ip: False, block_ip=fw)
    assert action == "detect_only" and fw.calls == []


@pytest.mark.parametrize("status,expected", [
    ("blocked", "blocked"), ("already_blocked", "blocked"),
    ("whitelisted", "whitelisted"), ("failed", "alert_only"),
])
def test_block_result_maps_to_action(status, expected):
    fw = FakeFirewall(status)
    action = resolve_action("blocked", ATTACKER, detect_only=False,
                            is_whitelisted=lambda ip: False, block_ip=fw)
    assert action == expected and fw.calls == [ATTACKER]


def test_alert_only_is_never_blocked():
    fw = FakeFirewall()
    assert resolve_action("alert_only", ATTACKER, detect_only=False,
                          is_whitelisted=lambda ip: False, block_ip=fw) == "alert_only"
    assert fw.calls == []


# ── Record contract ───────────────────────────────────────────────────────────

def test_threat_record_matches_contract():
    t = make_threat(ts=1760277802.7, src_ip=ATTACKER, src_port=51544, dst_ip=ME, dst_port=80,
                    protocol="TCP", label="PortScan", confidence=0.97123, trigger="both",
                    action="blocked", packet_count=40,
                    evidence=[{"feature": "distinct ports in 5 s", "value": 38}])
    assert list(t) == CONTRACT_FIELDS
    assert "id" not in t and "attack_type" not in t and "blocked" not in t
    assert t["timestamp"] == "2025-10-12T14:03:22Z"
    assert t["confidence"] == 0.9712
    json.dumps(t, allow_nan=False)


def test_rule_only_record_has_null_confidence():
    t = make_threat(ts=T0, src_ip=ATTACKER, src_port=None, dst_ip=ME, dst_port=None, protocol="ICMP",
                    label="IcmpFlood", confidence=None, trigger="rule", action="detect_only",
                    packet_count=101, evidence=[])
    assert t["confidence"] is None


def test_iso_utc_format():
    assert iso_utc(0) == "1970-01-01T00:00:00Z"


# ── Throttle ──────────────────────────────────────────────────────────────────

def _threat(count, label="DoS", src=ATTACKER):
    return make_threat(ts=T0, src_ip=src, src_port=1, dst_ip=ME, dst_port=80, protocol="TCP",
                       label=label, confidence=0.95, trigger="model", action="blocked",
                       packet_count=count, evidence=[])


def test_throttle_holds_repeats_and_adds_packet_counts():
    th = AlertThrottle(window=5)
    assert [t["packet_count"] for t in th.offer(_threat(10), now=0)] == [10]
    assert th.offer(_threat(5), now=1) == []
    assert th.offer(_threat(7), now=2) == []
    assert th.offer(_threat(3, label="PortScan"), now=2) != []       # other label is independent
    assert th.offer(_threat(3, src="203.0.113.7"), now=2) != []      # other source is independent
    assert th.flush(now=4) == []
    released = th.flush(now=5)
    assert [t["packet_count"] for t in released] == [12]
    assert th.flush(now=20) == []


def test_throttle_merges_held_counts_into_next_record():
    th = AlertThrottle(window=5)
    th.offer(_threat(10), now=0)
    th.offer(_threat(5), now=1)
    assert [t["packet_count"] for t in th.offer(_threat(1), now=6)] == [6]


# ── Engine ────────────────────────────────────────────────────────────────────

class FakeClassifier:
    """Labels every flow with a fixed verdict."""
    features = ["Flow Duration"]

    def __init__(self, label="Benign", confidence=0.99):
        self.verdict = (label, confidence)

    def classify_many(self, vectors):
        return [self.verdict] * len(vectors)

    @staticmethod
    def is_attack(label):
        return label != "Benign"

    @staticmethod
    def evidence(vector):
        return [{"feature": "Flow Packets/s", "value": 2100.5}]


class Clock:
    now = T0

    def __call__(self):
        return self.now


def make_engine(label="Benign", confidence=0.99, detect_only=False, whitelist=(), firewall=None, min_flows=1):
    records = []
    clock = Clock()
    engine = DetectionEngine(
        FakeClassifier(label, confidence), records.append, local_ips={ME},
        detect_only=detect_only, block_confidence=0.90,
        is_whitelisted=lambda ip: ip in whitelist, block_ip=firewall or FakeFirewall(),
        model_block_min_flows=min_flows,
        throttle=AlertThrottle(window=5), clock=clock,
    )
    return engine, records, clock


def closed_flow(first_src, first_dst, t=0.0):
    tracker = FlowTracker()
    tracker.add_packet(PacketInfo(T0 + t, first_src, first_dst, 40000, 80, "TCP", 0, syn=True))
    tracker.add_packet(PacketInfo(T0 + t + 0.001, first_dst, first_src, 80, 40000, "TCP", 0, syn=True, ack=True))
    return tracker.flush()


def port_scan_hit(t=0.0):
    rules = RuleEngine(local_ips={ME})
    hits = []
    for i in range(21):
        hits += rules.observe(PacketInfo(T0 + t + i * 0.01, ATTACKER, ME, 40000 + i, 1000 + i, "TCP", 0, syn=True))
    assert len(hits) == 1
    return hits[0]


def test_benign_flows_produce_no_record_but_are_counted():
    engine, records, _ = make_engine("Benign")
    engine.handle_flows(closed_flow(ATTACKER, ME) + closed_flow("203.0.113.5", ME))
    assert records == []
    assert (engine.stats.flows, engine.stats.attacks) == (2, 0)


def test_model_only_high_confidence_blocks_remote_side():
    fw = FakeFirewall()
    engine, records, _ = make_engine("DoS", 0.97, firewall=fw)
    engine.handle_flows(closed_flow(ATTACKER, ME))
    r, = records
    assert (r["src_ip"], r["src_port"], r["dst_ip"], r["dst_port"]) == (ATTACKER, 40000, ME, 80)
    assert (r["label"], r["trigger"], r["action"], r["confidence"]) == ("DoS", "model", "blocked", 0.97)
    assert r["packet_count"] == 2
    assert fw.calls == [ATTACKER]


def test_flow_started_by_this_machine_still_blames_the_remote_side():
    fw = FakeFirewall()
    engine, records, _ = make_engine("Botnet", 0.95, firewall=fw)
    engine.handle_flows(closed_flow(ME, ATTACKER))
    r, = records
    assert (r["src_ip"], r["src_port"], r["dst_ip"], r["dst_port"]) == (ATTACKER, 80, ME, 40000)
    assert fw.calls == [ATTACKER]                                    # never this machine


def test_model_alone_needs_several_attack_flows_before_blocking():
    fw = FakeFirewall()
    engine, records, _ = make_engine("PortScan", 0.99, firewall=fw, min_flows=3)
    engine.throttle = AlertThrottle(window=0)                        # look at every record

    engine.handle_flows(closed_flow(ATTACKER, ME, t=0.0))            # a single flow: could be a stray probe
    engine.handle_flows(closed_flow(ATTACKER, ME, t=1.0))
    assert [r["action"] for r in records] == ["alert_only", "alert_only"] and fw.calls == []

    engine.handle_flows(closed_flow(ATTACKER, ME, t=2.0))            # third within the window
    assert records[-1]["action"] == "blocked" and fw.calls == [ATTACKER]


def test_attack_flows_outside_the_window_do_not_add_up():
    fw = FakeFirewall()
    engine, records, _ = make_engine("PortScan", 0.99, firewall=fw, min_flows=3)
    engine.throttle = AlertThrottle(window=0)
    for t in (0.0, 30.0, 60.0):                                      # 30 s apart; the window is 10 s
        engine.handle_flows(closed_flow(ATTACKER, ME, t=t))
    assert [r["action"] for r in records] == ["alert_only"] * 3 and fw.calls == []


def test_flow_count_is_per_source_and_does_not_delay_rules():
    fw = FakeFirewall()
    engine, records, _ = make_engine("PortScan", 0.99, firewall=fw, min_flows=3)
    engine.throttle = AlertThrottle(window=0)
    engine.handle_flows(closed_flow(ATTACKER, ME, t=0.0))
    engine.handle_flows(closed_flow("203.0.113.5", ME, t=0.5))
    engine.handle_flows(closed_flow("203.0.113.6", ME, t=1.0))
    assert fw.calls == []                                            # three sources, one flow each

    engine.handle_rule_hit(port_scan_hit(t=1.5))                     # a rule blocks at once
    assert records[-1]["action"] == "blocked" and fw.calls == [ATTACKER]


def test_model_only_low_confidence_is_alert_only():
    fw = FakeFirewall()
    engine, records, _ = make_engine("DDoS", 0.6, firewall=fw)
    engine.handle_flows(closed_flow(ATTACKER, ME))
    assert records[0]["action"] == "alert_only" and fw.calls == []


def test_rule_only_record():
    engine, records, _ = make_engine("Benign", detect_only=True)
    engine.handle_rule_hit(port_scan_hit())
    r, = records
    assert (r["label"], r["trigger"], r["action"], r["confidence"]) == ("PortScan", "rule", "detect_only", None)
    assert r["evidence"] == [{"feature": "distinct ports in 5 s", "value": 21}]
    assert (r["src_ip"], r["dst_ip"], r["protocol"]) == (ATTACKER, ME, "TCP")


def test_rule_then_model_gives_both():
    engine, records, clock = make_engine("PortScan", 0.55)
    engine.handle_rule_hit(port_scan_hit())
    clock.now += 6                                                     # past the throttle window
    engine.handle_flows(closed_flow(ATTACKER, ME, t=1))
    assert [r["trigger"] for r in records] == ["rule", "both"]
    both = records[1]
    assert both["action"] == "blocked" and both["confidence"] == 0.55   # rule fired: blocks at any confidence
    assert both["evidence"] == [{"feature": "distinct ports in 5 s", "value": 21},
                                {"feature": "Flow Packets/s", "value": 2100.5}]


def test_model_then_rule_gives_both():
    engine, records, clock = make_engine("DoS", 0.7)
    engine.handle_flows(closed_flow(ATTACKER, ME))
    clock.now += 6
    engine.handle_rule_hit(port_scan_hit(t=2))
    assert [(r["trigger"], r["label"]) for r in records] == [("model", "DoS"), ("both", "DoS")]


def test_correlation_window_expires():
    engine, records, clock = make_engine("DoS", 0.7)
    engine.handle_flows(closed_flow(ATTACKER, ME))
    clock.now += 60
    engine.handle_rule_hit(port_scan_hit(t=60))
    assert [r["trigger"] for r in records] == ["model", "rule"]


def test_whitelisted_source():
    fw = FakeFirewall()
    engine, records, _ = make_engine("DoS", 0.99, whitelist={ATTACKER}, firewall=fw)
    engine.handle_flows(closed_flow(ATTACKER, ME))
    assert records[0]["action"] == "whitelisted" and fw.calls == []


def test_repeated_detections_are_throttled_then_released_by_tick():
    engine, records, clock = make_engine("DoS", 0.99, detect_only=True)
    for i in range(5):
        engine.handle_flows(closed_flow(ATTACKER, ME, t=i * 0.1))
    assert [r["packet_count"] for r in records] == [2]
    assert engine.stats.attacks == 5

    clock.now += 5
    engine.tick()
    assert [r["packet_count"] for r in records] == [2, 8]


def test_every_record_is_strict_json():
    engine, records, _ = make_engine("DoS", 0.99)
    engine.handle_flows(closed_flow(ATTACKER, ME))
    engine.handle_rule_hit(port_scan_hit(t=30))
    for r in records:
        assert list(r) == CONTRACT_FIELDS
        json.dumps(r, allow_nan=False)


def test_stats_snapshot_keeps_dashboard_names():
    stats = Stats(blocked_ips=lambda: {"1.2.3.4"})
    stats.packets, stats.flows, stats.attacks = 100, 10, 3
    snap = stats.snapshot()
    assert {"totalPackets", "totalAttacks", "blockedIPs", "threatLevel", "updatedAt"} <= set(snap)
    assert (snap["totalPackets"], snap["totalAttacks"], snap["blockedIPs"], snap["threatLevel"]) == (100, 3, 1, 30.0)
