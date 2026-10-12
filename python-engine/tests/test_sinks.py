"""sinks.handle_detection: SSE payload keeps the old dashboard fields without changing the record."""

import copy

import pytest

import sinks
from detector import make_threat


@pytest.fixture
def sent(monkeypatch):
    events = []
    monkeypatch.setattr(sinks, "broadcast_event", lambda kind, data: events.append((kind, data)))
    sinks.set_stats_provider(lambda: {"totalPackets": 5, "totalAttacks": 1, "blockedIPs": 0,
                                      "threatLevel": 20.0, "updatedAt": "now"})
    yield events
    sinks.set_stats_provider(None)


def _record(action):
    return make_threat(ts=1_760_000_000, src_ip="198.51.100.42", src_port=51544, dst_ip="192.168.1.4",
                       dst_port=80, protocol="TCP", label="PortScan", confidence=0.97, trigger="both",
                       action=action, packet_count=40,
                       evidence=[{"feature": "distinct ports in 5 s", "value": 38}])


@pytest.mark.parametrize("action,blocked", [("blocked", True), ("detect_only", False), ("alert_only", False)])
def test_sse_payload_adds_legacy_fields_only_to_the_copy(sent, action, blocked):
    record = _record(action)
    original = copy.deepcopy(record)
    sinks.handle_detection(record)

    assert record == original                                  # the record itself is untouched
    (kind, data), = sent
    assert kind == "THREAT_EVENT"
    sse = data["threat"]
    assert sse["attack_type"] == "PortScan"
    assert sse["blocked"] is blocked
    assert sse["id"].startswith("live-")
    assert {k: v for k, v in sse.items() if k not in ("id", "attack_type", "blocked")} == record
    assert data["stats"]["totalPackets"] == 5


def test_ids_are_unique(sent):
    sinks.handle_detection(_record("blocked"))
    sinks.handle_detection(_record("blocked"))
    assert sent[0][1]["threat"]["id"] != sent[1][1]["threat"]["id"]


def test_publish_stats_sends_stats_without_threat(sent):
    sinks.publish_stats()
    (kind, data), = sent
    assert kind == "THREAT_EVENT" and "threat" not in data and data["stats"]["totalAttacks"] == 1
