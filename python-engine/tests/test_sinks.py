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


# ── Firestore and explanations (Part B) ───────────────────────────────────────

class FakeCloud:
    def __init__(self, doc_id="doc-1"):
        self.doc_id = doc_id
        self.threats, self.audits, self.stats = [], [], []

    def store_threat(self, threat):
        self.threats.append(threat)
        return self.doc_id

    def write_audit(self, event, ip=None, **kwargs):
        self.audits.append((event, ip, kwargs.get("detail")))

    def update_stats(self, snapshot, force=False):
        self.stats.append((snapshot["totalAttacks"], force))


class FakeExplainer:
    def __init__(self):
        self.requests = []

    def request(self, doc_id, threat):
        self.requests.append((doc_id, threat["label"]))


@pytest.fixture
def cloud(monkeypatch, sent):
    fake_cloud, fake_explainer = FakeCloud(), FakeExplainer()
    monkeypatch.setattr(sinks, "_cloud", fake_cloud)
    monkeypatch.setattr(sinks, "_explainer", fake_explainer)
    return fake_cloud, fake_explainer


def test_detection_is_stored_unchanged_and_explained(cloud):
    fake_cloud, fake_explainer = cloud
    record = _record("alert_only")
    sinks.handle_detection(record)

    assert fake_cloud.threats == [record]
    assert "id" not in fake_cloud.threats[0] and "attack_type" not in fake_cloud.threats[0]
    assert fake_explainer.requests == [("doc-1", "PortScan")]
    assert fake_cloud.audits == []                              # nothing was blocked


def test_only_blocks_are_audited(cloud):
    fake_cloud, _ = cloud
    for action in ("blocked", "detect_only", "alert_only", "whitelisted"):
        sinks.handle_detection(_record(action))
    assert fake_cloud.audits == [("block", "198.51.100.42", "PortScan (trigger: both)")]


def test_no_explanation_is_requested_when_the_threat_was_not_stored(cloud):
    fake_cloud, fake_explainer = cloud
    fake_cloud.doc_id = None                                    # write queue was full
    sinks.handle_detection(_record("blocked"))
    assert fake_explainer.requests == []


def test_stats_go_to_the_cloud_with_the_force_flag(cloud, sent):
    fake_cloud, _ = cloud
    sinks.publish_stats()
    sinks.publish_stats(force=True)
    assert fake_cloud.stats == [(1, False), (1, True)]
    assert len(sent) == 2                                       # the local dashboard still gets both


def test_without_the_cloud_detections_still_reach_the_local_dashboard(sent):
    assert sinks._cloud is None
    sinks.handle_detection(_record("blocked"))
    assert len(sent) == 1
