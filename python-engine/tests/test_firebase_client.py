"""Firestore link: threat storage, throttled stats, audit entries and unblock commands."""

from datetime import datetime, timezone

import pytest

from fake_firestore import SERVER_TS, FakeFirestore
from firebase_client import CloudStore

T0 = 1_760_000_000.0
ADMIN, VIEWER = "uid-admin", "uid-viewer"
ATTACKER = "198.51.100.42"

THREAT = {
    "timestamp": "2026-10-12T14:03:22Z", "src_ip": ATTACKER, "src_port": 51544,
    "dst_ip": "192.168.1.4", "dst_port": 80, "protocol": "TCP", "label": "PortScan",
    "confidence": 0.97, "trigger": "both", "action": "blocked", "packet_count": 40,
    "evidence": [{"feature": "distinct ports in 5 s", "value": 38}],
}


class Clock:
    now = T0

    def __call__(self):
        return self.now


class Firewall:
    def __init__(self, result=True):
        self.result = result
        self.calls = []

    def __call__(self, ip):
        self.calls.append(ip)
        return self.result


@pytest.fixture
def setup():
    db = FakeFirestore()
    db.add("users", {"email": "admin@example.com", "role": "admin"}, ADMIN)
    db.add("users", {"email": "viewer@example.com", "role": "viewer"}, VIEWER)
    clock, firewall = Clock(), Firewall()
    store = CloudStore(db, unblock=firewall, clock=clock, server_timestamp=SERVER_TS,
                       stats_interval=60, command_max_age=300, detect_only=False, model_version="v1")
    return store, db, clock, firewall


def when(seconds_ago, clock):
    return datetime.fromtimestamp(clock.now - seconds_ago, tz=timezone.utc)


def command(db, clock, *, ip=ATTACKER, by=ADMIN, action="unblock", status="pending", age=1):
    return db.add("commands", {"action": action, "ip": ip, "requested_by": by,
                               "requested_at": when(age, clock), "status": status})


# ── threats ───────────────────────────────────────────────────────────────────

def test_store_threat_returns_id_at_once_and_writes_in_the_background(setup):
    store, db, _, _ = setup
    doc_id = store.store_threat(THREAT)
    assert doc_id and db.docs("threats") == {}                 # nothing written on the caller's thread

    store.drain()
    assert db.docs("threats")[doc_id] == {**THREAT, "created_at": SERVER_TS}


def test_explanation_is_added_to_the_stored_threat(setup):
    store, db, _, _ = setup
    doc_id = store.store_threat(THREAT)
    explanation = {"severity": "HIGH", "summary": "s", "mechanism": "m", "recommendation": "r", "source": "ai"}
    store.update_explanation(doc_id, explanation)
    store.drain()
    assert db.docs("threats")[doc_id]["explanation"] == explanation
    assert db.docs("threats")[doc_id]["label"] == "PortScan"   # the rest of the record is untouched


def test_a_failing_network_never_raises(setup):
    store, db, _, _ = setup
    db.fail = True
    store.store_threat(THREAT)
    store.update_stats({"totalPackets": 1}, force=True)
    store.write_audit("block", ATTACKER)
    assert store.drain() == 3                                  # all attempted, all swallowed
    assert db.docs("threats") == {} and db.docs("audit") == {}


def test_full_queue_drops_the_write_instead_of_blocking():
    store = CloudStore(FakeFirestore(), server_timestamp=SERVER_TS, queue_size=2)
    assert store.store_threat(THREAT) and store.store_threat(THREAT)
    assert store.store_threat(THREAT) is None


# ── stats ─────────────────────────────────────────────────────────────────────

SNAPSHOT = {"totalPackets": 900, "totalFlows": 120, "totalAttacks": 3, "blockedIPs": 1,
            "threatLevel": 2.5, "updatedAt": "ignored"}


def test_stats_use_the_contract_field_names(setup):
    store, db, _, _ = setup
    assert store.update_stats(SNAPSHOT) is True
    store.drain()
    assert db.docs("stats")["live"] == {
        "total_packets": 900, "total_flows": 120, "total_attacks": 3, "blocked_ips": 1,
        "detect_only": False, "model_version": "v1", "updated_at": SERVER_TS,
    }


def test_stats_are_written_at_most_once_a_minute(setup):
    store, _, clock, _ = setup
    writes = 0
    for second in range(0, 181, 3):                            # the engine publishes every 3 seconds
        clock.now = T0 + second
        writes += store.update_stats(SNAPSHOT)
    assert writes == 4                                         # at 0, 60, 120 and 180 seconds


def test_forced_stats_ignore_the_throttle(setup):
    store, _, _, _ = setup
    assert store.update_stats(SNAPSHOT) and not store.update_stats(SNAPSHOT)
    assert store.update_stats(SNAPSHOT, force=True)


# ── audit ─────────────────────────────────────────────────────────────────────

def test_audit_entry_fields(setup):
    store, db, _, _ = setup
    store.write_audit("block", ATTACKER, detail="PortScan (trigger: both)")
    store.drain()
    entry, = db.docs("audit").values()
    assert entry == {"timestamp": "2025-10-09T08:53:20Z", "created_at": SERVER_TS, "actor": "engine",
                     "actor_email": None, "event": "block", "ip": ATTACKER, "detail": "PortScan (trigger: both)"}


# ── unblock commands ──────────────────────────────────────────────────────────

def run(store, db, cmd_id):
    return store.handle_command(cmd_id, db.docs("commands")[cmd_id])


def test_admin_unblock_removes_rule_updates_threats_and_audits(setup):
    store, db, clock, firewall = setup
    blocked = db.add("threats", dict(THREAT))
    other = db.add("threats", {**THREAT, "src_ip": "203.0.113.9"})
    alert = db.add("threats", {**THREAT, "action": "alert_only"})
    cmd = command(db, clock)

    assert run(store, db, cmd) == "done"
    store.drain()

    assert firewall.calls == [ATTACKER]
    assert db.docs("commands")[cmd]["status"] == "done"
    assert db.docs("commands")[cmd]["completed_at"] == SERVER_TS
    assert db.docs("threats")[blocked]["action"] == "unblocked"
    assert db.docs("threats")[blocked]["unblocked_by"] == ADMIN
    assert db.docs("threats")[other]["action"] == "blocked"          # a different source
    assert db.docs("threats")[alert]["action"] == "alert_only"       # was never blocked
    entry, = db.docs("audit").values()
    assert (entry["event"], entry["actor"], entry["actor_email"], entry["ip"]) == \
        ("unblock", ADMIN, "admin@example.com", ATTACKER)


@pytest.mark.parametrize("change,reason", [
    ({"by": VIEWER}, "not an admin"),
    ({"by": "uid-nobody"}, "not an admin"),                         # no users document at all
    ({"by": ""}, "no requester"),
    ({"ip": "not-an-ip"}, "valid IP"),
    ({"ip": "1.2.3.4; del C:\\"}, "valid IP"),
    ({"ip": None}, "valid IP"),
    ({"action": "block"}, "Unknown action"),
    ({"age": 301}, "expired"),
])
def test_refused_commands_never_touch_the_firewall(setup, change, reason):
    store, db, clock, firewall = setup
    cmd = command(db, clock, **change)

    assert run(store, db, cmd) == "failed"
    store.drain()

    assert firewall.calls == []
    assert db.docs("commands")[cmd]["status"] == "failed"
    assert reason in db.docs("commands")[cmd]["message"]
    entry, = db.docs("audit").values()
    assert entry["event"] == "unblock_failed"


def test_role_field_must_be_lowercase_role(setup):
    store, db, clock, firewall = setup
    db.add("users", {"email": "x@example.com", "Role": "admin"}, "uid-typo")
    cmd = command(db, clock, by="uid-typo")
    assert run(store, db, cmd) == "failed" and firewall.calls == []


def test_firewall_failure_is_reported_and_threats_stay_blocked(setup):
    store, db, clock, firewall = setup
    firewall.result = False
    threat = db.add("threats", dict(THREAT))
    cmd = command(db, clock)

    assert run(store, db, cmd) == "failed"
    assert firewall.calls == [ATTACKER]
    assert db.docs("threats")[threat]["action"] == "blocked"
    assert "No firewall rule was removed" in db.docs("commands")[cmd]["message"]


def test_commands_already_handled_are_left_alone(setup):
    store, db, clock, firewall = setup
    cmd = command(db, clock, status="done")
    assert run(store, db, cmd) == "done"
    assert firewall.calls == [] and db.docs("audit") == {}


def test_ip_is_normalised_before_use(setup):
    store, db, clock, firewall = setup
    cmd = command(db, clock, ip="  198.51.100.42 ")
    assert run(store, db, cmd) == "done" and firewall.calls == [ATTACKER]


def test_listener_queues_new_pending_commands(setup):
    store, db, clock, firewall = setup
    store.listen_for_commands()
    cmd = command(db, clock)
    db.fire_added("commands", cmd)
    assert firewall.calls == []                                # queued, not run on the listener's thread

    store.drain()
    assert firewall.calls == [ATTACKER] and db.docs("commands")[cmd]["status"] == "done"


def test_missing_requested_at_falls_back_to_creation_time(setup):
    store, db, clock, firewall = setup
    request = {"action": "unblock", "ip": ATTACKER, "requested_by": ADMIN, "status": "pending"}
    old = db.add("commands", dict(request))
    assert store.handle_command(old, dict(request), created=clock.now - 1000) == "failed"      # too old
    assert firewall.calls == []

    recent = db.add("commands", dict(request))
    assert store.handle_command(recent, dict(request), created=clock.now - 5) == "done"
