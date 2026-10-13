"""
seed_firestore.py — sample data for dashboard development
========================================================
    python python-engine/tools/seed_firestore.py           # write the sample documents
    python python-engine/tools/seed_firestore.py --clear   # delete them again

Writes about 30 threat records covering every label, trigger and action, a few
audit entries and a stats/live document, so the dashboard can be built and shown
without the engine running. Every document carries "seeded": true and an ID
starting with "seed-", and --clear removes exactly those.

The addresses are from ranges reserved for documentation; none is a real host.
"""

import os
import random
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ai                                   # noqa: E402
from config import ACTIVE_MODEL, FIREBASE_CRED   # noqa: E402

VICTIM = "192.168.1.4"
SOURCES = ["198.51.100.42", "198.51.100.77", "203.0.113.9", "203.0.113.150", "192.0.2.61", "192.0.2.200"]

# label → (trigger, confidence, protocol, destination port, packet count, evidence)
SHAPES = {
    "PortScan":   [("both", 0.99, "TCP", 445, 312, [{"feature": "distinct ports in 5 s", "value": 38},
                                                    {"feature": "Flow Packets/s", "value": 21276.6}]),
                   ("model", 0.97, "TCP", 3389, 2, [{"feature": "Flow Packets/s", "value": 25000.0}]),
                   ("rule", None, "TCP", 22, 41, [{"feature": "distinct ports in 5 s", "value": 41}])],
    "SynFlood":   [("rule", None, "TCP", 80, 2400, [{"feature": "SYNs without ACK in 2 s", "value": 1180}])],
    "IcmpFlood":  [("rule", None, "ICMP", None, 1500, [{"feature": "ICMP packets in 2 s", "value": 640}])],
    "DoS":        [("model", 0.98, "TCP", 80, 14, [{"feature": "Bwd Packet Length Mean", "value": 1932.5},
                                                   {"feature": "Flow IAT Max", "value": 98600000.0}]),
                   ("model", 0.74, "TCP", 8080, 9, [{"feature": "Packet Length Std", "value": 2303.5}])],
    "DDoS":       [("model", 0.99, "TCP", 80, 8, [{"feature": "Total Length of Bwd Packets", "value": 11601.0},
                                                  {"feature": "Bwd Packet Length Max", "value": 5840.0}])],
    "BruteForce": [("model", 0.96, "TCP", 22, 41, [{"feature": "Total Fwd Packets", "value": 22},
                                                   {"feature": "Flow Duration", "value": 11894120.0}]),
                   ("model", 0.81, "TCP", 21, 17, [{"feature": "Fwd IAT Mean", "value": 1486765.0}])],
    "Botnet":     [("model", 0.62, "TCP", 8080, 7, [{"feature": "Flow IAT Std", "value": 41200000.0}])],
}


def build(now: datetime) -> list:
    rng = random.Random(42)
    records = []
    labels = [label for label, shapes in SHAPES.items() for _ in range(4)]
    rng.shuffle(labels)
    for i, label in enumerate(labels[:30]):
        trigger, confidence, protocol, port, packets, evidence = rng.choice(SHAPES[label])
        if trigger == "model" and confidence < 0.90:
            action = "alert_only"
        else:
            action = rng.choice(["blocked", "blocked", "blocked", "detect_only", "whitelisted", "unblocked"])
        when = now - timedelta(minutes=7 * i + rng.randint(0, 5))
        record = {
            "timestamp": when.strftime("%Y-%m-%dT%H:%M:%SZ"), "created_at": when,
            "src_ip": rng.choice(SOURCES), "src_port": None if protocol == "ICMP" else rng.randint(1024, 65000),
            "dst_ip": VICTIM, "dst_port": port, "protocol": protocol,
            "label": label, "confidence": confidence, "trigger": trigger, "action": action,
            "packet_count": packets, "evidence": evidence, "seeded": True,
        }
        if i % 9 != 4:                              # a few are left without one, as while it is being written
            record["explanation"] = ai.offline_explanation(label)
        records.append((f"seed-{i:02d}", record))
    return records


def main() -> int:
    import firebase_admin
    from firebase_admin import credentials, firestore

    firebase_admin.initialize_app(credentials.Certificate(FIREBASE_CRED))
    db = firestore.client()

    removed = 0
    for collection in ("threats", "audit"):
        for doc in db.collection(collection).list_documents():
            if doc.id.startswith("seed-"):
                doc.delete()
                removed += 1
    stats = db.collection("stats").document("live")
    snapshot = stats.get()
    if snapshot.exists and (snapshot.to_dict() or {}).get("seeded"):
        stats.delete()
        removed += 1
    if "--clear" in sys.argv:
        print(f"Removed {removed} seeded document(s).")
        return 0

    now = datetime.now(timezone.utc)
    records = build(now)
    batch = db.batch()
    for doc_id, record in records:
        batch.set(db.collection("threats").document(doc_id), record)
    blocked = [r for _, r in records if r["action"] in ("blocked", "unblocked")]
    for i, record in enumerate(blocked[:6]):
        unblocked = record["action"] == "unblocked"
        batch.set(db.collection("audit").document(f"seed-{i:02d}"), {
            "timestamp": record["timestamp"], "created_at": record["created_at"],
            "actor": "seed-admin" if unblocked else "engine",
            "actor_email": "admin@example.com" if unblocked else None,
            "event": "unblock" if unblocked else "block", "ip": record["src_ip"],
            "detail": f"Firewall rule for {record['src_ip']} removed" if unblocked
                      else f"{record['label']} (trigger: {record['trigger']})",
            "seeded": True,
        })
    if snapshot.exists and not (snapshot.to_dict() or {}).get("seeded"):
        print("stats/live belongs to a real engine run; left untouched.")
    else:
        batch.set(stats, {
            "total_packets": 184_220, "total_flows": 9_431, "total_attacks": len(records),
            "blocked_ips": len({r["src_ip"] for _, r in records if r["action"] == "blocked"}),
            "detect_only": False, "model_version": ACTIVE_MODEL, "updated_at": now, "seeded": True,
        })
    batch.commit()
    print(f"Wrote {len(records)} sample threats, {min(len(blocked), 6)} audit entries and stats/live.")
    print("Remove them with:  python python-engine/tools/seed_firestore.py --clear")
    return 0


if __name__ == "__main__":
    sys.exit(main())
