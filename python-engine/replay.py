"""
replay.py — Offline replay and demo export for CyberSentinel
===========================================================
Produces threat records (PART_A_DETECTION_ENGINE.md section 5) without live
capture, Administrator rights or the firewall, using the real model, rules and
decision logic of the engine.

Two sources of traffic:

  CSV mode        If the CICIDS2017 MachineLearningCVE CSVs are present
                  (training/data/MachineLearningCVE/*.csv), dataset rows are
                  classified by the real model and detections become records.

  Synthetic mode  Otherwise, scripted attack scenarios (port scan, SYN flood,
                  ICMP flood, HTTP DoS, slow DoS, DDoS, SSH/FTP brute force,
                  botnet beacons) are generated packet by packet and run through
                  the real FlowTracker, RuleEngine, model and DetectionEngine.

Rule detections (SynFlood, IcmpFlood, PortScan rule) always come from synthetic
packet bursts, because the CSVs contain flows, not packets.

Labels, confidences and evidence are whatever the engine decides. IP addresses
and source ports are always synthetic (documentation ranges); the CSVs carry no
addresses. In CSV mode the destination port comes from the dataset row.

Usage:
    python replay.py                                            # print a summary
    python replay.py --export ../frontend/public/demo/replay.json
"""

import argparse
import glob
import json
import math
import os
import random
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

from config import ACTIVE_MODEL, REPO_ROOT, BLOCK_CONFIDENCE, BENIGN_LABEL
from classifier import ThreatClassifier
from detector import AlertThrottle, DetectionEngine, decide, is_reportable, make_threat, resolve_action
from feature_extractor import FlowTracker, PacketInfo
from rules import RuleEngine
from ai import offline_explanation

DEFAULT_DATA_DIR = os.path.join(REPO_ROOT, "training", "data", "MachineLearningCVE")
VICTIM = "192.168.1.4"

# CICIDS2017 original label → model class (same mapping as train_cicids2017.ipynb)
CLASS_MAP = {
    "BENIGN": "Benign",
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS", "DoS slowloris": "DoS", "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
    "Bot": "Botnet",
}


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic addresses
# ─────────────────────────────────────────────────────────────────────────────

class AddressPool:
    """Distinct attacker IPs from the documentation ranges (RFC 5737)."""

    def __init__(self, rng: random.Random):
        self._ips = [f"{net}.{host}" for net in ("198.51.100", "203.0.113", "192.0.2")
                     for host in range(2, 255)]
        rng.shuffle(self._ips)

    def next(self) -> str:
        return self._ips.pop()


def ephemeral(rng: random.Random) -> int:
    return rng.randint(49152, 65535)


def simulated_firewall():
    """A stand-in for blocker.block_ip() with the same statuses. The firewall is never touched."""
    blocked = set()

    def block(ip):
        if ip in blocked:
            return "already_blocked"
        blocked.add(ip)
        return "blocked"
    return block


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic scenarios: each returns a list of PacketInfo starting at time t0
# ─────────────────────────────────────────────────────────────────────────────

def _tcp(ts, src, dst, sport, dport, size=0, *, syn=False, ack=True, fin=False, rst=False):
    return PacketInfo(ts, src, dst, sport, dport, "TCP", size, syn=syn, ack=ack, fin=fin, rst=rst)


def _conversation(t, client, server, cport, sport, steps, *, rtt, closer="client"):
    """
    One TCP connection: handshake, then steps of (sender, payload bytes, pause before),
    where sender is "c" or "s"; the other side ACKs each data packet. Ends with a FIN
    from `closer` ("client", "server" or None to leave it open). Returns (packets, end time).
    """
    def c(ts, n=0, **f):
        return _tcp(ts, client, server, cport, sport, n, **f)

    def s(ts, n=0, **f):
        return _tcp(ts, server, client, sport, cport, n, **f)

    pk = [c(t, syn=True, ack=False), s(t + rtt / 2, syn=True), c(t + rtt)]
    t += rtt
    for sender, size, pause in steps:
        t += pause
        pk.append(c(t, size) if sender == "c" else s(t, size))
        t += rtt / 2
        pk.append(s(t) if sender == "c" else c(t))
    if closer:
        t += rtt / 2
        pk.append(c(t, fin=True) if closer == "client" else s(t, fin=True))
    return pk, t


def _web_page(rng):
    """A ~11.6 kB page as captured with segmentation offload (two large segments)."""
    return [("s", 5840, 0.0005), ("s", rng.randint(5600, 5800), 0.0002)]


def scenario_port_scan(rng, t0, attacker):
    """SYN scan of many ports: closed ports answer RST, open ones SYN-ACK."""
    ports = rng.sample(range(1, 10000), rng.randint(40, 150))
    open_ports = set(rng.sample(ports, 3))
    pk, t = [], t0
    for port in ports:
        sport = ephemeral(rng)
        t += rng.uniform(0.002, 0.02)
        pk.append(_tcp(t, attacker, VICTIM, sport, port, syn=True, ack=False))
        if port in open_ports:
            pk.append(_tcp(t + 0.0003, VICTIM, attacker, port, sport, syn=True))
            pk.append(_tcp(t + 0.0006, attacker, VICTIM, sport, port, rst=True, ack=False))
        else:
            pk.append(_tcp(t + 0.0002, VICTIM, attacker, port, sport, rst=True))
    return pk


def scenario_syn_flood(rng, t0, attacker):
    """Half-open connections to port 80 as fast as possible."""
    pk, t = [], t0
    for _ in range(rng.randint(200, 600)):
        t += rng.uniform(0.0005, 0.004)
        sport = ephemeral(rng)
        pk.append(_tcp(t, attacker, VICTIM, sport, 80, syn=True, ack=False))
        pk.append(_tcp(t + 0.0003, VICTIM, attacker, 80, sport, syn=True))
    return pk


def scenario_icmp_flood(rng, t0, attacker):
    """Ping flood; the victim answers every echo request."""
    size = rng.choice([56, 1472])
    pk, t = [], t0
    for _ in range(rng.randint(200, 500)):
        t += rng.uniform(0.001, 0.006)
        pk.append(PacketInfo(t, attacker, VICTIM, None, None, "ICMP", size))
        pk.append(PacketInfo(t + 0.0002, VICTIM, attacker, None, None, "ICMP", size))
    return pk


def scenario_http_dos(rng, t0, attacker):
    """HULK: many connections, each a GET with long random parameters for the whole page."""
    pk, t = [], t0
    for _ in range(rng.randint(15, 40)):
        t += rng.uniform(0.005, 0.05)
        steps = [("c", rng.randint(300, 420), 0.0005)] + _web_page(rng)
        conn, _ = _conversation(t, attacker, VICTIM, ephemeral(rng), 80, steps,
                                rtt=rng.uniform(0.0005, 0.005), closer="server")
        pk += conn
    return pk


def scenario_slow_dos(rng, t0, attacker):
    """Slowloris: connections kept open with a few header bytes every few seconds."""
    pk, t = [], t0
    for _ in range(rng.randint(5, 12)):
        t += rng.uniform(0.01, 0.2)
        steps = [("c", rng.randint(200, 260), 0.001)] + \
                [("c", rng.randint(5, 20), rng.uniform(5, 12)) for _ in range(rng.randint(4, 9))]
        conn, _ = _conversation(t, attacker, VICTIM, ephemeral(rng), 80, steps, rtt=0.03, closer=None)
        pk += conn
    return pk


def scenario_ddos(rng, t0, attackers):
    """LOIC HTTP flood from several sources: short fixed GETs for the whole page."""
    pk = []
    for attacker in attackers:
        t = t0 + rng.uniform(0, 0.5)
        for _ in range(rng.randint(3, 8)):
            t += rng.uniform(0.01, 0.3)
            steps = [("c", 20, 0.0005)] + _web_page(rng)
            conn, _ = _conversation(t, attacker, VICTIM, ephemeral(rng), 80, steps,
                                    rtt=rng.uniform(0.0005, 0.005), closer="server")
            pk += conn
    return pk


def scenario_ssh_bruteforce(rng, t0, attacker):
    """SSH-Patator: key exchange, then a few password guesses per connection."""
    pk, t = [], t0
    for _ in range(rng.randint(4, 10)):
        t += rng.uniform(0.2, 1.0)
        steps = [("s", rng.randint(21, 41), 0.01), ("c", rng.randint(21, 41), 0.01),
                 ("c", rng.randint(1000, 1400), 0.01), ("s", rng.randint(900, 1100), 0.01),
                 ("c", 48, 0.01), ("s", rng.randint(250, 300), 0.02), ("c", 16, 0.01)]
        for _ in range(rng.randint(2, 6)):
            steps += [("c", rng.randint(60, 100), rng.uniform(0.2, 2.5)), ("s", rng.randint(30, 60), 0.01)]
        conn, t = _conversation(t, attacker, VICTIM, ephemeral(rng), 22, steps, rtt=0.004)
        pk += conn
    return pk


def scenario_ftp_bruteforce(rng, t0, attacker):
    """FTP-Patator: three USER/PASS guesses per connection, ~3 s failure delay, server hangs up."""
    pk, t = [], t0
    for _ in range(rng.randint(4, 10)):
        t += rng.uniform(0.05, 0.4)
        steps = [("s", rng.randint(20, 60), 0.001)]
        for _ in range(3):
            steps += [("c", rng.randint(10, 16), 0.001), ("s", 34, 0.001),
                      ("c", rng.randint(10, 18), 0.001), ("s", 22, rng.uniform(2.5, 3.5))]
        conn, t = _conversation(t, attacker, VICTIM, ephemeral(rng), 21, steps,
                                rtt=rng.uniform(0.0005, 0.005), closer="server")
        pk += conn
    return pk


def scenario_botnet(rng, t0, attacker):
    """Ares-style bot on this machine polling its command server on port 8080."""
    pk, t = [], t0
    for _ in range(rng.randint(4, 10)):
        t += rng.uniform(1.0, 6.0)
        steps = [("c", rng.randint(180, 330), 0.001), ("s", rng.randint(120, 260), 0.05)]
        conn, t = _conversation(t, VICTIM, attacker, ephemeral(rng), 8080, steps,
                                rtt=rng.uniform(0.04, 0.2))
        pk += conn
    return pk


SCENARIOS = {
    "port_scan": scenario_port_scan,
    "syn_flood": scenario_syn_flood,
    "icmp_flood": scenario_icmp_flood,
    "http_dos": scenario_http_dos,
    "slow_dos": scenario_slow_dos,
    "ddos": scenario_ddos,
    "ssh_bruteforce": scenario_ssh_bruteforce,
    "ftp_bruteforce": scenario_ftp_bruteforce,
    "botnet": scenario_botnet,
}


class _SimClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def run_synthetic(classifier, rng, rounds: int, detect_only: bool) -> list:
    """Run every scenario `rounds` times through the real engine. Returns threat records."""
    records = []
    clock = _SimClock()
    engine = DetectionEngine(
        classifier, records.append, local_ips={VICTIM},
        detect_only=detect_only, block_confidence=BLOCK_CONFIDENCE,
        is_whitelisted=lambda ip: False, block_ip=simulated_firewall(),
        model_block_min_flows=1,          # each dataset row is one isolated flow
        throttle=AlertThrottle(), clock=clock,
    )
    tracker = FlowTracker()
    rules = RuleEngine(local_ips={VICTIM})
    pool = AddressPool(rng)

    t = datetime(2026, 10, 12, 9, 0, tzinfo=timezone.utc).timestamp()
    for _ in range(rounds):
        for name, scenario in SCENARIOS.items():
            if name == "ddos":
                packets = scenario(rng, t, [pool.next() for _ in range(rng.randint(4, 8))])
            else:
                packets = scenario(rng, t, pool.next())
            for pkt in sorted(packets, key=lambda p: p.ts):
                clock.now = pkt.ts
                new_flow, closed = tracker.add_packet(pkt)
                for hit in rules.observe(pkt, new_flow):
                    engine.handle_rule_hit(hit)
                if closed:
                    engine.handle_flows(closed)
            # Let every flow of this scenario go idle, as the live sweeper would
            t = clock.now = max(p.ts for p in packets) + 60
            engine.handle_flows(tracker.sweep(clock.now))
            rules.prune(clock.now)
            engine.tick()
    return records


# ─────────────────────────────────────────────────────────────────────────────
# CSV mode
# ─────────────────────────────────────────────────────────────────────────────

def run_csv(classifier, rng, data_dir: str, per_class: int, detect_only: bool) -> list:
    """Classify a sample of dataset rows per class and turn detections into records."""
    import numpy as np
    import pandas as pd

    files = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    wanted = set(classifier.features) | {"Label", "Destination Port"}
    parts = []
    for f in files:
        d = pd.read_csv(f, encoding="latin-1", usecols=lambda c: c.strip() in wanted)
        d.columns = [c.strip() for c in d.columns]
        d["class"] = d["Label"].map(CLASS_MAP)
        parts.append(d[d["class"].notna() & (d["class"] != BENIGN_LABEL)])
    rows = pd.concat(parts, ignore_index=True)
    rows[classifier.features] = rows[classifier.features].replace([np.inf, -np.inf], np.nan)
    rows = rows[rows["Flow Duration"] >= 0]
    sample = pd.concat([group.sample(n=min(len(group), per_class), random_state=rng.randint(0, 2**31 - 1))
                        for _, group in rows.groupby("class")])

    vectors = sample[classifier.features].astype(float).values.tolist()
    verdicts = classifier.classify_many(vectors)
    pool = AddressPool(rng)
    block = simulated_firewall()
    records = []
    t = datetime(2026, 10, 12, 9, 0, tzinfo=timezone.utc).timestamp()
    for (_, row), vector, (label, confidence) in zip(sample.iterrows(), vectors, verdicts):
        if not is_reportable(classifier, label, confidence):     # same filter as the live engine
            continue
        src_ip = pool.next()
        trigger, action = decide(False, True, confidence, BLOCK_CONFIDENCE)
        action = resolve_action(action, src_ip, detect_only=detect_only,
                                is_whitelisted=lambda ip: False, block_ip=block)
        port = row.get("Destination Port")
        dst_port = None if port is None or math.isnan(port) else int(port)
        # The CSVs have no protocol column; every attack class of the model is TCP in CICIDS2017
        records.append(make_threat(
            ts=t, src_ip=src_ip, src_port=ephemeral(rng),
            dst_ip=VICTIM, dst_port=dst_port, protocol="TCP", label=label, confidence=confidence,
            trigger=trigger, action=action,
            packet_count=int(row["Total Fwd Packets"] + row["Total Backward Packets"]),
            evidence=classifier.evidence(vector),
        ))
    return records


# ─────────────────────────────────────────────────────────────────────────────
# Balancing and export
# ─────────────────────────────────────────────────────────────────────────────

def balance(records: list, count: int, rng: random.Random) -> list:
    """
    Pick about `count` records spread as evenly as possible across labels. Within a
    label, rarer (trigger, action) combinations are picked first so the demo shows them.
    """
    by_label = defaultdict(list)
    for r in records:
        by_label[r["label"]].append(r)
    for group in by_label.values():
        rng.shuffle(group)
        combos = Counter((r["trigger"], r["action"]) for r in group)
        group.sort(key=lambda r: combos[(r["trigger"], r["action"])], reverse=True)   # pop() takes the rarest

    picked = []
    labels = sorted(by_label)
    while len(picked) < count and any(by_label.values()):
        for label in labels:
            if by_label[label] and len(picked) < count:
                picked.append(by_label[label].pop())
    rng.shuffle(picked)
    return picked


def build_export(records: list, rng: random.Random, start: datetime) -> dict:
    """Wrap records in the replay format, re-timing them along one demo timeline.

    Each record gets the offline explanation for its label (ai.offline_explanation).
    """
    events = []
    t = start.timestamp()
    for record in records:
        delay_ms = rng.randint(600, 2500)
        t += delay_ms / 1000
        # The demo has no engine to generate explanations later, so ship the offline one
        threat = {**record, "timestamp": _iso(t), "explanation": offline_explanation(record["label"])}
        events.append({"delay_ms": delay_ms, "threat": threat})
    return {
        "model_version": ACTIVE_MODEL,
        "generated_at": _iso(start.timestamp()),
        "events": events,
    }


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay CICIDS2017 rows or synthetic attack traffic through the real "
                    "CyberSentinel model, rules and decision logic, and optionally export a demo file.",
        epilog="IP addresses in every record are synthetic (RFC 5737 documentation ranges): "
               "the CICIDS2017 CSVs contain no addresses, and synthetic traffic has none to begin with. "
               "The firewall is never touched.",
    )
    parser.add_argument("--export", metavar="PATH", help="write a replay JSON file for the dashboard demo")
    parser.add_argument("--count", type=int, default=84, help="number of events to export (60-100, default 84)")
    parser.add_argument("--data", default=DEFAULT_DATA_DIR, help="folder with the CICIDS2017 MachineLearningCVE CSVs")
    parser.add_argument("--synthetic", action="store_true", help="use synthetic traffic even if the CSVs exist")
    parser.add_argument("--detect-only", action="store_true", help="mark would-be blocks as detect_only")
    parser.add_argument("--seed", type=int, default=42, help="random seed (default 42)")
    args = parser.parse_args(argv)

    if not 60 <= args.count <= 100:
        parser.error("--count must be between 60 and 100")

    rng = random.Random(args.seed)
    classifier = ThreatClassifier()

    use_csv = not args.synthetic and glob.glob(os.path.join(args.data, "*.csv"))
    if use_csv:
        print(f"[REPLAY] CSV mode: {args.data}")
        records = run_csv(classifier, rng, args.data, per_class=60, detect_only=args.detect_only)
        records += [r for r in run_synthetic(classifier, rng, rounds=12, detect_only=args.detect_only)
                    if r["trigger"] != "model"]
    else:
        print("[REPLAY] Synthetic mode (CICIDS2017 CSVs not found)" if not args.synthetic
              else "[REPLAY] Synthetic mode")
        records = run_synthetic(classifier, rng, rounds=14, detect_only=args.detect_only)

    print(f"[REPLAY] {len(records)} records produced")
    for (label, trigger, action), n in sorted(Counter((r["label"], r["trigger"], r["action"]) for r in records).items()):
        print(f"    {label:<11s} trigger={trigger:<5s} action={action:<11s} {n}")
    missing = sorted(set(classifier.classes) - {BENIGN_LABEL} - {r["label"] for r in records})
    if missing:
        print(f"[REPLAY] No detections of: {', '.join(missing)}")

    if not args.export:
        return 0

    picked = balance(records, args.count, rng)
    if len(picked) < 60:
        print(f"[REPLAY] Only {len(picked)} records available; at least 60 are needed for an export.")
        return 1
    export = build_export(picked, rng, datetime.now(timezone.utc).replace(microsecond=0))
    os.makedirs(os.path.dirname(os.path.abspath(args.export)), exist_ok=True)
    with open(args.export, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2)
        f.write("\n")
    print(f"[REPLAY] Wrote {len(picked)} events to {args.export}")
    print("    " + ", ".join(f"{k}: {v}" for k, v in sorted(Counter(r["label"] for r in picked).items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
