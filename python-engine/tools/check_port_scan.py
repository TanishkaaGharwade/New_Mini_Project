"""
check_port_scan.py — re-run the port-scan result of TRAINING_LOG.md entry 12
===========================================================================
    python python-engine/tools/check_port_scan.py

Builds real Scapy packets for two common scan styles (300 ports each, every probe
answered by a reset) and a few kinds of normal traffic, and passes them through the
engine's own parser, flow tracker and model_v1 twice:

  before  TCP length is the true payload (what the engine did before entry 12)
  after   TCP length counts short-frame padding the way CICIDS2017 does (the engine now)

Expected: the scan probes go from 0 of 600 PortScan to 600 of 600, and normal traffic
stays Benign in both runs. Synthetic packets only: no capture, no firewall, no
Administrator rights needed. The packets are generated here, so they are not the exact
packets of entry 12, but they have the same shapes.
"""

import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging

logging.disable(logging.WARNING)            # scapy and model start-up messages

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw   # noqa: E402

import feature_extractor as fx              # noqa: E402
from classifier import ThreatClassifier     # noqa: E402

ATTACKER = "198.51.100.42"                  # documentation range, never a real host
VICTIM = "192.168.1.2"
SERVER = "203.0.113.10"
DNS_SERVER = "192.168.1.1"
FULL_OPTIONS = [("MSS", 1460), ("NOP", None), ("WScale", 8), ("NOP", None), ("NOP", None), ("SAckOK", b"")]


def packet(t, ip_layer, l4):
    """A fully built packet (so header lengths are real) stamped with time t."""
    p = IP(bytes(ip_layer / l4))
    p.time = t
    return p


def scan(options):
    """One SYN to each of 300 ports, each answered by RST-ACK 150 µs later."""
    out, t = [], 1_000.0
    for i, port in enumerate(range(1, 301)):
        sport = 40_000 + i
        t += 0.002
        out.append(packet(t, IP(src=ATTACKER, dst=VICTIM),
                          TCP(sport=sport, dport=port, flags="S", seq=1000, options=options)))
        out.append(packet(t + 0.00015, IP(src=VICTIM, dst=ATTACKER),
                          TCP(sport=port, dport=sport, flags="RA", seq=0, ack=1001)))
    return out


def https_sessions(n=40):
    """Short HTTPS-like downloads from this PC: handshake, request, reply, close."""
    out, t = [], 2_000.0
    for i in range(n):
        c, s = 50_000 + i, 443
        rtt = 0.02
        t += 1.0
        steps = [
            (t, VICTIM, SERVER, c, s, "S", 0, FULL_OPTIONS),
            (t + rtt / 2, SERVER, VICTIM, s, c, "SA", 0, FULL_OPTIONS),
            (t + rtt, VICTIM, SERVER, c, s, "A", 0, []),
            (t + rtt + 0.001, VICTIM, SERVER, c, s, "PA", 517, []),
            (t + 1.5 * rtt, SERVER, VICTIM, s, c, "A", 0, []),
            (t + 1.6 * rtt, SERVER, VICTIM, s, c, "PA", 1400, []),
            (t + 1.6 * rtt + 0.0002, SERVER, VICTIM, s, c, "PA", 1400, []),
            (t + 1.6 * rtt + 0.0004, SERVER, VICTIM, s, c, "PA", 900, []),
            (t + 2.1 * rtt, VICTIM, SERVER, c, s, "A", 0, []),
            (t + 2.2 * rtt, VICTIM, SERVER, c, s, "PA", 80, []),
            (t + 2.7 * rtt, SERVER, VICTIM, s, c, "PA", 4200, []),
            (t + 3.2 * rtt, VICTIM, SERVER, c, s, "A", 0, []),
            (t + 3.3 * rtt, VICTIM, SERVER, c, s, "FA", 0, []),
        ]
        for ts, src, dst, sp, dp, flags, size, opts in steps:
            l4 = TCP(sport=sp, dport=dp, flags=flags, options=opts)
            out.append(packet(ts, IP(src=src, dst=dst), l4 / Raw(b"x" * size) if size else l4))
    return out


def dns_lookups(n=40):
    """One question and one answer each."""
    out, t = [], 3_000.0
    for i in range(n):
        t += 0.5
        q = DNS(id=i, rd=1, qd=DNSQR(qname=f"host{i}.example.com"))
        out.append(packet(t, IP(src=VICTIM, dst=DNS_SERVER), UDP(sport=52_000 + i, dport=53) / q))
        out.append(packet(t + 0.004, IP(src=DNS_SERVER, dst=VICTIM),
                          UDP(sport=53, dport=52_000 + i) / Raw(b"a" * 90)))
    return out


def refused_outbound(n=50):
    """This PC connects to a remote port that is closed; the server answers RST."""
    out, t = [], 4_000.0
    for i in range(n):
        t += 0.2
        out.append(packet(t, IP(src=VICTIM, dst=SERVER),
                          TCP(sport=55_000 + i, dport=8443, flags="S", options=FULL_OPTIONS)))
        out.append(packet(t + 0.03, IP(src=SERVER, dst=VICTIM),
                          TCP(sport=8443, dport=55_000 + i, flags="RA")))
    return out


def classify(packets, clf, padding: bool):
    """Labels and confidences of every flow, with or without the dataset's padding rule."""
    fx._MIN_ETHERNET_PAYLOAD = 46 if padding else 0
    tracker = fx.FlowTracker()
    flows = []
    for p in packets:
        info = fx.parse_packet(p)
        if info is not None:
            flows.extend(tracker.add_packet(info)[1])
    flows.extend(tracker.flush())
    return clf.classify_many([fx.feature_vector(f) for f in flows])


def summary(results):
    labels = Counter(label for label, _ in results)
    text = ", ".join(f"{n} {label}" for label, n in labels.most_common())
    attacks = [conf for label, conf in results if label != "Benign"]
    if attacks:
        text += f" (attack confidence {min(attacks):.2f} to {max(attacks):.2f})"
    return text


def main() -> int:
    clf = ThreatClassifier()
    scenarios = [
        ("Scan, SYN with MSS only (nmap -sS style), 300 ports", scan([("MSS", 1460)]), True),
        ("Scan, SYN with full options (nmap -sT style), 300 ports", scan(FULL_OPTIONS), True),
        ("Normal HTTPS downloads, 40 sessions", https_sessions(), False),
        ("Normal DNS lookups, 40", dns_lookups(), False),
        ("Outbound connections refused by a server, 50", refused_outbound(), False),
    ]
    probes = {"before": [0, 0], "after": [0, 0]}
    benign_changed = 0
    for name, pkts, is_scan in scenarios:
        print(name)
        for run, padding in (("before", False), ("after", True)):
            res = classify(pkts, clf, padding)
            print(f"   {run:6s} {summary(res)}")
            if is_scan:
                probes[run][0] += sum(label == "PortScan" for label, _ in res)
                probes[run][1] += len(res)
            elif padding:
                benign_changed += sum(label != "Benign" for label, _ in res)
    fx._MIN_ETHERNET_PAYLOAD = 46

    print()
    for run in ("before", "after"):
        found, total = probes[run]
        print(f"Scan probes labelled PortScan {run:6s} the fix: {found} of {total}")
    print(f"Normal flows labelled as an attack after the fix: {benign_changed}")
    ok = probes["before"][0] == 0 and probes["after"][0] == probes["after"][1] and benign_changed == 0
    print("RESULT:", "matches TRAINING_LOG.md entry 12" if ok else "DIFFERS from entry 12 - see above")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
