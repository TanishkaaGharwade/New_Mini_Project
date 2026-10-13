"""
Feature extraction tests: hand-built packet sequences with exact expected values.
No network access or Administrator rights needed.
"""

import json
import math

import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from config import FEATURES_PATH
from feature_extractor import (
    FEATURE_NAMES, FlowTracker, PacketInfo, build_features, feature_vector, flow_key, parse_packet,
)

T0 = 1_760_000_000.0          # a realistic capture timestamp (seconds since the epoch)
A = ("10.0.0.5", 51544)       # side that sends first → forward
B = ("10.0.0.9", 80)


def pkt(t, frm, to, size=0, proto="TCP", **flags):
    """A PacketInfo at T0 + t seconds from endpoint `frm` to endpoint `to`."""
    return PacketInfo(T0 + t, frm[0], to[0], frm[1], to[1], proto, size, **flags)


def run(packets, **tracker_args):
    """Feed packets to a fresh tracker, then close whatever is still open."""
    tracker = FlowTracker(**tracker_args)
    closed = []
    for p in packets:
        closed += tracker.add_packet(p)[1]
    return closed + tracker.flush()


def features_of(packets):
    flows = run(packets)
    assert len(flows) == 1
    return build_features(flows[0])


# ── Required cases (PART_A section 6, step A8) ────────────────────────────────

def test_one_forward_one_backward_1ms_apart():
    f = features_of([pkt(0, A, B, 10, ack=True), pkt(0.001, B, A, 40, ack=True)])

    assert f["Flow Duration"] == 1000
    assert f["Total Fwd Packets"] == 1
    assert f["Total Backward Packets"] == 1
    assert f["Total Length of Fwd Packets"] == 10
    assert f["Total Length of Bwd Packets"] == 40
    assert f["Fwd Packet Length Max"] == 10
    assert f["Fwd Packet Length Mean"] == 10
    assert f["Bwd Packet Length Max"] == 40
    assert f["Bwd Packet Length Mean"] == 40
    # First packet counted twice: (10 + 10 + 40) / 3
    assert f["Packet Length Mean"] == pytest.approx(20)
    assert f["Packet Length Std"] == pytest.approx(17.3205, abs=1e-4)
    assert f["Flow Bytes/s"] == pytest.approx(50_000)
    assert f["Flow Packets/s"] == pytest.approx(2000)
    assert f["Flow IAT Mean"] == 1000
    assert f["Flow IAT Std"] == 0
    assert f["Flow IAT Max"] == 1000
    assert f["Fwd IAT Mean"] == 0
    assert f["Bwd IAT Mean"] == 0
    assert f["Down/Up Ratio"] == 1


def test_single_syn_no_reply():
    f = features_of([pkt(0, A, B, 0, syn=True)])

    assert f["Flow Duration"] == 0
    assert math.isnan(f["Flow Bytes/s"])
    assert math.isnan(f["Flow Packets/s"])
    assert f["Total Fwd Packets"] == 1
    assert f["Total Backward Packets"] == 0
    for name in ("Total Length of Fwd Packets", "Total Length of Bwd Packets",
                 "Fwd Packet Length Max", "Fwd Packet Length Mean",
                 "Bwd Packet Length Max", "Bwd Packet Length Mean",
                 "Packet Length Mean", "Packet Length Std",
                 "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
                 "Fwd IAT Mean", "Bwd IAT Mean", "Down/Up Ratio"):
        assert f[name] == 0, name


def test_three_forward_one_backward():
    # Arrival order: fwd 0 B @0, bwd 20 B @1 ms, fwd 100 B @2 ms, fwd 50 B @6 ms
    f = features_of([
        pkt(0.000, A, B, 0, syn=True),
        pkt(0.001, B, A, 20, syn=True, ack=True),
        pkt(0.002, A, B, 100, ack=True),
        pkt(0.006, A, B, 50, ack=True),
    ])

    assert f["Flow Duration"] == 6000
    assert f["Total Fwd Packets"] == 3
    assert f["Total Backward Packets"] == 1
    assert f["Total Length of Fwd Packets"] == 150
    assert f["Total Length of Bwd Packets"] == 20
    assert f["Fwd Packet Length Max"] == 100
    assert f["Fwd Packet Length Mean"] == 50
    assert f["Bwd Packet Length Max"] == 20
    assert f["Bwd Packet Length Mean"] == 20
    # Lengths with the first counted twice: [0, 0, 20, 100, 50]
    assert f["Packet Length Mean"] == pytest.approx(34)
    assert f["Packet Length Std"] == pytest.approx(math.sqrt(7120 / 4))
    assert f["Flow Bytes/s"] == pytest.approx(170 / 0.006)
    assert f["Flow Packets/s"] == pytest.approx(4 / 0.006)
    # Gaps: 1000, 1000, 4000
    assert f["Flow IAT Mean"] == pytest.approx(2000)
    assert f["Flow IAT Std"] == pytest.approx(math.sqrt(3_000_000))
    assert f["Flow IAT Max"] == 4000
    # Forward gaps: 2000, 4000
    assert f["Fwd IAT Mean"] == pytest.approx(3000)
    assert f["Bwd IAT Mean"] == 0
    assert f["Down/Up Ratio"] == 0


def test_same_flow_seen_from_both_directions_is_one_flow():
    packets = [pkt(0, A, B, 0, syn=True), pkt(0.001, B, A, 0, syn=True, ack=True),
               pkt(0.002, A, B, 0, ack=True), pkt(0.003, B, A, 500, ack=True)]
    assert flow_key(packets[0]) == flow_key(packets[1])

    tracker = FlowTracker()
    started = [tracker.add_packet(p)[0] for p in packets]
    assert started == [True, False, False, False]
    assert len(tracker) == 1

    flow, = tracker.flush()
    assert (flow.src_ip, flow.src_port) == A          # first packet's sender is forward
    assert (flow.fwd_count, flow.bwd_count) == (2, 2)


def test_flow_idle_past_timeout_is_closed_by_sweep():
    tracker = FlowTracker(idle_timeout=15)
    tracker.add_packet(pkt(0, A, B, 0, syn=True))
    tracker.add_packet(pkt(0.5, B, A, 0, syn=True, ack=True))

    assert tracker.sweep(T0 + 0.5 + 14.9) == []
    assert len(tracker) == 1

    closed = tracker.sweep(T0 + 0.5 + 15)
    assert len(closed) == 1
    assert closed[0].close_reason == "idle"
    assert closed[0].packet_count == 2
    assert len(tracker) == 0


# ── Flow closing ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("flag", ["fin", "rst"])
def test_fin_or_rst_closes_flow_including_that_packet(flag):
    tracker = FlowTracker()
    assert tracker.add_packet(pkt(0, A, B, 0, syn=True))[1] == []
    _, closed = tracker.add_packet(pkt(0.001, B, A, 0, ack=True, **{flag: True}))

    assert len(closed) == 1
    assert closed[0].close_reason == flag
    assert closed[0].packet_count == 2
    assert len(tracker) == 0

    # The next packet of the same connection starts a new flow
    started, closed = tracker.add_packet(pkt(0.002, A, B, 0, ack=True))
    assert started and closed == []


def test_fin_on_udp_field_is_ignored():
    tracker = FlowTracker()
    tracker.add_packet(pkt(0, A, B, 10, proto="UDP"))
    _, closed = tracker.add_packet(pkt(0.001, B, A, 10, proto="UDP", fin=True))
    assert closed == []


def test_max_duration_starts_a_new_flow():
    tracker = FlowTracker(idle_timeout=15, max_duration=120)
    times = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 119.9]
    for t in times:
        assert tracker.add_packet(pkt(t, A, B, 1))[1] == []

    started, closed = tracker.add_packet(pkt(120, A, B, 1))
    assert started
    assert len(closed) == 1
    assert closed[0].close_reason == "max_duration"
    assert closed[0].packet_count == len(times)
    assert build_features(closed[0])["Flow Duration"] == 119_900_000


def test_packet_after_idle_gap_starts_a_new_flow():
    tracker = FlowTracker(idle_timeout=15)
    tracker.add_packet(pkt(0, A, B, 1))
    started, closed = tracker.add_packet(pkt(16, B, A, 1))
    assert started
    assert [f.close_reason for f in closed] == ["idle"]
    flow, = tracker.flush()
    assert (flow.src_ip, flow.src_port) == B           # the new flow's first sender is forward


def test_sweep_closes_flows_at_max_duration():
    tracker = FlowTracker(idle_timeout=15, max_duration=120)
    for t in range(0, 120, 10):
        tracker.add_packet(pkt(t, A, B, 1))
    closed = tracker.sweep(T0 + 120)
    assert [f.close_reason for f in closed] == ["max_duration"]


def test_open_flow_cap_evicts_least_recently_active():
    tracker = FlowTracker(max_flows=2)
    c = ("10.0.0.7", 443)
    tracker.add_packet(pkt(0, A, B, 1))
    tracker.add_packet(pkt(1, A, c, 1))
    tracker.add_packet(pkt(2, B, A, 1))                 # A↔B is now the most recent
    started, closed = tracker.add_packet(pkt(3, ("10.0.0.8", 1), B, 1))

    assert started
    assert len(tracker) == 2
    assert [(f.dst_ip, f.close_reason) for f in closed] == [(c[0], "evicted")]


def test_out_of_order_timestamp_never_goes_negative():
    f = features_of([pkt(0.010, A, B, 1), pkt(0.005, B, A, 1), pkt(0.020, A, B, 1)])
    assert f["Flow Duration"] == 10_000
    assert f["Flow IAT Max"] == 10_000
    assert min(f.values()) >= 0


def test_icmp_flow_without_ports():
    ping = ("10.0.0.5", None)
    host = ("10.0.0.9", None)
    f = features_of([pkt(0, ping, host, 56, proto="ICMP"), pkt(0.002, host, ping, 56, proto="ICMP")])
    assert f["Total Fwd Packets"] == 1 and f["Total Backward Packets"] == 1
    assert f["Flow IAT Mean"] == 2000


# ── Vector order ──────────────────────────────────────────────────────────────

def test_vector_follows_features_json_order():
    with open(FEATURES_PATH, encoding="utf-8") as fh:
        expected = json.load(fh)["features"]
    assert FEATURE_NAMES == expected
    assert len(expected) == 19

    flow, = run([pkt(0, A, B, 10), pkt(0.001, B, A, 40)])
    values = build_features(flow)
    assert feature_vector(flow) == [values[name] for name in expected]


# ── Packet parsing with real Scapy packets ────────────────────────────────────

def eth():
    """Explicit MACs, so Scapy never sends ARP to resolve one."""
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def _wire(packet, time=T0):
    """Serialise and re-dissect, as a captured packet would arrive."""
    captured = Ether(bytes(packet))
    captured.time = time
    return captured


def test_parse_bare_syn_counts_short_frame_padding_like_the_dataset():
    raw = eth() / IP(src="198.51.100.42", dst="192.168.1.4") / TCP(sport=40000, dport=22, flags="S")
    unpadded = _wire(raw)                                                      # 54 bytes, as captured when sent
    padded = Ether(bytes(unpadded) + b"\x00" * (60 - len(bytes(unpadded))))   # 60 bytes, as received
    padded.time = T0
    assert (len(bytes(unpadded)), len(bytes(padded))) == (54, 60)

    # A 40-byte IP packet is 6 bytes short of the Ethernet minimum; the dataset reports 6
    expected = PacketInfo(T0, "198.51.100.42", "192.168.1.4", 40000, 22, "TCP", 6,
                          syn=True, ack=False, fin=False, rst=False)
    assert parse_packet(padded) == expected
    assert parse_packet(unpadded) == expected      # same answer whether or not the capture saw the padding


@pytest.mark.parametrize("options,payload,expected", [
    ([], b"", 6),                                    # bare ACK or RST: 40-byte IP packet
    ([("MSS", 1460)], b"", 2),                       # SYN with only an MSS option: 44 bytes
    ([("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)), ("NOP", None), ("WScale", 7)], b"", 0),  # 60 bytes
    ([], b"abc", 6),                                 # 3 data bytes + 3 padding
    ([], b"x" * 6, 6),                               # exactly at the minimum, no padding
    ([], b"x" * 100, 100),
])
def test_parse_tcp_length_matches_dataset_convention(options, payload, expected):
    packet = eth() / IP() / TCP(flags="A", options=options)
    if payload:
        packet = packet / Raw(payload)
    assert parse_packet(_wire(packet)).payload_len == expected


def test_parse_tcp_payload_excludes_options():
    raw = (eth() / IP(src="10.0.0.1", dst="10.0.0.2")
           / TCP(sport=1234, dport=80, flags="PA", options=[("MSS", 1460), ("NOP", None), ("NOP", None)])
           / Raw(b"hello"))
    info = parse_packet(_wire(raw))
    assert info.payload_len == 5
    assert (info.syn, info.ack, info.fin, info.rst) == (False, True, False, False)


@pytest.mark.parametrize("flags,expected", [
    ("FA", (False, True, True, False)),
    ("R", (False, False, False, True)),
    ("SA", (True, True, False, False)),
])
def test_parse_tcp_flags(flags, expected):
    info = parse_packet(_wire(eth() / IP() / TCP(flags=flags)))
    assert (info.syn, info.ack, info.fin, info.rst) == expected


def test_parse_udp_and_icmp_payloads():
    udp = parse_packet(_wire(eth() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=5353, dport=53) / Raw(b"x" * 12)))
    assert (udp.protocol, udp.src_port, udp.dst_port, udp.payload_len) == ("UDP", 5353, 53, 12)

    icmp = parse_packet(_wire(eth() / IP() / ICMP() / Raw(b"y" * 32)))
    assert (icmp.protocol, icmp.src_port, icmp.dst_port, icmp.payload_len) == ("ICMP", None, None, 32)


def test_parse_uses_capture_time_and_ignores_non_ip():
    info = parse_packet(_wire(eth() / IP() / TCP(), time=T0 + 1.25))
    assert info.ts == T0 + 1.25
    assert parse_packet(eth() / ARP()) is None
