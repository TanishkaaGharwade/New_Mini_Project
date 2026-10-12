"""Rule engine tests: per-source sliding windows, thresholds and cooldown."""

from feature_extractor import PacketInfo
from rules import RuleEngine, SYN_FLOOD, PORT_SCAN, ICMP_FLOOD

T0 = 1_760_000_000.0
ME = "192.168.1.4"
ATTACKER = "198.51.100.42"


def syn(t, port=80, src=ATTACKER, ack=False):
    return PacketInfo(T0 + t, src, ME, 40000, port, "TCP", 0, syn=True, ack=ack)


def icmp(t, src=ATTACKER):
    return PacketInfo(T0 + t, src, ME, None, None, "ICMP", 56)


def udp(t, port, src=ATTACKER):
    return PacketInfo(T0 + t, src, ME, 5000, port, "UDP", 20)


def feed(engine, packets, new_flow=False):
    hits = []
    for p in packets:
        hits += engine.observe(p, new_flow)
    return hits


def test_syn_flood_fires_above_threshold_within_window():
    rules = RuleEngine(local_ips={ME})
    hits = feed(rules, [syn(i * 0.01) for i in range(100)])
    assert hits == []                                      # exactly 100 is not "more than 100"

    hits = feed(rules, [syn(1.0)])
    assert [h.label for h in hits] == [SYN_FLOOD]
    assert hits[0].src_ip == ATTACKER
    assert hits[0].packet_count == 101
    assert hits[0].evidence == [{"feature": "SYNs without ACK in 2 s", "value": 101}]


def test_syn_flood_ignores_slow_syns_and_syn_ack():
    rules = RuleEngine(local_ips={ME})
    assert feed(rules, [syn(i * 0.03) for i in range(150)]) == []          # 66 per 2 s
    assert feed(rules, [syn(10 + i * 0.001, ack=True) for i in range(300)]) == []


def test_rules_ignore_packets_from_this_machine():
    rules = RuleEngine(local_ips={ME})
    out = [PacketInfo(T0 + i * 0.001, ME, ATTACKER, 40000, i, "TCP", 0, syn=True) for i in range(300)]
    assert feed(rules, out) == []
    assert len(rules) == 0


def test_cooldown_then_fires_again():
    rules = RuleEngine(local_ips={ME}, cooldown=5)
    first = feed(rules, [syn(i * 0.001) for i in range(300)])
    assert len(first) == 1                                 # not once per packet
    assert feed(rules, [syn(4.0 + i * 0.001) for i in range(200)]) == []
    again = feed(rules, [syn(6.0 + i * 0.001) for i in range(200)])
    assert [h.label for h in again] == [SYN_FLOOD]


def test_port_scan_counts_distinct_ports():
    rules = RuleEngine(local_ips={ME})
    assert feed(rules, [syn(i * 0.01, port=1000 + i) for i in range(20)]) == []
    assert feed(rules, [syn(0.5, port=1005)]) == []        # repeat port, still 20 distinct

    hits = feed(rules, [syn(0.6, port=2000)])
    assert [h.label for h in hits] == [PORT_SCAN]
    assert hits[0].evidence == [{"feature": "distinct ports in 5 s", "value": 21}]
    assert hits[0].packet_count == 22
    assert hits[0].packet.dst_port == 2000


def test_port_scan_window_slides():
    rules = RuleEngine(local_ips={ME})
    # 21 distinct ports, but spread over more than 5 seconds
    assert feed(rules, [syn(i * 0.3, port=3000 + i) for i in range(21)]) == []


def test_udp_counts_only_when_it_opens_a_flow():
    rules = RuleEngine(local_ips={ME})
    assert feed(rules, [udp(i * 0.01, 6000 + i) for i in range(50)], new_flow=False) == []
    hits = feed(rules, [udp(1 + i * 0.01, 7000 + i) for i in range(21)], new_flow=True)
    assert [h.label for h in hits] == [PORT_SCAN]


def test_icmp_flood():
    rules = RuleEngine(local_ips={ME})
    hits = feed(rules, [icmp(i * 0.005) for i in range(101)])
    assert [h.label for h in hits] == [ICMP_FLOOD]
    assert hits[0].evidence == [{"feature": "ICMP packets in 2 s", "value": 101}]
    assert hits[0].packet.protocol == "ICMP"


def test_sources_are_independent():
    rules = RuleEngine(local_ips={ME})
    packets = [syn(i * 0.001, src=f"203.0.113.{i % 3 + 1}") for i in range(300)]
    assert feed(rules, packets) == []                      # 100 each: no single source exceeds 100
    hits = feed(rules, [syn(0.3, src=f"203.0.113.{n}") for n in (1, 2, 3)])
    assert sorted(h.src_ip for h in hits) == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]


def test_prune_and_source_cap():
    rules = RuleEngine(local_ips={ME}, max_sources=2)
    for i in range(3):
        rules.observe(syn(i, src=f"203.0.113.{i}"))
    assert len(rules) == 2                                  # oldest forgotten
    rules.prune(T0 + 100)
    assert len(rules) == 0


def test_event_cap_keeps_memory_bounded():
    rules = RuleEngine(local_ips={ME}, max_events=150)
    feed(rules, [syn(i * 0.0001) for i in range(1000)])
    src = rules._sources[ATTACKER]
    assert len(src.syns) <= 150
