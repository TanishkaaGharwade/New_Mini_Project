"""
rules.py — Rate-based detection rules for CyberSentinel
======================================================
Independently of flows, keeps a short sliding window per remote source IP of:
  - TCP SYN packets without ACK          → SynFlood
  - distinct destination ports touched   → PortScan
  - ICMP packets                         → IcmpFlood

Only packets coming from a remote source towards this machine are counted.
A destination port counts as "touched" by a TCP SYN without ACK, or by a UDP
packet that opens a new flow (so replies to our own connections never count).

Thresholds live in config.py. The same rule fires at most once per source
every RULE_COOLDOWN seconds.
"""

import threading
from collections import OrderedDict, deque
from dataclasses import dataclass, field

from config import (
    SYN_FLOOD_THRESHOLD, SYN_FLOOD_WINDOW,
    PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW,
    ICMP_FLOOD_THRESHOLD, ICMP_FLOOD_WINDOW,
    RULE_COOLDOWN, MAX_TRACKED_SOURCES, MAX_EVENTS_PER_SOURCE,
)
from feature_extractor import PacketInfo

SYN_FLOOD  = "SynFlood"
PORT_SCAN  = "PortScan"
ICMP_FLOOD = "IcmpFlood"


@dataclass(frozen=True)
class RuleHit:
    label: str              # SynFlood, PortScan or IcmpFlood
    src_ip: str             # the remote source
    ts: float               # time of the packet that crossed the threshold
    packet_count: int       # packets from this source inside the rule's window
    evidence: list          # [{"feature": ..., "value": ...}]
    packet: PacketInfo = field(repr=False)   # the packet that crossed the threshold


class _SourceHistory:
    __slots__ = ("syns", "icmps", "ports", "port_counts", "last_fired", "last_seen")

    def __init__(self):
        self.syns = deque()            # timestamps
        self.icmps = deque()           # timestamps
        self.ports = deque()           # (timestamp, port)
        self.port_counts = {}          # port → occurrences inside self.ports
        self.last_fired = {}           # rule label → timestamp
        self.last_seen = 0.0


def _trim(times: deque, cutoff: float, cap: int) -> None:
    while times and (times[0] <= cutoff or len(times) > cap):
        times.popleft()


class RuleEngine:
    """Thread-safe per-source sliding windows and the three rate rules."""

    def __init__(self, local_ips=None,
                 syn_threshold: int = SYN_FLOOD_THRESHOLD, syn_window: float = SYN_FLOOD_WINDOW,
                 scan_threshold: int = PORT_SCAN_THRESHOLD, scan_window: float = PORT_SCAN_WINDOW,
                 icmp_threshold: int = ICMP_FLOOD_THRESHOLD, icmp_window: float = ICMP_FLOOD_WINDOW,
                 cooldown: float = RULE_COOLDOWN,
                 max_sources: int = MAX_TRACKED_SOURCES,
                 max_events: int = MAX_EVENTS_PER_SOURCE):
        self.local_ips = set(local_ips or ())
        self.syn_threshold, self.syn_window = syn_threshold, syn_window
        self.scan_threshold, self.scan_window = scan_threshold, scan_window
        self.icmp_threshold, self.icmp_window = icmp_threshold, icmp_window
        self.cooldown = cooldown
        self.max_sources = max_sources
        self.max_events = max_events
        self._sources: OrderedDict = OrderedDict()   # least recently seen first
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._sources)

    def observe(self, pkt: PacketInfo, new_flow: bool = False) -> list:
        """Record one packet. Returns the RuleHits it triggered (usually none)."""
        if pkt.src_ip in self.local_ips:
            return []

        syn_only = pkt.protocol == "TCP" and pkt.syn and not pkt.ack
        is_icmp = pkt.protocol == "ICMP"
        touches_port = syn_only or (pkt.protocol == "UDP" and new_flow)
        if not (syn_only or is_icmp or touches_port):
            return []

        hits = []
        with self._lock:
            src = self._source(pkt.src_ip, pkt.ts)

            if syn_only:
                src.syns.append(pkt.ts)
                _trim(src.syns, pkt.ts - self.syn_window, self.max_events)
                if len(src.syns) > self.syn_threshold:
                    self._fire(hits, src, SYN_FLOOD, pkt, len(src.syns),
                               f"SYNs without ACK in {self.syn_window:g} s", len(src.syns))

            if touches_port:
                src.ports.append((pkt.ts, pkt.dst_port))
                src.port_counts[pkt.dst_port] = src.port_counts.get(pkt.dst_port, 0) + 1
                cutoff = pkt.ts - self.scan_window
                while src.ports and (src.ports[0][0] <= cutoff or len(src.ports) > self.max_events):
                    _, old = src.ports.popleft()
                    src.port_counts[old] -= 1
                    if src.port_counts[old] == 0:
                        del src.port_counts[old]
                distinct = len(src.port_counts)
                if distinct > self.scan_threshold:
                    self._fire(hits, src, PORT_SCAN, pkt, len(src.ports),
                               f"distinct ports in {self.scan_window:g} s", distinct)

            if is_icmp:
                src.icmps.append(pkt.ts)
                _trim(src.icmps, pkt.ts - self.icmp_window, self.max_events)
                if len(src.icmps) > self.icmp_threshold:
                    self._fire(hits, src, ICMP_FLOOD, pkt, len(src.icmps),
                               f"ICMP packets in {self.icmp_window:g} s", len(src.icmps))
        return hits

    def prune(self, now: float) -> None:
        """Forget sources that have been quiet longer than every window and the cooldown."""
        horizon = now - max(self.syn_window, self.scan_window, self.icmp_window, self.cooldown)
        with self._lock:
            while self._sources:
                ip, src = next(iter(self._sources.items()))
                if src.last_seen > horizon:
                    break
                del self._sources[ip]

    def _source(self, ip: str, ts: float) -> _SourceHistory:
        src = self._sources.get(ip)
        if src is None:
            while len(self._sources) >= self.max_sources:
                self._sources.popitem(last=False)
            src = self._sources[ip] = _SourceHistory()
        else:
            self._sources.move_to_end(ip)
        src.last_seen = max(src.last_seen, ts)
        return src

    def _fire(self, hits: list, src: _SourceHistory, label: str, pkt: PacketInfo,
              packet_count: int, evidence_name: str, evidence_value: int) -> None:
        last = src.last_fired.get(label)
        if last is not None and pkt.ts - last < self.cooldown:
            return
        src.last_fired[label] = pkt.ts
        hits.append(RuleHit(
            label=label, src_ip=pkt.src_ip, ts=pkt.ts, packet_count=packet_count,
            evidence=[{"feature": evidence_name, "value": evidence_value}], packet=pkt,
        ))
