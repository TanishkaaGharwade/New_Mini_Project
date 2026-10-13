"""
feature_extractor.py — CyberSentinel Feature Extraction Pipeline
==============================================================
Layer 1: parse_packet()    — one Scapy packet → PacketInfo (headers, payload length, flags)
Layer 2: FlowTracker       — groups packets into bi-directional flows and closes them
Layer 3: build_features()  — one closed flow → the 19 CICIDS2017 features

The features are computed the way the CICIDS2017 dataset computed them
(see PART_A_DETECTION_ENGINE.md section 4):
  - lengths are TCP/UDP payload bytes, never whole packet sizes; for TCP they also
    include the Ethernet padding of short frames, as the dataset's tool counted it
  - times are whole microseconds
  - "Packet Length Mean/Std" count the first packet's length twice; Std divides by n - 1
  - the two rate features are NaN when the flow lasts zero microseconds
  - "Down/Up Ratio" is backward packets // forward packets
"""

import json
import math
import threading
from collections import OrderedDict
from dataclasses import dataclass

from scapy.layers.inet import IP, TCP, UDP, ICMP

from config import (
    FEATURES_PATH, FLOW_IDLE_TIMEOUT, FLOW_MAX_DURATION, MAX_OPEN_FLOWS,
)

with open(FEATURES_PATH, encoding="utf-8") as _f:
    FEATURE_NAMES: list = json.load(_f)["features"]

_US = 1_000_000  # microseconds per second

# An Ethernet frame carries at least 46 bytes; a shorter IP packet is padded up to that.
# The dataset's tool counted that padding as TCP payload: a bare ACK or RST (40-byte IP
# packet) has length 6 there, and a SYN with only an MSS option (44 bytes) has length 2.
# model_v1 learned those values, so the engine reproduces them (TRAINING_LOG.md entry 12).
_MIN_ETHERNET_PAYLOAD = 46


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 1 — Packet parser
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class PacketInfo:
    ts: float              # capture time, seconds since the epoch
    src_ip: str
    dst_ip: str
    src_port: int | None   # None for ICMP
    dst_port: int | None
    protocol: str          # "TCP", "UDP" or "ICMP"
    payload_len: int       # bytes after the IP and TCP/UDP/ICMP headers; TCP adds short-frame padding
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False


def parse_packet(packet) -> PacketInfo | None:
    """
    Extract what the flow tracker and rules need from a Scapy packet.
    Returns None for anything that is not IPv4 TCP, UDP or ICMP.
    """
    if IP not in packet:
        return None
    ip = packet[IP]

    # Lengths come from the IP total-length field, so they do not depend on whether
    # the capture happened before or after the network card padded the frame
    ip_header = (ip.ihl or 5) * 4
    ip_total = ip.len if ip.len is not None else len(ip)
    ts = float(packet.time)

    if TCP in packet:
        tcp = packet[TCP]
        flags = int(tcp.flags)
        tcp_header = (tcp.dataofs or 5) * 4
        return PacketInfo(
            ts, ip.src, ip.dst, int(tcp.sport), int(tcp.dport), "TCP",
            max(0, ip_total - ip_header - tcp_header) + max(0, _MIN_ETHERNET_PAYLOAD - ip_total),
            syn=bool(flags & 0x02), ack=bool(flags & 0x10),
            fin=bool(flags & 0x01), rst=bool(flags & 0x04),
        )
    if UDP in packet:
        udp = packet[UDP]
        return PacketInfo(
            ts, ip.src, ip.dst, int(udp.sport), int(udp.dport), "UDP",
            max(0, ip_total - ip_header - 8),
        )
    if ICMP in packet:
        return PacketInfo(
            ts, ip.src, ip.dst, None, None, "ICMP",
            max(0, ip_total - ip_header - 8),
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 2 — Flow tracker
# ─────────────────────────────────────────────────────────────────────────────

def flow_key(pkt: PacketInfo) -> tuple:
    """Same key for both directions of a connection."""
    return (frozenset({(pkt.src_ip, pkt.src_port), (pkt.dst_ip, pkt.dst_port)}), pkt.protocol)


class Flow:
    """
    Running statistics for one bi-directional flow. Individual packets are not kept.
    Forward is the direction of the first packet seen. Times are whole microseconds.
    """

    __slots__ = (
        "key", "protocol", "src_ip", "src_port", "dst_ip", "dst_port",
        "first_ts", "last_ts", "close_reason",
        "fwd_count", "bwd_count", "fwd_bytes", "bwd_bytes", "fwd_max", "bwd_max",
        "len_n", "len_sum", "len_sumsq",
        "iat_n", "iat_sum", "iat_sumsq", "iat_max",
        "fwd_last_ts", "fwd_iat_n", "fwd_iat_sum",
        "bwd_last_ts", "bwd_iat_n", "bwd_iat_sum",
    )

    def __init__(self, pkt: PacketInfo):
        ts = _to_us(pkt.ts)
        self.key = flow_key(pkt)
        self.protocol = pkt.protocol
        self.src_ip, self.src_port = pkt.src_ip, pkt.src_port
        self.dst_ip, self.dst_port = pkt.dst_ip, pkt.dst_port
        self.first_ts = self.last_ts = ts
        self.close_reason = None

        self.fwd_count, self.fwd_bytes, self.fwd_max = 1, pkt.payload_len, pkt.payload_len
        self.bwd_count, self.bwd_bytes, self.bwd_max = 0, 0, 0

        # Dataset quirk: the first packet's length is counted twice in features 10 and 11
        self.len_n = 2
        self.len_sum = 2 * pkt.payload_len
        self.len_sumsq = 2 * pkt.payload_len ** 2

        self.iat_n = self.iat_sum = self.iat_sumsq = self.iat_max = 0
        self.fwd_last_ts, self.fwd_iat_n, self.fwd_iat_sum = ts, 0, 0
        self.bwd_last_ts, self.bwd_iat_n, self.bwd_iat_sum = None, 0, 0

    @property
    def packet_count(self) -> int:
        return self.fwd_count + self.bwd_count

    def is_forward(self, pkt: PacketInfo) -> bool:
        return pkt.src_ip == self.src_ip and pkt.src_port == self.src_port

    def add(self, pkt: PacketInfo) -> None:
        # Never let time run backwards inside a flow
        ts = max(_to_us(pkt.ts), self.last_ts)
        size = pkt.payload_len

        gap = ts - self.last_ts
        self.iat_n += 1
        self.iat_sum += gap
        self.iat_sumsq += gap * gap
        self.iat_max = max(self.iat_max, gap)
        self.last_ts = ts

        self.len_n += 1
        self.len_sum += size
        self.len_sumsq += size * size

        if self.is_forward(pkt):
            self.fwd_count += 1
            self.fwd_bytes += size
            self.fwd_max = max(self.fwd_max, size)
            self.fwd_iat_n += 1
            self.fwd_iat_sum += ts - self.fwd_last_ts
            self.fwd_last_ts = ts
        else:
            self.bwd_count += 1
            self.bwd_bytes += size
            self.bwd_max = max(self.bwd_max, size)
            if self.bwd_last_ts is not None:
                self.bwd_iat_n += 1
                self.bwd_iat_sum += ts - self.bwd_last_ts
            self.bwd_last_ts = ts


def _to_us(ts: float) -> int:
    return int(round(ts * _US))


class FlowTracker:
    """
    Thread-safe table of open flows.

    add_packet() and sweep() return the flows they closed; the caller classifies them.
    A flow closes when a TCP FIN or RST is seen (that packet is included), when it has
    been idle for idle_timeout seconds, or when it reaches max_duration seconds. When
    more than max_flows are open, the least recently active flow is closed early.
    """

    def __init__(self, idle_timeout: float = FLOW_IDLE_TIMEOUT,
                 max_duration: float = FLOW_MAX_DURATION,
                 max_flows: int = MAX_OPEN_FLOWS):
        self.idle_timeout_us = int(idle_timeout * _US)
        self.max_duration_us = int(max_duration * _US)
        self.max_flows = max_flows
        self._flows: OrderedDict = OrderedDict()   # oldest activity first
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._flows)

    def add_packet(self, pkt: PacketInfo) -> tuple[bool, list]:
        """
        Add one packet. Returns (started_new_flow, closed_flows).
        """
        key = flow_key(pkt)
        ts = _to_us(pkt.ts)
        closed = []

        with self._lock:
            flow = self._flows.get(key)

            if flow is not None:
                if ts - flow.last_ts >= self.idle_timeout_us:
                    closed.append(self._close(key, "idle"))
                    flow = None
                elif ts - flow.first_ts >= self.max_duration_us:
                    closed.append(self._close(key, "max_duration"))
                    flow = None

            started = flow is None
            if started:
                while len(self._flows) >= self.max_flows:
                    oldest = next(iter(self._flows))
                    closed.append(self._close(oldest, "evicted"))
                flow = Flow(pkt)
                self._flows[key] = flow
            else:
                flow.add(pkt)
                self._flows.move_to_end(key)

            if pkt.protocol == "TCP" and (pkt.fin or pkt.rst):
                closed.append(self._close(key, "rst" if pkt.rst else "fin"))

        return started, closed

    def sweep(self, now: float) -> list:
        """Close every flow idle for idle_timeout or older than max_duration at time now."""
        now_us = _to_us(now)
        closed = []
        with self._lock:
            for key, flow in list(self._flows.items()):
                if now_us - flow.last_ts >= self.idle_timeout_us:
                    closed.append(self._close(key, "idle"))
                elif now_us - flow.first_ts >= self.max_duration_us:
                    closed.append(self._close(key, "max_duration"))
        return closed

    def flush(self) -> list:
        """Close every open flow (used at shutdown and by the replay tool)."""
        with self._lock:
            return [self._close(key, "flush") for key in list(self._flows)]

    def _close(self, key, reason: str) -> Flow:
        flow = self._flows.pop(key)
        flow.close_reason = reason
        return flow


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 3 — Feature builder
# ─────────────────────────────────────────────────────────────────────────────

def _sample_std(n: int, total: int, sumsq: int) -> float:
    """Sample standard deviation (divide by n - 1) from integer running sums."""
    if n < 2:
        return 0.0
    var = (n * sumsq - total * total) / (n * (n - 1))
    return math.sqrt(var) if var > 0 else 0.0


def build_features(flow: Flow) -> dict:
    """All 19 features of a closed flow, by name."""
    duration = flow.last_ts - flow.first_ts                       # µs
    total_bytes = flow.fwd_bytes + flow.bwd_bytes
    seconds = duration / _US

    return {
        "Flow Duration":               float(duration),
        "Total Fwd Packets":           float(flow.fwd_count),
        "Total Backward Packets":      float(flow.bwd_count),
        "Total Length of Fwd Packets": float(flow.fwd_bytes),
        "Total Length of Bwd Packets": float(flow.bwd_bytes),
        "Fwd Packet Length Max":       float(flow.fwd_max),
        "Fwd Packet Length Mean":      flow.fwd_bytes / flow.fwd_count,
        "Bwd Packet Length Max":       float(flow.bwd_max),
        "Bwd Packet Length Mean":      flow.bwd_bytes / flow.bwd_count if flow.bwd_count else 0.0,
        "Packet Length Mean":          flow.len_sum / flow.len_n,
        "Packet Length Std":           _sample_std(flow.len_n, flow.len_sum, flow.len_sumsq),
        "Flow Bytes/s":                total_bytes / seconds if duration > 0 else math.nan,
        "Flow Packets/s":              flow.packet_count / seconds if duration > 0 else math.nan,
        "Flow IAT Mean":               flow.iat_sum / flow.iat_n if flow.iat_n else 0.0,
        "Flow IAT Std":                _sample_std(flow.iat_n, flow.iat_sum, flow.iat_sumsq),
        "Flow IAT Max":                float(flow.iat_max),
        "Fwd IAT Mean":                flow.fwd_iat_sum / flow.fwd_iat_n if flow.fwd_iat_n else 0.0,
        "Bwd IAT Mean":                flow.bwd_iat_sum / flow.bwd_iat_n if flow.bwd_iat_n else 0.0,
        "Down/Up Ratio":               float(flow.bwd_count // flow.fwd_count),
    }


def feature_vector(flow: Flow, names: list = FEATURE_NAMES) -> list:
    """The features of a closed flow as a list, in features.json order."""
    values = build_features(flow)
    return [values[name] for name in names]


_missing = set(FEATURE_NAMES) - set(build_features(Flow(PacketInfo(0.0, "0.0.0.1", "0.0.0.2", 1, 2, "TCP", 0))))
if _missing:
    raise RuntimeError(f"features.json lists features this extractor cannot compute: {sorted(_missing)}")
