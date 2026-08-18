"""
feature_extractor.py — CyberSentinel Feature Extraction Pipeline
==============================================================
Layer 1: parse_packet()        — adapted from Repo 2 (Vanshika110/network-monitor-dashboard) parser.py
Layer 2: build_feature_vector() — adapted from Repo 1 (21Sandesh/CyberSentinel) util.py

Key fix over original repo:
  - Filters on dst IP (incoming attacks) instead of src IP (outgoing traffic)
  - Uses Scapy layer accessors instead of PyShark (no Wireshark dependency)
  - Adds flow-level aggregation window before ML inference
"""

from scapy.all import IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime
import time


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 1 — Protocol Parser (from Repo 2 parser.py)
# ─────────────────────────────────────────────────────────────────────────────

def parse_packet(packet) -> dict | None:
    """
    Extract IP/TCP/UDP/ICMP header fields from a Scapy packet.
    Returns None if packet has no IP layer (e.g. ARP, broadcast).
    
    Source: Repo 2 (Vanshika110) parser.py — ported and extended.
    """
    if IP not in packet:
        return None

    ip = packet[IP]
    proto    = "OTHER"
    src_port = None
    dst_port = None
    flags    = None

    if TCP in packet:
        proto    = "tcp"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags    = _decode_tcp_flags(packet[TCP].flags)
    elif UDP in packet:
        proto    = "udp"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        flags    = "SF"   # UDP connections treated as completed
    elif ICMP in packet:
        proto    = "icmp"
        flags    = "SF"

    return {
        "src_ip":    ip.src,
        "dst_ip":    ip.dst,
        "protocol":  proto,
        "src_port":  src_port,
        "dst_port":  dst_port,
        "length":    len(packet),
        "flags":     flags,
        "timestamp": time.time(),
        "raw_pkt":   packet,
    }


def _decode_tcp_flags(flag_int) -> str:
    """Map Scapy TCP flag integer to NSL-KDD flag string."""
    # Convert to integer if it's a FlagValue object
    try:
        flags = int(flag_int)
    except (TypeError, ValueError):
        return "OTH"

    SYN = bool(flags & 0x02)
    ACK = bool(flags & 0x10)
    FIN = bool(flags & 0x01)
    RST = bool(flags & 0x04)

    if SYN and ACK:
        return "SF"   # normal established
    if SYN and not ACK:
        return "S0"   # SYN sent, no reply — classic Nmap stealth scan
    if RST:
        return "REJ"  # connection rejected
    if FIN:
        return "SF"
    return "OTH"


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 2 — NSL-KDD Feature Builder (from Repo 1 util.py)
# ─────────────────────────────────────────────────────────────────────────────

def init_state_dicts() -> dict:
    """
    Initialize all connection-tracking state dictionaries.
    These accumulate statistics across packets to compute NSL-KDD features.
    Adapted from Repo 1 PacketCapture.py StartCapture().
    """
    return {
        "count_dict":                  defaultdict(lambda: {"timestamp": 0, "count": 0}),
        "diff_srv_rates":              defaultdict(lambda: {"total_connections": 0, "unique_services": set()}),
        "dst_host_count":              defaultdict(int),
        "rerror_rate_dict":            {"total_connections": 0, "rej_errors": 0},
        "srv_count":                   defaultdict(int),
        "srv_host_count":              defaultdict(set),
        "dst_host_srv_count":          defaultdict(int),
        "dst_host_src_port_count":     defaultdict(int),
        "dst_host_srv_diff_host_count":defaultdict(set),
        "prev_time":                   0,
    }


def build_feature_vector(parsed: dict, state: dict) -> list | None:
    """
    Compute all 21 NSL-KDD features from a parsed packet dict + running state.
    Returns a list of 21 values, or None if packet can't produce valid features.
    
    Feature order matches preprocessor.pkl column expectations.
    Adapted from Repo 1 util.py — ported from PyShark to Scapy.
    """
    try:
        src_ip   = parsed["src_ip"]
        dst_ip   = parsed["dst_ip"]
        src_port = parsed["src_port"]
        dst_port = parsed["dst_port"]
        protocol = parsed["protocol"]
        flag     = parsed["flags"] or "OTH"
        length   = parsed["length"]
        current_time = parsed["timestamp"]

        # ── Duration ──────────────────────────────────────────────────────────
        duration = 0
        if state["prev_time"] > 0:
            duration = max(0, int(current_time - state["prev_time"]))
        state["prev_time"] = current_time

        # ── Bytes ─────────────────────────────────────────────────────────────
        src_bytes = length
        dst_bytes = length

        # ── diff_srv_rate (per source IP) ─────────────────────────────────────
        state["diff_srv_rates"][src_ip]["total_connections"] += 1
        if src_port:
            state["diff_srv_rates"][src_ip]["unique_services"].add(src_port)

        total_conns   = state["diff_srv_rates"][src_ip]["total_connections"]
        unique_srvs   = len(state["diff_srv_rates"][src_ip]["unique_services"])
        diff_srv_rate = round(unique_srvs / total_conns, 2) if total_conns else 0

        # ── count (connections to same host in last 2s) ────────────────────────
        count = _calculate_count(src_ip, state["count_dict"])

        # ── srv_count ─────────────────────────────────────────────────────────
        if dst_port:
            state["srv_count"][dst_port] += 1
        srv_count_val = state["srv_count"].get(dst_port, 0)

        # ── error rates ───────────────────────────────────────────────────────
        serror_rate     = _serror_rate(protocol, flag)
        srv_serror_rate = _srv_serror_rate(protocol, flag, dst_port, state)
        rerror_rate     = _rerror_rate(flag, state["rerror_rate_dict"])
        srv_rerror_rate = rerror_rate  # simplified; same dict

        # ── same_srv_rate ──────────────────────────────────────────────────────
        same_srv_rate = _same_srv_rate(dst_port, state["srv_count"], total_conns)

        # ── srv_diff_host_rate ─────────────────────────────────────────────────
        srv_diff_host_rate = _srv_diff_host_rate(
            src_ip, dst_port, state["srv_host_count"], state["srv_count"]
        )

        # ── dst_host_count ─────────────────────────────────────────────────────
        state["dst_host_count"][dst_ip] += 1
        dst_host_count_val = state["dst_host_count"][dst_ip]

        # ── dst_host_srv_count ─────────────────────────────────────────────────
        dst_host_srv_count_val = _dst_host_srv_count(
            dst_ip, dst_port, state["dst_host_srv_count"]
        )

        # ── dst_host_same_srv_rate ────────────────────────────────────────────
        dst_host_same_srv_rate = _dst_host_same_srv_rate(
            dst_ip, dst_port, state["dst_host_srv_count"]
        )

        # ── dst_host_diff_srv_rate ─────────────────────────────────────────────
        dst_host_diff_srv_rate = _dst_host_diff_srv_rate(
            dst_ip, dst_port, state["dst_host_srv_count"], total_conns
        )

        # ── dst_host_same_src_port_rate ────────────────────────────────────────
        dst_host_same_src_port_rate = _dst_host_same_src_port_rate(
            src_ip, src_port, dst_ip, state["dst_host_src_port_count"]
        )

        # ── dst_host_srv_diff_host_rate ────────────────────────────────────────
        dst_host_srv_diff_host_rate = _dst_host_srv_diff_host_rate(
            dst_ip, dst_port, src_ip,
            state["dst_host_srv_count"], state["dst_host_srv_diff_host_count"]
        )

        return [
            duration, protocol, src_port or 0, flag,
            src_bytes, dst_bytes,
            count, srv_count_val,
            serror_rate, srv_serror_rate,
            rerror_rate, srv_rerror_rate,
            round(same_srv_rate, 2),
            round(diff_srv_rate, 2),
            round(srv_diff_host_rate, 2),
            dst_host_count_val,
            dst_host_srv_count_val,
            round(dst_host_same_srv_rate, 2),
            round(dst_host_diff_srv_rate, 2),
            round(dst_host_same_src_port_rate, 2),
            round(dst_host_srv_diff_host_rate, 2),
        ]

    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions (ported from Repo 1 util.py)
# ─────────────────────────────────────────────────────────────────────────────

def _calculate_count(src_ip: str, count_dict: dict) -> int:
    """Count connections from same src IP in last 2 seconds."""
    now = time.time()
    if src_ip in count_dict:
        if now - count_dict[src_ip]["timestamp"] <= 2:
            count_dict[src_ip]["count"] += 1
        else:
            count_dict[src_ip] = {"timestamp": now, "count": 1}
    else:
        count_dict[src_ip] = {"timestamp": now, "count": 1}
    return count_dict[src_ip]["count"]


def _serror_rate(protocol: str, flag: str) -> float:
    """SYN error rate: 1.0 if SYN without ACK (S0), else 0."""
    if protocol == "tcp" and flag == "S0":
        return 1.0
    return 0.0


def _srv_serror_rate(protocol: str, flag: str, dst_port, state: dict) -> float:
    """Service-level SYN error rate."""
    return _serror_rate(protocol, flag)


def _rerror_rate(flag: str, rerror_dict: dict) -> float:
    """REJ error rate across all connections."""
    rerror_dict["total_connections"] += 1
    if flag == "REJ":
        rerror_dict["rej_errors"] += 1
    total = rerror_dict["total_connections"]
    return round(rerror_dict["rej_errors"] / total, 2) if total else 0.0


def _same_srv_rate(dst_port, srv_count: dict, total_conns: int) -> float:
    """Fraction of connections going to same service (port)."""
    if not dst_port or total_conns == 0:
        return 0.0
    return srv_count.get(dst_port, 0) / total_conns


def _srv_diff_host_rate(src_ip: str, dst_port, srv_host_count: dict, srv_count: dict) -> float:
    """Fraction of connections to this service from different hosts."""
    if not dst_port:
        return 0.0
    srv_host_count[dst_port].add(src_ip)
    total = srv_count.get(dst_port, 1)
    diff  = total - len(srv_host_count[dst_port])
    return round(diff / total, 2) if total else 0.0


def _dst_host_srv_count(dst_ip: str, dst_port, dst_host_srv_count: dict) -> int:
    """Count of connections to same service on destination host."""
    if not dst_port:
        return 0
    key = (dst_ip, dst_port)
    dst_host_srv_count[key] += 1
    return dst_host_srv_count[key]


def _dst_host_same_srv_rate(dst_ip: str, dst_port, dst_host_srv_count: dict) -> float:
    if not dst_port:
        return 0.0
    key   = (dst_ip, dst_port)
    total = sum(dst_host_srv_count.values())
    same  = dst_host_srv_count.get(key, 0)
    return round(same / total, 2) if total else 0.0


def _dst_host_diff_srv_rate(dst_ip: str, dst_port, dst_host_srv_count: dict, total_conns: int) -> float:
    if not dst_port or total_conns == 0:
        return 0.0
    total_srv = sum(dst_host_srv_count.values())
    same      = dst_host_srv_count.get((dst_ip, dst_port), 0)
    diff      = total_srv - same
    return round(diff / total_conns, 2)


def _dst_host_same_src_port_rate(src_ip: str, src_port, dst_ip: str, dst_host_src_port_count: dict) -> float:
    if not src_port:
        return 0.0
    key = (dst_ip, src_port)
    dst_host_src_port_count[key] += 1
    total = sum(dst_host_src_port_count.values())
    same  = dst_host_src_port_count[key]
    return round(same / total, 2) if total else 0.0


def _dst_host_srv_diff_host_rate(dst_ip, dst_port, src_ip, dst_host_srv_count, dst_host_srv_diff_host_count) -> float:
    if not dst_port:
        return 0.0
    key = (dst_ip, dst_port)
    dst_host_srv_count[key] += 1
    dst_host_srv_diff_host_count[key].add(src_ip)
    total = dst_host_srv_count[key]
    diff  = len(dst_host_srv_diff_host_count[key])
    return round(diff / total, 2) if total else 0.0
