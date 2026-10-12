"""
sniffer.py — Live Packet Capture for CyberSentinel
=================================================
Captures IPv4 TCP/UDP/ICMP packets where this machine is the source OR the
destination, parses each one, and puts it on packet_queue. The flow tracker in
the worker thread does everything else, so the capture callback stays fast:
parse, enqueue, return.
"""

import logging
import queue

from scapy.all import sniff

from config import NET_INTERFACE, QUEUE_MAXSIZE
from feature_extractor import parse_packet

logger = logging.getLogger("cybersentinel.sniffer")

# Thread-safe queue of PacketInfo between the capture thread and the flow worker
packet_queue: queue.Queue = queue.Queue(maxsize=QUEUE_MAXSIZE)

# Packets dropped because the worker fell behind
dropped_packets = 0

_local_ips: frozenset = frozenset()

_BPF_FILTER = "ip and (tcp or udp or icmp)"


def _handle_packet(pkt):
    """Scapy callback — called for every captured packet."""
    global dropped_packets
    info = parse_packet(pkt)
    if info is None:
        return
    if info.src_ip not in _local_ips and info.dst_ip not in _local_ips:
        return
    try:
        packet_queue.put_nowait(info)
    except queue.Full:
        dropped_packets += 1


def start_capture(local_ips) -> None:
    """
    Start live packet capture of traffic to or from any of local_ips.
    Runs the Scapy sniff() loop — blocks the calling thread.
    """
    global _local_ips
    _local_ips = frozenset(local_ips)

    logger.info(f"[CAPTURE] This machine: {sorted(_local_ips)}")
    logger.info(f"[CAPTURE] Interface: {NET_INTERFACE or 'default'} | traffic in both directions")

    try:
        sniff(iface=NET_INTERFACE, prn=_handle_packet, store=False, filter=_BPF_FILTER)
    except RuntimeError as rerr:
        if "winpcap" in str(rerr).lower() or "libpcap" in str(rerr).lower():
            logger.warning("[CAPTURE] WinPcap/Npcap not detected; switching to Scapy's layer 3 raw socket")
            try:
                from scapy.all import L3RawSocket
                sniff(L3socket=L3RawSocket, prn=_handle_packet, store=False)
            except Exception as inner_e:
                logger.error(f"[CAPTURE] Layer 3 fallback capture failed: {inner_e}. "
                             "Install Npcap from https://npcap.com/")
                raise
        else:
            raise
    except PermissionError:
        logger.error("[CAPTURE] Scapy requires Administrator privileges. Run main.py as Administrator.")
        raise
