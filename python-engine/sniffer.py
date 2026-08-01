"""
sniffer.py — Live Packet Capture for NetSentinel
=================================================
Pattern: Repo 2 (Vanshika110/network-monitor-dashboard) capture.py
Threading: Repo 1 (21Sandesh/NetSentinel) PacketCapture.py

Key differences from original repo:
  - Uses Scapy sniff() instead of PyShark (no Wireshark dependency)
  - Captures packets DESTINED TO this machine (dst filter) not outgoing (src)
  - Flow aggregation: buffers packets per source IP before queuing for ML
"""

import queue
import threading
import time
import socket
from scapy.all import sniff, IP, get_if_list

from feature_extractor import parse_packet
from config import NET_INTERFACE, QUEUE_MAXSIZE, FLOW_WINDOW_PACKETS, FLOW_WINDOW_SECONDS

# Thread-safe queue between capture thread and processing thread
packet_queue = queue.Queue(maxsize=QUEUE_MAXSIZE)

# Flow buffer: groups packets by src_ip before sending to classifier
# { src_ip: {"packets": [...], "first_seen": timestamp} }
_flow_buffer: dict = {}
_flow_lock = threading.Lock()


def _get_my_ip() -> str:
    """Get the local machine's primary IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


MY_IP = _get_my_ip()


def _handle_packet(pkt):
    """
    Scapy callback — called for every captured packet.
    Filters for packets INCOMING to this machine (dst == MY_IP or loopback).
    Buffers by source IP for flow-level aggregation before ML.
    """
    if IP not in pkt:
        return

    dst_ip = pkt[IP].dst
    src_ip = pkt[IP].src

    # Only process packets destined FOR this machine (incoming attacks/traffic)
    # This fixes the critical bug in the original repo which used src == userIP
    if dst_ip != MY_IP and dst_ip != "127.0.0.1":
        return

    parsed = parse_packet(pkt)
    if parsed is None:
        return

    now = time.time()

    with _flow_lock:
        if src_ip not in _flow_buffer:
            _flow_buffer[src_ip] = {"packets": [], "first_seen": now}

        _flow_buffer[src_ip]["packets"].append(parsed)

        flow = _flow_buffer[src_ip]
        pkt_count = len(flow["packets"])
        elapsed   = now - flow["first_seen"]

        # Flush flow to queue when window is full or time expired
        should_flush = (
            pkt_count >= FLOW_WINDOW_PACKETS or
            elapsed   >= FLOW_WINDOW_SECONDS
        )

        if should_flush:
            flow_snapshot = list(flow["packets"])
            del _flow_buffer[src_ip]

            # Put aggregated flow (list of parsed packets) onto processing queue
            if not packet_queue.full():
                packet_queue.put({
                    "src_ip":  src_ip,
                    "packets": flow_snapshot,
                    "count":   pkt_count,
                })


def _flush_stale_flows():
    """
    Background thread: periodically flush flows that haven't been flushed
    by packet count (prevents silent flows getting stuck in buffer).
    """
    while True:
        time.sleep(FLOW_WINDOW_SECONDS)
        now = time.time()
        to_flush = []

        with _flow_lock:
            for src_ip, flow in list(_flow_buffer.items()):
                if now - flow["first_seen"] >= FLOW_WINDOW_SECONDS:
                    to_flush.append((src_ip, list(flow["packets"])))
                    del _flow_buffer[src_ip]

        for src_ip, pkts in to_flush:
            if pkts and not packet_queue.full():
                packet_queue.put({
                    "src_ip":  src_ip,
                    "packets": pkts,
                    "count":   len(pkts),
                })


def start_capture():
    """
    Start live packet capture.
    Runs the Scapy sniff() loop — blocks the calling thread.
    Call this in a dedicated thread or as the main thread.
    """
    print(f"[*] My IP: {MY_IP}")
    print(f"[*] Starting capture on: {NET_INTERFACE or 'default interface'}")
    print(f"[*] Flow window: {FLOW_WINDOW_PACKETS} packets or {FLOW_WINDOW_SECONDS}s")
    print("[*] Monitoring incoming traffic only (dst == my IP)")

    # Start stale-flow flusher as daemon
    flusher = threading.Thread(target=_flush_stale_flows, daemon=True)
    flusher.start()

    # Start Scapy capture — try default L2 first, fallback to L3 socket if Npcap is missing
    try:
        sniff(
            iface=NET_INTERFACE,
            prn=_handle_packet,
            store=False,      # don't keep packets in memory
            filter="ip",      # only IP packets (skip ARP etc.)
        )
    except RuntimeError as rerr:
        if "winpcap" in str(rerr).lower() or "libpcap" in str(rerr).lower():
            print("[!] WinPcap/Npcap driver not detected on Windows.")
            print("[*] Switching to Scapy Layer 3 Raw Socket fallback...")
            try:
                from scapy.all import conf, L3RawSocket
                sniff(
                    L3socket=L3RawSocket,
                    prn=_handle_packet,
                    store=False,
                )
            except Exception as inner_e:
                print(f"[ERROR] Layer 3 fallback capture failed: {inner_e}")
                print("        Recommendation: Install Npcap from https://npcap.com/")
                raise inner_e
        else:
            raise rerr
    except PermissionError:
        print("[ERROR] Scapy requires administrator/root privileges.")
        print("        Run: python main.py  as Administrator")
        raise
    except Exception as e:
        print(f"[ERROR] Capture failed: {e}")
        raise
