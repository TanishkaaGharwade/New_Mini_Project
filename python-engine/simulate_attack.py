"""
simulate_attack.py — Attack Simulation Generator for CyberSentinel Demo
======================================================================
Sends a burst of SYN packets from a simulated attacker IP to your laptop
so you can test packet detection, ML classification, and active blocking
without needing a second laptop or Nmap installed.

Usage:
    python simulate_attack.py
"""

import sys
import time
import socket
from scapy.all import IP, TCP, send

def get_my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def simulate_nmap_scan(target_ip):
    attacker_ip = "198.51.100.42"  # Simulated external attacker IP (TEST-NET-2)
    print(f"\n[*] Simulating Stealth Port Scan Attack...")
    print(f"[*] Attacker IP : {attacker_ip}")
    print(f"[*] Target IP   : {target_ip}")
    print(f"[*] Sending 40 SYN packets to ports 20..60...")

    for port in range(20, 60):
        # Create TCP SYN packet (flags="S") with no reply (classic Nmap stealth scan)
        pkt = IP(src=attacker_ip, dst=target_ip) / TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.02)

    print(f"[SUCCESS] Attack burst complete! Check your CyberSentinel console and React dashboard.")

if __name__ == "__main__":
    my_ip = get_my_ip()
    print("=" * 60)
    print("  CyberSentinel — Demo Attack Simulator")
    print("=" * 60)
    simulate_nmap_scan(my_ip)
