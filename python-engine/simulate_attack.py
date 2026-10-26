"""
simulate_attack.py — One-laptop attack simulator for CyberSentinel demos
=======================================================================
Fakes attack traffic from documentation-range addresses (198.51.100.0/24, which
never exist on a real network) so the engine's rate rules fire without a second
machine. Run it as Administrator while main.py is running:

    python simulate_attack.py                # all three attacks, one after another
    python simulate_attack.py portscan       # 60 SYNs to 60 different ports   -> PortScan
    python simulate_attack.py synflood       # 200 SYNs to port 80             -> SynFlood
    python simulate_attack.py icmpflood      # 200 pings                       -> IcmpFlood

Why raw frames: Windows delivers a packet addressed to its own IP internally
(through loopback), so an ordinary send() never appears on the Wi-Fi/Ethernet
adapter the engine captures from — the engine would only see this machine's
replies. sendp() puts each frame on that adapter, where it is captured exactly like
a packet from a real attacker. The frames are addressed to this machine's own MAC,
so nothing else on the network acts on them.

With blocking on (main.py --block) each fake address gets a firewall rule. They are
harmless, and can be removed from the dashboard or with:
    Remove-NetFirewallRule -DisplayName 'CyberSentinel Block 198.51.100.*'
"""

import argparse
import random
import socket
import sys

from scapy.all import Ether, ICMP, IP, TCP, conf, get_if_hwaddr, sendp

ATTACKS = {
    # name: (fake source address, packet count, what the engine should report)
    "portscan":  ("198.51.100.42", 60,  "PortScan  (more than 20 ports in 5 s)"),
    "synflood":  ("198.51.100.66", 200, "SynFlood  (more than 100 SYNs in 2 s)"),
    "icmpflood": ("198.51.100.77", 200, "IcmpFlood (more than 100 pings in 2 s)"),
}


def my_ip() -> str:
    """The address this machine uses on the network (no packet is actually sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def build(attack: str, target: str, mac: str) -> list:
    src, count, _ = ATTACKS[attack]
    head = Ether(dst=mac, src="02:00:00:00:00:01") / IP(src=src, dst=target)
    if attack == "portscan":
        ports = random.sample(range(1, 1025), count)
        return [head / TCP(sport=random.randint(40000, 60000), dport=p, flags="S") for p in ports]
    if attack == "synflood":
        return [head / TCP(sport=random.randint(1024, 65535), dport=80, flags="S") for _ in range(count)]
    return [head / ICMP(id=0x4353, seq=i) / (b"x" * 56) for i in range(count)]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Fake attack traffic for a one-laptop CyberSentinel demo")
    parser.add_argument("attack", nargs="?", choices=[*ATTACKS, "all"], default="all")
    args = parser.parse_args(argv)

    target = my_ip()
    iface = conf.route.route("8.8.8.8")[0]        # the adapter the engine captures on by default
    mac = get_if_hwaddr(iface)

    print("=" * 60)
    print("  CyberSentinel — Demo Attack Simulator")
    print("=" * 60)
    print(f"[*] Target: this machine, {target}")

    for name in (ATTACKS if args.attack == "all" else [args.attack]):
        src, count, expect = ATTACKS[name]
        try:
            sendp(build(name, target, mac), iface=iface, verbose=0)
        except PermissionError:
            print("[!] Permission denied. Run this as Administrator.")
            return 1
        print(f"[+] {name:<9s} {count:>3} packets from {src}  -> expect {expect}")

    print("[SUCCESS] Done. Detections appear in the engine console and on the dashboard within seconds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
