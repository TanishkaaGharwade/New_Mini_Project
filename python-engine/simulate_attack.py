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

From a second computer (both on the same network, simulator run as Administrator
there; it needs Python, scapy and Npcap):

    python simulate_attack.py --target 192.168.1.2            # the protected PC's IP
    python simulate_attack.py portscan --target 192.168.1.2

In --target mode the packets carry the attacking computer's real address, so with
blocking on (main.py --block) the protected PC blocks that computer — the full
prevention loop. Unblock it from the dashboard afterwards.

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

from scapy.all import Ether, ICMP, IP, TCP, conf, get_if_hwaddr, send, sendp

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


def build(attack: str, target: str, mac: str | None, src: str | None = None) -> list:
    """Packets for one attack. With `mac` they are raw frames for this machine (sendp);
    without it they are IP packets for another machine (send)."""
    fake_src, count, _ = ATTACKS[attack]
    if mac:
        head = Ether(dst=mac, src="02:00:00:00:00:01") / IP(src=src or fake_src, dst=target)
    else:
        head = IP(src=src, dst=target) if src else IP(dst=target)
    if attack == "portscan":
        ports = random.sample(range(1, 1025), count)
        return [head / TCP(sport=random.randint(40000, 60000), dport=p, flags="S") for p in ports]
    if attack == "synflood":
        return [head / TCP(sport=random.randint(1024, 65535), dport=80, flags="S") for _ in range(count)]
    return [head / ICMP(id=0x4353, seq=i) / (b"x" * 56) for i in range(count)]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Attack traffic for a CyberSentinel demo")
    parser.add_argument("attack", nargs="?", choices=[*ATTACKS, "all"], default="all")
    parser.add_argument("--target", metavar="IP",
                        help="attack another computer running the engine (default: this machine, with fake attacker addresses)")
    args = parser.parse_args(argv)

    me = my_ip()
    remote = args.target not in (None, me)
    target = args.target if remote else me
    iface = conf.route.route(target if remote else "8.8.8.8")[0]

    print("=" * 60)
    print("  CyberSentinel — Demo Attack Simulator")
    print("=" * 60)
    if remote:
        print(f"[*] Target: {target}, from this computer ({me}). With blocking on, {me} will be blocked there.")
    else:
        print(f"[*] Target: this machine, {target}")

    mac = None if remote else get_if_hwaddr(iface)
    for name in (ATTACKS if args.attack == "all" else [args.attack]):
        fake_src, count, expect = ATTACKS[name]
        try:
            packets = build(name, target, mac)
            if remote:
                send(packets, verbose=0)
            else:
                sendp(packets, iface=iface, verbose=0)
        except PermissionError:
            print("[!] Permission denied. Run this as Administrator.")
            return 1
        print(f"[+] {name:<9s} {count:>3} packets from {me if remote else fake_src}  -> expect {expect}")

    print("[SUCCESS] Done. Detections appear in the engine console and on the dashboard within seconds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
