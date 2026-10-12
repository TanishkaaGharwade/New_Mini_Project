"""
netinfo.py — Facts about this machine's network
===============================================
Finds this machine's own IP addresses, its default gateways and its DNS servers.
The sniffer uses the local IPs to keep only traffic to or from this machine, and
the blocker never blocks any of these addresses.

Every lookup fails soft: a missing value means a smaller set, never a crash.
"""

import ipaddress
import json
import logging
import socket
import subprocess
import sys

logger = logging.getLogger("cybersentinel.netinfo")

# Asks Windows for default-route next hops and configured DNS servers, as JSON
_PS_QUERY = (
    "$g = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue"
    " | ForEach-Object { $_.NextHop });"
    "$d = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue"
    " | ForEach-Object { $_.ServerAddresses });"
    "@{gateways = $g; dns = $d} | ConvertTo-Json -Compress"
)


def _valid(ip) -> str | None:
    """Return ip in canonical form, or None if it is not a usable unicast address."""
    try:
        addr = ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return None
    if addr.is_unspecified:
        return None
    return str(addr)


def local_ips() -> set[str]:
    """This machine's own IP addresses, always including loopback."""
    ips = {"127.0.0.1", "::1"}

    # Address of the interface that routes to the internet (no packet is sent)
    for family, probe in ((socket.AF_INET, "8.8.8.8"), (socket.AF_INET6, "2001:4860:4860::8888")):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.connect((probe, 80))
                ip = _valid(s.getsockname()[0])
                if ip:
                    ips.add(ip)
        except OSError:
            pass

    # Every address registered for this host name
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = _valid(info[4][0])
            if ip:
                ips.add(ip)
    except OSError:
        pass

    return ips


def primary_ip() -> str:
    """The IPv4 address used to reach the internet, or 127.0.0.1."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def gateways_and_dns() -> tuple[set[str], set[str]]:
    """Default gateways and DNS servers configured in Windows."""
    gateways: set[str] = set()
    dns: set[str] = set()

    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_QUERY],
                capture_output=True, text=True, timeout=15,
            )
            data = json.loads(result.stdout or "{}")
            gateways.update(filter(None, map(_valid, _as_list(data.get("gateways")))))
            dns.update(filter(None, map(_valid, _as_list(data.get("dns")))))
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            logger.warning(f"[NETINFO] Could not read gateways/DNS from Windows: {e}")

    # Fallback for the IPv4 gateway: Scapy's routing table
    if not any(":" not in g for g in gateways):
        try:
            from scapy.all import conf
            gw = _valid(conf.route.route("0.0.0.0")[2])
            if gw:
                gateways.add(gw)
        except Exception as e:
            logger.debug(f"[NETINFO] Scapy gateway lookup failed: {e}")

    return gateways, dns


def _as_list(value) -> list:
    # ConvertTo-Json turns a one-element array into a bare value
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
