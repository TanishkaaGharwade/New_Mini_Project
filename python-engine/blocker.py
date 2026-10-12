"""
blocker.py — Windows Firewall Active Blocking for CyberSentinel
=============================================================
Source: Repo 3 (Chanveasna-ENG/Network-Intrusion-Detection-and-Monitoring-Tool) util.py
        block_ip() function — adapted and hardened.

Adds inbound Windows Firewall rules named "CyberSentinel Block <ip>".
Requires the script to be run as Administrator.

block_ip() returns one of:
  "blocked"          a new rule was created
  "already_blocked"  a rule for this IP already exists
  "whitelisted"      the IP must never be blocked
  "failed"           the input was not an IP address, or netsh failed
"""

import ipaddress
import logging
import subprocess
import sys
import threading

import netinfo
from config import NEVER_BLOCK_NETWORKS, DNS_SERVERS

logger = logging.getLogger("cybersentinel.blocker")

BLOCKED         = "blocked"
ALREADY_BLOCKED = "already_blocked"
WHITELISTED     = "whitelisted"
FAILED          = "failed"

RULE_PREFIX = "CyberSentinel Block "

# IPs with a CyberSentinel rule in the firewall (loaded at startup, kept in sync)
_blocked_ips: set = set()
_lock = threading.Lock()

_static_networks = [ipaddress.ip_network(n, strict=False) for n in NEVER_BLOCK_NETWORKS]
_dynamic_ips: set | None = None   # own IPs, gateways, DNS servers; detected on first use


def _parse_ip(ip) -> str | None:
    """Canonical string form of ip, or None if it is not a valid IP address."""
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return None


def set_dynamic_whitelist(ips) -> None:
    """Replace the detected never-block addresses (own IPs, gateways, DNS servers)."""
    global _dynamic_ips
    _dynamic_ips = {p for p in map(_parse_ip, ips) if p}


def init_whitelist() -> set:
    """Detect this machine's IPs, default gateways and DNS servers and never block them."""
    gateways, dns = netinfo.gateways_and_dns()
    ips = netinfo.local_ips() | gateways | dns | set(DNS_SERVERS)
    set_dynamic_whitelist(ips)
    logger.info(f"[WHITELIST] own IPs, gateways and DNS servers: {sorted(_dynamic_ips)}")
    return set(_dynamic_ips)


def is_whitelisted(ip) -> bool:
    """True if ip must never be blocked. Invalid input counts as whitelisted."""
    canonical = _parse_ip(ip)
    if canonical is None:
        return True
    if _dynamic_ips is None:
        init_whitelist()
    addr = ipaddress.ip_address(canonical)
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return True
    if isinstance(addr, ipaddress.IPv4Address) and addr == ipaddress.IPv4Address("255.255.255.255"):
        return True
    if canonical in _dynamic_ips:
        return True
    return any(addr.version == net.version and addr in net for net in _static_networks)


def _run(args: list, timeout: int = 10) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def _rule_exists(rule_name: str) -> bool:
    """Ask the firewall whether a rule with this exact name exists."""
    try:
        result = _run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"])
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def load_existing_rules() -> int:
    """
    Read existing "CyberSentinel Block *" rules so the blocked list survives a restart.
    Returns the number of distinct blocked IPs found.
    """
    if sys.platform != "win32":
        return 0
    try:
        result = _run([
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            f"Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' -ErrorAction SilentlyContinue"
            " | ForEach-Object { $_.DisplayName }",
        ], timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning(f"[BLOCKER] Could not read existing firewall rules: {e}")
        return 0

    names = [line.strip() for line in result.stdout.splitlines() if line.strip().startswith(RULE_PREFIX)]
    found = {p for p in (_parse_ip(n[len(RULE_PREFIX):]) for n in names) if p}
    with _lock:
        _blocked_ips.update(found)
    if len(names) > len(found):
        logger.warning(
            f"[BLOCKER] {len(names) - len(found)} duplicate or malformed CyberSentinel rules found. "
            f"Clean up with: Remove-NetFirewallRule -DisplayName '{RULE_PREFIX}*'"
        )
    logger.info(f"[BLOCKER] Loaded {len(found)} blocked IPs from existing firewall rules")
    return len(found)


def block_ip(src_ip: str) -> str:
    """
    Add a Windows Firewall inbound block rule for src_ip.
    Returns "blocked", "already_blocked", "whitelisted" or "failed".
    """
    ip = _parse_ip(src_ip)
    if ip is None:
        logger.warning(f"[BLOCK FAILED] {src_ip!r} is not a valid IP address")
        return FAILED

    if is_whitelisted(ip):
        logger.info(f"[BLOCK SKIPPED] {ip} is whitelisted")
        return WHITELISTED

    rule_name = f"{RULE_PREFIX}{ip}"

    with _lock:
        if ip in _blocked_ips:
            return ALREADY_BLOCKED

        # The rule may exist without us knowing (created by an earlier run)
        if _rule_exists(rule_name):
            _blocked_ips.add(ip)
            return ALREADY_BLOCKED

        try:
            result = _run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
                "profile=any",
            ])
        except (OSError, subprocess.SubprocessError) as e:
            logger.error(f"[BLOCK ERROR] {ip}: {e}")
            return FAILED

        if result.returncode != 0:
            msg = (result.stderr or result.stdout).strip()
            logger.warning(f"[BLOCK FAILED] {ip}: {msg} (run main.py as Administrator)")
            return FAILED

        _blocked_ips.add(ip)

    logger.info(f"[BLOCKED] {ip} — Windows Firewall rule created: '{rule_name}'")
    return BLOCKED


def unblock_ip(src_ip: str) -> bool:
    """
    Remove the Windows Firewall block rule for src_ip.
    Used by dashboard 'Unblock' button action.
    """
    ip = _parse_ip(src_ip)
    if ip is None:
        logger.warning(f"[UNBLOCK FAILED] {src_ip!r} is not a valid IP address")
        return False

    rule_name = f"{RULE_PREFIX}{ip}"

    try:
        result = _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
    except (OSError, subprocess.SubprocessError) as e:
        logger.error(f"[UNBLOCK ERROR] {e}")
        return False

    if result.returncode == 0:
        with _lock:
            _blocked_ips.discard(ip)
        logger.info(f"[UNBLOCKED] {ip}")
        return True

    logger.warning(f"[UNBLOCK FAILED] {ip}: {(result.stderr or result.stdout).strip()}")
    return False


def unblock_all() -> int:
    """
    Remove ALL CyberSentinel firewall rules (cleanup after demo).
    Returns count of IPs that were known to be blocked.
    """
    try:
        _run([
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            f"Remove-NetFirewallRule -DisplayName '{RULE_PREFIX}*'",
        ], timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        logger.error(f"[UNBLOCK ALL ERROR] {e}")
        return 0
    with _lock:
        count = len(_blocked_ips)
        _blocked_ips.clear()
    logger.info(f"[UNBLOCK ALL] Cleared {count} CyberSentinel firewall rules")
    return count


def get_blocked_ips() -> set:
    """Return the set of currently blocked IPs."""
    with _lock:
        return set(_blocked_ips)
