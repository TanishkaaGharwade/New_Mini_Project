"""
blocker.py — Windows Firewall Active Blocking for NetSentinel
=============================================================
Source: Repo 3 (Chanveasna-ENG/Network-Intrusion-Detection-and-Monitoring-Tool) util.py
        block_ip() function — directly adapted and extended.

Adds inbound Windows Firewall rules to block attacker source IPs.
Requires the script to be run as Administrator.
"""

import subprocess
import logging
from config import NEVER_BLOCK_IPS

logger = logging.getLogger("netsentinel.blocker")

# In-memory set of IPs already blocked this session (avoids duplicate netsh calls)
_blocked_ips: set = set()


# Subnet prefixes to ignore (Microsoft Teams, Windows Update, Google Cloud CDN)
NEVER_BLOCK_PREFIXES = ("127.", "192.168.1.1", "192.168.0.1", "13.107.", "34.54.", "172.188.")

def block_ip(src_ip: str) -> bool:
    """
    Add a Windows Firewall inbound block rule for src_ip.
    Adapted from Repo 3 util.py block_ip().
    """
    # Never block loopback / own machine / trusted cloud subnets
    if src_ip in NEVER_BLOCK_IPS or any(src_ip.startswith(p) for p in NEVER_BLOCK_PREFIXES):
        logger.debug(f"[BLOCK SKIPPED] {src_ip} is in never-block list")
        return False

    # Skip if already blocked this session
    if src_ip in _blocked_ips:
        logger.debug(f"[BLOCK SKIPPED] {src_ip} already blocked")
        return False

    rule_name = f"NetSentinel Block {src_ip}"

    try:
        result = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={src_ip}",
                "enable=yes",
                "profile=any",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.returncode == 0:
            _blocked_ips.add(src_ip)
            logger.info(f"[BLOCKED] {src_ip} — Windows Firewall rule created: '{rule_name}'")
            print(f"[BLOCK] Firewall rule added: block {src_ip}")
            return True
        else:
            logger.warning(f"[BLOCK FAILED] {src_ip}: {result.stderr.strip()}")
            print(f"[BLOCK FAILED] {src_ip} — {result.stderr.strip()}")
            print("  Tip: Make sure you run main.py as Administrator")
            return False

    except PermissionError:
        logger.warning("[BLOCK ERROR] Run python-engine as Administrator")
        print("[BLOCK ERROR] Requires Administrator privileges")
        return False
    except subprocess.TimeoutExpired:
        logger.warning(f"[BLOCK TIMEOUT] netsh timed out for {src_ip}")
        return False
    except Exception as e:
        logger.error(f"[BLOCK ERROR] {e}")
        return False


def unblock_ip(src_ip: str) -> bool:
    """
    Remove the Windows Firewall block rule for src_ip.
    Used by dashboard 'Unblock' button action.
    """
    rule_name = f"NetSentinel Block {src_ip}"

    try:
        result = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.returncode == 0:
            _blocked_ips.discard(src_ip)
            logger.info(f"[UNBLOCKED] {src_ip}")
            print(f"[UNBLOCK] Firewall rule removed for {src_ip}")
            return True
        else:
            logger.warning(f"[UNBLOCK FAILED] {src_ip}: {result.stderr.strip()}")
            return False

    except Exception as e:
        logger.error(f"[UNBLOCK ERROR] {e}")
        return False


def unblock_all() -> int:
    """
    Remove ALL NetSentinel firewall rules (cleanup after demo).
    Returns count of rules removed.
    """
    try:
        result = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                "name=all",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        count = len(_blocked_ips)
        _blocked_ips.clear()
        print(f"[UNBLOCK ALL] Cleared {count} NetSentinel firewall rules")
        return count
    except Exception as e:
        logger.error(f"[UNBLOCK ALL ERROR] {e}")
        return 0


def get_blocked_ips() -> set:
    """Return the set of currently blocked IPs in this session."""
    return set(_blocked_ips)
