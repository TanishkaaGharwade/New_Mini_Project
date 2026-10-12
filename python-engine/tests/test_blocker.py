"""Blocker tests. netsh and PowerShell are replaced by a fake; the real firewall is never touched."""

import subprocess
import sys

import pytest

import blocker


class FakeShell:
    """Records commands and answers like netsh / PowerShell would."""

    def __init__(self, existing_rules=(), add_ok=True, listing=""):
        self.rules = set(existing_rules)
        self.add_ok = add_ok
        self.listing = listing
        self.calls = []

    def __call__(self, args, timeout=10):
        self.calls.append(args)
        if args[0] == "powershell":
            return subprocess.CompletedProcess(args, 0, stdout=self.listing, stderr="")
        verb = args[3]
        name = args[5][len("name="):]
        if verb == "show":
            return subprocess.CompletedProcess(args, 0 if name in self.rules else 1, "", "")
        if verb == "add":
            if not self.add_ok:
                return subprocess.CompletedProcess(args, 1, "", "The requested operation requires elevation")
            self.rules.add(name)
            return subprocess.CompletedProcess(args, 0, "Ok.", "")
        if verb == "delete":
            found = name in self.rules
            self.rules.discard(name)
            return subprocess.CompletedProcess(args, 0 if found else 1, "", "")
        raise AssertionError(args)

    def adds(self):
        return [a for a in self.calls if a[0] == "netsh" and a[3] == "add"]


@pytest.fixture
def shell(monkeypatch):
    fake = FakeShell()
    monkeypatch.setattr(blocker, "_run", fake)
    monkeypatch.setattr(blocker, "_blocked_ips", set())
    # Detected own IP, gateway and DNS server (so the test never asks Windows)
    monkeypatch.setattr(blocker, "_dynamic_ips", {"192.168.1.34", "192.168.1.1", "8.8.8.8"})
    return fake


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "127.9.9.9", "::1",               # loopback
    "192.168.1.34", "192.168.1.1", "8.8.8.8",      # own IP, gateway, DNS (detected)
    "192.168.0.1", "13.107.4.50",                  # configured networks
    "224.0.0.251", "255.255.255.255", "0.0.0.0",   # multicast, broadcast, unspecified
])
def test_whitelisted(shell, ip):
    assert blocker.is_whitelisted(ip)
    assert blocker.block_ip(ip) == blocker.WHITELISTED
    assert shell.adds() == []


@pytest.mark.parametrize("ip", ["192.168.1.10", "192.168.1.19", "192.168.1.100", "192.168.1.199",
                                "198.51.100.42"])
def test_old_prefix_bug_is_gone(shell, ip):
    # "192.168.1.1" used to match every address starting with it
    assert not blocker.is_whitelisted(ip)


@pytest.mark.parametrize("bad", ["", "localhost", "999.1.1.1", "1.2.3.4; del *", "1.2.3.4 name=x"])
def test_invalid_input_never_reaches_netsh(shell, bad):
    assert blocker.block_ip(bad) == blocker.FAILED
    assert blocker.is_whitelisted(bad)              # invalid input is never treated as blockable
    assert shell.calls == []


def test_block_once_then_already_blocked(shell):
    assert blocker.block_ip("198.51.100.42") == blocker.BLOCKED
    assert blocker.block_ip("198.51.100.42") == blocker.ALREADY_BLOCKED
    assert len(shell.adds()) == 1
    assert blocker.get_blocked_ips() == {"198.51.100.42"}
    add = shell.adds()[0]
    assert "name=CyberSentinel Block 198.51.100.42" in add and "remoteip=198.51.100.42" in add


def test_existing_rule_is_not_duplicated(shell):
    shell.rules.add("CyberSentinel Block 203.0.113.7")
    assert blocker.block_ip("203.0.113.7") == blocker.ALREADY_BLOCKED
    assert shell.adds() == []
    assert "203.0.113.7" in blocker.get_blocked_ips()


def test_ipv6_is_canonicalised(shell):
    assert blocker.block_ip("2001:DB8:0:0::1") == blocker.BLOCKED
    assert blocker.block_ip("2001:db8::1") == blocker.ALREADY_BLOCKED
    assert len(shell.adds()) == 1


def test_failed_add(shell):
    shell.add_ok = False
    assert blocker.block_ip("198.51.100.42") == blocker.FAILED
    assert blocker.get_blocked_ips() == set()


def test_unblock(shell):
    blocker.block_ip("198.51.100.42")
    assert blocker.unblock_ip("198.51.100.42") is True
    assert blocker.get_blocked_ips() == set()
    assert blocker.unblock_ip("198.51.100.42") is False         # no rule left
    assert blocker.unblock_ip("not-an-ip") is False


def test_load_existing_rules(shell, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    shell.listing = ("CyberSentinel Block 198.51.100.42\n"
                     "CyberSentinel Block 198.51.100.42\n"           # duplicate from the old build
                     "CyberSentinel Block 203.0.113.9\n"
                     "CyberSentinel Block garbage\n")
    assert blocker.load_existing_rules() == 2
    assert blocker.get_blocked_ips() == {"198.51.100.42", "203.0.113.9"}
    assert blocker.block_ip("203.0.113.9") == blocker.ALREADY_BLOCKED
    assert shell.adds() == []
