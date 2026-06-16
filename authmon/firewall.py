#!/usr/bin/env python3
"""Firewall backend: ipset (preferred) with per-rule iptables fallback.

Why ipset: v4 inserted one iptables rule per IP at the top of INPUT, which
degrades packet processing linearly and makes the ruleset unauditable. ipset
gives O(1) hash lookups, a single iptables rule, and kernel-side TTL expiry.

Blocks live in the state DB as source of truth; reconcile() rebuilds the
kernel state from the DB after a reboot.
"""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
from datetime import datetime, timezone

from .events import parse_ts

IPSET_MAX_TIMEOUT = 2147483  # kernel limit (~24.8 days)


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError as exc:
        return 1, str(exc)
    return proc.returncode, (proc.stderr or "").strip()


def _available(binary: str) -> bool:
    return shutil.which(binary) is not None


class Firewall:
    def __init__(self, cfg: dict):
        enf = cfg["enforcement"]
        self.set_v4 = f"{enf['set_prefix']}-v4"
        self.set_v6 = f"{enf['set_prefix']}-v6"
        self.chain = str(enf["chain"])
        self.target = str(enf["target"])
        self.backend = str(enf.get("backend", "ipset"))
        if self.backend == "ipset" and not _available("ipset"):
            self.backend = "iptables"

    # -- setup ---------------------------------------------------------------

    def ensure(self) -> list[str]:
        """Idempotent: create sets and the single match rule per family."""
        problems: list[str] = []
        if self.backend != "ipset":
            return problems
        for set_name, family in ((self.set_v4, "inet"), (self.set_v6, "inet6")):
            code, err = _run(
                ["ipset", "create", set_name, "hash:ip", "family", family, "timeout", "0", "-exist"]
            )
            if code != 0:
                problems.append(f"ipset create {set_name}: {err}")
        for binary, set_name in (("iptables", self.set_v4), ("ip6tables", self.set_v6)):
            if not _available(binary):
                continue
            rule = ["-m", "set", "--match-set", set_name, "src", "-j", self.target]
            code, _ = _run([binary, "-C", self.chain, *rule])
            if code != 0:
                code, err = _run([binary, "-I", self.chain, "1", *rule])
                if code != 0:
                    problems.append(f"{binary} insert match rule: {err}")
        return problems

    # -- operations ----------------------------------------------------------

    def _binaries_for(self, ip: str) -> tuple[str, str]:
        version = ipaddress.ip_address(ip).version
        return ("iptables", self.set_v4) if version == 4 else ("ip6tables", self.set_v6)

    def block(self, ip: str, ttl_seconds: int) -> str | None:
        binary, set_name = self._binaries_for(ip)
        if self.backend == "ipset":
            timeout = max(1, min(int(ttl_seconds), IPSET_MAX_TIMEOUT))
            code, err = _run(["ipset", "add", set_name, ip, "timeout", str(timeout), "-exist"])
            return None if code == 0 else (err or f"ipset add exit {code}")
        # iptables fallback: no kernel TTL; the agent's reconcile loop removes
        # expired blocks based on the state DB.
        code, _ = _run([binary, "-C", self.chain, "-s", ip, "-j", self.target])
        if code == 0:
            return None
        code, err = _run([binary, "-I", self.chain, "1", "-s", ip, "-j", self.target])
        return None if code == 0 else (err or f"{binary} insert exit {code}")

    def unblock(self, ip: str) -> str | None:
        binary, set_name = self._binaries_for(ip)
        if self.backend == "ipset":
            code, err = _run(["ipset", "del", set_name, ip, "-exist"])
            return None if code == 0 else (err or f"ipset del exit {code}")
        last_err = None
        while True:
            code, _ = _run([binary, "-C", self.chain, "-s", ip, "-j", self.target])
            if code != 0:
                return last_err
            code, err = _run([binary, "-D", self.chain, "-s", ip, "-j", self.target])
            if code != 0:
                return err or f"{binary} delete exit {code}"

    # -- port allowlist ------------------------------------------------------

    def _iptables_for(self, protocol: str) -> str:
        return "ip6tables" if protocol == "ipv6" else "iptables"

    def allow_port(self, ip: str, port: int, protocol: str = "tcp") -> str | None:
        binary = self._iptables_for(protocol)
        rule = ["-p", protocol, "--dport", str(port), "-s", ip, "-j", "ACCEPT"]
        code, _ = _run([binary, "-C", "INPUT", *rule])
        if code == 0:
            return None
        code, err = _run([binary, "-I", "INPUT", "1", *rule])
        return None if code == 0 else (err or f"{binary} insert port rule exit {code}")

    def deny_port(self, ip: str, port: int, protocol: str = "tcp") -> str | None:
        binary = self._iptables_for(protocol)
        rule = ["-p", protocol, "--dport", str(port), "-s", ip, "-j", "ACCEPT"]
        last_err = None
        while True:
            code, _ = _run([binary, "-C", "INPUT", *rule])
            if code != 0:
                return last_err
            code, err = _run([binary, "-D", "INPUT", *rule])
            if code != 0:
                return err or f"{binary} delete port rule exit {code}"

    def reconcile_port_allowlist(self, entries: list[dict]) -> tuple[int, list[str]]:
        applied, errors = 0, []
        for entry in entries:
            err = self.allow_port(entry["ip"], int(entry["port"]), entry["protocol"])
            if err:
                errors.append(f"{entry['ip']}:{entry['port']}/{entry['protocol']}: {err}")
            else:
                applied += 1
        return applied, errors

    # -- recovery ------------------------------------------------------------

    def reconcile(self, active_blocks: list[dict]) -> tuple[int, list[str]]:
        """Re-apply DB blocks to the kernel (used at startup; reboot-safe)."""
        now = datetime.now(timezone.utc)
        applied, errors = 0, []
        for entry in active_blocks:
            expires = parse_ts(entry.get("expires_at", ""))
            if expires is None:
                continue
            remaining = int((expires - now).total_seconds())
            if remaining <= 0:
                continue
            err = self.block(entry["ip"], remaining)
            if err:
                errors.append(f"{entry['ip']}: {err}")
            else:
                applied += 1
        return applied, errors
