#!/usr/bin/env python3
"""IP validation and the never-block guard.

v4 lesson: the server-side listener applied any block it received, including
private ranges and (potentially) the broker or the node itself. In v5 every
enforcement path goes through Guard.check() — there is no code path that
touches the firewall without it.
"""
from __future__ import annotations

import ipaddress
import socket


def normalize_ip(value: str) -> str | None:
    candidate = str(value).strip().strip("[]")
    if not candidate:
        return None
    if "%" in candidate:  # IPv6 zone id
        candidate = candidate.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def is_public_unicast(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _parse_networks(values: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets = []
    for value in values:
        try:
            nets.append(ipaddress.ip_network(str(value).strip(), strict=False))
        except ValueError:
            continue
    return nets


def _in_networks(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in nets)


def resolve_host_ips(host: str) -> set[str]:
    out: set[str] = set()
    try:
        for info in socket.getaddrinfo(host, None):
            ip = normalize_ip(info[4][0])
            if ip:
                out.add(ip)
    except OSError:
        pass
    return out


def resolve_self_ips(broker_host: str) -> set[str]:
    """Local addresses plus the source IP used to reach the broker."""
    out: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = normalize_ip(info[4][0])
            if ip:
                out.add(ip)
    except OSError:
        pass
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.connect((broker_host, 1))
                ip = normalize_ip(sock.getsockname()[0])
                if ip:
                    out.add(ip)
        except OSError:
            continue
    return out


class Guard:
    def __init__(
        self,
        *,
        allowlist: list[str],
        never_block: list[str],
        protected_ips: set[str],
    ):
        self.allow_nets = _parse_networks(allowlist)
        self.never_nets = _parse_networks(never_block)
        self.protected_ips = set(protected_ips)

    @classmethod
    def build(cls, cfg: dict, *, extra_allowlist: list[str] | None = None) -> "Guard":
        enf = cfg["enforcement"]
        broker_host = str(cfg["mqtt"]["host"])
        protected = resolve_self_ips(broker_host) | resolve_host_ips(broker_host)
        # Resolve peer node IPs — grid members must never be blocked by each other.
        for peer in enf.get("peers", []):
            protected |= resolve_host_ips(str(peer))
        return cls(
            allowlist=list(enf.get("allowlist", [])) + list(extra_allowlist or []),
            never_block=list(enf.get("never_block", [])),
            protected_ips=protected,
        )

    def is_allowlisted(self, ip: str) -> bool:
        return _in_networks(ip, self.allow_nets)

    def check(self, ip: str) -> tuple[bool, str]:
        """Returns (blockable, reason). reason explains the denial."""
        normalized = normalize_ip(ip)
        if not normalized:
            return False, "invalid_ip"
        if not is_public_unicast(normalized):
            return False, "non_public_address"
        if normalized in self.protected_ips:
            return False, "protected_self_broker_or_peer"
        if _in_networks(normalized, self.never_nets):
            return False, "never_block_list"
        if self.is_allowlisted(normalized):
            return False, "allowlisted"
        return True, "ok"
