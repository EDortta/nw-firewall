#!/usr/bin/env python3
"""
Policy enforcer: whitelist-first, TTL lifecycle, and idempotent block/unblock.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import subprocess
from typing import Callable

from state import (
    delete_ip_state,
    get_ip_state,
    list_expired_blocks,
    record_decision,
    record_event,
    upsert_ip_state,
)


@dataclass
class EnforcerResult:
    action: str  # blocked|skipped_allowlist|skipped_invalid|already_blocked|unblocked|noop
    ip: str
    reason: str


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_in_cidrs(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def block_ip(ip: str, set_name: str, runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> None:
    runner(["ipset", "add", set_name, ip, "-exist"], check=True)


def unblock_ip(ip: str, set_name: str, runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> None:
    runner(["ipset", "del", set_name, ip], check=False)


class PolicyEnforcer:
    def __init__(
        self,
        *,
        conn,
        set_name: str,
        allowlist: list[str],
        ignore_cidrs: list[str],
        block_ttl_seconds: int,
        dry_run: bool = False,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    ):
        self.conn = conn
        self.set_name = set_name
        self.allowlist = allowlist
        self.ignore_cidrs = ignore_cidrs
        self.block_ttl_seconds = block_ttl_seconds
        self.dry_run = dry_run
        self.runner = runner

    def is_allowlisted(self, ip: str) -> bool:
        return ip in self.allowlist or _is_in_cidrs(ip, self.allowlist) or _is_in_cidrs(ip, self.ignore_cidrs)

    def apply_risk_event(self, event: dict, now: datetime | None = None) -> EnforcerResult:
        now = now or datetime.now(timezone.utc)
        now_iso = now.isoformat()

        ip = str(event.get("ip", "")).strip()
        event_id = str(event.get("event_id", "")).strip()
        if not _is_ip(ip):
            record_decision(
                self.conn,
                ip=ip or "invalid",
                event_id=event_id,
                action="skip",
                reason="invalid_ip",
                created_at=now_iso,
                raw=event,
            )
            return EnforcerResult(action="skipped_invalid", ip=ip, reason="invalid_ip")

        if self.is_allowlisted(ip):
            record_decision(
                self.conn,
                ip=ip,
                event_id=event_id,
                action="skip",
                reason="allowlisted",
                created_at=now_iso,
                raw=event,
            )
            return EnforcerResult(action="skipped_allowlist", ip=ip, reason="allowlisted")

        current = get_ip_state(self.conn, ip)
        blocked_until = (now + timedelta(seconds=self.block_ttl_seconds)).isoformat()
        reasons = [str(r) for r in event.get("reasons", [])]

        if current and current.get("status") == "blocked" and current.get("blocked_until", "") > now_iso:
            upsert_ip_state(
                self.conn,
                ip=ip,
                status="blocked",
                score=int(event.get("score", current.get("score", 0))),
                first_seen=current.get("first_seen", now_iso),
                last_seen=now_iso,
                blocked_until=blocked_until,
                source_server=str(event.get("origin_server", current.get("source_server", ""))),
                reasons=reasons or current.get("reasons", []),
            )
            record_decision(
                self.conn,
                ip=ip,
                event_id=event_id,
                action="refresh_ttl",
                reason="already_blocked",
                created_at=now_iso,
                raw=event,
            )
            record_event(self.conn, event)
            return EnforcerResult(action="already_blocked", ip=ip, reason="ttl_refreshed")

        if not self.dry_run:
            block_ip(ip, self.set_name, runner=self.runner)

        upsert_ip_state(
            self.conn,
            ip=ip,
            status="blocked",
            score=int(event.get("score", 0)),
            first_seen=(current or {}).get("first_seen", now_iso),
            last_seen=now_iso,
            blocked_until=blocked_until,
            source_server=str(event.get("origin_server", "")),
            reasons=reasons,
        )
        record_event(self.conn, event)
        record_decision(
            self.conn,
            ip=ip,
            event_id=event_id,
            action="block" if not self.dry_run else "dry_run_block",
            reason="risk_threshold_reached",
            created_at=now_iso,
            raw=event,
        )
        return EnforcerResult(action="blocked", ip=ip, reason="risk_threshold_reached")

    def reconcile_expired(self, now: datetime | None = None) -> list[EnforcerResult]:
        now = now or datetime.now(timezone.utc)
        now_iso = now.isoformat()
        results: list[EnforcerResult] = []

        for ip in list_expired_blocks(self.conn, now_iso):
            if not self.dry_run:
                unblock_ip(ip, self.set_name, runner=self.runner)
            delete_ip_state(self.conn, ip)
            record_decision(
                self.conn,
                ip=ip,
                event_id="",
                action="unblock" if not self.dry_run else "dry_run_unblock",
                reason="ttl_expired",
                created_at=now_iso,
                raw={},
            )
            results.append(EnforcerResult(action="unblocked", ip=ip, reason="ttl_expired"))
        return results
