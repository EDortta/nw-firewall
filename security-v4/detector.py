#!/usr/bin/env python3
"""
Detector for scanner/bot intent based on nginx/auth normalized signals.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable
import ipaddress
import json
import re
import uuid


@dataclass
class SignalEvent:
    source: str  # nginx|auth
    ip: str
    ts: datetime
    kind: str  # nginx_404|auth_fail|high_risk_path|unique_path_probe
    path: str = ""
    status: int = 0
    method: str = ""
    user_agent: str = ""


NGINX_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>[^\s"]+)\s+[^\"]*"\s+(?P<status>\d{3})\s+\S+\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
)


def parse_nginx_timestamp(raw: str) -> datetime:
    # Example: 08/Apr/2026:18:05:54 +0000
    return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)


def parse_nginx_access_line(line: str) -> SignalEvent | None:
    m = NGINX_ACCESS_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = parse_nginx_timestamp(m.group("ts"))
        status = int(m.group("status"))
    except Exception:
        return None

    return SignalEvent(
        source="nginx",
        ip=m.group("ip"),
        ts=ts,
        kind="nginx_404" if status == 404 else "",
        path=m.group("path"),
        status=status,
        method=m.group("method"),
        user_agent=m.group("ua"),
    )


def _is_ignored_ip(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _matches_any(path: str, patterns: list[str]) -> bool:
    p = (path or "").lower()
    for pat in patterns:
        if pat.lower() in p:
            return True
    return False


def enrich_nginx_signal(
    event: SignalEvent,
    *,
    high_risk_paths: list[str],
    ignore_path_patterns: list[str],
) -> list[SignalEvent]:
    """
    Expand a parsed nginx event into detection signals.
    - ignores status/health endpoints by path pattern
    - emits rule-specific signals for scoring
    """
    path = event.path or ""
    if _matches_any(path, ignore_path_patterns):
        return []

    out: list[SignalEvent] = []
    if event.status in (401, 403, 404):
        out.append(SignalEvent(**{**event.__dict__, "kind": "nginx_404"}))
    if _matches_any(path, high_risk_paths):
        out.append(SignalEvent(**{**event.__dict__, "kind": "high_risk_path"}))
    if event.status >= 400:
        out.append(SignalEvent(**{**event.__dict__, "kind": "unique_path_probe"}))
    return out


def events_from_nginx_lines(
    lines: Iterable[str],
    *,
    high_risk_paths: list[str],
    ignore_path_patterns: list[str],
) -> list[SignalEvent]:
    out: list[SignalEvent] = []
    for line in lines:
        parsed = parse_nginx_access_line(line)
        if not parsed:
            continue
        out.extend(
            enrich_nginx_signal(
                parsed,
                high_risk_paths=high_risk_paths,
                ignore_path_patterns=ignore_path_patterns,
            )
        )
    return out


def score_events(
    events: Iterable[SignalEvent],
    *,
    ignore_cidrs: list[str],
    weights: dict[str, int],
    thresholds: dict[str, int],
    windows: dict[str, int],
    block_score: int,
    debounce_seconds: int,
    node_id: str,
) -> list[dict]:
    per_ip: dict[str, dict[str, deque[datetime]]] = defaultdict(
        lambda: {
            "nginx_404_burst": deque(),
            "auth_fail_burst": deque(),
            "high_risk_path_burst": deque(),
            "unique_path_probe_burst": deque(),
        },
    )
    per_ip_paths: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
    last_emit: dict[str, datetime] = {}

    out: list[dict] = []
    for event in sorted(events, key=lambda e: e.ts):
        if _is_ignored_ip(event.ip, ignore_cidrs):
            continue

        now = event.ts
        buckets = per_ip[event.ip]

        rule_key = {
            "nginx_404": "nginx_404_burst",
            "auth_fail": "auth_fail_burst",
            "high_risk_path": "high_risk_path_burst",
            "unique_path_probe": "unique_path_probe_burst",
        }.get(event.kind)
        if not rule_key:
            continue
        buckets[rule_key].append(now)

        if event.path:
            per_ip_paths[event.ip].append((now, event.path))

        score = 0
        reasons: list[str] = []
        counts: dict[str, int] = {}

        for rule, dq in buckets.items():
            window = windows.get(rule, 120)
            cutoff = now - timedelta(seconds=window)
            while dq and dq[0] < cutoff:
                dq.popleft()
            count = len(dq)
            counts[rule] = count
            if count >= thresholds.get(rule, 999999):
                score += weights.get(rule, 0)
                reasons.append(rule)

        # Evaluate distinct probe paths in the probe window.
        probe_window = windows.get("unique_path_probe_burst", 120)
        probe_cutoff = now - timedelta(seconds=probe_window)
        path_deque = per_ip_paths[event.ip]
        while path_deque and path_deque[0][0] < probe_cutoff:
            path_deque.popleft()
        unique_paths = sorted({p for _, p in path_deque})
        counts["unique_probe_paths"] = len(unique_paths)

        if score < block_score:
            continue

        if event.ip in last_emit:
            elapsed = (now - last_emit[event.ip]).total_seconds()
            if elapsed < debounce_seconds:
                continue

        last_emit[event.ip] = now
        sample_paths = unique_paths[:10]
        out.append(
            {
                "event_id": str(uuid.uuid4()),
                "type": "ip_risk_detected",
                "ip": event.ip,
                "score": score,
                "reasons": reasons,
                "counts": counts,
                "sample_paths": sample_paths,
                "window_sec": max(windows.values()) if windows else 0,
                "origin_server": node_id,
                "observed_at": now.astimezone(timezone.utc).isoformat(),
                "ttl_sec": windows.get("unique_path_probe_burst", 120),
            },
        )
    return out


if __name__ == "__main__":
    now = datetime.now(timezone.utc)
    sample = [
        SignalEvent(source="nginx", ip="203.0.113.10", ts=now, kind="nginx_404", path="/.env", status=404),
        SignalEvent(source="nginx", ip="203.0.113.10", ts=now, kind="high_risk_path", path="/.env", status=404),
        SignalEvent(source="nginx", ip="203.0.113.10", ts=now, kind="unique_path_probe", path="/wp-login.php", status=404),
    ]
    events = score_events(
        sample,
        ignore_cidrs=["127.0.0.1/32"],
        weights={
            "nginx_404_burst": 60,
            "auth_fail_burst": 40,
            "high_risk_path_burst": 30,
            "unique_path_probe_burst": 30,
        },
        thresholds={
            "nginx_404_burst": 1,
            "auth_fail_burst": 6,
            "high_risk_path_burst": 1,
            "unique_path_probe_burst": 1,
        },
        windows={
            "nginx_404_burst": 120,
            "auth_fail_burst": 300,
            "high_risk_path_burst": 120,
            "unique_path_probe_burst": 120,
        },
        block_score=80,
        debounce_seconds=30,
        node_id="demo",
    )
    print(json.dumps(events, indent=2))
