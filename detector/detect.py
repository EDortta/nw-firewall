#!/usr/bin/env python3
"""authmon v5 detector — parses web access logs and auth.log, scores
malicious behavior, and writes block intents to the outbox.

Supported log formats:
  - nginx combined   (nginx_access_logs)
  - apache combined  (apache_access_logs)  — identical format to nginx combined
  - lighttpd combined(lighttpd_access_logs) — identical format to nginx combined
  - caddy JSON       (caddy_access_logs)   — default Caddy structured log
  - traefik JSON     (traefik_access_logs) — default Traefik access log
  - haproxy HTTP     (haproxy_access_logs) — haproxy HTTP log format
  - auth.log / sshd  (auth_log)

Runs from a systemd timer (or cron). It never touches the firewall or MQTT:
the agent picks up the outbox, enforces locally and replicates to the grid.

Detection state (sliding windows) is persisted in the signals table, so
bursts spanning multiple runs are detected correctly — v4 re-read a fixed
tail each run and could both miss and double-count.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from authmon import logtail, state
from authmon.config import load_config, ConfigError
from authmon.events import make_event, utc_now_iso
from authmon.ipguard import Guard, is_public_unicast, normalize_ip

# Matches both nginx combined and Apache combined log formats.
# Pattern: IP ident user [timestamp] "METHOD path proto" status size "ref" "ua"
COMBINED_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+[^"]*"\s+'
    r'(?P<status>\d{3})\s+\S+\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
)
TRAVERSAL_RE = re.compile(r"(?:^|/)\.\.(?:/|\\\\|$)")
SSH_PATTERNS = (
    re.compile(r"sshd\[\d+\]:\s+Invalid user\s+.+\s+from\s+(?P<host>\S+)", re.IGNORECASE),
    re.compile(r"sshd\[\d+\]:\s+Failed password for\s+.+\s+from\s+(?P<host>\S+)", re.IGNORECASE),
)
SCANNER_UA_HINTS = (
    "shodan", "zgrab", "masscan", "nmap", "sqlmap", "nikto",
    "nessus", "gobuster", "dirbuster", "nuclei",
)

# HAProxy HTTP log format (haproxy.cfg: option httplog)
# client_ip:port [ts] frontend backend/server timers STATUS bytes captured flags conns queues "METHOD path proto"
HAPROXY_RE = re.compile(
    r'(?P<ip>\d[\d.]+):\d+\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'\S+\s+\S+\s+'         # frontend backend/server
    r'\S+\s+'               # timers (0/0/0/0/0)
    r'(?P<status>\d{3})\s+'
    r'(?:\S+\s+){6}'        # bytes captured flags connections queues
    r'"(?P<method>[A-Z]+)\s+(?P<target>\S+)'
)


def log(msg: str, *, err: bool = False) -> None:
    print(f"{utc_now_iso()} detector {msg}", file=sys.stderr if err else sys.stdout, flush=True)


def parse_combined_ts(raw: str) -> datetime | None:
    """Parse timestamp from nginx/apache/lighttpd combined log format."""
    try:
        return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        return None


def parse_caddy_log(line: str) -> tuple[str, str, str, int, str] | None:
    """Return (ip, target, method, status, ua) from a Caddy JSON log line, or None."""
    try:
        d = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    req = d.get("request") or d.get("Request") or {}
    ip = str(req.get("remote_ip") or req.get("client_ip") or "").strip()
    if not ip:
        return None
    status = int(d.get("status") or d.get("Status") or 0)
    if status == 0:
        return None
    target = str(req.get("uri") or req.get("URI") or "/").strip()
    method = str(req.get("method") or req.get("Method") or "GET").strip().upper()
    hdrs   = req.get("headers") or {}
    ua_list = hdrs.get("User-Agent") or hdrs.get("user-agent") or []
    ua = ua_list[0] if isinstance(ua_list, list) and ua_list else str(ua_list)
    return ip, target, method, status, ua


def parse_traefik_log(line: str) -> tuple[str, str, str, int, str] | None:
    """Return (ip, target, method, status, ua) from a Traefik JSON log line, or None."""
    try:
        d = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    ip = str(d.get("ClientHost") or d.get("client_host") or "").strip()
    if not ip:
        return None
    status = int(d.get("DownstreamStatus") or d.get("downstream_status") or 0)
    if status == 0:
        return None
    target = str(d.get("RequestPath") or d.get("request_path") or "/").strip()
    method = str(d.get("RequestMethod") or d.get("request_method") or "GET").strip().upper()
    ua_raw = d.get("request_User-Agent") or d.get("RequestUserAgent") or []
    ua = ua_raw[0] if isinstance(ua_raw, list) and ua_raw else str(ua_raw)
    return ip, target, method, status, ua


def matches_any(text: str, patterns: list[str]) -> str | None:
    lowered = text.lower()
    for pattern in patterns:
        if str(pattern).lower() in lowered:
            return str(pattern)
    return None


def looks_like_traversal(raw_target: str, decoded: str) -> bool:
    if TRAVERSAL_RE.search(decoded):
        return True
    raw_lower = raw_target.lower()
    return "%2e%2e" in raw_lower or "..%2f" in raw_lower or "%2f.." in raw_lower


def is_scanner_ua(ua: str) -> bool:
    lowered = ua.lower()
    return any(hint in lowered for hint in SCANNER_UA_HINTS)


def ssh_ip_from_line(line: str) -> str | None:
    if "sshd" not in line:
        return None
    for pattern in SSH_PATTERNS:
        match = pattern.search(line)
        if match:
            value = match.group("host").strip().strip("[]")
            if value.count(":") == 1 and "." in value:  # host:port
                host, _, maybe_port = value.partition(":")
                if maybe_port.isdigit():
                    value = host
            return normalize_ip(value)
    return None


class Detector:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        det = cfg["detection"]
        self.det = det
        self.conn = state.connect(cfg["state"]["db_path"])
        self.guard = Guard.build(cfg, extra_allowlist=state.allowlist_ips(self.conn))
        self.ignore_ip_guard = Guard(
            allowlist=list(det.get("ignore_ips", [])), never_block=[], protected_ips=set()
        )
        self.ttl = int(cfg["enforcement"]["default_ttl_seconds"])
        self.offenders: dict[str, set[str]] = {}

    def skip_ip(self, ip: str) -> bool:
        return (
            not is_public_unicast(ip)
            or not self.guard.check(ip)[0]
            or self.ignore_ip_guard.is_allowlisted(ip)
        )

    def flag(self, ip: str, reason: str) -> None:
        self.offenders.setdefault(ip, set()).add(reason)

    # -- web access logs (nginx combined / apache combined) ------------------

    def process_combined_log_line(self, line: str) -> None:
        match = COMBINED_LOG_RE.match(line)
        if not match:
            return
        self._score(
            ip=normalize_ip(match.group("ip")),
            target=match.group("target"),
            method=match.group("method"),
            status=int(match.group("status")),
            ua=match.group("ua"),
            ts=parse_combined_ts(match.group("ts")) or datetime.now(timezone.utc),
        )

    def _score(self, ip: str, target: str, method: str, status: int, ua: str,
               ts: datetime) -> None:
        """Apply detection rules given already-extracted fields."""
        if not ip or self.skip_ip(ip):
            return
        decoded = unquote(target).lower()
        if matches_any(decoded, self.det["ignore_path_patterns"]):
            return
        ts_iso = ts.isoformat()

        hit = matches_any(decoded, self.det["immediate_block_paths"]) or (
            matches_any(target.lower(), self.det["immediate_block_paths"])
        )
        if hit:
            self.flag(ip, f"immediate:{hit}")
            return

        if looks_like_traversal(target, decoded):
            self.flag(ip, "path_traversal")
            return

        if matches_any(decoded, self.det.get("high_risk_paths", [])):
            state.add_signal(self.conn, ip=ip, kind="high_risk_path", ts_iso=ts_iso, path=decoded)

        if status >= 400:
            state.add_signal(self.conn, ip=ip, kind="bad_status", ts_iso=ts_iso, path=decoded)
            if is_scanner_ua(ua):
                self.flag(ip, "scanner_user_agent")
        if status == 404:
            state.add_signal(self.conn, ip=ip, kind="http_404", ts_iso=ts_iso, path=decoded)

        self.evaluate_windows(ip, ts)

    # -- caddy JSON --------------------------------------------------------------

    def process_caddy_line(self, line: str) -> None:
        parsed = parse_caddy_log(line)
        if not parsed:
            return
        ip, target, method, status, ua = parsed
        self._score(normalize_ip(ip), target, method, status, ua, datetime.now(timezone.utc))

    # -- traefik JSON ------------------------------------------------------------

    def process_traefik_line(self, line: str) -> None:
        parsed = parse_traefik_log(line)
        if not parsed:
            return
        ip, target, method, status, ua = parsed
        self._score(normalize_ip(ip), target, method, status, ua, datetime.now(timezone.utc))

    # -- haproxy HTTP ------------------------------------------------------------

    def process_haproxy_line(self, line: str) -> None:
        match = HAPROXY_RE.search(line)
        if not match:
            return
        ip = normalize_ip(match.group("ip"))
        status = int(match.group("status"))
        target = match.group("target")
        ts = parse_combined_ts(match.group("ts")) or datetime.now(timezone.utc)
        self._score(ip, target, "GET", status, "", ts)

    def evaluate_windows(self, ip: str, now: datetime) -> None:
        det = self.det
        since_404 = (now - timedelta(seconds=int(det["http_404_window_seconds"]))).isoformat()
        if state.count_signals(self.conn, ip=ip, kind="http_404", since_iso=since_404) >= int(
            det["http_404_burst_threshold"]
        ):
            self.flag(ip, "http_404_burst")

        since_bad = (now - timedelta(seconds=int(det["bad_status_window_seconds"]))).isoformat()
        bad = state.count_signals(self.conn, ip=ip, kind="bad_status", since_iso=since_bad)
        if bad >= int(det["bad_status_threshold"]):
            if state.count_unique_paths(self.conn, ip=ip, since_iso=since_bad) >= int(
                det["unique_path_threshold"]
            ):
                self.flag(ip, "bad_status_unique_path_burst")

    # -- auth.log ------------------------------------------------------------

    def process_auth_line(self, line: str) -> None:
        ip = ssh_ip_from_line(line)
        if not ip or self.skip_ip(ip):
            return
        now = datetime.now(timezone.utc)
        state.add_signal(self.conn, ip=ip, kind="auth_fail", ts_iso=now.isoformat())
        since = (now - timedelta(seconds=int(self.det["auth_fail_window_seconds"]))).isoformat()
        if state.count_signals(self.conn, ip=ip, kind="auth_fail", since_iso=since) >= int(
            self.det["auth_fail_threshold"]
        ):
            self.flag(ip, "ssh_auth_fail_burst")

    # -- run -----------------------------------------------------------------

    def _process_web_logs(self, key: str, handler) -> int:
        count = 0
        for log_path in self.det.get(key, []):
            for line in logtail.read_new_lines(self.conn, str(log_path)):
                handler(line)
                count += 1
        return count

    def run(self) -> None:
        counts = {
            "nginx":    self._process_web_logs("nginx_access_logs",    self.process_combined_log_line),
            "apache":   self._process_web_logs("apache_access_logs",   self.process_combined_log_line),
            "lighttpd": self._process_web_logs("lighttpd_access_logs", self.process_combined_log_line),
            "caddy":    self._process_web_logs("caddy_access_logs",    self.process_caddy_line),
            "traefik":  self._process_web_logs("traefik_access_logs",  self.process_traefik_line),
            "haproxy":  self._process_web_logs("haproxy_access_logs",  self.process_haproxy_line),
        }
        self.conn.commit()

        auth_lines = 0
        auth_log = str(self.det.get("auth_log", "")).strip()
        if auth_log:
            for line in logtail.read_new_lines(self.conn, auth_log):
                self.process_auth_line(line)
                auth_lines += 1
        self.conn.commit()

        emitted = 0
        for ip in sorted(self.offenders):
            if state.get_active_block(self.conn, ip) is not None:
                continue  # already blocked; agent TTL refresh comes via grid events
            reasons = "; ".join(sorted(self.offenders[ip]))
            event = make_event(
                "block", self.cfg["node_id"], ip=ip, reason=reasons, ttl=self.ttl, detector="v5"
            )
            state.outbox_add(self.conn, event)
            state.record_decision(self.conn, ip=ip, action="detected", reason=reasons)
            emitted += 1
            log(f"detected ip={ip} reasons={reasons}")

        max_window = max(
            int(self.det["http_404_window_seconds"]),
            int(self.det["bad_status_window_seconds"]),
            int(self.det["auth_fail_window_seconds"]),
        )
        state.prune_signals(self.conn, max_window * 2)
        web_summary = " ".join(f"{k}={v}" for k, v in counts.items() if v)
        log(f"run {web_summary} auth={auth_lines} offenders={len(self.offenders)} emitted={emitted}")


def main() -> None:
    try:
        cfg = load_config()
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        sys.exit(1)
    Detector(cfg).run()


if __name__ == "__main__":
    main()
