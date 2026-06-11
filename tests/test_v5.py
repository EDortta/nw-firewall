#!/usr/bin/env python3
"""authmon v5 test suite: signing/replay, guard, logtail rotation, detector
rules, TTL state, rate limiter, config secret rejection."""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from authmon import logtail, state
from authmon.config import ConfigError, _reject_inline_secrets, load_config
from authmon.events import (
    make_event,
    sign_event,
    validate_incoming,
    verify_signature,
)
from authmon.ipguard import Guard, is_public_unicast, normalize_ip

SECRET = "test-secret"


@pytest.fixture
def conn(tmp_path):
    c = state.connect(tmp_path / "test.db")
    yield c
    c.close()


# --- events: signature, freshness, replay -----------------------------------

def test_sign_and_verify_roundtrip():
    event = make_event("block", "node-a", ip="45.83.20.9", reason="test", ttl=60)
    signed = sign_event(event, SECRET)
    assert verify_signature(signed, [SECRET])
    assert not verify_signature(signed, ["wrong"])


def test_tampered_event_rejected():
    signed = sign_event(make_event("block", "node-a", ip="45.83.20.9"), SECRET)
    signed["ip"] = "45.83.20.10"
    ok, why = validate_incoming(signed, secrets=[SECRET], max_age_seconds=300)
    assert not ok and why == "invalid_signature"


def test_unsigned_event_rejected():
    event = make_event("block", "node-a", ip="45.83.20.9")
    ok, why = validate_incoming(event, secrets=[SECRET], max_age_seconds=300)
    assert not ok and why == "invalid_signature"


def test_stale_event_rejected():
    event = make_event("unblock", "node-a", ip="45.83.20.9")
    event["ts"] = (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat()
    signed = sign_event(event, SECRET)
    ok, why = validate_incoming(signed, secrets=[SECRET], max_age_seconds=300)
    assert not ok and why == "stale_event"


def test_heartbeat_exempt_from_freshness():
    event = make_event("heartbeat", "node-a")
    event["ts"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    signed = sign_event(event, SECRET)
    ok, _ = validate_incoming(signed, secrets=[SECRET], max_age_seconds=300)
    assert ok


def test_key_rotation_previous_secret_accepted():
    signed = sign_event(make_event("block", "n", ip="45.83.20.9"), "old-secret")
    ok, _ = validate_incoming(signed, secrets=["new-secret", "old-secret"], max_age_seconds=300)
    assert ok


def test_replay_dedupe(conn):
    event = sign_event(make_event("block", "n", ip="45.83.20.9"), SECRET)
    event_id = event["event_id"]
    assert not state.has_seen(conn, event_id)
    state.mark_seen(conn, event_id)
    assert state.has_seen(conn, event_id)


# --- ipguard -----------------------------------------------------------------

def test_private_and_reserved_not_blockable():
    for ip in ("10.1.2.3", "192.168.0.5", "172.16.9.1", "127.0.0.1",
               "169.254.1.1", "::1", "fe80::1", "224.0.0.1", "0.0.0.0"):
        assert not is_public_unicast(ip), ip
    assert is_public_unicast("45.83.20.9")


def test_guard_denies_allowlist_protected_and_never_block():
    guard = Guard(
        allowlist=["9.9.9.0/24"],
        never_block=["8.8.4.4"],
        protected_ips={"1.1.1.1"},
    )
    assert guard.check("9.9.9.7") == (False, "allowlisted")
    assert guard.check("8.8.4.4") == (False, "never_block_list")
    assert guard.check("1.1.1.1") == (False, "protected_self_or_broker")
    assert guard.check("10.0.0.1") == (False, "non_public_address")
    assert guard.check("not-an-ip") == (False, "invalid_ip")
    assert guard.check("45.83.20.9") == (True, "ok")


def test_normalize_ip():
    assert normalize_ip("[2001:db8::1]") == "2001:db8::1"
    assert normalize_ip("fe80::1%eth0") == "fe80::1"
    assert normalize_ip("203.0.113.009") is None or normalize_ip("45.83.20.9") == "45.83.20.9"
    assert normalize_ip("garbage") is None


# --- config: inline secrets refused ------------------------------------------

def test_inline_secret_rejected(tmp_path):
    cfg = {"mqtt": {"host": "h", "topic": "t", "password": "leaked!"}}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(cfg))
    with pytest.raises(ConfigError, match="inline secret"):
        load_config(path)


def test_clean_config_loads(tmp_path):
    cfg = {"mqtt": {"host": "broker.test", "topic": "authmon/v5/events"}}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(cfg))
    loaded = load_config(path)
    assert loaded["mqtt"]["host"] == "broker.test"
    assert loaded["mqtt"]["tls"] is True  # secure default
    assert loaded["node_id"]


def test_reject_inline_secrets_nested():
    with pytest.raises(ConfigError):
        _reject_inline_secrets({"a": [{"hmac_secret": "x"}]})


# --- logtail: offsets and rotation --------------------------------------------

def test_logtail_reads_only_new_lines(conn, tmp_path):
    log = tmp_path / "access.log"
    log.write_text("line1\nline2\n")
    assert logtail.read_new_lines(conn, str(log)) == ["line1", "line2"]
    assert logtail.read_new_lines(conn, str(log)) == []
    with open(log, "a") as f:
        f.write("line3\n")
    assert logtail.read_new_lines(conn, str(log)) == ["line3"]


def test_logtail_handles_truncation(conn, tmp_path):
    log = tmp_path / "access.log"
    log.write_text("old1\nold2\nold3\n")
    logtail.read_new_lines(conn, str(log))
    log.write_text("new1\n")  # rotation/truncate
    assert logtail.read_new_lines(conn, str(log)) == ["new1"]


def test_logtail_keeps_partial_line(conn, tmp_path):
    log = tmp_path / "access.log"
    log.write_text("done\npartial-without-newline")
    assert logtail.read_new_lines(conn, str(log)) == ["done"]
    with open(log, "a") as f:
        f.write("-finished\n")
    assert logtail.read_new_lines(conn, str(log)) == ["partial-without-newline-finished"]


# --- state: blocks TTL ---------------------------------------------------------

def test_block_ttl_lifecycle(conn):
    state.upsert_block(conn, ip="45.83.20.9", reason="r", source="s", ttl_seconds=3600)
    assert state.get_active_block(conn, "45.83.20.9")
    assert state.list_expired_blocks(conn) == []
    state.upsert_block(conn, ip="45.83.20.8", reason="r", source="s", ttl_seconds=-1)
    assert state.list_expired_blocks(conn) == ["45.83.20.8"]
    state.deactivate_block(conn, "45.83.20.8")
    assert state.list_expired_blocks(conn) == []


def test_outbox_at_least_once(conn):
    event = make_event("block", "n", ip="45.83.20.9")
    state.outbox_add(conn, event)
    pending = state.outbox_pending(conn)
    assert len(pending) == 1
    row_id, loaded, applied = pending[0]
    assert loaded["ip"] == "45.83.20.9" and not applied
    state.outbox_mark_applied(conn, row_id)
    assert state.outbox_pending(conn)[0][2] is True  # applied, still unpublished
    state.outbox_mark_published(conn, row_id)
    assert state.outbox_pending(conn) == []


# --- detector rules -------------------------------------------------------------

def _make_detector(tmp_path, conn_path, **det_overrides):
    from detector.detect import Detector

    det = {
        "nginx_access_logs": [],
        "auth_log": "",
        "http_404_burst_threshold": 3,
        "http_404_window_seconds": 120,
        "bad_status_threshold": 5,
        "unique_path_threshold": 3,
        "bad_status_window_seconds": 600,
        "auth_fail_threshold": 3,
        "auth_fail_window_seconds": 300,
        "immediate_block_paths": ["/.env", "etc/passwd"],
        "high_risk_paths": ["/wp-login.php"],
        "ignore_path_patterns": ["/health"],
        "ignore_ips": [],
    }
    det.update(det_overrides)
    cfg = {
        "node_id": "test-node",
        "mqtt": {"host": "127.0.0.1", "port": 1883, "topic": "t", "qos": 1,
                 "keepalive": 60, "tls": False, "username": "", "password_env": "X"},
        "security": {"hmac_env": "X", "hmac_previous_env": "Y", "max_event_age_seconds": 300},
        "enforcement": {"backend": "ipset", "set_prefix": "t", "chain": "INPUT",
                        "target": "DROP", "default_ttl_seconds": 3600,
                        "max_blocks_per_minute": 30, "max_sync_entries": 100,
                        "never_block": [], "allowlist": []},
        "detection": det,
        "state": {"db_path": str(conn_path), "seen_events_retention_days": 14},
        "sync": {"heartbeat_interval_seconds": 300, "state_sync_interval_seconds": 3600},
    }
    return Detector(cfg)


def _nginx_line(ip, path, status, ts=None, ua="curl/8"):
    ts = ts or datetime.now(timezone.utc)
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "GET {path} HTTP/1.1" {status} 123 "-" "{ua}"'


def test_detector_immediate_block_path(tmp_path):
    detector = _make_detector(tmp_path, tmp_path / "d.db")
    detector.process_combined_log_line(_nginx_line("45.83.20.9", "/.env", 404))
    assert any(r.startswith("immediate:") for r in detector.offenders["45.83.20.9"])


def test_detector_404_burst(tmp_path):
    detector = _make_detector(tmp_path, tmp_path / "d.db")
    for i in range(3):
        detector.process_combined_log_line(_nginx_line("45.83.20.9", f"/missing-{i}", 404))
    assert "http_404_burst" in detector.offenders.get("45.83.20.9", set())


def test_detector_ignores_health_and_private(tmp_path):
    detector = _make_detector(tmp_path, tmp_path / "d.db")
    for i in range(10):
        detector.process_combined_log_line(_nginx_line("45.83.20.9", "/health", 404))
        detector.process_combined_log_line(_nginx_line("10.0.0.5", f"/x-{i}", 404))
    assert detector.offenders == {}


def test_detector_ssh_burst(tmp_path):
    detector = _make_detector(tmp_path, tmp_path / "d.db")
    line = "May 11 10:00:00 host sshd[123]: Failed password for root from 45.83.20.77 port 5142 ssh2"
    for _ in range(3):
        detector.process_auth_line(line)
    assert "ssh_auth_fail_burst" in detector.offenders.get("45.83.20.77", set())


def test_detector_traversal(tmp_path):
    detector = _make_detector(tmp_path, tmp_path / "d.db")
    detector.process_combined_log_line(_nginx_line("45.83.20.9", "/foo/..%2f..%2fsecret", 404))
    assert "path_traversal" in detector.offenders.get("45.83.20.9", set())


# --- detector: Caddy / Traefik / HAProxy ------------------------------------------

def _caddy_line(ip, path, status, ua="curl/8"):
    return json.dumps({
        "level": "info", "ts": 1718000000.0,
        "request": {"remote_ip": ip, "uri": path, "method": "GET",
                    "headers": {"User-Agent": [ua]}},
        "status": status,
    })


def _traefik_line(ip, path, status, ua="curl/8"):
    return json.dumps({
        "ClientHost": ip, "RequestPath": path, "RequestMethod": "GET",
        "DownstreamStatus": status, "request_User-Agent": [ua],
        "StartUTC": "2024-06-10T12:00:00Z",
    })


def _haproxy_line(ip, path, status):
    return (
        f'Jun 10 12:00:00 host haproxy[1]: {ip}:1234 '
        f'[10/Jun/2024:12:00:00.000] frontend backend/server '
        f'0/0/1/2/3 {status} 512 - - ---- 1/1/1/1/0 0/0 '
        f'"GET {path} HTTP/1.1"'
    )


def test_caddy_immediate_block(tmp_path):
    detector = _make_detector(tmp_path, tmp_path / "d.db")
    detector.process_caddy_line(_caddy_line("45.83.20.9", "/.env", 200))
    assert any(r.startswith("immediate:") for r in detector.offenders["45.83.20.9"])


def test_caddy_404_burst(tmp_path):
    detector = _make_detector(tmp_path, tmp_path / "d.db")
    for i in range(3):
        detector.process_caddy_line(_caddy_line("45.83.20.9", f"/miss-{i}", 404))
    assert "http_404_burst" in detector.offenders.get("45.83.20.9", set())


def test_caddy_ignores_invalid_json(tmp_path):
    detector = _make_detector(tmp_path, tmp_path / "d.db")
    detector.process_caddy_line("not json at all")
    assert detector.offenders == {}


def test_traefik_immediate_block(tmp_path):
    detector = _make_detector(tmp_path, tmp_path / "d.db")
    detector.process_traefik_line(_traefik_line("45.83.20.9", "/.env", 200))
    assert any(r.startswith("immediate:") for r in detector.offenders.get("45.83.20.9", set()))


def test_traefik_404_burst(tmp_path):
    detector = _make_detector(tmp_path, tmp_path / "d.db")
    for i in range(3):
        detector.process_traefik_line(_traefik_line("45.83.20.9", f"/miss-{i}", 404))
    assert "http_404_burst" in detector.offenders.get("45.83.20.9", set())


def test_haproxy_immediate_block(tmp_path):
    detector = _make_detector(tmp_path, tmp_path / "d.db")
    detector.process_haproxy_line(_haproxy_line("45.83.20.9", "/.env", 200))
    assert any(r.startswith("immediate:") for r in detector.offenders.get("45.83.20.9", set()))


def test_haproxy_404_burst(tmp_path):
    detector = _make_detector(tmp_path, tmp_path / "d.db")
    for i in range(3):
        detector.process_haproxy_line(_haproxy_line("45.83.20.9", f"/miss-{i}", 404))
    assert "http_404_burst" in detector.offenders.get("45.83.20.9", set())


def test_haproxy_ignores_private(tmp_path):
    detector = _make_detector(tmp_path, tmp_path / "d.db")
    for i in range(10):
        detector.process_haproxy_line(_haproxy_line("10.0.0.1", f"/x-{i}", 404))
    assert detector.offenders == {}


# --- agent rate limiter -----------------------------------------------------------

def test_rate_limiter():
    from authmon.ratelimit import RateLimiter

    limiter = RateLimiter(3)
    assert [limiter.allow() for _ in range(4)] == [True, True, True, False]
