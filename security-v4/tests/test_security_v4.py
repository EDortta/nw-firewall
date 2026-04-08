from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

import sys

BASE = Path(__file__).resolve().parents[1]
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

import detector  # noqa: E402
import enforcer  # noqa: E402
import publisher  # noqa: E402
import subscriber  # noqa: E402
import state  # noqa: E402


class TestDetector(unittest.TestCase):
    def test_parse_and_ignore_status_health(self) -> None:
        line_status = '172.18.0.1 - - [08/Apr/2026:18:05:54 +0000] "GET /v1/core/status HTTP/1.1" 404 10 "-" "curl/8.0"'
        line_probe = '172.18.0.1 - - [08/Apr/2026:18:05:55 +0000] "GET /.env HTTP/1.1" 404 10 "-" "curl/8.0"'

        events = detector.events_from_nginx_lines(
            [line_status, line_probe],
            high_risk_paths=["/.env"],
            ignore_path_patterns=["/status", "/health", "/api/health/"],
        )

        self.assertTrue(any(e.path == "/.env" for e in events))
        self.assertFalse(any("/status" in e.path for e in events))

    def test_scoring_emits_risk_event(self) -> None:
        now = datetime.now(timezone.utc)
        events = [
            detector.SignalEvent(source="nginx", ip="198.51.100.10", ts=now, kind="nginx_404", path="/.env", status=404),
            detector.SignalEvent(source="nginx", ip="198.51.100.10", ts=now, kind="high_risk_path", path="/.env", status=404),
            detector.SignalEvent(source="nginx", ip="198.51.100.10", ts=now, kind="unique_path_probe", path="/wp-login.php", status=404),
        ]

        out = detector.score_events(
            events,
            ignore_cidrs=["127.0.0.1/32"],
            weights={
                "nginx_404_burst": 60,
                "auth_fail_burst": 40,
                "high_risk_path_burst": 30,
                "unique_path_probe_burst": 30,
            },
            thresholds={
                "nginx_404_burst": 1,
                "auth_fail_burst": 99,
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
            debounce_seconds=1,
            node_id="node-a",
        )

        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["type"], "ip_risk_detected")
        self.assertGreaterEqual(out[0]["score"], 80)


class _FakeRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, cmd, check=False):  # type: ignore[override]
        self.calls.append(list(cmd))

        class Result:
            returncode = 0

        return Result()


class TestEnforcerAndReplication(unittest.TestCase):
    def test_allowlist_precedence_and_ttl_unblock(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            conn = state.connect(str(Path(td) / "db.sqlite"))
            fake = _FakeRunner()
            pol = enforcer.PolicyEnforcer(
                conn=conn,
                set_name="risk_block_v4",
                allowlist=["203.0.113.0/24"],
                ignore_cidrs=["10.0.0.0/8"],
                block_ttl_seconds=2,
                dry_run=False,
                runner=fake,
            )

            event_allow = {
                "event_id": "evt-allow",
                "ip": "203.0.113.11",
                "score": 90,
                "reasons": ["high_risk_path_burst"],
                "origin_server": "node-a",
                "observed_at": datetime.now(timezone.utc).isoformat(),
            }
            r1 = pol.apply_risk_event(event_allow)
            self.assertEqual(r1.action, "skipped_allowlist")
            self.assertEqual(len(fake.calls), 0)

            event_block = {
                "event_id": "evt-block",
                "ip": "198.51.100.7",
                "score": 90,
                "reasons": ["high_risk_path_burst"],
                "origin_server": "node-a",
                "observed_at": datetime.now(timezone.utc).isoformat(),
            }
            r2 = pol.apply_risk_event(event_block)
            self.assertEqual(r2.action, "blocked")
            self.assertTrue(any(c[:3] == ["ipset", "add", "risk_block_v4"] for c in fake.calls))

            future = datetime.now(timezone.utc) + timedelta(seconds=5)
            expired = pol.reconcile_expired(now=future)
            self.assertEqual(len(expired), 1)
            self.assertTrue(any(c[:3] == ["ipset", "del", "risk_block_v4"] for c in fake.calls))

    def test_signed_replication_validation_and_dedupe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            conn = state.connect(str(Path(td) / "db.sqlite"))
            secret = "super-secret"
            event = {
                "event_id": "evt-1",
                "type": "ip_risk_detected",
                "ip": "198.51.100.15",
                "score": 90,
                "origin_server": "node-a",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "ttl_sec": 120,
                "reasons": ["nginx_404_burst"],
                "counts": {"nginx_404_burst": 20},
            }
            signed = publisher.build_signed_event(event, secret)

            ok, reason = subscriber.validate_incoming_event(conn=conn, event=signed, secret=secret)
            self.assertTrue(ok)
            self.assertEqual(reason, "ok")

            # second time must be duplicate
            ok2, reason2 = subscriber.validate_incoming_event(conn=conn, event=signed, secret=secret)
            self.assertFalse(ok2)
            self.assertEqual(reason2, "duplicate")


class TestEndToEndPipeline(unittest.TestCase):
    def test_e2e_detect_block_publish_validate_apply(self) -> None:
        lines = [
            '198.51.100.22 - - [08/Apr/2026:18:05:54 +0000] "GET /.env HTTP/1.1" 404 10 "-" "scanner"',
            '198.51.100.22 - - [08/Apr/2026:18:05:55 +0000] "GET /wp-login.php HTTP/1.1" 404 10 "-" "scanner"',
            '198.51.100.22 - - [08/Apr/2026:18:05:56 +0000] "GET /phpmyadmin HTTP/1.1" 404 10 "-" "scanner"',
        ]

        signals = detector.events_from_nginx_lines(
            lines,
            high_risk_paths=["/.env", "/wp-login.php", "/phpmyadmin"],
            ignore_path_patterns=["/status", "/health", "/api/health/"],
        )
        risks = detector.score_events(
            signals,
            ignore_cidrs=[],
            weights={
                "nginx_404_burst": 60,
                "auth_fail_burst": 40,
                "high_risk_path_burst": 30,
                "unique_path_probe_burst": 30,
            },
            thresholds={
                "nginx_404_burst": 2,
                "auth_fail_burst": 99,
                "high_risk_path_burst": 1,
                "unique_path_probe_burst": 2,
            },
            windows={
                "nginx_404_burst": 120,
                "auth_fail_burst": 300,
                "high_risk_path_burst": 120,
                "unique_path_probe_burst": 120,
            },
            block_score=80,
            debounce_seconds=10,
            node_id="node-a",
        )
        self.assertTrue(risks)
        event_now = datetime.fromisoformat(risks[0]["observed_at"])

        secret = "secret"
        signed = publisher.build_signed_event(risks[0], secret)

        with tempfile.TemporaryDirectory() as td:
            conn_a = state.connect(str(Path(td) / "a.sqlite"))
            conn_b = state.connect(str(Path(td) / "b.sqlite"))
            fake_a = _FakeRunner()
            fake_b = _FakeRunner()

            en_a = enforcer.PolicyEnforcer(
                conn=conn_a,
                set_name="risk_block_v4",
                allowlist=[],
                ignore_cidrs=[],
                block_ttl_seconds=300,
                dry_run=False,
                runner=fake_a,
            )
            en_b = enforcer.PolicyEnforcer(
                conn=conn_b,
                set_name="risk_block_v4",
                allowlist=[],
                ignore_cidrs=[],
                block_ttl_seconds=300,
                dry_run=False,
                runner=fake_b,
            )

            ra = en_a.apply_risk_event(risks[0], now=event_now)
            self.assertEqual(ra.action, "blocked")

            ok, reason = subscriber.validate_incoming_event(conn=conn_b, event=signed, secret=secret, now=event_now)
            self.assertTrue(ok, reason)
            rb = en_b.apply_risk_event(signed, now=event_now)
            self.assertEqual(rb.action, "blocked")
            self.assertTrue(any(c[:3] == ["ipset", "add", "risk_block_v4"] for c in fake_b.calls))


if __name__ == "__main__":
    unittest.main()
