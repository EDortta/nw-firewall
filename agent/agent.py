#!/usr/bin/env python3
"""authmon v5 agent — the only process that touches the firewall and MQTT.

Responsibilities:
- enforce local detections from the outbox (local-first: works with broker down);
- publish outbox events to the grid (at-least-once, marked per row — replaces
  v4's fragile timestamp watermark);
- subscribe to the grid and enforce validated remote events;
- TTL lifecycle (expire + unblock), startup reconciliation (reboot-safe);
- heartbeat and periodic state sync so offline nodes converge.

Every enforcement passes: signature → freshness → dedupe → Guard → rate limit.
"""
from __future__ import annotations

import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from authmon import state
from authmon.ratelimit import RateLimiter
from authmon.config import load_config, load_secret, load_hmac_secrets, ConfigError
from authmon.events import (
    ENFORCEMENT_EVENTS,
    make_event,
    parse_ts,
    utc_now_iso,
    validate_incoming,
)
from authmon.firewall import Firewall
from authmon.ipguard import Guard, normalize_ip
from authmon.mqttbus import MqttBus


def log(msg: str, *, err: bool = False) -> None:
    print(f"{utc_now_iso()} {msg}", file=sys.stderr if err else sys.stdout, flush=True)


class Agent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.node_id = str(cfg["node_id"])
        self.conn = state.connect(cfg["state"]["db_path"])
        self.db_lock = threading.Lock()
        self.secrets = load_hmac_secrets(cfg)
        self.guard = Guard.build(cfg, extra_allowlist=state.allowlist_ips(self.conn))
        self.firewall = Firewall(cfg)
        enf = cfg["enforcement"]
        self.default_ttl = int(enf["default_ttl_seconds"])
        self.max_sync_entries = int(enf["max_sync_entries"])
        self.limiter = RateLimiter(int(enf["max_blocks_per_minute"]))
        self.max_event_age = int(cfg["security"]["max_event_age_seconds"])
        self.stop_event = threading.Event()
        self.bus = MqttBus(
            cfg,
            client_id_role="agent",
            password=load_secret(str(cfg["mqtt"]["password_env"]), required=bool(cfg["mqtt"]["username"])),
            hmac_secret=self.secrets[0],
            on_event=self.handle_event,
        )

    # -- enforcement core ------------------------------------------------

    def enforce_block(self, ip: str, reason: str, source: str, ttl: int | None) -> str:
        allowed, why = self.guard.check(ip)
        if not allowed:
            with self.db_lock:
                state.record_decision(self.conn, ip=ip, action="reject_block", reason=why, detail=source)
            return why
        if not self.limiter.allow():
            with self.db_lock:
                state.record_decision(self.conn, ip=ip, action="reject_block", reason="rate_limited", detail=source)
            log(f"error: rate limit hit, dropping block ip={ip} source={source}", err=True)
            return "rate_limited"

        ttl = ttl if ttl and ttl > 0 else self.default_ttl
        err = self.firewall.block(ip, ttl)
        if err:
            with self.db_lock:
                state.record_decision(self.conn, ip=ip, action="block_failed", reason=err, detail=source)
            log(f"error: block failed ip={ip} reason={err}", err=True)
            return "firewall_error"
        with self.db_lock:
            state.upsert_block(self.conn, ip=ip, reason=reason, source=source, ttl_seconds=ttl)
            state.record_decision(self.conn, ip=ip, action="block", reason=reason, detail=source)
        log(f"block ip={ip} ttl={ttl} source={source} reason={reason}")
        return "ok"

    def enforce_unblock(self, ip: str, source: str) -> str:
        err = self.firewall.unblock(ip)
        if err:
            with self.db_lock:
                state.record_decision(self.conn, ip=ip, action="unblock_failed", reason=err, detail=source)
            return "firewall_error"
        with self.db_lock:
            state.deactivate_block(self.conn, ip)
            state.record_decision(self.conn, ip=ip, action="unblock", reason="requested", detail=source)
        log(f"unblock ip={ip} source={source}")
        return "ok"

    # -- incoming events ---------------------------------------------------

    def handle_event(self, payload: dict) -> None:
        ok, why = validate_incoming(
            payload, secrets=self.secrets, max_age_seconds=self.max_event_age
        )
        if not ok:
            if why not in {"wrong_version"}:  # tolerate mixed v4/v5 topics quietly
                log(f"warn: rejected event reason={why}", err=True)
            return

        event_id = str(payload["event_id"])
        event_type = str(payload["event"]).strip().lower()

        with self.db_lock:
            if state.has_seen(self.conn, event_id):
                return
            state.mark_seen(self.conn, event_id)

        source = f"{event_type}@{payload.get('node', 'unknown')}"

        if event_type == "heartbeat":
            log(f"heartbeat node={payload.get('node')} blocks={payload.get('active_blocks', '?')}")
            return
        if event_type == "node_offline":
            log(f"warn: node offline: {payload.get('node')}", err=True)
            return

        if event_type == "block":
            ip = normalize_ip(str(payload.get("ip", "")))
            if ip:
                self.enforce_block(ip, str(payload.get("reason", "")), source, int(payload.get("ttl", 0) or 0))
            return
        if event_type == "unblock":
            ip = normalize_ip(str(payload.get("ip", "")))
            if ip:
                self.enforce_unblock(ip, source)
            return
        if event_type == "allow_add":
            ip = normalize_ip(str(payload.get("ip", "")))
            if ip:
                with self.db_lock:
                    state.allowlist_add(self.conn, ip, str(payload.get("reason", "")))
                self.guard = Guard.build(self.cfg, extra_allowlist=state.allowlist_ips(self.conn))
                self.enforce_unblock(ip, source)
            return
        if event_type == "allow_remove":
            ip = normalize_ip(str(payload.get("ip", "")))
            if ip:
                with self.db_lock:
                    state.allowlist_remove(self.conn, ip)
                self.guard = Guard.build(self.cfg, extra_allowlist=state.allowlist_ips(self.conn))
            return
        if event_type == "sync_state":
            if str(payload.get("node", "")) == self.node_id:
                return
            entries = payload.get("blocks")
            if not isinstance(entries, list):
                return
            applied = 0
            now = datetime.now(timezone.utc)
            for entry in entries[: self.max_sync_entries]:
                if not isinstance(entry, dict):
                    continue
                ip = normalize_ip(str(entry.get("ip", "")))
                expires = parse_ts(str(entry.get("expires_at", "")))
                if not ip or expires is None:
                    continue
                remaining = int((expires - now).total_seconds())
                if remaining <= 0:
                    continue
                with self.db_lock:
                    already = state.get_active_block(self.conn, ip) is not None
                if already:
                    continue
                if self.enforce_block(ip, str(entry.get("reason", "sync")), source, remaining) == "ok":
                    applied += 1
            log(f"sync_state from={payload.get('node')} entries={len(entries)} applied={applied}")
            return

    # -- periodic work (main thread; never inside mqtt callbacks) -----------

    def pump_outbox(self) -> None:
        with self.db_lock:
            pending = state.outbox_pending(self.conn)
        for row_id, event, applied in pending:
            event_type = str(event.get("event", "")).strip().lower()
            ip = normalize_ip(str(event.get("ip", "")))

            if not applied:
                if event_type == "block" and ip:
                    self.enforce_block(
                        ip, str(event.get("reason", "")), f"local:{event.get('detector', 'outbox')}",
                        int(event.get("ttl", 0) or 0),
                    )
                elif event_type == "unblock" and ip:
                    self.enforce_unblock(ip, "local:outbox")
                with self.db_lock:
                    state.outbox_mark_applied(self.conn, row_id)

            # Refresh ts/event_id at publish time so receivers' freshness
            # window applies to transmission, not detection lag.
            wire = dict(event)
            wire.update({"ts": utc_now_iso(), "node": self.node_id})
            with self.db_lock:
                state.mark_seen(self.conn, str(wire.get("event_id", "")))
            err = self.bus.publish_signed(wire)
            if err:
                log(f"warn: outbox publish deferred id={row_id}: {err}", err=True)
                break  # broker likely down; retry next cycle in order
            with self.db_lock:
                state.outbox_mark_published(self.conn, row_id)

    def expire_blocks(self) -> None:
        with self.db_lock:
            expired = state.list_expired_blocks(self.conn)
        for ip in expired:
            err = self.firewall.unblock(ip)
            with self.db_lock:
                state.deactivate_block(self.conn, ip)
                state.record_decision(
                    self.conn, ip=ip, action="unblock", reason="ttl_expired", detail=err or ""
                )
            log(f"unblock ip={ip} reason=ttl_expired")

    def send_heartbeat(self) -> None:
        with self.db_lock:
            count = len(state.list_active_blocks(self.conn))
        event = make_event("heartbeat", self.node_id, active_blocks=count, role="agent")
        with self.db_lock:
            state.mark_seen(self.conn, event["event_id"])
        err = self.bus.publish_signed(event)
        if err:
            log(f"warn: heartbeat publish failed: {err}", err=True)

    def send_state_sync(self) -> None:
        with self.db_lock:
            blocks = state.list_active_blocks(self.conn)
        if len(blocks) > self.max_sync_entries:
            log(f"warn: sync truncated {len(blocks)} -> {self.max_sync_entries}", err=True)
            blocks = blocks[: self.max_sync_entries]
        event = make_event("sync_state", self.node_id, blocks=blocks)
        with self.db_lock:
            state.mark_seen(self.conn, event["event_id"])
        err = self.bus.publish_signed(event)
        if err:
            log(f"warn: state sync publish failed: {err}", err=True)

    # -- main loop -----------------------------------------------------------

    def run(self) -> None:
        problems = self.firewall.ensure()
        for problem in problems:
            log(f"error: firewall setup: {problem}", err=True)
        with self.db_lock:
            active = state.list_active_blocks(self.conn)
        applied, errors = self.firewall.reconcile(active)
        log(f"startup reconcile blocks={len(active)} applied={applied} errors={len(errors)}")
        for error in errors[:10]:
            log(f"error: reconcile: {error}", err=True)

        self.bus.start()

        heartbeat_every = int(self.cfg["sync"]["heartbeat_interval_seconds"])
        sync_every = int(self.cfg["sync"]["state_sync_interval_seconds"])
        retention_days = int(self.cfg["state"]["seen_events_retention_days"])
        last_heartbeat = 0.0
        last_sync = time.monotonic()  # first full sync after one interval
        last_expire = 0.0
        last_prune = 0.0

        signal.signal(signal.SIGTERM, lambda *_: self.stop_event.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop_event.set())
        log(f"agent started node={self.node_id} backend={self.firewall.backend}")

        while not self.stop_event.is_set():
            now = time.monotonic()
            try:
                self.pump_outbox()
                if now - last_expire >= 30:
                    self.expire_blocks()
                    last_expire = now
                if now - last_heartbeat >= heartbeat_every:
                    self.send_heartbeat()
                    last_heartbeat = now
                if now - last_sync >= sync_every:
                    self.send_state_sync()
                    last_sync = now
                if now - last_prune >= 6 * 3600:
                    with self.db_lock:
                        state.prune_seen(self.conn, retention_days)
                    last_prune = now
            except Exception as exc:  # keep the daemon alive; systemd restarts on hard crash
                log(f"error: periodic loop: {exc}", err=True)
            self.stop_event.wait(5)

        self.bus.stop()
        log("agent stopped")


def main() -> None:
    try:
        cfg = load_config()
        agent = Agent(cfg)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        sys.exit(1)
    agent.run()


if __name__ == "__main__":
    main()
