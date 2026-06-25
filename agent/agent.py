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
from authmon.ipguard import Guard, normalize_ip, resolve_primary_ip
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
        self.retain_seconds = int(cfg["enforcement"].get("peer_ip_retention_seconds", 86400))
        self.protected_ports: list[dict] = cfg["enforcement"].get("protected_ports", [])
        self.guard = self._build_guard()
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

    # -- guard rebuild ---------------------------------------------------

    def _build_guard(self) -> Guard:
        with self.db_lock:
            extra_al = state.allowlist_ips(self.conn)
            extra_protected = state.peer_ip_protected_set(self.conn)
        return Guard.build(self.cfg, extra_allowlist=extra_al, extra_protected=extra_protected)

    # -- own IP tracking -------------------------------------------------

    def _check_own_ip(self) -> None:
        """Detect own IP changes and announce them to the grid."""
        broker_host = str(self.cfg["mqtt"]["host"])
        current_ip = resolve_primary_ip(broker_host)
        if not current_ip:
            return
        with self.db_lock:
            stored_ip = state.peer_ip_get_active(self.conn, self.node_id)
        if stored_ip is None:
            # First run — register without announcing (no "old" IP to retire).
            with self.db_lock:
                state.peer_ip_upsert(self.conn, self.node_id, current_ip)
            self.guard = self._build_guard()
            log(f"peer_ip registered node={self.node_id} ip={current_ip}")
            return
        if stored_ip == current_ip:
            return
        # IP changed — announce to the grid, retire old.
        log(f"peer_ip changed node={self.node_id} old={stored_ip} new={current_ip}")
        with self.db_lock:
            state.peer_ip_upsert(self.conn, self.node_id, current_ip, "active")
            state.peer_ip_retire(self.conn, stored_ip, self.retain_seconds)
        self.guard = self._build_guard()
        event = make_event(
            "ip_change", self.node_id,
            old_ip=stored_ip, new_ip=current_ip,
            retain_seconds=self.retain_seconds,
        )
        with self.db_lock:
            state.mark_seen(self.conn, event["event_id"])
        err = self.bus.publish_signed(event)
        if err:
            log(f"warn: ip_change publish failed: {err}", err=True)

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

    # -- ip_change -------------------------------------------------------

    def _handle_ip_change(self, payload: dict) -> None:
        node   = str(payload.get("node", "unknown")).strip()
        old_ip = normalize_ip(str(payload.get("old_ip", "")))
        new_ip = normalize_ip(str(payload.get("new_ip", "")))
        retain = int(payload.get("retain_seconds", self.retain_seconds))

        if new_ip:
            with self.db_lock:
                state.peer_ip_upsert(self.conn, node, new_ip, "active")
                # If this IP was retiring (transferred from another node), cancel that.
                state.peer_ip_cancel_retirement(self.conn, new_ip)
        if old_ip and old_ip != new_ip:
            with self.db_lock:
                state.peer_ip_retire(self.conn, old_ip, retain)
        self.guard = self._build_guard()
        log(f"ip_change node={node} old={old_ip} new={new_ip} retain={retain}s")

    # -- port allowlist --------------------------------------------------

    def _applies_here(self, target_node: str) -> bool:
        return target_node in ("*", "all") or target_node == self.node_id

    def _handle_port_allow(self, event_type: str, payload: dict) -> None:
        ip = normalize_ip(str(payload.get("ip", "")))
        if not ip:
            return
        try:
            port = int(payload.get("port", 0))
        except (TypeError, ValueError):
            return
        if not (1 <= port <= 65535):
            return
        protocol = str(payload.get("protocol", "tcp")).strip().lower()
        if protocol not in ("tcp", "udp"):
            return
        target_node = str(payload.get("target_node", "*")).strip() or "*"
        reason = str(payload.get("reason", ""))
        applies = self._applies_here(target_node)

        if event_type == "port_allow_add":
            # Persist for every node (audit + reconcile); enforce only on the target.
            with self.db_lock:
                state.port_allowlist_add(
                    self.conn, ip=ip, port=port, protocol=protocol,
                    reason=reason, created_by=str(payload.get("node", "")),
                    target_node=target_node,
                )
            if applies:
                err = self.firewall.allow_port(ip, port, protocol)
                status = f"error={err}" if err else "applied"
            else:
                status = "stored (not target)"
            log(f"port_allow_add ip={ip} port={port}/{protocol} node={target_node} {status}")
        else:  # port_allow_remove
            with self.db_lock:
                removed = state.port_allowlist_remove(
                    self.conn, ip=ip, port=port, protocol=protocol, target_node=target_node,
                )
            if applies:
                self.firewall.deny_port(ip, port, protocol)
            log(f"port_allow_remove ip={ip} port={port}/{protocol} node={target_node} "
                f"was_present={removed}")

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
        if event_type == "ip_change":
            self._handle_ip_change(payload)
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
                self.guard = self._build_guard()
                self.enforce_unblock(ip, source)
            return
        if event_type == "allow_remove":
            ip = normalize_ip(str(payload.get("ip", "")))
            if ip:
                with self.db_lock:
                    state.allowlist_remove(self.conn, ip)
                self.guard = self._build_guard()
            return
        if event_type in ("port_allow_add", "port_allow_remove"):
            self._handle_port_allow(event_type, payload)
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

        if event_type == "geo_enriched":
            entries = payload.get("entries", [])
            stored = 0
            for entry in entries:
                ip = normalize_ip(str(entry.get("ip", "")))
                if not ip:
                    continue
                try:
                    with self.db_lock:
                        state.geo_upsert(
                            self.conn, ip=ip,
                            lat=float(entry.get("lat") or 0),
                            lon=float(entry.get("lon") or 0),
                            cc=str(entry.get("cc", "")),
                            city=str(entry.get("city", "")),
                            country=str(entry.get("country", "")),
                            region=str(entry.get("region", "")),
                            asn=str(entry.get("asn", "")),
                            org=str(entry.get("org", "")),
                            isp=str(entry.get("isp", "")),
                        )
                    stored += 1
                except Exception:
                    pass
            log(f"geo_enriched from={payload.get('node')} stored={stored}/{len(entries)}")
            return
        if event_type == "geo_claim":
            return  # handled by geo-enricher service

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

        with self.db_lock:
            port_entries = state.port_allowlist_list(self.conn, target_node=self.node_id)
        pa, pe = self.firewall.reconcile_port_allowlist(port_entries, self.protected_ports)
        log(f"startup reconcile port_allowlist={len(port_entries)} applied={pa} errors={len(pe)}")
        for error in pe[:10]:
            log(f"error: reconcile port: {error}", err=True)

        self._check_own_ip()  # register/announce own IP before connecting to grid
        self.bus.start()

        heartbeat_every = int(self.cfg["sync"]["heartbeat_interval_seconds"])
        sync_every = int(self.cfg["sync"]["state_sync_interval_seconds"])
        retention_days = int(self.cfg["state"]["seen_events_retention_days"])
        last_heartbeat = 0.0
        last_sync = time.monotonic()  # first full sync after one interval
        last_expire = 0.0
        last_prune = 0.0
        last_ip_check = time.monotonic()

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
                        state.peer_ip_prune(self.conn)
                    last_prune = now
                if now - last_ip_check >= 300:  # re-check own IP every 5 min
                    self._check_own_ip()
                    last_ip_check = now
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
