#!/usr/bin/env python3
"""Geo enrichment service — persistent daemon that enriches blocked IPs with
geolocation data, coordinates with the fleet via geo_claim/geo_enriched MQTT
events, and persists results to the local SQLite state DB.

One instance runs per node. Coordination:
  geo_claim    → "I'm geocoding these IPs, skip them"
  geo_enriched → "Done; here is the data for the fleet"

Fleet nodes running only the agent also store geo_enriched events (agent.py
handles them), so geo data propagates to every node automatically.
"""
from __future__ import annotations

import signal
import sys
import time
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import requests
except ImportError:
    print("error: pip install requests", file=sys.stderr)
    sys.exit(1)

from authmon import state
from authmon.config import load_config, load_secret, load_hmac_secrets, ConfigError
from authmon.events import make_event, utc_now_iso
from authmon.ipguard import normalize_ip
from authmon.mqttbus import MqttBus

IPAPI_URL    = "http://ip-api.com/batch"
IPAPI_FIELDS = "status,country,countryCode,city,region,lat,lon,as,org,isp,query"
BATCH_SIZE   = 100
POLL_INTERVAL = 60       # seconds between enrichment cycles
CLAIM_WINDOW  = 2.0      # wait after geo_claim before geocoding
CLAIM_TTL     = 600      # seconds a remote claim is considered valid


def log(msg: str, *, err: bool = False) -> None:
    print(f"{utc_now_iso()} [geo-enricher] {msg}",
          file=sys.stderr if err else sys.stdout, flush=True)


class GeoEnricher:
    def __init__(self, cfg: dict):
        self.cfg      = cfg
        self.node_id  = str(cfg["node_id"])
        self.conn     = state.connect(cfg["state"]["db_path"])
        self.db_lock  = threading.Lock()
        self.secrets  = load_hmac_secrets(cfg)
        self.stop_event = threading.Event()

        # ip → expiry monotonic timestamp: IPs claimed by *other* nodes
        self._remote_claims: dict[str, float] = {}
        self._claims_lock = threading.Lock()

        self.bus = MqttBus(
            cfg,
            client_id_role="geo",
            password=load_secret(
                str(cfg["mqtt"]["password_env"]),
                required=bool(cfg["mqtt"]["username"]),
            ),
            hmac_secret=self.secrets[0],
            on_event=self._handle_event,
        )

    # ── MQTT event handler ───────────────────────────────────────────────────

    def _handle_event(self, payload: dict) -> None:
        event_type = str(payload.get("event", "")).lower()
        sender     = str(payload.get("node", ""))

        if event_type == "geo_claim" and sender != self.node_id:
            ips    = payload.get("ips", [])
            expiry = time.monotonic() + CLAIM_TTL
            with self._claims_lock:
                for ip in ips:
                    self._remote_claims[ip] = expiry
            log(f"geo_claim from={sender} ips={len(ips)}")

        elif event_type == "geo_enriched" and sender != self.node_id:
            entries = payload.get("entries", [])
            stored  = 0
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
                except Exception as exc:
                    log(f"warn: store failed ip={ip}: {exc}", err=True)
            # Remove from remote claims — they're done
            with self._claims_lock:
                for entry in entries:
                    self._remote_claims.pop(str(entry.get("ip", "")), None)
            log(f"geo_enriched from={sender} stored={stored}/{len(entries)}")

    # ── internal helpers ─────────────────────────────────────────────────────

    def _purge_expired_claims(self) -> None:
        now = time.monotonic()
        with self._claims_lock:
            expired = [ip for ip, exp in self._remote_claims.items() if exp <= now]
            for ip in expired:
                del self._remote_claims[ip]

    def _is_claimed(self, ip: str) -> bool:
        with self._claims_lock:
            exp = self._remote_claims.get(ip)
        if exp is None:
            return False
        if exp <= time.monotonic():
            with self._claims_lock:
                self._remote_claims.pop(ip, None)
            return False
        return True

    def _geocode_batch(self, ips: list[str]) -> list[dict]:
        try:
            resp = requests.post(
                IPAPI_URL,
                params={"fields": IPAPI_FIELDS},
                json=ips,
                timeout=15,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            log(f"warn: ip-api.com error: {exc}", err=True)
            return []

    def _enrich(self, ips: list[str]) -> list[dict]:
        """Geocode a batch, persist, return enriched entries."""
        raw     = self._geocode_batch(ips)
        entries = []
        for d in raw:
            if d.get("status") != "success":
                continue
            ip = normalize_ip(str(d.get("query", "")))
            if not ip:
                continue
            entry = {
                "ip":      ip,
                "lat":     d.get("lat"),
                "lon":     d.get("lon"),
                "cc":      d.get("countryCode", ""),
                "city":    d.get("city", ""),
                "country": d.get("country", ""),
                "region":  d.get("region", ""),
                "asn":     d.get("as", ""),
                "org":     d.get("org", ""),
                "isp":     d.get("isp", ""),
            }
            try:
                with self.db_lock:
                    state.geo_upsert(self.conn, **entry)
            except Exception as exc:
                log(f"warn: store failed ip={ip}: {exc}", err=True)
                continue
            entries.append(entry)
        return entries

    # ── main cycle ───────────────────────────────────────────────────────────

    def _run_cycle(self) -> None:
        self._purge_expired_claims()

        with self.db_lock:
            candidates = state.geo_missing(self.conn, limit=BATCH_SIZE * 2)

        ours = [ip for ip in candidates if not self._is_claimed(ip)]
        if not ours:
            return

        ours = ours[:BATCH_SIZE]
        log(f"claiming {len(ours)} IPs")

        claim_event = make_event("geo_claim", self.node_id, ips=ours)
        with self.db_lock:
            state.mark_seen(self.conn, claim_event["event_id"])
        err = self.bus.publish_signed(claim_event)
        if err:
            log(f"warn: geo_claim publish failed: {err}", err=True)

        # Give other nodes time to see the claim
        time.sleep(CLAIM_WINDOW)

        # Re-check: drop any beaten by a faster remote claim
        ours = [ip for ip in ours if not self._is_claimed(ip)]
        if not ours:
            log("all IPs claimed by remote nodes, skipping batch")
            return

        entries = self._enrich(ours)
        log(f"enriched {len(entries)}/{len(ours)} IPs")

        if not entries:
            return

        enriched_event = make_event("geo_enriched", self.node_id, entries=entries)
        with self.db_lock:
            state.mark_seen(self.conn, enriched_event["event_id"])
        err = self.bus.publish_signed(enriched_event)
        if err:
            log(f"warn: geo_enriched publish failed: {err}", err=True)

    # ── lifecycle ────────────────────────────────────────────────────────────

    def run(self) -> None:
        self.bus.start()
        log(f"started node={self.node_id}")

        signal.signal(signal.SIGTERM, lambda *_: self.stop_event.set())
        signal.signal(signal.SIGINT,  lambda *_: self.stop_event.set())

        while not self.stop_event.is_set():
            try:
                self._run_cycle()
            except Exception as exc:
                log(f"error: cycle: {exc}", err=True)
            self.stop_event.wait(POLL_INTERVAL)

        self.bus.stop()
        log("stopped")


def main() -> None:
    try:
        cfg      = load_config()
        enricher = GeoEnricher(cfg)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        sys.exit(1)
    enricher.run()


if __name__ == "__main__":
    main()
