#!/usr/bin/env python3
"""Event schema, canonical HMAC signing and incoming validation.

Every event on the wire is signed. Enforcement events (anything that mutates
firewall or allowlist state) additionally require freshness (max age) and
event_id dedupe — v4's signed-but-replayable design is the main thing this
module fixes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any

EVENT_VERSION = 5

ENFORCEMENT_EVENTS = {"block", "unblock", "allow_add", "allow_remove", "sync_state", "ip_change",
                      "port_allow_add", "port_allow_remove"}
INFORMATIONAL_EVENTS = {"heartbeat", "node_offline", "geo_claim", "geo_enriched"}
KNOWN_EVENTS = ENFORCEMENT_EVENTS | INFORMATIONAL_EVENTS


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_ts(value: str) -> datetime | None:
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


def canonical_payload(event: dict[str, Any]) -> bytes:
    unsigned = {k: v for k, v in event.items() if k != "sig"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_event(event: dict[str, Any], secret: str) -> dict[str, Any]:
    digest = hmac.new(secret.encode("utf-8"), canonical_payload(event), hashlib.sha256).digest()
    out = dict(event)
    out["sig"] = base64.b64encode(digest).decode("ascii")
    return out


def verify_signature(event: dict[str, Any], secrets: list[str]) -> bool:
    received = str(event.get("sig", ""))
    if not received:
        return False
    payload = canonical_payload(event)
    for secret in secrets:
        digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
        expected = base64.b64encode(digest).decode("ascii")
        if hmac.compare_digest(received, expected):
            return True
    return False


def make_event(event_type: str, node_id: str, **fields: Any) -> dict[str, Any]:
    event = {
        "v": EVENT_VERSION,
        "event": event_type,
        "event_id": str(uuid.uuid4()),
        "ts": utc_now_iso(),
        "node": node_id,
    }
    event.update(fields)
    return event


def validate_incoming(
    event: Any,
    *,
    secrets: list[str],
    max_age_seconds: int,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Structural + signature + freshness validation. Dedupe is the caller's
    job (it needs the state DB)."""
    now = now or datetime.now(timezone.utc)

    if not isinstance(event, dict):
        return False, "not_an_object"
    if event.get("v") != EVENT_VERSION:
        return False, "wrong_version"

    event_type = str(event.get("event", "")).strip().lower()
    if event_type not in KNOWN_EVENTS:
        return False, "unknown_event"
    if not str(event.get("event_id", "")).strip():
        return False, "missing_event_id"

    if not verify_signature(event, secrets):
        return False, "invalid_signature"

    if event_type in ENFORCEMENT_EVENTS:
        ts = parse_ts(str(event.get("ts", "")))
        if ts is None:
            return False, "missing_timestamp"
        age = (now - ts).total_seconds()
        if age > max_age_seconds:
            return False, "stale_event"
        if age < -max_age_seconds:
            return False, "future_timestamp"

    return True, "ok"
