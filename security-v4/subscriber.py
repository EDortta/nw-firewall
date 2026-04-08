#!/usr/bin/env python3
"""
Subscriber helpers for replicated risk/block events.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from state import has_seen, mark_seen, record_decision


def verify_event(event: dict[str, Any], secret: str) -> bool:
    received = str(event.get("signature", ""))
    if not received:
        return False
    unsigned = dict(event)
    unsigned.pop("signature", None)
    payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode("ascii")
    return hmac.compare_digest(received, expected)


def is_not_expired(event: dict[str, Any], now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    ts = datetime.fromisoformat(str(event["observed_at"]).replace("Z", "+00:00"))
    ttl = int(event.get("ttl_sec", 0))
    return now <= ts + timedelta(seconds=ttl)


def validate_incoming_event(
    *,
    conn,
    event: dict[str, Any],
    secret: str,
    now: datetime | None = None,
) -> tuple[bool, str]:
    now = now or datetime.now(timezone.utc)
    now_iso = now.isoformat()
    event_id = str(event.get("event_id", "")).strip()

    if not event_id:
        record_decision(
            conn,
            ip=str(event.get("ip", "")),
            event_id="",
            action="reject",
            reason="missing_event_id",
            created_at=now_iso,
            raw=event,
        )
        return False, "missing_event_id"

    if has_seen(conn, event_id):
        record_decision(
            conn,
            ip=str(event.get("ip", "")),
            event_id=event_id,
            action="reject",
            reason="duplicate",
            created_at=now_iso,
            raw=event,
        )
        return False, "duplicate"

    if not verify_event(event, secret):
        record_decision(
            conn,
            ip=str(event.get("ip", "")),
            event_id=event_id,
            action="reject",
            reason="invalid_signature",
            created_at=now_iso,
            raw=event,
        )
        return False, "invalid_signature"

    if not is_not_expired(event, now=now):
        record_decision(
            conn,
            ip=str(event.get("ip", "")),
            event_id=event_id,
            action="reject",
            reason="expired",
            created_at=now_iso,
            raw=event,
        )
        mark_seen(conn, event_id, now_iso)
        return False, "expired"

    mark_seen(conn, event_id, now_iso)
    return True, "ok"


if __name__ == "__main__":
    print("subscriber helpers ready")
