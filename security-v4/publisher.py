#!/usr/bin/env python3
"""
MQTT publisher for risk/block events with deterministic HMAC signature.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any


def canonical_payload(event: dict[str, Any]) -> bytes:
    unsigned = dict(event)
    unsigned.pop("signature", None)
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_event(event: dict[str, Any], secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), canonical_payload(event), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def build_signed_event(event: dict[str, Any], secret: str) -> dict[str, Any]:
    out = dict(event)
    out["signature"] = sign_event(out, secret)
    return out


def publish_event(
    client: Any,
    *,
    topic: str,
    event: dict[str, Any],
    qos: int = 1,
    retain: bool = False,
) -> None:
    payload = json.dumps(event, sort_keys=True, separators=(",", ":"))
    info = client.publish(topic, payload=payload, qos=qos, retain=retain)
    rc = getattr(info, "rc", 0)
    if rc not in (0, None):
        raise RuntimeError(f"mqtt publish failed rc={rc}")


def publish_stub(event: dict[str, Any]) -> None:
    topic = "security/risk-ip/v1"
    print(f"[publish stub] topic={topic} payload={json.dumps(event, sort_keys=True)}")


if __name__ == "__main__":
    secret = os.getenv("SECURITY_EVENT_HMAC", "")
    if not secret:
        raise SystemExit("SECURITY_EVENT_HMAC not set")

    sample = {
        "event_id": "demo",
        "type": "ip_risk_detected",
        "ip": "203.0.113.10",
        "score": 90,
        "origin_server": "demo-node",
        "observed_at": "2026-03-20T00:00:00Z",
        "ttl_sec": 3600,
        "reasons": ["nginx_404_burst"],
        "counts": {"nginx_404_burst": 20},
    }
    publish_stub(build_signed_event(sample, secret))
