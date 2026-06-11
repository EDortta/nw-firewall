#!/usr/bin/env python3
"""authmon v5 border API — manual control plane, broker node only.

Hardening vs v4:
- block requests pass the same Guard as automatic enforcement (the v4 API
  would happily propagate a block for a private IP or the broker itself);
- per-key simple rate limit on write endpoints;
- all writes audited in the decisions table;
- binds 127.0.0.1 by default; expose via nginx with TLS + client auth.

Auth: Bearer token from AUTHMON_API_KEY (constant-time compare).
"""
from __future__ import annotations

import hmac
import os
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Annotated

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from fastapi import Depends, FastAPI, HTTPException
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    from pydantic import BaseModel, field_validator
    import uvicorn
except ImportError:
    print("error: pip install fastapi 'uvicorn[standard]'", file=sys.stderr)
    sys.exit(1)

from authmon import state
from authmon.config import load_config, load_secret, load_hmac_secrets, ConfigError
from authmon.events import make_event
from authmon.ipguard import Guard, normalize_ip
from authmon.mqttbus import MqttBus

_HOST = os.getenv("AUTHMON_API_HOST", "127.0.0.1")
_PORT = int(os.getenv("AUTHMON_API_PORT", "8741"))
_API_KEY_ENV = "AUTHMON_API_KEY"
_WRITE_RATE_PER_MINUTE = int(os.getenv("AUTHMON_API_WRITE_RATE", "30"))

try:
    CFG = load_config()
    SECRETS = load_hmac_secrets(CFG)
    API_KEY = load_secret(_API_KEY_ENV)
except ConfigError as exc:
    print(f"config error: {exc}", file=sys.stderr)
    sys.exit(1)

CONN = state.connect(CFG["state"]["db_path"])
DB_LOCK = threading.Lock()
GUARD = Guard.build(CFG)
BUS = MqttBus(
    CFG,
    client_id_role="api",
    password=load_secret(str(CFG["mqtt"]["password_env"]), required=bool(CFG["mqtt"]["username"])),
    hmac_secret=SECRETS[0],
)
BUS.start()

_bearer = HTTPBearer()
_write_times: deque[float] = deque()
_write_lock = threading.Lock()


def _auth(creds: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)]) -> None:
    if not hmac.compare_digest(creds.credentials.encode(), API_KEY.encode()):
        raise HTTPException(status_code=401, detail="invalid API key")


def _write_rate_limit() -> None:
    now = time.monotonic()
    with _write_lock:
        while _write_times and _write_times[0] < now - 60:
            _write_times.popleft()
        if len(_write_times) >= _WRITE_RATE_PER_MINUTE:
            raise HTTPException(status_code=429, detail="write rate limit exceeded")
        _write_times.append(now)


def _publish_or_503(event: dict) -> None:
    with DB_LOCK:
        state.mark_seen(CONN, event["event_id"])  # don't re-apply our own echo
    err = BUS.publish_signed(event)
    if err:
        raise HTTPException(status_code=503, detail=f"MQTT propagation failed: {err}")


class IpRequest(BaseModel):
    ip: str
    reason: str = "manual"

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        normalized = normalize_ip(v)
        if not normalized:
            raise ValueError(f"invalid IP: {v!r}")
        return normalized


app = FastAPI(title="authmon v5 border API", version="5.0.0")


@app.get("/v5/health", dependencies=[Depends(_auth)])
def health():
    try:
        with DB_LOCK:
            CONN.execute("SELECT 1").fetchone()
        db_ok = True
    except Exception:
        db_ok = False
    return {"status": "ok" if db_ok else "degraded", "db": db_ok, "node": CFG["node_id"]}


@app.get("/v5/blocked", dependencies=[Depends(_auth)])
def blocked():
    with DB_LOCK:
        rows = state.list_active_blocks(CONN)
    return {"blocks": rows, "count": len(rows)}


@app.get("/v5/allowlist", dependencies=[Depends(_auth)])
def allowlist():
    with DB_LOCK:
        ips = state.allowlist_ips(CONN)
    return {"allowlist": ips, "count": len(ips)}


@app.get("/v5/ip/{ip}", dependencies=[Depends(_auth)])
def ip_status(ip: str):
    normalized = normalize_ip(ip)
    if not normalized:
        raise HTTPException(status_code=422, detail=f"invalid IP: {ip!r}")
    with DB_LOCK:
        block = state.get_active_block(CONN, normalized)
        allowed = normalized in state.allowlist_ips(CONN)
    return {"ip": normalized, "blocked": block, "allowlisted": allowed}


@app.post("/v5/block", status_code=202, dependencies=[Depends(_auth)])
def block(req: IpRequest):
    _write_rate_limit()
    blockable, why = GUARD.check(req.ip)
    if not blockable:
        with DB_LOCK:
            state.record_decision(CONN, ip=req.ip, action="api_reject_block", reason=why)
        raise HTTPException(status_code=409, detail=f"refused: {why}")
    event = make_event(
        "block", CFG["node_id"], ip=req.ip, reason=f"api: {req.reason}",
        ttl=int(CFG["enforcement"]["default_ttl_seconds"]),
    )
    _publish_or_503(event)
    with DB_LOCK:
        state.record_decision(CONN, ip=req.ip, action="api_block", reason=req.reason)
    return {"ip": req.ip, "action": "block", "event_id": event["event_id"]}


@app.post("/v5/unblock", status_code=202, dependencies=[Depends(_auth)])
def unblock(req: IpRequest):
    _write_rate_limit()
    event = make_event("unblock", CFG["node_id"], ip=req.ip, reason=f"api: {req.reason}")
    _publish_or_503(event)
    with DB_LOCK:
        state.record_decision(CONN, ip=req.ip, action="api_unblock", reason=req.reason)
    return {"ip": req.ip, "action": "unblock", "event_id": event["event_id"]}


@app.post("/v5/allowlist", status_code=202, dependencies=[Depends(_auth)])
def allowlist_add(req: IpRequest):
    _write_rate_limit()
    event = make_event("allow_add", CFG["node_id"], ip=req.ip, reason=req.reason)
    _publish_or_503(event)
    with DB_LOCK:
        state.record_decision(CONN, ip=req.ip, action="api_allow_add", reason=req.reason)
    return {"ip": req.ip, "action": "allow_add", "event_id": event["event_id"]}


@app.delete("/v5/allowlist/{ip}", status_code=202, dependencies=[Depends(_auth)])
def allowlist_remove(ip: str):
    _write_rate_limit()
    normalized = normalize_ip(ip)
    if not normalized:
        raise HTTPException(status_code=422, detail=f"invalid IP: {ip!r}")
    event = make_event("allow_remove", CFG["node_id"], ip=normalized, reason="api remove")
    _publish_or_503(event)
    with DB_LOCK:
        state.record_decision(CONN, ip=normalized, action="api_allow_remove", reason="")
    return {"ip": normalized, "action": "allow_remove", "event_id": event["event_id"]}


if __name__ == "__main__":
    uvicorn.run(app, host=_HOST, port=_PORT, log_level="info")
