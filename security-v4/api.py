#!/usr/bin/env python3
"""
Reactive Firewall Border API — runs on the MQTT broker node only.

Exposes a REST control plane for the distributed reactive firewall.
Reads from a local SQLite border state DB; writes publish signed MQTT events
that all subscriber nodes (listen-to-mosquitto.py) enforce immediately.

Auth: Bearer token via SECURITY_API_KEY environment variable.
Bind: 127.0.0.1:8741 by default — expose externally via nginx proxy.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

try:
    from fastapi import Depends, FastAPI, HTTPException
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    from pydantic import BaseModel, field_validator
    import uvicorn
except ImportError:
    print(
        "error: run  python3 -m pip install fastapi 'uvicorn[standard]'  first",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("error: paho-mqtt not installed", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Paths / settings (all overridable via environment)
# ---------------------------------------------------------------------------

_BASE = Path(__file__).resolve().parent.parent
_CONFIG_PATH = Path(os.getenv("AUTH_MONITOR_CONFIG", str(_BASE / "config" / "config.json")))
_DB_PATH = Path(os.getenv("BORDER_API_DB_PATH", "/var/lib/auth-monitor/border.db"))
_LOCK_FILE = Path(os.getenv("BORDER_API_LOCK_FILE", "/var/run/auth-monitor-border-api.lock"))
_HOST = os.getenv("BORDER_API_HOST", "127.0.0.1")
_PORT = int(os.getenv("BORDER_API_PORT", "8741"))
_API_KEY_ENV = "SECURITY_API_KEY"

# ---------------------------------------------------------------------------
# Border state DB
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS blocks (
    ip         TEXT PRIMARY KEY,
    reason     TEXT NOT NULL DEFAULT '',
    blocked_at TEXT NOT NULL,
    blocked_by TEXT NOT NULL DEFAULT 'api'
);
CREATE TABLE IF NOT EXISTS allowlist (
    ip       TEXT PRIMARY KEY,
    reason   TEXT NOT NULL DEFAULT '',
    added_at TEXT NOT NULL,
    added_by TEXT NOT NULL DEFAULT 'api'
);
"""

_db_conn: sqlite3.Connection | None = None


def _get_db() -> sqlite3.Connection:
    global _db_conn
    if _db_conn is None:
        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _db_conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
        _db_conn.row_factory = sqlite3.Row
        _db_conn.executescript(_DDL)
        _db_conn.commit()
    return _db_conn


def _row(r: sqlite3.Row | None) -> dict | None:
    return dict(r) if r else None


# ---------------------------------------------------------------------------
# MQTT publish helpers
# ---------------------------------------------------------------------------

def _load_mqtt_cfg() -> dict:
    cfg = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
    mc = cfg.get("mqtt", {})
    password_env = str(mc.get("password_env", "AUTH_MONITOR_MQTT_PASSWORD")).strip()
    hmac_env = str(mc.get("event_hmac_env", "SECURITY_EVENT_HMAC")).strip() or "SECURITY_EVENT_HMAC"
    return {
        "host": str(mc.get("host", "127.0.0.1")),
        "port": int(mc.get("port", 1883)),
        "topic": str(mc.get("topic", "auth-monitor/blocked-ips")),
        "username": str(mc.get("username", "")).strip(),
        "password": os.getenv(password_env, "").strip(),
        "qos": int(mc.get("qos", 1)),
        "hmac_secret": os.getenv(hmac_env, "").strip(),
    }


def _sign(event: dict, secret: str) -> dict:
    unsigned = {k: v for k, v in event.items() if k != "signature"}
    body = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    digest = hmac.new(secret.encode(), body, hashlib.sha256).digest()
    return {**unsigned, "signature": base64.b64encode(digest).decode()}


def _publish(event: dict) -> None:
    mc = _load_mqtt_cfg()
    if mc["hmac_secret"]:
        event = _sign(event, mc["hmac_secret"])

    cid = f"border-api-{uuid.uuid4().hex[:8]}"
    if hasattr(mqtt, "CallbackAPIVersion"):
        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id=cid
        )
    else:
        client = mqtt.Client(client_id=cid)

    if mc["username"]:
        client.username_pw_set(mc["username"], mc["password"])

    client.connect(mc["host"], mc["port"], keepalive=10)
    client.loop_start()
    payload = json.dumps(event, sort_keys=True, separators=(",", ":"))
    info = client.publish(mc["topic"], payload=payload, qos=mc["qos"])
    info.wait_for_publish(timeout=5.0)
    client.loop_stop()
    client.disconnect()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _node() -> str:
    return socket.gethostname()


def _validate_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Invalid IP address: {ip!r}")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

_bearer_scheme = HTTPBearer()


def _auth(creds: Annotated[HTTPAuthorizationCredentials, Depends(_bearer_scheme)]) -> None:
    expected = os.getenv(_API_KEY_ENV, "").strip()
    if not expected:
        raise HTTPException(status_code=500, detail="SECURITY_API_KEY not configured on server")
    if not hmac.compare_digest(creds.credentials.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Invalid API key")


# ---------------------------------------------------------------------------
# App + request models
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Reactive Firewall Border API",
    version="1.0.0",
    description=(
        "Control plane for the distributed reactive firewall. "
        "Runs on the MQTT broker node only. "
        "Writes publish signed MQTT events that all nodes enforce immediately."
    ),
)


class BlockRequest(BaseModel):
    ip: str
    reason: str = "manual"

    @field_validator("ip")
    @classmethod
    def _v(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError(f"invalid IP: {v!r}")


class UnblockRequest(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def _v(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError(f"invalid IP: {v!r}")


class AllowlistAddRequest(BaseModel):
    ip: str
    reason: str = ""

    @field_validator("ip")
    @classmethod
    def _v(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError(f"invalid IP: {v!r}")


# ---------------------------------------------------------------------------
# Read endpoints
# ---------------------------------------------------------------------------

@app.get("/v1/health", dependencies=[Depends(_auth)])
def health():
    try:
        _get_db().execute("SELECT 1").fetchone()
        db_ok = True
    except Exception:
        db_ok = False
    return {"status": "ok" if db_ok else "degraded", "db": db_ok, "node": _node()}


@app.get("/v1/stats", dependencies=[Depends(_auth)])
def stats():
    db = _get_db()
    return {
        "active_blocks": db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0],
        "allowlist_size": db.execute("SELECT COUNT(*) FROM allowlist").fetchone()[0],
        "node": _node(),
    }


@app.get("/v1/blocked", dependencies=[Depends(_auth)])
def list_blocked():
    rows = _get_db().execute(
        "SELECT ip, reason, blocked_at, blocked_by FROM blocks ORDER BY blocked_at DESC"
    ).fetchall()
    return {"blocks": [dict(r) for r in rows], "count": len(rows)}


@app.get("/v1/ip/{ip}", dependencies=[Depends(_auth)])
def get_ip(ip: str):
    ip = _validate_ip(ip)
    db = _get_db()
    return {
        "ip": ip,
        "blocked": _row(db.execute("SELECT * FROM blocks WHERE ip=?", (ip,)).fetchone()),
        "allowlisted": _row(db.execute("SELECT * FROM allowlist WHERE ip=?", (ip,)).fetchone()),
    }


@app.get("/v1/whitelist", dependencies=[Depends(_auth)])
def list_whitelist():
    rows = _get_db().execute(
        "SELECT ip, reason, added_at, added_by FROM allowlist ORDER BY added_at DESC"
    ).fetchall()
    return {"allowlist": [dict(r) for r in rows], "count": len(rows)}


# ---------------------------------------------------------------------------
# Write endpoints
# ---------------------------------------------------------------------------

@app.post("/v1/block", status_code=202, dependencies=[Depends(_auth)])
def block(req: BlockRequest):
    db = _get_db()
    if db.execute("SELECT 1 FROM allowlist WHERE ip=?", (req.ip,)).fetchone():
        raise HTTPException(
            status_code=409,
            detail=f"{req.ip} is in the allowlist — remove it from the allowlist first",
        )
    now = _now()
    db.execute(
        "INSERT OR REPLACE INTO blocks(ip,reason,blocked_at,blocked_by) VALUES(?,?,?,?)",
        (req.ip, req.reason, now, "api"),
    )
    db.commit()
    try:
        _publish({
            "event": "blocked_ip_change",
            "ip": req.ip,
            "action": "block",
            "reason": req.reason,
            "timestamp": now,
            "client_name": f"border-api@{_node()}",
            "client_ip": _node(),
        })
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"recorded locally but MQTT propagation failed: {exc}",
        )
    return {"ip": req.ip, "action": "blocked", "reason": req.reason}


@app.post("/v1/unblock", status_code=202, dependencies=[Depends(_auth)])
def unblock(req: UnblockRequest):
    db = _get_db()
    was_blocked = db.execute("DELETE FROM blocks WHERE ip=?", (req.ip,)).rowcount > 0
    db.commit()
    now = _now()
    try:
        _publish({
            "event": "blocked_ip_change",
            "ip": req.ip,
            "action": "unblock",
            "reason": "manual unblock via API",
            "timestamp": now,
            "client_name": f"border-api@{_node()}",
            "client_ip": _node(),
        })
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"MQTT propagation failed: {exc}")
    return {"ip": req.ip, "action": "unblocked", "was_blocked": was_blocked}


@app.post("/v1/whitelist", status_code=202, dependencies=[Depends(_auth)])
def whitelist_add(req: AllowlistAddRequest):
    db = _get_db()
    now = _now()
    db.execute(
        "INSERT OR REPLACE INTO allowlist(ip,reason,added_at,added_by) VALUES(?,?,?,?)",
        (req.ip, req.reason, now, "api"),
    )
    db.commit()

    events: list[dict] = []

    # Article 5: if currently blocked, lift the block immediately across all nodes.
    if db.execute("SELECT 1 FROM blocks WHERE ip=?", (req.ip,)).fetchone():
        db.execute("DELETE FROM blocks WHERE ip=?", (req.ip,))
        db.commit()
        events.append({
            "event": "blocked_ip_change",
            "ip": req.ip,
            "action": "unblock",
            "reason": f"added to allowlist: {req.reason}",
            "timestamp": now,
            "client_name": f"border-api@{_node()}",
            "client_ip": _node(),
        })

    events.append({
        "event": "whitelist_change",
        "ip": req.ip,
        "operation": "add",
        "reason": req.reason,
        "timestamp": now,
        "client_name": f"border-api@{_node()}",
        "client_ip": _node(),
    })

    try:
        for ev in events:
            _publish(ev)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"recorded locally but MQTT propagation failed: {exc}",
        )
    return {"ip": req.ip, "action": "allowlisted", "reason": req.reason}


@app.delete("/v1/whitelist/{ip}", status_code=202, dependencies=[Depends(_auth)])
def whitelist_remove(ip: str):
    ip = _validate_ip(ip)
    db = _get_db()
    was_listed = db.execute("DELETE FROM allowlist WHERE ip=?", (ip,)).rowcount > 0
    db.commit()
    now = _now()
    try:
        _publish({
            "event": "whitelist_change",
            "ip": ip,
            "operation": "remove",
            "reason": "removed via API",
            "timestamp": now,
            "client_name": f"border-api@{_node()}",
            "client_ip": _node(),
        })
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"MQTT propagation failed: {exc}")
    return {"ip": ip, "action": "removed_from_allowlist", "was_allowlisted": was_listed}


# ---------------------------------------------------------------------------
# Single-instance lock + entrypoint
# ---------------------------------------------------------------------------

def _acquire_lock() -> None:
    _LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    fp = open(_LOCK_FILE, "a+", encoding="utf-8")
    try:
        fcntl.flock(fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print(f"border-api already running (lock={_LOCK_FILE})", file=sys.stderr)
        sys.exit(0)
    fp.seek(0)
    fp.truncate()
    fp.write(str(os.getpid()))
    fp.flush()
    globals()["_lock_fp"] = fp  # keep reference so lock is held for process lifetime


if __name__ == "__main__":
    _acquire_lock()
    uvicorn.run(app, host=_HOST, port=_PORT, log_level="info")
