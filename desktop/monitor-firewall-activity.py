#!/usr/bin/env python3
"""
authmon v5 — terminal activity monitor

Live dashboard: nodes online, blocked IPs, recent events.
Subscribes to the MQTT grid (read-only, no enforcement).

Usage:
  python3 monitor-firewall-activity.py [--config /etc/authmon/config.json]

Config:  /etc/authmon/config.json  (or $AUTHMON_CONFIG)
Secrets: $AUTHMON_MQTT_PASSWORD, $AUTHMON_EVENT_HMAC
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import signal
import socket
import ssl
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:
    import paho.mqtt.client as mqtt
except ImportError:
    sys.exit("paho-mqtt is required: apt install python3-paho-mqtt")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _load_config(path: Path) -> dict:
    d = json.loads(path.read_text())
    m = d.get("mqtt", {})
    host = str(m.get("host", "")).strip()
    if not host:
        raise ValueError("mqtt.host missing")
    pw_env   = str(m.get("password_env", "AUTHMON_MQTT_PASSWORD")).strip()
    hmac_env = str(d.get("security", {}).get("hmac_env", "AUTHMON_EVENT_HMAC")).strip()
    password    = str(m.get("password", "")).strip() or os.getenv(pw_env, "").strip()
    hmac_secret = str(d.get("security", {}).get("hmac_secret", "")).strip() or os.getenv(hmac_env, "").strip()
    return {
        "host":        host,
        "port":        int(m.get("port", 8883)),
        "tls":         bool(m.get("tls", True)),
        "tls_ca":      str(m.get("tls_ca", "")).strip() or None,
        "username":    str(m.get("username", "")).strip(),
        "password":    password,
        "topic":       str(m.get("topic", "authmon/v5/events")).strip(),
        "keepalive":   int(m.get("keepalive", 60)),
        "hmac_secret": hmac_secret,
        "client_id":   f"authmon5-monitor-{socket.gethostname()}-{os.getpid()}",
    }


# ---------------------------------------------------------------------------
# HMAC v5
# ---------------------------------------------------------------------------

def _verify(payload: dict, secret: str) -> bool:
    if not secret:
        return True
    sig = str(payload.get("sig", "")).strip()
    if not sig:
        return False
    copy = {k: v for k, v in payload.items() if k != "sig"}
    body = json.dumps(copy, sort_keys=True, separators=(",", ":")).encode()
    expected = base64.b64encode(
        hmac.new(secret.encode(), body, hashlib.sha256).digest()
    ).decode()
    return hmac.compare_digest(sig, expected)


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

def _parse_ts(v: str | None) -> float:
    if not v:
        return time.time()
    try:
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return time.time()


def _age(seconds: float) -> str:
    if seconds < 60:   return f"{int(seconds)}s"
    if seconds < 3600: return f"{int(seconds//60)}m{int(seconds%60):02d}s"
    return f"{int(seconds//3600)}h{int((seconds%3600)//60):02d}m"


@dataclass
class NodeStatus:
    node_id:    str
    last_ts:    float
    active_blocks: int = 0
    last_event: str = "heartbeat"


@dataclass
class BlockEntry:
    ip:     str
    reason: str
    node:   str
    ts:     float


# ---------------------------------------------------------------------------
# MQTT client factory
# ---------------------------------------------------------------------------

def _make_client(client_id: str) -> mqtt.Client:
    if hasattr(mqtt, "CallbackAPIVersion"):
        try:
            return mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id=client_id,
            )
        except Exception:
            pass
    return mqtt.Client(client_id=client_id)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="authmon v5 terminal monitor")
    _default_cfg = os.getenv("AUTHMON_CONFIG") or (
        "/etc/authmon/config.json"
        if Path("/etc/authmon/config.json").exists()
        else str(Path.home() / ".config/authmon/config.json")
    )
    parser.add_argument("--config", default=_default_cfg)
    parser.add_argument("--refresh", type=float, default=2.0, help="Screen refresh interval (s)")
    parser.add_argument("--stale",   type=float, default=180.0, help="Seconds before node marked STALE")
    parser.add_argument("--events",  type=int,   default=15, help="Number of recent events to show")
    parser.add_argument("--no-verify", action="store_true", help="Skip HMAC verification")
    args = parser.parse_args()

    try:
        cfg = _load_config(Path(args.config))
    except Exception as exc:
        sys.exit(f"config error: {exc}")

    nodes:   dict[str, NodeStatus] = {}
    blocked: dict[str, BlockEntry] = {}
    events:  deque[str] = deque(maxlen=args.events)
    rejected = 0
    lock = threading.Lock()
    running = True

    def evt(line: str) -> None:
        events.appendleft(f"{datetime.now().strftime('%H:%M:%S')} {line}")

    def on_connect(c, _u, _f, rc, _p=None):
        code = getattr(rc, "value", rc)
        try:   code = int(code)
        except Exception: code = 0 if str(rc).lower() == "success" else 1
        if code != 0:
            with lock: evt(f"connect_failed rc={rc}")
            return
        c.subscribe(cfg["topic"], qos=1)
        with lock: evt(f"subscribed {cfg['topic']} {cfg['host']}:{cfg['port']}")

    def on_disconnect(_c, _u, *args):
        rc = args[1] if len(args) >= 2 else (args[0] if args else "?")
        with lock: evt(f"disconnected rc={rc} — reconnecting…")

    def on_message(_c, _u, msg):
        nonlocal rejected
        try:
            data = json.loads(msg.payload.decode("utf-8", "ignore"))
        except Exception:
            return
        if not isinstance(data, dict):
            return
        if int(data.get("v", 5)) != 5:
            return

        if not args.no_verify and not _verify(data, cfg["hmac_secret"]):
            with lock:
                rejected += 1
                evt("invalid_sig rejected")
            return

        event  = str(data.get("event", "")).strip().lower()
        node   = str(data.get("node", "unknown")).strip()
        ts     = _parse_ts(str(data.get("ts", "")).strip())

        with lock:
            if event == "heartbeat":
                nodes[node] = NodeStatus(
                    node_id=node,
                    last_ts=ts,
                    active_blocks=int(data.get("active_blocks", 0)),
                    last_event="heartbeat",
                )
                evt(f"heartbeat node={node} blocks={data.get('active_blocks','?')}")

            elif event == "block":
                ip     = str(data.get("ip", "")).strip()
                reason = str(data.get("reason", "")).strip()
                if ip:
                    blocked[ip] = BlockEntry(ip=ip, reason=reason, node=node, ts=ts)
                    evt(f"block ip={ip} node={node} reason={reason or '-'}")
                    if node in nodes:
                        nodes[node].active_blocks += 1
                        nodes[node].last_event = "block"

            elif event == "unblock":
                ip = str(data.get("ip", "")).strip()
                if ip:
                    blocked.pop(ip, None)
                    evt(f"unblock ip={ip} node={node}")

            elif event == "node_offline":
                evt(f"NODE OFFLINE: {node}")
                if node in nodes:
                    nodes[node].last_event = "OFFLINE"

            elif event == "sync_state":
                n = len(data.get("blocks", []))
                evt(f"sync_state node={node} entries={n}")

            else:
                evt(f"event={event} node={node}")

    client = _make_client(cfg["client_id"])
    if cfg["username"]:
        client.username_pw_set(cfg["username"], cfg["password"])
    if cfg["tls"]:
        client.tls_set(ca_certs=cfg["tls_ca"], cert_reqs=ssl.CERT_REQUIRED,
                       tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    client.on_message    = on_message
    client.reconnect_delay_set(min_delay=1, max_delay=60)

    try:
        client.connect(cfg["host"], cfg["port"], cfg["keepalive"])
    except Exception as exc:
        sys.exit(f"connect error: {exc}")
    client.loop_start()

    signal.signal(signal.SIGINT,  lambda *_: globals().update(running=False) or None)
    signal.signal(signal.SIGTERM, lambda *_: globals().update(running=False) or None)

    # running flag via a list to avoid nonlocal complexity
    stop = threading.Event()

    def _stop(_sig, _frame):
        stop.set()

    signal.signal(signal.SIGINT,  _stop)
    signal.signal(signal.SIGTERM, _stop)

    try:
        while not stop.is_set():
            now = time.time()
            with lock:
                sys.stdout.write("\x1b[2J\x1b[H")
                print(f"authmon v5  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                      f"  broker={cfg['host']}:{cfg['port']}  rejected={rejected}")
                print()

                # --- Nodes ---
                print(f"{'NODES':─<60}")
                if nodes:
                    for n in sorted(nodes.values(), key=lambda x: x.last_ts, reverse=True):
                        age   = max(0.0, now - n.last_ts)
                        state = "STALE" if age > args.stale else "ok"
                        print(f"  {n.node_id:<28} {state:<6} age={_age(age):<8}"
                              f" blocks={n.active_blocks:<4} last={n.last_event}")
                else:
                    print("  (waiting for heartbeats…)")
                print()

                # --- Blocked IPs ---
                blist = sorted(blocked.values(), key=lambda x: x.ts, reverse=True)
                print(f"{'BLOCKED IPs':─<60}  ({len(blist)} active)")
                if blist:
                    for b in blist:
                        age = max(0.0, now - b.ts)
                        print(f"  {b.ip:<18} age={_age(age):<8}"
                              f" node={b.node:<24} {b.reason or '-'}")
                else:
                    print("  (none)")
                print()

                # --- Events ---
                print(f"{'RECENT EVENTS':─<60}")
                for line in list(events)[:args.events]:
                    print(f"  {line}")
                if not events:
                    print("  (none yet)")
                print()
                print("  Ctrl+C to stop")

            stop.wait(args.refresh)

    finally:
        client.loop_stop()
        client.disconnect()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
