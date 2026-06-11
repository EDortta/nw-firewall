#!/usr/bin/env python3
"""
authmon v5 — desktop notifier

Subscribe to the MQTT grid and fire a notify-send notification whenever an IP
is blocked on any node.  Intended to run as a systemd --user service.

Config:  /etc/authmon/config.json  (or $AUTHMON_CONFIG)
Secrets: $AUTHMON_MQTT_PASSWORD, $AUTHMON_EVENT_HMAC
         (set in ~/.config/authmon/env and sourced by the service unit)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import ssl
import socket
import subprocess
import sys
import threading
from pathlib import Path

try:
    import paho.mqtt.client as mqtt
except ImportError:
    sys.exit("paho-mqtt is required: apt install python3-paho-mqtt")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path(os.getenv("AUTHMON_CONFIG", "/etc/authmon/config.json"))
_NOTIFY_CMD  = os.getenv("NOTIFY_CMD", "notify-send")
_BATCH_WINDOW = float(os.getenv("NOTIFY_BATCH_WINDOW", "4"))
_MAX_DETAIL   = 2


def _load_config(path: Path) -> dict:
    d = json.loads(path.read_text())
    m = d.get("mqtt", {})
    host = str(m.get("host", "")).strip()
    if not host:
        raise ValueError("mqtt.host missing")
    pw_env = str(m.get("password_env", "AUTHMON_MQTT_PASSWORD")).strip()
    hmac_env = str(d.get("security", {}).get("hmac_env", "AUTHMON_EVENT_HMAC")).strip()
    return {
        "host":      host,
        "port":      int(m.get("port", 8883)),
        "tls":       bool(m.get("tls", True)),
        "tls_ca":    str(m.get("tls_ca", "")).strip() or None,
        "username":  str(m.get("username", "")).strip(),
        "password":  os.getenv(pw_env, "").strip(),
        "topic":     str(m.get("topic", "authmon/v5/events")).strip(),
        "keepalive": int(m.get("keepalive", 60)),
        "hmac_secret": os.getenv(hmac_env, "").strip(),
        "client_id": f"authmon5-notify-{socket.gethostname()}-{os.getpid()}",
    }


# ---------------------------------------------------------------------------
# HMAC v5 (same canonical form as events.py)
# ---------------------------------------------------------------------------

def _verify(payload: dict, secret: str) -> bool:
    if not secret:
        return True  # no secret configured → accept all (subscribe-only, not enforcement)
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
# Batching
# ---------------------------------------------------------------------------

_buffer: dict[tuple[str, str], list[str]] = {}
_seen:   dict[str, set[str]] = {}
_timer:  threading.Timer | None = None
_lock = threading.Lock()


def _notify(title: str, body: str) -> None:
    try:
        subprocess.run(
            [_NOTIFY_CMD, "-u", "normal", "-i", "security-high", title, body],
            check=False, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    print(f"[notify] {title} | {body}", flush=True)


def _flush() -> None:
    global _timer
    with _lock:
        groups = list(_buffer.items())
        _buffer.clear()
        _timer = None
        for (ip, reason), _ in groups:
            _seen.setdefault(ip, set()).add(reason)

    for (ip, reason), nodes in groups[:_MAX_DETAIL]:
        parts = [f"Node: {nodes[0]}"]
        if len(nodes) > 1:
            parts.append(f"+{len(nodes)-1} more")
        if reason:
            parts.append(f"Reason: {reason}")
        _notify(f"IP Blocked: {ip}", "\n".join(parts))

    rest = groups[_MAX_DETAIL:]
    if rest:
        all_nodes = {n for _, ns in rest for n in ns}
        _notify(
            f"+{len(rest)} more IP{'s' if len(rest)>1 else ''} blocked",
            f"Across {len(all_nodes)} node{'s' if len(all_nodes)>1 else ''}",
        )


def _queue(ip: str, node: str, reason: str) -> None:
    global _timer
    with _lock:
        if reason in _seen.get(ip, set()):
            return
        ns = _buffer.setdefault((ip, reason), [])
        if node not in ns:
            ns.append(node)
        if _timer is None:
            _timer = threading.Timer(_BATCH_WINDOW, _flush)
            _timer.daemon = True
            _timer.start()


def _clear_seen(ip: str) -> None:
    with _lock:
        _seen.pop(ip, None)


# ---------------------------------------------------------------------------
# MQTT
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


def main() -> None:
    try:
        cfg = _load_config(_CONFIG_PATH)
    except Exception as exc:
        sys.exit(f"config error: {exc}")

    client = _make_client(cfg["client_id"])

    if cfg["username"]:
        client.username_pw_set(cfg["username"], cfg["password"])

    if cfg["tls"]:
        ca = cfg["tls_ca"] or None
        client.tls_set(ca_certs=ca, cert_reqs=ssl.CERT_REQUIRED,
                       tls_version=ssl.PROTOCOL_TLS_CLIENT)

    def on_connect(c, _u, _f, rc, _p=None):
        code = getattr(rc, "value", rc)
        try:
            code = int(code)
        except Exception:
            code = 0 if str(rc).lower() == "success" else 1
        if code != 0:
            print(f"error: connect failed rc={rc}", file=sys.stderr, flush=True)
            return
        c.subscribe(cfg["topic"], qos=1)
        print(f"subscribed topic={cfg['topic']} host={cfg['host']}:{cfg['port']}", flush=True)

    def on_message(_c, _u, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8", "ignore"))
        except Exception:
            return
        if not isinstance(payload, dict):
            return

        # silently ignore wrong-version events (v4 grid still on old topic if any)
        if int(payload.get("v", 5)) != 5:
            return

        if not _verify(payload, cfg["hmac_secret"]):
            print(f"warn: invalid signature — dropped", file=sys.stderr, flush=True)
            return

        event = str(payload.get("event", "")).strip().lower()
        ip    = str(payload.get("ip", "")).strip()
        node  = str(payload.get("node", "unknown")).strip()

        if event == "block" and ip:
            reason = str(payload.get("reason", "")).strip()
            _queue(ip, node, reason)
        elif event == "unblock" and ip:
            _clear_seen(ip)

    client.on_connect = on_connect
    client.on_message = on_message
    client.reconnect_delay_set(min_delay=1, max_delay=60)

    print(f"connecting host={cfg['host']}:{cfg['port']} tls={cfg['tls']}", flush=True)
    client.connect(cfg["host"], cfg["port"], cfg["keepalive"])
    client.loop_forever()


if __name__ == "__main__":
    main()
