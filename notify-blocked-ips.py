#!/usr/bin/env python3
"""
Subscribe to the auth-monitor MQTT broker and show a desktop notification
whenever an IP is blocked.

Reads MQTT connection details from config/config.json (same file used by the
rest of the auth-monitor tooling).  Respects AUTH_MONITOR_CONFIG to override
the config path, and AUTH_MONITOR_MQTT_PASSWORD to override the password.

Intended to run as a systemd --user service via desktop/install.sh.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

try:
    import paho.mqtt.client as mqtt
except ImportError:
    sys.exit("paho-mqtt is required: pip install paho-mqtt")

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.getenv("AUTH_MONITOR_CONFIG", str(SCRIPT_DIR / "config" / "config.json")))
NOTIFY_CMD = os.getenv("NOTIFY_CMD", "notify-send")


def _load_config(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    mqtt_cfg = data.get("mqtt")
    if not mqtt_cfg:
        raise ValueError(f"config.mqtt missing in {path}")
    host = str(mqtt_cfg.get("host", "")).strip()
    if not host:
        raise ValueError("config.mqtt.host is required")
    topic = str(mqtt_cfg.get("topic", "auth-monitor/blocked-ips")).strip()
    if not topic:
        raise ValueError("config.mqtt.topic is required")

    env_name = str(mqtt_cfg.get("password_env", "AUTH_MONITOR_MQTT_PASSWORD")).strip()
    password = (os.getenv(env_name, "").strip() if env_name else "") or str(mqtt_cfg.get("password", "")).strip()

    hostname = socket.gethostname()
    client_id = f"auth-monitor-notify-{hostname}-{os.getpid()}"

    return {
        "host": host,
        "port": int(mqtt_cfg.get("port", 1883)),
        "username": str(mqtt_cfg.get("username", "")).strip(),
        "password": password,
        "topic": topic,
        "keepalive": int(mqtt_cfg.get("keepalive", 60)),
        "client_id": client_id,
    }


def _create_client(client_id: str) -> mqtt.Client:
    # paho-mqtt v2 requires callback_api_version; v1 does not.
    if hasattr(mqtt, "CallbackAPIVersion"):
        try:
            return mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id=client_id,
            )
        except (TypeError, ValueError, AttributeError):
            pass
    return mqtt.Client(client_id=client_id)


def _notify(title: str, body: str) -> None:
    try:
        subprocess.run(
            [NOTIFY_CMD, "-u", "normal", "-i", "security-high", title, body],
            check=False,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    print(f"[notify] {title} | {body}")


def main() -> None:
    try:
        cfg = _load_config(CONFIG_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        sys.exit(f"config error: {exc}")

    def on_connect(client, userdata, flags, reason_code, properties=None):
        rc = getattr(reason_code, "value", reason_code)
        try:
            rc = int(rc)
        except (TypeError, ValueError):
            rc = 0 if str(reason_code).lower() == "success" else 1
        if rc != 0:
            print(f"error: connect failed rc={rc}", file=sys.stderr)
            return
        client.subscribe(cfg["topic"])
        print(f"subscribed topic={cfg['topic']} host={cfg['host']}:{cfg['port']}")

    def on_message(client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8", "ignore"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        if not isinstance(payload, dict):
            return

        event = str(payload.get("event", "")).strip().lower()
        action = str(payload.get("action", "block")).strip().lower()

        if event and event != "blocked_ip_change":
            return
        if action != "block":
            return

        ip = str(payload.get("ip", "")).strip()
        if not ip:
            return

        reason = str(payload.get("reason", "")).strip()
        sender = (
            str(payload.get("client_name", "")).strip()
            or str(payload.get("client_ip", "")).strip()
            or "unknown"
        )

        body_parts = [f"Server: {sender}"]
        if reason:
            body_parts.append(f"Reason: {reason}")

        print(f"blocked ip={ip} sender={sender} reason={reason or '-'}")
        _notify(f"IP Blocked: {ip}", "\n".join(body_parts))

    client = _create_client(cfg["client_id"])
    client.on_connect = on_connect
    client.on_message = on_message

    if cfg["username"]:
        client.username_pw_set(cfg["username"], cfg["password"])

    print(f"connecting host={cfg['host']} port={cfg['port']} client_id={cfg['client_id']}")
    client.connect(cfg["host"], cfg["port"], cfg["keepalive"])
    client.loop_forever()


if __name__ == "__main__":
    main()
