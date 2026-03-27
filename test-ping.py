#!/usr/bin/env python3
import argparse
import json
import socket
import sys
import time
import uuid
from pathlib import Path

try:
    import paho.mqtt.client as mqtt  # type: ignore
except Exception:
    print("error: paho-mqtt not installed", file=sys.stderr)
    sys.exit(2)


def load_cfg(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    m = payload.get("mqtt", {})
    return {
        "host": str(m.get("host", "")).strip(),
        "port": int(m.get("port", 1883)),
        "username": str(m.get("username", "")).strip(),
        "password": str(m.get("password", "")).strip(),
    }


def mk_client(client_id: str) -> mqtt.Client:
    if hasattr(mqtt, "CallbackAPIVersion"):
        try:
            return mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
        except Exception:
            pass
    return mqtt.Client(client_id=client_id)


def main() -> int:
    parser = argparse.ArgumentParser(description="Send MQTT ping and wait for pong")
    parser.add_argument("--config", default=str(Path(__file__).resolve().parent / "config" / "config.json"))
    parser.add_argument("--topic-base", default="auth-monitor/test")
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    cfg = load_cfg(Path(args.config))
    host = cfg["host"]
    if not host:
        print("error: mqtt.host missing in config", file=sys.stderr)
        return 2

    ping_topic = f"{args.topic_base.rstrip('/')}/ping"
    pong_topic = f"{args.topic_base.rstrip('/')}/pong"
    ping_id = str(uuid.uuid4())
    received = {"ok": False, "msg": None}

    client = mk_client(f"auth-monitor-test-ping-{socket.gethostname()}")
    if cfg["username"]:
        client.username_pw_set(cfg["username"], cfg["password"])

    def on_connect(c, _u, _f, rc, _p=None):
        if rc != 0:
            print(f"connect_failed rc={rc}", file=sys.stderr)
            return
        c.subscribe(pong_topic, qos=0)
        payload = {
            "kind": "ping",
            "id": ping_id,
            "origin": socket.gethostname(),
            "ts": int(time.time() * 1000),
        }
        c.publish(ping_topic, json.dumps(payload, ensure_ascii=False), qos=0)
        print(f"ping_sent id={ping_id} topic={ping_topic}")

    def on_message(_c, _u, msg):
        try:
            data = json.loads(msg.payload.decode("utf-8", errors="replace"))
        except Exception:
            return
        if data.get("id") == ping_id and data.get("kind") == "pong":
            received["ok"] = True
            received["msg"] = data

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(host, cfg["port"], keepalive=30)
    client.loop_start()

    started = time.time()
    while time.time() - started < args.timeout:
        if received["ok"]:
            break
        time.sleep(0.1)

    client.loop_stop()
    client.disconnect()

    if received["ok"]:
        print("pong_received", json.dumps(received["msg"], ensure_ascii=False))
        return 0

    print(f"timeout_waiting_pong id={ping_id} topic={pong_topic}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
