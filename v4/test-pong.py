#!/usr/bin/env python3
import argparse
import json
import socket
import sys
import time
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
    parser = argparse.ArgumentParser(description="Respond to MQTT ping with pong")
    parser.add_argument("--config", default=str(Path(__file__).resolve().parent / "config" / "config.json"))
    parser.add_argument("--topic-base", default="auth-monitor/test")
    args = parser.parse_args()

    cfg = load_cfg(Path(args.config))
    host = cfg["host"]
    if not host:
        print("error: mqtt.host missing in config", file=sys.stderr)
        return 2

    ping_topic = f"{args.topic_base.rstrip('/')}/ping"
    pong_topic = f"{args.topic_base.rstrip('/')}/pong"
    client = mk_client(f"auth-monitor-test-pong-{socket.gethostname()}")
    if cfg["username"]:
        client.username_pw_set(cfg["username"], cfg["password"])

    def on_connect(c, _u, _f, rc, _p=None):
        if rc != 0:
            print(f"connect_failed rc={rc}", file=sys.stderr)
            return
        c.subscribe(ping_topic, qos=0)
        print(f"listening topic={ping_topic} reply_topic={pong_topic}")

    def on_message(c, _u, msg):
        try:
            data = json.loads(msg.payload.decode("utf-8", errors="replace"))
        except Exception:
            return
        ping_id = data.get("id")
        out = {
            "kind": "pong",
            "id": ping_id,
            "responder": socket.gethostname(),
            "ts": int(time.time() * 1000),
            "echo": data,
        }
        c.publish(pong_topic, json.dumps(out, ensure_ascii=False), qos=0)
        print(f"pong_sent id={ping_id}")

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(host, cfg["port"], keepalive=30)
    client.loop_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
