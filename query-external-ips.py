#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import os
import socket
import sys
import time
import uuid
from pathlib import Path


def resolve_mqtt_password(mqtt_cfg: dict) -> str:
    env_name = str(mqtt_cfg.get("password_env", "AUTH_MONITOR_MQTT_PASSWORD")).strip()
    if env_name:
        value = os.getenv(env_name, "").strip()
        if value:
            return value
    return str(mqtt_cfg.get("password", "")).strip()


def load_config(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    mqtt_cfg = payload.get("mqtt")
    if not isinstance(mqtt_cfg, dict):
        raise ValueError("config.mqtt missing/invalid")

    host = str(mqtt_cfg.get("host", "")).strip()
    topic = str(mqtt_cfg.get("topic", "")).strip()
    if not host or not topic:
        raise ValueError("config.mqtt.host and config.mqtt.topic are required")

    hmac_env = str(mqtt_cfg.get("event_hmac_env", "AUTH_MONITOR_EVENT_HMAC")).strip() or "AUTH_MONITOR_EVENT_HMAC"
    return {
        "host": host,
        "port": int(mqtt_cfg.get("port", 1883)),
        "topic": topic,
        "username": str(mqtt_cfg.get("username", "")).strip(),
        "password": resolve_mqtt_password(mqtt_cfg),
        "client_id": f"auth-monitor-external-ip-query-{socket.gethostname()}-{os.getpid()}",
        "keepalive": int(mqtt_cfg.get("keepalive", 60)),
        "hmac_secret": os.getenv(hmac_env, "").strip(),
    }


def sign_payload(payload: dict, secret: str) -> str:
    unsigned = dict(payload)
    unsigned.pop("signature", None)
    body = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def make_client(client_id: str):
    try:
        import paho.mqtt.client as mqtt  # type: ignore
    except Exception:
        print("error: paho-mqtt not installed", file=sys.stderr)
        raise SystemExit(2)

    if hasattr(mqtt, "CallbackAPIVersion"):
        try:
            return mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
        except Exception:
            pass
    return mqtt.Client(client_id=client_id)


def parse_targets(raw: str) -> list[str]:
    if not raw.strip():
        return []
    out: list[str] = []
    for part in raw.split(","):
        item = part.strip()
        if item:
            out.append(item)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Query all MQTT clients for their external IP and collect replies")
    parser.add_argument("--config", default=str(Path(__file__).resolve().parent / "config" / "config.json"))
    parser.add_argument("--timeout", type=float, default=25.0, help="seconds to wait for replies")
    parser.add_argument("--targets", default="", help="optional comma-separated targets (name/ip/name|ip)")
    parser.add_argument("--json", action="store_true", help="print JSON output instead of table")
    args = parser.parse_args()

    cfg = load_config(Path(args.config))
    request_id = str(uuid.uuid4())
    targets = parse_targets(args.targets)
    responses: dict[str, dict] = {}
    connected = {"ok": False}
    query_sent = {"ok": False}
    last_query_publish_ts = {"value": 0.0}

    def build_query_payload() -> dict:
        payload = {
            "event": "external_ip_query",
            "request_id": request_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": "auth-monitor/v4/query-external-ips.py",
        }
        if targets:
            payload["targets"] = targets
        if cfg["hmac_secret"]:
            payload["signature"] = sign_payload(payload, cfg["hmac_secret"])
        return payload

    def on_connect(client, _u, _f, reason_code, _p=None):
        rc = getattr(reason_code, "value", reason_code)
        try:
            rc = int(rc)
        except Exception:
            rc = 0 if str(reason_code).lower() == "success" else 1
        if rc != 0:
            print(f"error: MQTT connect failed rc={reason_code}", file=sys.stderr)
            return
        connected["ok"] = True
        client.subscribe(cfg["topic"], qos=0)

    def on_subscribe(client, _u, _mid, _granted_qos, _p=None):
        if not connected["ok"]:
            return
        payload = build_query_payload()
        client.publish(cfg["topic"], json.dumps(payload, separators=(",", ":")), qos=1, retain=False)
        query_sent["ok"] = True
        last_query_publish_ts["value"] = time.time()

    def on_message(_c, _u, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8", errors="replace"))
        except Exception:
            return
        if not isinstance(payload, dict):
            return
        if str(payload.get("event", "")).strip() != "external_ip_response":
            return
        if str(payload.get("request_id", "")).strip() != request_id:
            return

        client_name = str(payload.get("client_name", "")).strip() or "unknown"
        client_ip = str(payload.get("client_ip", "")).strip() or "unknown"
        external_ip = str(payload.get("external_ip", "")).strip() or "unknown"
        key = f"{client_name}|{client_ip}"
        responses[key] = {
            "client_name": client_name,
            "client_ip": client_ip,
            "external_ip": external_ip,
            "timestamp": str(payload.get("timestamp", "")).strip(),
        }

    client = make_client(cfg["client_id"])
    if cfg["username"]:
        client.username_pw_set(cfg["username"], cfg["password"])
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    client.connect(cfg["host"], cfg["port"], cfg["keepalive"])
    client.loop_start()

    started = time.time()
    try:
        while time.time() - started < max(1.0, args.timeout):
            now = time.time()
            if connected["ok"] and (
                (not query_sent["ok"]) or (now - last_query_publish_ts["value"] >= 4.0)
            ):
                payload = build_query_payload()
                info = client.publish(cfg["topic"], json.dumps(payload, separators=(",", ":")), qos=1, retain=False)
                info.wait_for_publish()
                query_sent["ok"] = True
                last_query_publish_ts["value"] = now
            time.sleep(0.1)
    finally:
        client.loop_stop()
        client.disconnect()

    if not connected["ok"]:
        print("error: not connected to MQTT", file=sys.stderr)
        return 1

    rows = sorted(
        responses.values(),
        key=lambda x: (x["client_name"], x["client_ip"]),
    )

    if args.json:
        print(json.dumps({"request_id": request_id, "count": len(rows), "items": rows}, ensure_ascii=False, indent=2))
        return 0

    print(f"request_id={request_id} responses={len(rows)} topic={cfg['topic']}")
    if not rows:
        print("no responses")
        return 0

    print("client_name,client_ip,external_ip,timestamp")
    for row in rows:
        print(f"{row['client_name']},{row['client_ip']},{row['external_ip']},{row['timestamp']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
