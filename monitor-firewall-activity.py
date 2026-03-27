#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import os
import signal
import socket
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    import paho.mqtt.client as mqtt  # type: ignore
except Exception:
    print("error: paho-mqtt not installed", file=sys.stderr)
    raise SystemExit(2)


@dataclass
class ClientStatus:
    name: str
    ip: str
    source: str
    last_seen_ts: float
    last_event: str


@dataclass
class BlockedEntry:
    ip: str
    reason: str
    source_client: str
    since_ts: float


def parse_ts(value: str | None) -> float:
    if not value:
        return time.time()
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return time.time()


def fmt_age(seconds: float) -> str:
    if seconds < 1:
        return "0s"
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m{int(seconds % 60)}s"
    return f"{int(seconds // 3600)}h{int((seconds % 3600) // 60)}m"


def clear_screen() -> None:
    sys.stdout.write("\x1b[2J\x1b[H")


def resolve_mqtt_password(mqtt_cfg: dict) -> str:
    env_name = str(mqtt_cfg.get("password_env", "AUTH_MONITOR_MQTT_PASSWORD")).strip()
    if env_name:
        env_val = os.getenv(env_name, "").strip()
        if env_val:
            return env_val
    return str(mqtt_cfg.get("password", "")).strip()


def load_config(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    mqtt_cfg = payload.get("mqtt", {})
    if not isinstance(mqtt_cfg, dict):
        raise ValueError("config.mqtt missing/invalid")
    host = str(mqtt_cfg.get("host", "")).strip()
    topic = str(mqtt_cfg.get("topic", "")).strip()
    if not host or not topic:
        raise ValueError("config.mqtt.host and config.mqtt.topic are required")
    return {
        "host": host,
        "port": int(mqtt_cfg.get("port", 1883)),
        "topic": topic,
        "username": str(mqtt_cfg.get("username", "")).strip(),
        "password": resolve_mqtt_password(mqtt_cfg),
        "client_id": (
            str(mqtt_cfg.get("monitor_client_id", "")).strip()
            or f"auth-monitor-activity-{socket.gethostname()}-{os.getpid()}"
        ),
        "keepalive": int(mqtt_cfg.get("keepalive", 60)),
        "hmac_secret": os.getenv(
            str(mqtt_cfg.get("event_hmac_env", "AUTH_MONITOR_EVENT_HMAC")).strip() or "AUTH_MONITOR_EVENT_HMAC",
            "",
        ).strip(),
    }


def verify_signature(payload: dict, secret: str) -> bool:
    signature = str(payload.get("signature", "")).strip()
    if not signature:
        return False
    candidate = dict(payload)
    candidate.pop("signature", None)
    body = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode("ascii")
    return hmac.compare_digest(signature, expected)


def make_client(client_id: str) -> mqtt.Client:
    if hasattr(mqtt, "CallbackAPIVersion"):
        try:
            return mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
        except Exception:
            pass
    return mqtt.Client(client_id=client_id)


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor auth-monitor client activity and blocked IP changes")
    parser.add_argument("--config", default=str(Path(__file__).resolve().parent / "config" / "config.json"))
    parser.add_argument("--refresh", type=float, default=3.0, help="Dashboard refresh interval in seconds")
    parser.add_argument("--stale-seconds", type=float, default=120.0, help="Heartbeat age threshold to mark STALE")
    parser.add_argument("--max-events", type=int, default=12, help="How many recent events to display")
    parser.add_argument("--verify-signature", action="store_true", help="Require valid signature when secret is set")
    args = parser.parse_args()

    cfg = load_config(Path(args.config))
    topic = cfg["topic"]
    events: deque[str] = deque(maxlen=max(1, args.max_events))
    clients: dict[str, ClientStatus] = {}
    blocked: dict[str, BlockedEntry] = {}
    rejected_messages = 0
    lock = threading.Lock()
    running = True

    def append_event(line: str) -> None:
        events.appendleft(f"{datetime.now().strftime('%H:%M:%S')} {line}")

    def on_connect(c, _u, _f, reason_code, _p=None) -> None:
        rc = getattr(reason_code, "value", reason_code)
        try:
            rc = int(rc)
        except Exception:
            rc = 0 if str(reason_code).lower() == "success" else 1
        if rc != 0:
            with lock:
                append_event(f"connect_failed rc={reason_code}")
            return
        c.subscribe(topic, qos=0)
        with lock:
            append_event(f"subscribed topic={topic}")

    def on_message(_c, _u, msg) -> None:
        nonlocal rejected_messages
        try:
            data = json.loads(msg.payload.decode("utf-8", errors="replace"))
        except Exception:
            with lock:
                append_event("ignored invalid_json")
            return

        if not isinstance(data, dict):
            with lock:
                append_event("ignored non_object_payload")
            return

        if args.verify_signature and cfg["hmac_secret"]:
            if not verify_signature(data, cfg["hmac_secret"]):
                rejected_messages += 1
                with lock:
                    append_event("ignored invalid_signature")
                return

        event = str(data.get("event", "")).strip()
        if not event:
            event = str(data.get("kind", "")).strip()

        client_name = str(data.get("client_name", "")).strip() or str(data.get("origin", "")).strip() or "unknown"
        client_ip = str(data.get("client_ip", "")).strip() or "unknown"
        source = str(data.get("source", "")).strip() or "unknown"
        ts = parse_ts(str(data.get("timestamp", "")).strip())
        key = f"{client_name}|{client_ip}"

        with lock:
            if event in {"client_heartbeat", "ping"}:
                clients[key] = ClientStatus(
                    name=client_name,
                    ip=client_ip,
                    source=source,
                    last_seen_ts=ts,
                    last_event=event,
                )
                append_event(f"heartbeat client={client_name} ip={client_ip}")
            elif event == "blocked_ip_change":
                ip = str(data.get("ip", "")).strip()
                action = str(data.get("action", "block")).strip().lower() or "block"
                reason = str(data.get("reason", "")).strip()
                if ip:
                    if action == "block":
                        blocked[ip] = BlockedEntry(
                            ip=ip,
                            reason=reason,
                            source_client=f"{client_name}/{client_ip}",
                            since_ts=ts,
                        )
                        append_event(f"block ip={ip} by={client_name}/{client_ip}")
                    else:
                        blocked.pop(ip, None)
                        append_event(f"unblock ip={ip} by={client_name}/{client_ip}")
            elif event == "pong":
                append_event(f"pong id={data.get('id', '')} responder={data.get('responder', '')}")
            else:
                append_event(f"event={event or 'unknown'} client={client_name} ip={client_ip}")

    client = make_client(cfg["client_id"])
    if cfg["username"]:
        client.username_pw_set(cfg["username"], cfg["password"])
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(cfg["host"], cfg["port"], cfg["keepalive"])
    client.loop_start()

    def stop_handler(_sig, _frame) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    try:
        while running:
            now = time.time()
            with lock:
                clear_screen()
                print("Auth Monitor Firewall Activity")
                print(f"broker={cfg['host']}:{cfg['port']} topic={topic}")
                print(f"time={datetime.now().isoformat(timespec='seconds')} rejected_messages={rejected_messages}")
                print("")

                print("Clients")
                if clients:
                    rows = sorted(clients.values(), key=lambda x: x.last_seen_ts, reverse=True)
                    for c in rows:
                        age = max(0.0, now - c.last_seen_ts)
                        state = "WORKING" if age <= args.stale_seconds else "STALE"
                        print(
                            f"- {c.name:24} ip={c.ip:15} state={state:7} age={fmt_age(age):>8} event={c.last_event}"
                        )
                else:
                    print("- none")

                print("")
                print("Blocked IPs")
                if blocked:
                    rows = sorted(blocked.values(), key=lambda x: x.since_ts, reverse=True)
                    for b in rows:
                        age = max(0.0, now - b.since_ts)
                        reason = b.reason if b.reason else "-"
                        print(f"- {b.ip:16} age={fmt_age(age):>8} by={b.source_client} reason={reason}")
                else:
                    print("- none")

                print("")
                print("Recent Events")
                if events:
                    for line in list(events)[: args.max_events]:
                        print(f"- {line}")
                else:
                    print("- none")

                print("")
                print("Ctrl+C to stop")
            time.sleep(max(0.2, args.refresh))
    finally:
        client.loop_stop()
        client.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

