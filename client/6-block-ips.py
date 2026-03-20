#!/usr/bin/env python3

import ipaddress
import json
import os
import socket
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
DB_PATH = Path(os.getenv("BLOCKED_IPS_DB_PATH", str(BASE_DIR / "db" / "blocked_ips.db")))
CONFIG_PATH = Path(os.getenv("AUTH_MONITOR_CONFIG", str(BASE_DIR / "config" / "config.json")))
STATE_PATH = Path(os.getenv("MQTT_LAST_TS_PATH", str(BASE_DIR / "db" / ".mqtt_last_published_ts")))

ONLY_ACTION = os.getenv("BLOCKED_IPS_ONLY_ACTION", "block").strip().lower()
TOPIC_OVERRIDE = os.getenv("MQTT_TOPIC", "").strip()
DRY_RUN = os.getenv("MQTT_DRY_RUN", "0").strip().lower() in {"1", "true", "yes"}


def normalize_ip(value: str) -> str | None:
    candidate = value.strip().strip("[]")
    if not candidate:
        return None

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def parse_iso_ts(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        ts = datetime.fromisoformat(value)
    except ValueError:
        return None

    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    return ts


def load_state_timestamp(path: Path) -> datetime | None:
    if not path.exists():
        return None

    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None

    return parse_iso_ts(raw)


def save_state_timestamp(path: Path, ts: datetime) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(ts.astimezone(timezone.utc).isoformat(), encoding="utf-8")


def load_config(config_path: Path) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    mqtt = payload.get("mqtt")
    if not isinstance(mqtt, dict):
        raise ValueError("config.mqtt is missing or invalid")

    host = str(mqtt.get("host", "")).strip()
    if not host:
        raise ValueError("config.mqtt.host is required")

    port = int(mqtt.get("port", 1883))
    topic = TOPIC_OVERRIDE or str(mqtt.get("topic", "")).strip()
    if not topic:
        raise ValueError("config.mqtt.topic is required")

    base_client_id = (
        str(mqtt.get("publisher_client_id", "")).strip()
        or str(mqtt.get("client_id", "auth-monitor-client")).strip()
        or "auth-monitor-client"
    )
    unique_client_id = f"{base_client_id}-{socket.gethostname()}-{os.getpid()}"

    return {
        "host": host,
        "port": port,
        "username": str(mqtt.get("username", "")).strip(),
        "password": str(mqtt.get("password", "")).strip(),
        "topic": topic,
        "client_id": unique_client_id,
        "keepalive": int(mqtt.get("keepalive", 60)),
        "qos": int(mqtt.get("qos", 1)),
    }


def resolve_sender_identity(mqtt_host: str) -> tuple[str, str]:
    name = (
        os.getenv("AUTH_MONITOR_CLIENT_NAME", "").strip()
        or os.getenv("HOSTNAME", "").strip()
        or socket.gethostname()
    )

    forced_ip = os.getenv("AUTH_MONITOR_CLIENT_IP", "").strip()
    if forced_ip:
        return name, forced_ip

    # Best-effort local source IP used to reach MQTT broker.
    ip = "unknown"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((mqtt_host, 1883))
            ip = sock.getsockname()[0]
    except OSError:
        pass

    return name, ip


def load_rows_from_db(db_path: Path, only_action: str) -> list[dict]:
    if not db_path.exists():
        return []

    con = sqlite3.connect(db_path)
    cur = con.cursor()

    if only_action:
        cur.execute(
            """
            SELECT ip, reason, action, timestamp
            FROM blocked_ips
            WHERE ip IS NOT NULL
              AND TRIM(ip) <> ''
              AND LOWER(COALESCE(action, '')) = ?
            ORDER BY timestamp ASC
            """,
            (only_action,),
        )
    else:
        cur.execute(
            """
            SELECT ip, reason, action, timestamp
            FROM blocked_ips
            WHERE ip IS NOT NULL
              AND TRIM(ip) <> ''
            ORDER BY timestamp ASC
            """
        )

    rows = cur.fetchall()
    cur.close()
    con.close()

    out = []
    for raw_ip, reason, action, timestamp in rows:
        ip = normalize_ip(raw_ip)
        ts = parse_iso_ts(timestamp)
        if not ip or ts is None:
            continue

        out.append(
            {
                "ip": ip,
                "reason": (reason or "").strip(),
                "action": (action or "").strip() or "block",
                "timestamp": ts,
            }
        )

    return out


def publish_with_paho(messages: list[dict], cfg: dict) -> tuple[int, str | None]:
    try:
        import paho.mqtt.client as mqtt  # type: ignore
    except ImportError:
        return 0, "paho-mqtt not installed"

    published = 0

    def create_client() -> mqtt.Client:
        # paho-mqtt v2 requires callback_api_version; v1 does not.
        if hasattr(mqtt, "CallbackAPIVersion"):
            try:
                return mqtt.Client(
                    callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                    client_id=cfg["client_id"],
                )
            except (TypeError, ValueError, AttributeError):
                pass

        return mqtt.Client(client_id=cfg["client_id"])

    def on_connect(client, userdata, flags, reason_code, properties=None):
        rc = getattr(reason_code, "value", reason_code)
        try:
            rc = int(rc)
        except (TypeError, ValueError):
            rc = 0 if str(reason_code).lower() == "success" else 1
        if rc != 0:
            raise RuntimeError(f"MQTT connect failed: {reason_code}")

    client = create_client()
    client.on_connect = on_connect

    if cfg["username"]:
        client.username_pw_set(cfg["username"], cfg["password"])

    try:
        client.connect(cfg["host"], cfg["port"], cfg["keepalive"])
    except Exception as exc:
        return 0, f"connect failed: {exc}"

    client.loop_start()

    try:
        for payload in messages:
            body = json.dumps(payload, separators=(",", ":"))
            try:
                info = client.publish(cfg["topic"], body, qos=cfg["qos"], retain=False)
                info.wait_for_publish()
            except Exception as exc:
                return published, f"publish failed: {exc}"
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                return published, f"publish failed rc={info.rc}"
            published += 1
    finally:
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:
            pass

    return published, None


def publish_with_mosquitto_pub(messages: list[dict], cfg: dict) -> tuple[int, str | None]:
    published = 0

    for payload in messages:
        body = json.dumps(payload, separators=(",", ":"))
        cmd = [
            "mosquitto_pub",
            "-h",
            cfg["host"],
            "-p",
            str(cfg["port"]),
            "-t",
            cfg["topic"],
            "-q",
            str(cfg["qos"]),
            "-m",
            body,
        ]

        if cfg["username"]:
            cmd.extend(["-u", cfg["username"], "-P", cfg["password"]])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except OSError as exc:
            return published, f"mosquitto_pub exec failed: {exc}"

        if proc.returncode != 0:
            return published, (proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip()

        published += 1

    return published, None


def main() -> None:
    if not DB_PATH.exists():
        print(f"error: blocked DB not found: {DB_PATH}", file=sys.stderr)
        sys.exit(1)

    try:
        cfg = load_config(CONFIG_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        sys.exit(1)

    rows = load_rows_from_db(DB_PATH, ONLY_ACTION)
    last_ts = load_state_timestamp(STATE_PATH)

    pending = [row for row in rows if last_ts is None or row["timestamp"] > last_ts]

    sender_name, sender_ip = resolve_sender_identity(cfg["host"])
    heartbeat_ts = datetime.now(timezone.utc).isoformat()
    heartbeat_message = {
        "event": "client_heartbeat",
        "status": "working",
        "timestamp": heartbeat_ts,
        "source": "auth-monitor/v4/client/6-block-ips.py",
        "client_name": sender_name,
        "client_ip": sender_ip,
    }
    print(
        (
            f"mosquitto_heartbeat status=running host={cfg['host']} port={cfg['port']} "
            f"topic={cfg['topic']} client_name={sender_name} client_ip={sender_ip}"
        ),
        file=sys.stderr,
    )

    messages = []
    for row in pending:
        messages.append(
            {
                "event": "blocked_ip_change",
                "ip": row["ip"],
                "reason": row["reason"],
                "action": row["action"],
                "timestamp": row["timestamp"].astimezone(timezone.utc).isoformat(),
                "source": "auth-monitor/v4/client/6-block-ips.py",
                "client_name": sender_name,
                "client_ip": sender_ip,
            }
        )

    all_messages = [heartbeat_message] + messages

    if DRY_RUN:
        print(f"heartbeat client_name={sender_name} client_ip={sender_ip} host={cfg['host']}")
        for msg in messages:
            print(msg["ip"])
        print(
            (
                f"db_rows={len(rows)} pending={len(messages)} heartbeat=1 "
                f"published={len(all_messages)} backend=dry_run errors=0"
            ),
            file=sys.stderr,
        )
        return

    backend = "paho"
    published, error = publish_with_paho(all_messages, cfg)
    if error:
        backend = "mosquitto_pub"
        published, error = publish_with_mosquitto_pub(all_messages, cfg)

    if error:
        print(f"error: publish failed ({backend}): {error}", file=sys.stderr)
        print(
            (
                f"db_rows={len(rows)} pending={len(messages)} heartbeat=1 "
                f"published={published} backend={backend} errors=1"
            ),
            file=sys.stderr,
        )
        sys.exit(1)

    if published >= 1:
        print(f"heartbeat client_name={sender_name} client_ip={sender_ip} host={cfg['host']}")

    for msg in messages[:published]:
        print(msg["ip"])

    if messages:
        blocked_published = max(0, published - 1)
        if blocked_published > len(messages):
            blocked_published = len(messages)
        newest_idx = blocked_published - 1
        newest_ts = parse_iso_ts(messages[newest_idx]["timestamp"]) if newest_idx >= 0 else None
        if newest_ts is not None:
            save_state_timestamp(STATE_PATH, newest_ts)

    print(
        (
            f"db_rows={len(rows)} pending={len(messages)} heartbeat=1 "
            f"published={published} backend={backend} errors=0"
        ),
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
