#!/usr/bin/env python3

import argparse
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
WHITELIST_PATH = Path(os.getenv("WHITELIST_PATH", str(BASE_DIR / "db" / "whitelist.json")))
CONFIG_PATH = Path(os.getenv("AUTH_MONITOR_CONFIG", str(BASE_DIR / "config" / "config.json")))
LOG_PATH = Path(os.getenv("AUTH_MONITOR_LOG_PATH", "/var/log/nw-monitor.log"))


def normalize_ip(value: str) -> str | None:
    candidate = value.strip().strip("[]")
    if not candidate:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_line(message: str, *, is_error: bool = False) -> None:
    if is_error:
        print(message, file=sys.stderr)
    else:
        print(message)

    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(message + "\n")
    except OSError:
        pass


def load_mqtt_config(config_path: Path) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    mqtt_cfg = payload.get("mqtt")
    if not isinstance(mqtt_cfg, dict):
        raise ValueError("config.mqtt is missing or invalid")

    host = str(mqtt_cfg.get("host", "")).strip()
    topic = str(mqtt_cfg.get("topic", "")).strip()
    if not host:
        raise ValueError("config.mqtt.host is required")
    if not topic:
        raise ValueError("config.mqtt.topic is required")

    base_client_id = (
        str(mqtt_cfg.get("manager_client_id", "")).strip()
        or str(mqtt_cfg.get("client_id", "auth-monitor-client")).strip()
        or "auth-monitor-client"
    )
    unique_client_id = f"{base_client_id}-mgr-{socket.gethostname()}-{os.getpid()}"

    return {
        "host": host,
        "port": int(mqtt_cfg.get("port", 1883)),
        "topic": topic,
        "username": str(mqtt_cfg.get("username", "")).strip(),
        "password": str(mqtt_cfg.get("password", "")).strip(),
        "client_id": unique_client_id,
        "keepalive": int(mqtt_cfg.get("keepalive", 60)),
        "qos": int(mqtt_cfg.get("qos", 1)),
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

    ip = "unknown"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((mqtt_host, 1883))
            ip = sock.getsockname()[0]
    except OSError:
        pass

    return name, ip


def publish_with_paho(payload: dict, cfg: dict) -> str | None:
    try:
        import paho.mqtt.client as mqtt  # type: ignore
    except ImportError:
        return "paho-mqtt not installed"

    def create_client() -> mqtt.Client:
        if hasattr(mqtt, "CallbackAPIVersion"):
            try:
                return mqtt.Client(
                    callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                    client_id=cfg["client_id"],
                )
            except (TypeError, ValueError, AttributeError):
                pass
        return mqtt.Client(client_id=cfg["client_id"])

    client = create_client()
    if cfg["username"]:
        client.username_pw_set(cfg["username"], cfg["password"])

    client.connect(cfg["host"], cfg["port"], cfg["keepalive"])
    client.loop_start()
    try:
        body = json.dumps(payload, separators=(",", ":"))
        info = client.publish(cfg["topic"], body, qos=cfg["qos"], retain=False)
        info.wait_for_publish()
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            return f"publish failed rc={info.rc}"
    finally:
        client.loop_stop()
        client.disconnect()
    return None


def publish_with_mosquitto_pub(payload: dict, cfg: dict) -> str | None:
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
        return f"mosquitto_pub exec failed: {exc}"
    if proc.returncode != 0:
        return (proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip()
    return None


def publish_event(payload: dict) -> None:
    try:
        cfg = load_mqtt_config(CONFIG_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"warn: mqtt config not available: {exc}", file=sys.stderr)
        return

    error = publish_with_paho(payload, cfg)
    backend = "paho"
    if error:
        backend = "mosquitto_pub"
        error = publish_with_mosquitto_pub(payload, cfg)

    if error:
        log_line(f"warn: mqtt publish failed ({backend}): {error}", is_error=True)
    else:
        log_line(f"mqtt_published event={payload.get('event', 'unknown')} ip={payload.get('ip', '')} backend={backend}")


def publish_change(ip: str, action: str, reason: str) -> None:
    try:
        cfg = load_mqtt_config(CONFIG_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"warn: mqtt config not available: {exc}", file=sys.stderr)
        return
    sender_name, sender_ip = resolve_sender_identity(cfg["host"])
    payload = {
        "event": "blocked_ip_change",
        "ip": ip,
        "reason": reason,
        "action": action,
        "timestamp": utc_now_iso(),
        "source": "auth-monitor/v4/client/8-manage-ip-lists.py",
        "client_name": sender_name,
        "client_ip": sender_ip,
    }
    publish_event(payload)


def publish_whitelist_change(ip: str, operation: str, reason: str) -> None:
    try:
        cfg = load_mqtt_config(CONFIG_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"warn: mqtt config not available: {exc}", file=sys.stderr)
        return
    sender_name, sender_ip = resolve_sender_identity(cfg["host"])
    payload = {
        "event": "whitelist_change",
        "ip": ip,
        "operation": operation,
        "reason": reason,
        "timestamp": utc_now_iso(),
        "source": "auth-monitor/v4/client/8-manage-ip-lists.py",
        "client_name": sender_name,
        "client_ip": sender_ip,
    }
    publish_event(payload)


def ensure_blocked_schema(con: sqlite3.Connection) -> None:
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip text,
            reason text,
            action text,
            timestamp text
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ip_blocked_ips ON blocked_ips (ip)")
    con.commit()
    cur.close()


def upsert_blocked_ip(ip: str, action: str, reason: str) -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    ensure_blocked_schema(con)
    cur = con.cursor()
    now = utc_now_iso()
    cur.execute("SELECT ip FROM blocked_ips WHERE ip=?", (ip,))
    row = cur.fetchone()
    if row is None:
        cur.execute(
            "INSERT INTO blocked_ips (ip, reason, action, timestamp) VALUES (?, ?, ?, ?)",
            (ip, reason, action, now),
        )
    else:
        cur.execute(
            "UPDATE blocked_ips SET reason=?, action=?, timestamp=? WHERE ip=?",
            (reason, action, now, ip),
        )
    con.commit()
    cur.close()
    con.close()


def remove_from_blocked(ip: str) -> int:
    if not DB_PATH.exists():
        return 0
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    affected = cur.rowcount if cur.rowcount is not None else 0
    con.commit()
    cur.close()
    con.close()
    return affected


def load_whitelist(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError):
        return set()

    if isinstance(payload, list):
        candidates = payload
    elif isinstance(payload, dict):
        candidates = payload.get("whitelist") or payload.get("ips") or payload.get("allowed_ips") or []
    else:
        candidates = []

    out: set[str] = set()
    if isinstance(candidates, list):
        for item in candidates:
            ip = normalize_ip(str(item))
            if ip:
                out.add(ip)
    return out


def save_whitelist(path: Path, ips: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sorted_ips = sorted(ips, key=lambda v: (ipaddress.ip_address(v).version, int(ipaddress.ip_address(v))))
    payload = {"whitelist": sorted_ips}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def cmd_blacklist(ip: str, reason: str) -> None:
    whitelist = load_whitelist(WHITELIST_PATH)
    removed_from_whitelist = ip in whitelist
    whitelist.discard(ip)
    save_whitelist(WHITELIST_PATH, whitelist)

    final_reason = reason.strip() or "manual blacklist"
    upsert_blocked_ip(ip, "block", final_reason)
    publish_whitelist_change(ip, "remove", final_reason)
    publish_change(ip, "block", final_reason)

    log_line(
        (
            f"blacklisted ip={ip} reason={final_reason} "
            f"removed_from_whitelist={1 if removed_from_whitelist else 0}"
        )
    )


def cmd_whitelist(ip: str, reason: str) -> None:
    whitelist = load_whitelist(WHITELIST_PATH)
    already_whitelisted = ip in whitelist
    whitelist.add(ip)
    save_whitelist(WHITELIST_PATH, whitelist)

    final_reason = reason.strip() or "manual whitelist"
    upsert_blocked_ip(ip, "unblock", final_reason)
    publish_whitelist_change(ip, "add", final_reason)
    publish_change(ip, "unblock", final_reason)

    log_line(f"whitelisted ip={ip} already_whitelisted={1 if already_whitelisted else 0}")


def cmd_remove(ip: str) -> None:
    whitelist = load_whitelist(WHITELIST_PATH)
    removed_from_whitelist = ip in whitelist
    whitelist.discard(ip)
    save_whitelist(WHITELIST_PATH, whitelist)

    removed_rows = remove_from_blocked(ip)
    reason = "manual remove from lists"
    publish_whitelist_change(ip, "remove", reason)
    publish_change(ip, "unblock", reason)

    log_line(
        (
            f"removed ip={ip} removed_from_whitelist={1 if removed_from_whitelist else 0} "
            f"removed_from_blocked_rows={removed_rows}"
        )
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Manage blocked/whitelist IPs locally and publish MQTT change events "
            "so agents can apply block/unblock immediately."
        )
    )
    parser.add_argument(
        "command",
        choices=("blacklist", "whitelist", "remove"),
        help="operation to execute",
    )
    parser.add_argument("ip", help="IPv4/IPv6 address")
    parser.add_argument(
        "--reason",
        default="",
        help="reason to store when using blacklist/whitelist (optional)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ip = normalize_ip(args.ip)
    if not ip:
        log_line(f"error: invalid IP: {args.ip}", is_error=True)
        sys.exit(1)

    if args.command == "blacklist":
        cmd_blacklist(ip, args.reason)
        return
    if args.command == "whitelist":
        cmd_whitelist(ip, args.reason)
        return
    if args.command == "remove":
        cmd_remove(ip)
        return

    log_line(f"error: unsupported command {args.command}", is_error=True)
    sys.exit(1)


if __name__ == "__main__":
    main()
