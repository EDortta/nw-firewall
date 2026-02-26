#!/usr/bin/env python3

import fcntl
import ipaddress
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import paho.mqtt.client as mqtt  # type: ignore
except ImportError:
    print("error: paho-mqtt not installed", file=sys.stderr)
    sys.exit(1)

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
CONFIG_PATH = Path(os.getenv("AUTH_MONITOR_CONFIG", str(BASE_DIR / "config" / "config.json")))
LOCK_FILE = Path(os.getenv("MQTT_LISTENER_LOCK_FILE", "/var/run/auth-monitor-mqtt-listener.lock"))

IPTABLES_CMD = os.getenv("IPTABLES_CMD", "/usr/sbin/iptables")
IP6TABLES_CMD = os.getenv("IP6TABLES_CMD", "/usr/sbin/ip6tables")
CHAIN = os.getenv("IPTABLES_CHAIN", "INPUT")
TARGET = os.getenv("IPTABLES_TARGET", "DROP")
INSERT_AT_TOP = os.getenv("IPTABLES_INSERT_TOP", "1").strip().lower() in {"1", "true", "yes"}


def normalize_ip(value: str) -> str | None:
    candidate = value.strip().strip("[]")
    if not candidate:
        return None

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def run_command(cmd: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError as exc:
        return 1, str(exc)

    stderr = (proc.stderr or "").strip()
    return proc.returncode, stderr


def is_executable_available(cmd: str) -> bool:
    if os.path.sep in cmd:
        return Path(cmd).exists()
    return shutil.which(cmd) is not None


def rule_exists(cmd_bin: str, chain: str, ip: str, target: str) -> tuple[bool, str | None]:
    code, err = run_command([cmd_bin, "-C", chain, "-s", ip, "-j", target])
    if code == 0:
        return True, None
    if code in {1, 2}:
        return False, None
    return False, err or f"exit code {code}"


def add_rule(cmd_bin: str, chain: str, ip: str, target: str, insert_at_top: bool) -> str | None:
    if insert_at_top:
        cmd = [cmd_bin, "-I", chain, "1", "-s", ip, "-j", target]
    else:
        cmd = [cmd_bin, "-A", chain, "-s", ip, "-j", target]

    code, err = run_command(cmd)
    if code != 0:
        return err or f"exit code {code}"

    return None


def remove_rule(cmd_bin: str, chain: str, ip: str, target: str) -> str | None:
    # Remove all matching rules for this IP/action pair.
    while True:
        exists, exists_error = rule_exists(cmd_bin, chain, ip, target)
        if exists_error:
            return exists_error
        if not exists:
            return None

        code, err = run_command([cmd_bin, "-D", chain, "-s", ip, "-j", target])
        if code != 0:
            return err or f"exit code {code}"


def load_mqtt_config(config_path: Path) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    mqtt_cfg = payload.get("mqtt")
    if not isinstance(mqtt_cfg, dict):
        raise ValueError("config.mqtt is missing or invalid")

    host = str(mqtt_cfg.get("host", "")).strip()
    if not host:
        raise ValueError("config.mqtt.host is required")

    topic = str(mqtt_cfg.get("topic", "")).strip()
    if not topic:
        raise ValueError("config.mqtt.topic is required")

    return {
        "host": host,
        "port": int(mqtt_cfg.get("port", 1883)),
        "topic": os.getenv("MQTT_TOPIC", topic).strip() or topic,
        "username": str(mqtt_cfg.get("username", "")).strip(),
        "password": str(mqtt_cfg.get("password", "")).strip(),
        "client_id": str(mqtt_cfg.get("client_id", "auth-monitor-server")).strip() or "auth-monitor-server",
        "keepalive": int(mqtt_cfg.get("keepalive", 60)),
        "qos": int(mqtt_cfg.get("qos", 1)),
    }


def acquire_single_instance_lock(lock_file: Path):
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    lock_fp = open(lock_file, "a+", encoding="utf-8")

    try:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print(f"error: another listener instance is already running (lock={lock_file})", file=sys.stderr)
        sys.exit(1)

    lock_fp.seek(0)
    lock_fp.truncate()
    lock_fp.write(str(os.getpid()))
    lock_fp.flush()

    return lock_fp


def create_mqtt_client(client_id: str) -> mqtt.Client:
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


def apply_action(ip: str, action: str) -> tuple[bool, str]:
    version = ipaddress.ip_address(ip).version
    cmd_bin = IPTABLES_CMD if version == 4 else IP6TABLES_CMD

    if version == 6 and not is_executable_available(IP6TABLES_CMD):
        return False, f"ip6tables not found for IPv6 {ip}"

    if action == "block":
        exists, exists_error = rule_exists(cmd_bin, CHAIN, ip, TARGET)
        if exists_error:
            return False, exists_error
        if exists:
            return True, "already_blocked"

        add_error = add_rule(cmd_bin, CHAIN, ip, TARGET, INSERT_AT_TOP)
        if add_error:
            return False, add_error

        return True, "blocked"

    if action == "unblock":
        remove_error = remove_rule(cmd_bin, CHAIN, ip, TARGET)
        if remove_error:
            return False, remove_error

        return True, "unblocked"

    return False, f"unsupported action: {action}"


def main() -> None:
    if not is_executable_available(IPTABLES_CMD):
        print(f"error: iptables binary not found: {IPTABLES_CMD}", file=sys.stderr)
        sys.exit(1)

    _lock_handle = acquire_single_instance_lock(LOCK_FILE)

    try:
        cfg = load_mqtt_config(CONFIG_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        sys.exit(1)

    def on_connect(client, userdata, flags, reason_code, properties=None):
        rc = getattr(reason_code, "value", reason_code)
        try:
            rc = int(rc)
        except (TypeError, ValueError):
            rc = 0 if str(reason_code).lower() == "success" else 1
        if rc != 0:
            print(f"error: MQTT connect failed rc={rc}", file=sys.stderr)
            return

        client.subscribe(cfg["topic"], qos=cfg["qos"])
        print(f"subscribed topic={cfg['topic']} qos={cfg['qos']}")

    def on_message(client, userdata, msg):
        raw = msg.payload.decode("utf-8", "ignore")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            print(f"warn: invalid json payload: {raw}", file=sys.stderr)
            return

        if not isinstance(payload, dict):
            print("warn: ignored non-object MQTT payload", file=sys.stderr)
            return

        ip = normalize_ip(str(payload.get("ip", "")))
        action = str(payload.get("action", "block")).strip().lower()

        if not ip:
            print(f"warn: missing/invalid ip in payload: {payload}", file=sys.stderr)
            return

        ok, status = apply_action(ip, action)
        if ok:
            print(f"ip={ip} action={action} status={status}")
        else:
            print(f"error: ip={ip} action={action} reason={status}", file=sys.stderr)

    client = create_mqtt_client(cfg["client_id"])
    client.on_connect = on_connect
    client.on_message = on_message

    if cfg["username"]:
        client.username_pw_set(cfg["username"], cfg["password"])

    client.connect(cfg["host"], cfg["port"], cfg["keepalive"])
    print(f"connecting host={cfg['host']} port={cfg['port']} client_id={cfg['client_id']} lock={LOCK_FILE}")
    client.loop_forever()


if __name__ == "__main__":
    main()
