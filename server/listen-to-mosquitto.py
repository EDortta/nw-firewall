#!/usr/bin/env python3

import fcntl
import ipaddress
import base64
import hashlib
import hmac
import json
import os
import socket
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


def configure_stdio() -> None:
    # Force immediate log visibility when running as a long-lived process with redirected output.
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except AttributeError:
        pass


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




def parse_json_list_env(var_name: str) -> list[str]:
    raw = os.getenv(var_name, "").strip()
    if not raw:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        print(f"warn: invalid JSON in {var_name}", file=sys.stderr)
        return []
    if not isinstance(payload, list):
        return []

    values: list[str] = []
    for item in payload:
        value = str(item).strip()
        if value and value not in values:
            values.append(value)
    return values


def resolve_mqtt_password(mqtt_cfg: dict) -> str:
    env_name = str(mqtt_cfg.get("password_env", "AUTH_MONITOR_MQTT_PASSWORD")).strip()
    if env_name:
        from_env = os.getenv(env_name, "").strip()
        if from_env:
            return from_env

    all_passwords = parse_json_list_env("AUTH_MONITOR_MQTT_PASSWORDS_JSON")
    if all_passwords:
        return all_passwords[0]

    return str(mqtt_cfg.get("password", "")).strip()


def sign_payload(payload: dict, secret: str) -> str:
    unsigned = dict(payload)
    unsigned.pop("signature", None)
    body = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def verify_payload_signature(payload: dict, secret: str) -> bool:
    signature = str(payload.get("signature", ""))
    if not signature:
        return False
    expected = sign_payload(payload, secret)
    return hmac.compare_digest(signature, expected)

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

    base_client_id = (
        os.getenv("AUTH_MONITOR_SERVER_CLIENT_ID", "").strip()
        or str(mqtt_cfg.get("server_client_id", "")).strip()
        or "auth-monitor-server"
    )
    unique_client_id = f"{base_client_id}-{socket.gethostname()}"

    hmac_env_name = str(mqtt_cfg.get("event_hmac_env", "AUTH_MONITOR_EVENT_HMAC")).strip() or "AUTH_MONITOR_EVENT_HMAC"
    hmac_primary = os.getenv(hmac_env_name, "").strip()
    hmac_secrets: list[str] = []
    if hmac_primary:
        hmac_secrets.append(hmac_primary)

    for secret in parse_json_list_env("AUTH_MONITOR_EVENT_HMACS_JSON"):
        if secret not in hmac_secrets:
            hmac_secrets.append(secret)

    return {
        "host": host,
        "port": int(mqtt_cfg.get("port", 1883)),
        "topic": os.getenv("MQTT_TOPIC", topic).strip() or topic,
        "username": str(mqtt_cfg.get("username", "")).strip(),
        "password": resolve_mqtt_password(mqtt_cfg),
        "client_id": unique_client_id,
        "keepalive": int(mqtt_cfg.get("keepalive", 60)),
        "qos": int(mqtt_cfg.get("qos", 1)),
        "hmac_secret": hmac_primary,
        "hmac_secrets": hmac_secrets,
        "require_signed_events": os.getenv("AUTH_MONITOR_REQUIRE_SIGNATURE", "1").strip().lower() in {"1", "true", "yes"},
    }


def acquire_single_instance_lock(lock_file: Path):
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    lock_fp = open(lock_file, "a+", encoding="utf-8")

    try:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print(f"    listener already running (lock={lock_file})")
        sys.exit(0)

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


def resolve_server_identity(mqtt_host: str) -> tuple[str, str]:
    name = (
        os.getenv("AUTH_MONITOR_SERVER_NAME", "").strip()
        or os.getenv("HOSTNAME", "").strip()
        or socket.gethostname()
    )

    forced_ip = os.getenv("AUTH_MONITOR_SERVER_IP", "").strip()
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


def publish_json(client: mqtt.Client, cfg: dict, payload: dict) -> tuple[bool, str]:
    body = json.dumps(payload, separators=(",", ":"))
    info = client.publish(cfg["topic"], body, qos=cfg["qos"], retain=False)
    info.wait_for_publish()
    if info.rc != mqtt.MQTT_ERR_SUCCESS:
        return False, f"publish failed rc={info.rc}"
    return True, "ok"


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
    configure_stdio()

    if not is_executable_available(IPTABLES_CMD):
        print(f"error: iptables binary not found: {IPTABLES_CMD}", file=sys.stderr)
        sys.exit(1)

    _lock_handle = acquire_single_instance_lock(LOCK_FILE)

    try:
        cfg = load_mqtt_config(CONFIG_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        sys.exit(1)
    if cfg["require_signed_events"] and not cfg["hmac_secrets"]:
        print("config error: signed events required but no AUTH_MONITOR_EVENT_HMAC(S) configured", file=sys.stderr)
        sys.exit(1)
    server_name, server_ip = resolve_server_identity(cfg["host"])

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

        event = str(payload.get("event", "")).strip().lower()
        if event in {"blocked_ip_change", "whitelist_change"}:
            if cfg["require_signed_events"]:
                if not any(verify_payload_signature(payload, secret) for secret in cfg["hmac_secrets"]):
                    print(f"warn: invalid or missing signature for event={event}", file=sys.stderr)
                    return
        sender_name = str(payload.get("client_name", "")).strip()
        sender_ip = str(payload.get("client_ip", "")).strip()
        sender = sender_name or sender_ip or "unknown"

        if event == "client_heartbeat":
            status = str(payload.get("status", "working")).strip() or "working"
            print(f"heartbeat from={sender} status={status}")
            fanout_payload = {
                "event": "client_heartbeat_broadcast",
                "status": status,
                "timestamp": payload.get("timestamp") or "",
                "source": "auth-monitor/v4/server/listen-to-mosquitto.py",
                "client_name": server_name,
                "client_ip": server_ip,
                "observed_client_name": sender_name,
                "observed_client_ip": sender_ip,
            }
            ok, fanout_status = publish_json(client, cfg, fanout_payload)
            if ok:
                print(f"heartbeat_broadcast observer={server_name or server_ip} observed={sender} status={status}")
            else:
                print(
                    (
                        f"error: heartbeat_broadcast_failed observer={server_name or server_ip} "
                        f"observed={sender} reason={fanout_status}"
                    ),
                    file=sys.stderr,
                )
            return

        if event == "client_presence":
            status = str(payload.get("status", "working")).strip() or "working"
            observed_name = str(payload.get("observed_client_name", "")).strip()
            observed_ip = str(payload.get("observed_client_ip", "")).strip()
            observed = observed_name or observed_ip or "unknown"
            print(f"presence observer={sender} observed={observed} status={status}")
            return

        if event == "whitelist_change":
            ip = normalize_ip(str(payload.get("ip", "")))
            operation = str(payload.get("operation", "")).strip().lower()
            if not ip:
                print(f"warn: whitelist_change missing/invalid ip in payload: {payload}", file=sys.stderr)
                return
            print(f"whitelist_change sender={sender} op={operation} ip={ip}")
            return

        if event and event != "blocked_ip_change":
            print(f"warn: unsupported event={event} payload={payload}", file=sys.stderr)
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
