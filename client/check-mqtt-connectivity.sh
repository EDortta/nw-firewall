#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
CONFIG_PATH="${AUTH_MONITOR_CONFIG:-${BASE_DIR}/config/config.json}"

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "status=error reason=config_not_found path=${CONFIG_PATH}"
  exit 1
fi

readarray -t MQTT_INFO < <(
  python3 - "${CONFIG_PATH}" <<'PY'
import json
import sys
from pathlib import Path

cfg = Path(sys.argv[1])
payload = json.loads(cfg.read_text(encoding="utf-8"))
mqtt = payload.get("mqtt", {})
print(str(mqtt.get("host", "")).strip())
print(str(mqtt.get("port", 1883)).strip() or "1883")
print(str(mqtt.get("username", "")).strip())
print(str(mqtt.get("password", "")).strip())
print(str(mqtt.get("topic", "")).strip())
PY
)

MQTT_HOST="${MQTT_INFO[0]:-}"
MQTT_PORT="${MQTT_INFO[1]:-1883}"
MQTT_USER="${MQTT_INFO[2]:-}"
MQTT_PASS="${MQTT_INFO[3]:-}"
MQTT_TOPIC="${MQTT_INFO[4]:-}"

if [[ -z "${MQTT_HOST}" ]]; then
  echo "status=error reason=mqtt_host_missing config=${CONFIG_PATH}"
  exit 1
fi

if ! [[ "${MQTT_PORT}" =~ ^[0-9]+$ ]]; then
  echo "status=error reason=invalid_mqtt_port port=${MQTT_PORT}"
  exit 1
fi

MQTT_IP="$(getent ahostsv4 "${MQTT_HOST}" | awk 'NR==1{print $1}')"
if [[ -z "${MQTT_IP}" ]]; then
  MQTT_IP="${MQTT_HOST}"
fi

echo "check=mqtt_config host=${MQTT_HOST} ip=${MQTT_IP} port=${MQTT_PORT} topic=${MQTT_TOPIC:-unset}"

if command -v iptables >/dev/null 2>&1; then
  IPTABLES_OUTPUT=""
  if sudo -n iptables -S OUTPUT >/dev/null 2>&1; then
    IPTABLES_OUTPUT="$(sudo -n iptables -S OUTPUT 2>/dev/null || true)"
  else
    IPTABLES_OUTPUT="$(iptables -S OUTPUT 2>/dev/null || true)"
  fi

  if [[ -n "${IPTABLES_OUTPUT}" ]]; then
    OUTPUT_POLICY="$(printf '%s\n' "${IPTABLES_OUTPUT}" | awk 'NR==1 && $1=="-P"{print $3}')"
    OUTPUT_POLICY="${OUTPUT_POLICY:-unknown}"

    BLOCK_RULES="$(printf '%s\n' "${IPTABLES_OUTPUT}" | grep -E -- "-d (${MQTT_HOST}|${MQTT_IP})(/32)? .* -j (DROP|REJECT)" || true)"
    BLOCK_PORT_RULES="$(printf '%s\n' "${IPTABLES_OUTPUT}" | grep -E -- "--dport ${MQTT_PORT} .* -j (DROP|REJECT)" || true)"
    ALLOW_RULES="$(printf '%s\n' "${IPTABLES_OUTPUT}" | grep -E -- "-d (${MQTT_HOST}|${MQTT_IP})(/32)? .* --dport ${MQTT_PORT} .* -j ACCEPT" || true)"

    echo "check=iptables_output policy=${OUTPUT_POLICY}"
    if [[ -n "${BLOCK_RULES}" || -n "${BLOCK_PORT_RULES}" ]]; then
      echo "check=iptables_block status=warn detail=drop_or_reject_rule_detected"
    else
      echo "check=iptables_block status=ok detail=no_explicit_drop_reject_for_mqtt"
    fi

    if [[ -n "${ALLOW_RULES}" ]]; then
      echo "check=iptables_allow status=ok detail=explicit_accept_rule_found"
    else
      echo "check=iptables_allow status=info detail=no_explicit_accept_rule_found"
    fi
  else
    echo "check=iptables_output status=info detail=iptables_rules_unreadable"
  fi
else
  echo "check=iptables_output status=info detail=iptables_not_found"
fi

TCP_OK=0
PUB_OK=-1
if command -v nc >/dev/null 2>&1; then
  if nc -z -w 5 "${MQTT_HOST}" "${MQTT_PORT}" >/dev/null 2>&1; then
    TCP_OK=1
  fi
else
  if timeout 5 bash -c ">/dev/tcp/${MQTT_HOST}/${MQTT_PORT}" >/dev/null 2>&1; then
    TCP_OK=1
  fi
fi

if [[ "${TCP_OK}" -eq 1 ]]; then
  echo "check=tcp_connect status=ok target=${MQTT_HOST}:${MQTT_PORT}"
else
  echo "check=tcp_connect status=error target=${MQTT_HOST}:${MQTT_PORT} detail=connection_failed"
fi

if command -v mosquitto_pub >/dev/null 2>&1; then
  TEST_TOPIC="${MQTT_TOPIC:-auth-monitor/blocked-ips}/install-check"
  TEST_PAYLOAD="{\"event\":\"install_check\",\"source\":\"check-mqtt-connectivity.sh\"}"
  PUB_CMD=(mosquitto_pub -h "${MQTT_HOST}" -p "${MQTT_PORT}" -q 0 -t "${TEST_TOPIC}" -m "${TEST_PAYLOAD}")
  if [[ -n "${MQTT_USER}" ]]; then
    PUB_CMD+=(-u "${MQTT_USER}" -P "${MQTT_PASS}")
  fi

  PUB_RC=0
  if command -v timeout >/dev/null 2>&1; then
    timeout 8 "${PUB_CMD[@]}" >/dev/null 2>&1 || PUB_RC=$?
  else
    "${PUB_CMD[@]}" >/dev/null 2>&1 || PUB_RC=$?
  fi

  if [[ "${PUB_RC}" -eq 0 ]]; then
    PUB_OK=1
    echo "check=mosquitto_pub status=ok topic=${TEST_TOPIC}"
  else
    PUB_OK=0
    echo "check=mosquitto_pub status=warn topic=${TEST_TOPIC} detail=publish_failed"
  fi
else
  echo "check=mosquitto_pub status=info detail=mosquitto_pub_not_found"
fi

if [[ "${TCP_OK}" -eq 1 && ( "${PUB_OK}" -eq 1 || "${PUB_OK}" -eq -1 ) ]]; then
  echo "status=ok summary=mqtt_reachable"
  exit 0
fi

if [[ "${TCP_OK}" -eq 1 && "${PUB_OK}" -eq 0 ]]; then
  echo "status=warn summary=mqtt_publish_failed"
  exit 1
fi

echo "status=warn summary=mqtt_unreachable"
exit 1
