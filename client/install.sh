#!/usr/bin/env bash
set -euo pipefail

# Installs required runtime deps and a cron entry to publish block updates every minute.
# Defaults are resolved from the directory where this install script lives.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$(cd -- "${SCRIPT_DIR}/.." && pwd)}"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
SCRIPT_PATH="${SCRIPT_PATH:-${BASE_DIR}/client/6-block-ips.py}"
AGENT_SCRIPT_PATH="${AGENT_SCRIPT_PATH:-${BASE_DIR}/client/7-iptables-agent.py}"
LOG_PATH="${LOG_PATH:-/var/log/nw-monitor.log}"
CRON_SCHEDULE="${CRON_SCHEDULE:-* * * * *}"

CRON_CMD="${PYTHON_BIN} ${SCRIPT_PATH} >>${LOG_PATH} 2>&1"
AGENT_CRON_CMD="${PYTHON_BIN} ${AGENT_SCRIPT_PATH} >>${LOG_PATH} 2>&1"
CRON_LINE="${CRON_SCHEDULE} ${CRON_CMD}"
AGENT_CRON_LINE="${CRON_SCHEDULE} ${AGENT_CRON_CMD}"
MQTT_CHECK_SCRIPT_PATH="${MQTT_CHECK_SCRIPT_PATH:-${BASE_DIR}/client/check-mqtt-connectivity.sh}"
MQTT_CHECK_STRICT="${MQTT_CHECK_STRICT:-0}"
CONFIG_PATH="${AUTH_MONITOR_CONFIG:-${BASE_DIR}/config/config.json}"

log_install() {
  local msg="$1"
  echo "${msg}"
  {
    mkdir -p "$(dirname "${LOG_PATH}")"
    echo "${msg}" >> "${LOG_PATH}"
  } 2>/dev/null || true
}

ensure_mqtt_iptables_output_allow() {
  if ! command -v iptables >/dev/null 2>&1; then
    log_install "install_step component=client action=ensure_mqtt_iptables_allow status=skipped reason=iptables_not_found"
    return
  fi

  local mqtt_host mqtt_port
  readarray -t _mqtt_info < <(
    python3 - "${CONFIG_PATH}" <<'PY'
import json
import sys
from pathlib import Path

cfg = Path(sys.argv[1])
payload = json.loads(cfg.read_text(encoding="utf-8"))
mqtt = payload.get("mqtt", {})
print(str(mqtt.get("host", "")).strip())
print(str(mqtt.get("port", 1883)).strip() or "1883")
PY
  )
  mqtt_host="${_mqtt_info[0]:-}"
  mqtt_port="${_mqtt_info[1]:-1883}"

  if [[ -z "${mqtt_host}" ]]; then
    log_install "install_step component=client action=ensure_mqtt_iptables_allow status=skipped reason=mqtt_host_missing"
    return
  fi

  local prefix=()
  if [[ "${EUID}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      prefix=(sudo)
    else
      log_install "install_step component=client action=ensure_mqtt_iptables_allow status=failed reason=sudo_not_found"
      return
    fi
  fi

  local resolved=()
  while IFS= read -r ip; do
    [[ -n "${ip}" ]] && resolved+=("${ip}")
  done < <(getent ahostsv4 "${mqtt_host}" | awk '{print $1}' | sort -u)

  if [[ "${#resolved[@]}" -eq 0 ]]; then
    resolved=("${mqtt_host}")
  fi

  local ip
  for ip in "${resolved[@]}"; do
    if "${prefix[@]}" iptables -C OUTPUT -p tcp -d "${ip}" --dport "${mqtt_port}" -j ACCEPT >/dev/null 2>&1; then
      log_install "install_step component=client action=ensure_mqtt_iptables_allow status=exists ip=${ip} port=${mqtt_port}"
      continue
    fi

    if "${prefix[@]}" iptables -I OUTPUT 1 -p tcp -d "${ip}" --dport "${mqtt_port}" -j ACCEPT >/dev/null 2>&1; then
      log_install "install_step component=client action=ensure_mqtt_iptables_allow status=inserted ip=${ip} port=${mqtt_port}"
    else
      log_install "install_step component=client action=ensure_mqtt_iptables_allow status=failed ip=${ip} port=${mqtt_port}"
    fi
  done
}

ensure_debian_dependencies() {
  if [[ ! -f /etc/debian_version ]]; then
    echo "error: this installer supports Debian/Ubuntu only" >&2
    exit 1
  fi

  local apt_prefix=()
  if [[ "${EUID}" -ne 0 ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
      echo "error: sudo is required to install missing packages" >&2
      exit 1
    fi
    apt_prefix=(sudo)
  fi

  local need_update=0

  if ! command -v python3 >/dev/null 2>&1; then
    need_update=1
  fi

  if ! command -v mosquitto_pub >/dev/null 2>&1; then
    need_update=1
  fi

  if [[ "${need_update}" -eq 1 ]]; then
    "${apt_prefix[@]}" apt-get update -y
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    "${apt_prefix[@]}" apt-get install -y python3
  fi

if ! command -v mosquitto_pub >/dev/null 2>&1; then
    "${apt_prefix[@]}" apt-get install -y mosquitto-clients
  fi

  if ! "${PYTHON_BIN}" -c "import paho.mqtt.client" >/dev/null 2>&1; then
    "${apt_prefix[@]}" apt-get install -y python3-paho-mqtt
  fi
}

ensure_debian_dependencies

stop_running_processes() {
  local proc
  local pids=()

  # Stop current user publisher process (if running).
  if mapfile -t pids < <(pgrep -f -- "${SCRIPT_PATH}" 2>/dev/null); then
    for proc in "${pids[@]}"; do
      kill "${proc}" 2>/dev/null || true
    done
    sleep 1
    for proc in "${pids[@]}"; do
      kill -9 "${proc}" 2>/dev/null || true
    done
  fi

  # Stop root agent process (if running), it may keep old code loaded.
  if [[ "${EUID}" -eq 0 ]]; then
    if mapfile -t pids < <(pgrep -f -- "${AGENT_SCRIPT_PATH}" 2>/dev/null); then
      for proc in "${pids[@]}"; do
        kill "${proc}" 2>/dev/null || true
      done
      sleep 1
      for proc in "${pids[@]}"; do
        kill -9 "${proc}" 2>/dev/null || true
      done
    fi
  else
    if command -v sudo >/dev/null 2>&1; then
      sudo pkill -f -- "${AGENT_SCRIPT_PATH}" 2>/dev/null || true
      sudo pkill -9 -f -- "${AGENT_SCRIPT_PATH}" 2>/dev/null || true
    fi
  fi
}

log_install "install_start component=client host=$(hostname) script=${BASH_SOURCE[0]}"
stop_running_processes
log_install "install_step component=client action=stop_running_processes status=done"
ensure_mqtt_iptables_output_allow

if [[ -f "${MQTT_CHECK_SCRIPT_PATH}" ]]; then
  log_install "install_step component=client action=mqtt_connectivity_check status=starting script=${MQTT_CHECK_SCRIPT_PATH}"
  set +e
  MQTT_CHECK_OUTPUT="$(bash "${MQTT_CHECK_SCRIPT_PATH}" 2>&1)"
  MQTT_CHECK_RC=$?
  set -e

  while IFS= read -r line; do
    [[ -n "${line}" ]] && log_install "mqtt_check ${line}"
  done <<< "${MQTT_CHECK_OUTPUT}"

  if [[ "${MQTT_CHECK_RC}" -ne 0 ]]; then
    log_install "install_step component=client action=mqtt_connectivity_check status=failed rc=${MQTT_CHECK_RC}"
    if [[ "${MQTT_CHECK_STRICT}" == "1" ]]; then
      echo "error: mqtt connectivity check failed and MQTT_CHECK_STRICT=1" >&2
      exit 1
    fi
  else
    log_install "install_step component=client action=mqtt_connectivity_check status=ok"
  fi
else
  log_install "install_step component=client action=mqtt_connectivity_check status=skipped reason=script_not_found"
fi

mkdir -p "$(dirname "${LOG_PATH}")"
touch "${LOG_PATH}"

TMP_ROOT_CRON="$(mktemp)"
TMP_USER_CRON="$(mktemp)"
trap 'rm -f "${TMP_USER_CRON}" "${TMP_ROOT_CRON}"' EXIT

# User crontab: remove monitor jobs, they now run as root.
(crontab -l 2>/dev/null || true) | grep -F -v "${CRON_CMD}" | grep -F -v "${AGENT_CRON_CMD}" | grep -F -v "${SCRIPT_PATH}" | grep -F -v "${AGENT_SCRIPT_PATH}" > "${TMP_USER_CRON}" || true
crontab "${TMP_USER_CRON}"
log_install "install_step component=client action=update_user_crontab status=done"

# Root crontab: install both publisher and iptables agent.
if [[ "${EUID}" -eq 0 ]]; then
  (crontab -l -u root 2>/dev/null || true) \
    | grep -F -v "${CRON_CMD}" \
    | grep -F -v "${AGENT_CRON_CMD}" \
    | grep -F -v "${SCRIPT_PATH}" \
    | grep -F -v "${AGENT_SCRIPT_PATH}" > "${TMP_ROOT_CRON}" || true
  echo "${CRON_LINE}" >> "${TMP_ROOT_CRON}"
  echo "${AGENT_CRON_LINE}" >> "${TMP_ROOT_CRON}"
  crontab -u root "${TMP_ROOT_CRON}"
else
  if ! command -v sudo >/dev/null 2>&1; then
    echo "error: sudo is required to install root cron entry for 7-iptables-agent.py" >&2
    exit 1
  fi
  (sudo crontab -l -u root 2>/dev/null || true) \
    | grep -F -v "${CRON_CMD}" \
    | grep -F -v "${AGENT_CRON_CMD}" \
    | grep -F -v "${SCRIPT_PATH}" \
    | grep -F -v "${AGENT_SCRIPT_PATH}" > "${TMP_ROOT_CRON}" || true
  echo "${CRON_LINE}" >> "${TMP_ROOT_CRON}"
  echo "${AGENT_CRON_LINE}" >> "${TMP_ROOT_CRON}"
  sudo crontab -u root "${TMP_ROOT_CRON}"
fi

log_install "removed_from_user_crontab cmd=${CRON_CMD}"
log_install "installed_for_root cron=${CRON_LINE}"
log_install "installed_for_root cron=${AGENT_CRON_LINE}"
log_install "install_done component=client host=$(hostname) status=ok"
