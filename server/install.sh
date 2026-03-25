#!/usr/bin/env bash
set -euo pipefail

# Installs a cron entry to keep the MQTT listener running every minute.
# Defaults are resolved from the directory where this install script lives.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$(cd -- "${SCRIPT_DIR}/.." && pwd)}"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
SCRIPT_PATH="${SCRIPT_PATH:-${BASE_DIR}/server/listen-to-mosquitto.py}"
LOG_PATH="${LOG_PATH:-/var/log/nw-monitor.log}"
CRON_SCHEDULE="${CRON_SCHEDULE:-* * * * *}"
CONFIG_PATH="${AUTH_MONITOR_CONFIG:-${BASE_DIR}/config/config.json}"
AUTH_MONITOR_ALLOW_MISSING_SECRETS="${AUTH_MONITOR_ALLOW_MISSING_SECRETS:-0}"

CRON_CMD="${PYTHON_BIN} ${SCRIPT_PATH} >>${LOG_PATH} 2>&1"
CRON_LINE="${CRON_SCHEDULE} ${CRON_CMD}"

log_install() {
  local msg="$1"
  echo "${msg}"
  {
    mkdir -p "$(dirname "${LOG_PATH}")"
    echo "${msg}" >> "${LOG_PATH}"
  } 2>/dev/null || true
}


ensure_required_secrets() {
  local mqtt_pass_env hmac_env
  readarray -t _secret_keys < <(
    python3 - "${CONFIG_PATH}" <<'PY'
import json
import sys
from pathlib import Path

cfg = Path(sys.argv[1])
payload = json.loads(cfg.read_text(encoding="utf-8"))
mqtt = payload.get("mqtt", {})
print(str(mqtt.get("password_env", "AUTH_MONITOR_MQTT_PASSWORD")).strip() or "AUTH_MONITOR_MQTT_PASSWORD")
print(str(mqtt.get("event_hmac_env", "AUTH_MONITOR_EVENT_HMAC")).strip() or "AUTH_MONITOR_EVENT_HMAC")
PY
  )

  mqtt_pass_env="${_secret_keys[0]:-AUTH_MONITOR_MQTT_PASSWORD}"
  hmac_env="${_secret_keys[1]:-AUTH_MONITOR_EVENT_HMAC}"

  local missing=()
  local mqtt_val="${!mqtt_pass_env:-}"
  local hmac_val="${!hmac_env:-}"

  if [[ -z "${mqtt_val}" || "${mqtt_val}" == "change-me" ]]; then
    missing+=("${mqtt_pass_env}")
  fi
  if [[ -z "${hmac_val}" || "${hmac_val}" == "change-me" ]]; then
    missing+=("${hmac_env}")
  fi

  if [[ ${#missing[@]} -eq 0 ]]; then
    log_install "install_step component=server action=validate_secrets status=ok"
    return
  fi

  local joined
  joined="$(IFS=,; echo "${missing[*]}")"
  if [[ "${AUTH_MONITOR_ALLOW_MISSING_SECRETS}" == "1" ]]; then
    log_install "install_step component=server action=validate_secrets status=warn missing=${joined} bypass=1"
    return
  fi

  log_install "install_step component=server action=validate_secrets status=failed missing=${joined}"
  echo "error: required secrets missing. export ${joined} (or set AUTH_MONITOR_ALLOW_MISSING_SECRETS=1 to bypass)" >&2
  exit 1
}

ensure_mqtt_iptables_output_allow() {
  if ! command -v iptables >/dev/null 2>&1; then
    log_install "install_step component=server action=ensure_mqtt_iptables_allow status=skipped reason=iptables_not_found"
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
    log_install "install_step component=server action=ensure_mqtt_iptables_allow status=skipped reason=mqtt_host_missing"
    return
  fi

  local prefix=()
  if [[ "${EUID}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      prefix=(sudo)
    else
      log_install "install_step component=server action=ensure_mqtt_iptables_allow status=failed reason=sudo_not_found"
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
      log_install "install_step component=server action=ensure_mqtt_iptables_allow status=exists ip=${ip} port=${mqtt_port}"
      continue
    fi

    if "${prefix[@]}" iptables -I OUTPUT 1 -p tcp -d "${ip}" --dport "${mqtt_port}" -j ACCEPT >/dev/null 2>&1; then
      log_install "install_step component=server action=ensure_mqtt_iptables_allow status=inserted ip=${ip} port=${mqtt_port}"
    else
      log_install "install_step component=server action=ensure_mqtt_iptables_allow status=failed ip=${ip} port=${mqtt_port}"
    fi
  done
}

stop_running_processes() {
  local pid
  local pids=()

  if mapfile -t pids < <(pgrep -f -- "${SCRIPT_PATH}" 2>/dev/null); then
    for pid in "${pids[@]}"; do
      kill "${pid}" 2>/dev/null || true
    done
    sleep 1
    for pid in "${pids[@]}"; do
      kill -9 "${pid}" 2>/dev/null || true
    done
  fi

  if [[ "${EUID}" -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
    sudo pkill -f -- "${SCRIPT_PATH}" 2>/dev/null || true
    sudo pkill -9 -f -- "${SCRIPT_PATH}" 2>/dev/null || true
  fi
}

log_install "install_start component=server host=$(hostname) script=${BASH_SOURCE[0]}"
ensure_required_secrets
stop_running_processes
log_install "install_step component=server action=stop_running_processes status=done"
ensure_mqtt_iptables_output_allow

mkdir -p "$(dirname "${LOG_PATH}")"
touch "${LOG_PATH}"

TMP_ROOT_CRON="$(mktemp)"
TMP_USER_CRON="$(mktemp)"
trap 'rm -f "${TMP_USER_CRON}" "${TMP_ROOT_CRON}"' EXIT

# User crontab: remove monitor jobs, they now run as root.
(crontab -l 2>/dev/null || true) | grep -F -v "${CRON_CMD}" | grep -F -v "${SCRIPT_PATH}" > "${TMP_USER_CRON}" || true
crontab "${TMP_USER_CRON}"
log_install "install_step component=server action=update_user_crontab status=done"

# Root crontab: install listener with required privileges (iptables + /var/run lock).
if [[ "${EUID}" -eq 0 ]]; then
  (crontab -l -u root 2>/dev/null || true) \
    | grep -F -v "${CRON_CMD}" \
    | grep -F -v "${SCRIPT_PATH}" > "${TMP_ROOT_CRON}" || true
  echo "${CRON_LINE}" >> "${TMP_ROOT_CRON}"
  crontab -u root "${TMP_ROOT_CRON}"
else
  if ! command -v sudo >/dev/null 2>&1; then
    echo "error: sudo is required to install root cron entry for listen-to-mosquitto.py" >&2
    exit 1
  fi
  (sudo crontab -l -u root 2>/dev/null || true) \
    | grep -F -v "${CRON_CMD}" \
    | grep -F -v "${SCRIPT_PATH}" > "${TMP_ROOT_CRON}" || true
  echo "${CRON_LINE}" >> "${TMP_ROOT_CRON}"
  sudo crontab -u root "${TMP_ROOT_CRON}"
fi

log_install "removed_from_user_crontab cmd=${CRON_CMD}"
log_install "installed_for_root cron=${CRON_LINE}"
log_install "install_done component=server host=$(hostname) status=ok"
