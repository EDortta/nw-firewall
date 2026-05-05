#!/usr/bin/env bash
set -euo pipefail

# Installs a cron entry to keep the MQTT listener running every minute.
# Defaults are resolved from the directory where this install script lives.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$(cd -- "${SCRIPT_DIR}/.." && pwd)}"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
VENV_PATH="${VENV_PATH:-/opt/auth-monitor-venv}"
API_PYTHON_BIN="${VENV_PATH}/bin/python3"
SCRIPT_PATH="${SCRIPT_PATH:-${BASE_DIR}/server/listen-to-mosquitto.py}"
API_SCRIPT_PATH="${API_SCRIPT_PATH:-${BASE_DIR}/security-v4/api.py}"
LOG_PATH="${LOG_PATH:-/var/log/nw-monitor.log}"
CRON_SCHEDULE="${CRON_SCHEDULE:-* * * * *}"
CONFIG_PATH="${AUTH_MONITOR_CONFIG:-${BASE_DIR}/config/config.json}"
AUTH_MONITOR_ALLOW_MISSING_SECRETS="${AUTH_MONITOR_ALLOW_MISSING_SECRETS:-0}"
AUTH_MONITOR_ENV_FILE="${AUTH_MONITOR_ENV_FILE:-}"

CRON_ENV_PREFIX=""
if [[ -n "${AUTH_MONITOR_ENV_FILE}" ]]; then
  _env_file_escaped="${AUTH_MONITOR_ENV_FILE}"
  CRON_ENV_PREFIX="set -a; [ -f '${_env_file_escaped}' ] && . '${_env_file_escaped}'; set +a; "
fi

CRON_CMD="${CRON_ENV_PREFIX}${PYTHON_BIN} ${SCRIPT_PATH} >>${LOG_PATH} 2>&1"
CRON_LINE="${CRON_SCHEDULE} ${CRON_CMD}"
API_CRON_CMD="${CRON_ENV_PREFIX}${API_PYTHON_BIN} ${API_SCRIPT_PATH} >>${LOG_PATH} 2>&1"
API_CRON_LINE="${CRON_SCHEDULE} ${API_CRON_CMD}"

log_install() {
  local msg="$1"
  echo "${msg}"
  {
    mkdir -p "$(dirname "${LOG_PATH}")"
    echo "${msg}" >> "${LOG_PATH}"
  } 2>/dev/null || true
}


has_json_items() {
  local payload="${1:-}"
  python3 - "${payload}" <<'PY' 2>/dev/null
import json
import sys

raw = (sys.argv[1] or "").strip()
if not raw:
    print("0")
    raise SystemExit(0)

try:
    data = json.loads(raw)
except Exception:
    print("0")
    raise SystemExit(0)

if isinstance(data, list) and any(str(item).strip() for item in data):
    print("1")
else:
    print("0")
PY
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
  local mqtt_json="${AUTH_MONITOR_MQTT_PASSWORDS_JSON:-}"
  local hmac_json="${AUTH_MONITOR_EVENT_HMACS_JSON:-}"

  local mqtt_json_ok="$(has_json_items "${mqtt_json}")"
  local hmac_json_ok="$(has_json_items "${hmac_json}")"

  if [[ -z "${mqtt_val}" || "${mqtt_val}" == "change-me" ]]; then
    if [[ "${mqtt_json_ok}" != "1" ]]; then
      missing+=("${mqtt_pass_env}")
    fi
  fi
  if [[ -z "${hmac_val}" || "${hmac_val}" == "change-me" ]]; then
    if [[ "${hmac_json_ok}" != "1" ]]; then
      missing+=("${hmac_env}")
    fi
  fi

  if [[ -z "${SECURITY_API_KEY:-}" || "${SECURITY_API_KEY:-}" == "change-me" ]]; then
    missing+=("SECURITY_API_KEY")
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

ensure_border_api_dependencies() {
  local venv_prefix=()
  if [[ "${EUID}" -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
    venv_prefix=(sudo)
  fi

  # ensurepip is bundled with python3-venv; if it's missing the venv creation
  # will produce a half-broken venv (python3 but no pip).
  if ! "${PYTHON_BIN}" -c "import ensurepip" >/dev/null 2>&1; then
    local py_ver
    py_ver="$("${PYTHON_BIN}" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    "${venv_prefix[@]}" apt-get install -y "python${py_ver}-venv" 2>/dev/null \
      || "${venv_prefix[@]}" apt-get install -y python3-venv
  fi

  # Remove a broken venv (python3 present but pip missing — happens when the
  # venv was created before python3-venv was installed).
  if [[ -d "${VENV_PATH}" ]] && [[ ! -x "${VENV_PATH}/bin/pip" ]]; then
    "${venv_prefix[@]}" rm -rf "${VENV_PATH}"
  fi

  # Create a venv with --system-site-packages so paho-mqtt (apt) is inherited
  # and only fastapi + uvicorn need to be pip-installed on top.
  if [[ ! -x "${VENV_PATH}/bin/python3" ]]; then
    log_install "install_step component=server action=create_venv path=${VENV_PATH} status=starting"
    "${venv_prefix[@]}" "${PYTHON_BIN}" -m venv "${VENV_PATH}" --system-site-packages
    log_install "install_step component=server action=create_venv path=${VENV_PATH} status=done"
  fi

  if ! "${VENV_PATH}/bin/python3" -c "import fastapi" >/dev/null 2>&1; then
    log_install "install_step component=server action=pip_install package=fastapi status=starting"
    "${venv_prefix[@]}" "${VENV_PATH}/bin/pip" install fastapi "uvicorn[standard]" --quiet
    log_install "install_step component=server action=pip_install package=fastapi status=done"
  fi
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

  if mapfile -t pids < <(pgrep -f -- "${API_SCRIPT_PATH}" 2>/dev/null); then
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
    sudo pkill -f -- "${API_SCRIPT_PATH}" 2>/dev/null || true
    sudo pkill -9 -f -- "${API_SCRIPT_PATH}" 2>/dev/null || true
  fi
}

log_install "install_start component=server host=$(hostname) script=${BASH_SOURCE[0]}"
ensure_required_secrets
ensure_border_api_dependencies
stop_running_processes
log_install "install_step component=server action=stop_running_processes status=done"
ensure_mqtt_iptables_output_allow

mkdir -p "$(dirname "${LOG_PATH}")"
touch "${LOG_PATH}"

TMP_ROOT_CRON="$(mktemp)"
TMP_USER_CRON="$(mktemp)"
trap 'rm -f "${TMP_USER_CRON}" "${TMP_ROOT_CRON}"' EXIT

# User crontab: remove monitor jobs, they now run as root.
(crontab -l 2>/dev/null || true) \
  | grep -F -v "${CRON_CMD}" \
  | grep -F -v "${API_CRON_CMD}" \
  | grep -F -v "${SCRIPT_PATH}" \
  | grep -F -v "${API_SCRIPT_PATH}" > "${TMP_USER_CRON}" || true
crontab "${TMP_USER_CRON}"
log_install "install_step component=server action=update_user_crontab status=done"

# Root crontab: install listener and border API with required privileges.
if [[ "${EUID}" -eq 0 ]]; then
  (crontab -l -u root 2>/dev/null || true) \
    | grep -F -v "${CRON_CMD}" \
    | grep -F -v "${API_CRON_CMD}" \
    | grep -F -v "${SCRIPT_PATH}" \
    | grep -F -v "${API_SCRIPT_PATH}" > "${TMP_ROOT_CRON}" || true
  echo "${CRON_LINE}" >> "${TMP_ROOT_CRON}"
  echo "${API_CRON_LINE}" >> "${TMP_ROOT_CRON}"
  crontab -u root "${TMP_ROOT_CRON}"
else
  if ! command -v sudo >/dev/null 2>&1; then
    echo "error: sudo is required to install root cron entry for listen-to-mosquitto.py" >&2
    exit 1
  fi
  (sudo crontab -l -u root 2>/dev/null || true) \
    | grep -F -v "${CRON_CMD}" \
    | grep -F -v "${API_CRON_CMD}" \
    | grep -F -v "${SCRIPT_PATH}" \
    | grep -F -v "${API_SCRIPT_PATH}" > "${TMP_ROOT_CRON}" || true
  echo "${CRON_LINE}" >> "${TMP_ROOT_CRON}"
  echo "${API_CRON_LINE}" >> "${TMP_ROOT_CRON}"
  sudo crontab -u root "${TMP_ROOT_CRON}"
fi

log_install "removed_from_user_crontab cmd=${CRON_CMD}"
log_install "installed_for_root cron=${CRON_LINE}"
log_install "installed_for_root cron=${API_CRON_LINE}"
log_install "install_done component=server host=$(hostname) status=ok"
