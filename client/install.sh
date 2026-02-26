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

mkdir -p "$(dirname "${LOG_PATH}")"
touch "${LOG_PATH}"

TMP_CRON="$(mktemp)"
TMP_ROOT_CRON="$(mktemp)"
trap 'rm -f "${TMP_CRON}" "${TMP_ROOT_CRON}"' EXIT

# User crontab: keep only publisher job (6-block-ips.py).
(crontab -l 2>/dev/null || true) | grep -F -v "${CRON_CMD}" | grep -F -v "${AGENT_CRON_CMD}" | grep -F -v "${AGENT_SCRIPT_PATH}" > "${TMP_CRON}" || true
echo "${CRON_LINE}" >> "${TMP_CRON}"

crontab "${TMP_CRON}"

# Root crontab: install iptables agent (7-iptables-agent.py), because it needs /var/run and iptables perms.
if [[ "${EUID}" -eq 0 ]]; then
  (crontab -l -u root 2>/dev/null || true) | grep -F -v "${AGENT_CRON_CMD}" | grep -F -v "${AGENT_SCRIPT_PATH}" > "${TMP_ROOT_CRON}" || true
  echo "${AGENT_CRON_LINE}" >> "${TMP_ROOT_CRON}"
  crontab -u root "${TMP_ROOT_CRON}"
else
  if ! command -v sudo >/dev/null 2>&1; then
    echo "error: sudo is required to install root cron entry for 7-iptables-agent.py" >&2
    exit 1
  fi
  (sudo crontab -l -u root 2>/dev/null || true) | grep -F -v "${AGENT_CRON_CMD}" | grep -F -v "${AGENT_SCRIPT_PATH}" > "${TMP_ROOT_CRON}" || true
  echo "${AGENT_CRON_LINE}" >> "${TMP_ROOT_CRON}"
  sudo crontab -u root "${TMP_ROOT_CRON}"
fi

echo "installed: ${CRON_LINE}"
echo "installed for root: ${AGENT_CRON_LINE}"
