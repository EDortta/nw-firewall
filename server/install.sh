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

CRON_CMD="${PYTHON_BIN} ${SCRIPT_PATH} >>${LOG_PATH} 2>&1"
CRON_LINE="${CRON_SCHEDULE} ${CRON_CMD}"

mkdir -p "$(dirname "${LOG_PATH}")"
touch "${LOG_PATH}"

TMP_CRON="$(mktemp)"
trap 'rm -f "${TMP_CRON}"' EXIT

# Preserve existing crontab entries and remove duplicates of this command.
(crontab -l 2>/dev/null || true) | grep -F -v "${CRON_CMD}" > "${TMP_CRON}"
echo "${CRON_LINE}" >> "${TMP_CRON}"

crontab "${TMP_CRON}"

echo "installed: ${CRON_LINE}"
