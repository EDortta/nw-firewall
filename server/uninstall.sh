#!/usr/bin/env bash
set -euo pipefail

# Removes cron entries that run the server MQTT listener.
# Path defaults are resolved from the directory where this uninstall script lives.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$(cd -- "${SCRIPT_DIR}/.." && pwd)}"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
SCRIPT_PATH="${SCRIPT_PATH:-${BASE_DIR}/server/listen-to-mosquitto.py}"
LOG_PATH="${LOG_PATH:-/var/log/nw-monitor.log}"

CRON_CMD="${PYTHON_BIN} ${SCRIPT_PATH} >>${LOG_PATH} 2>&1"

TMP_CRON="$(mktemp)"
trap 'rm -f "${TMP_CRON}"' EXIT

CURRENT_CRON="$(mktemp)"
trap 'rm -f "${TMP_CRON}" "${CURRENT_CRON}"' EXIT

crontab -l 2>/dev/null > "${CURRENT_CRON}" || true

if [[ ! -s "${CURRENT_CRON}" ]]; then
  echo "no crontab found; nothing to uninstall"
  exit 0
fi

# Remove exact command entry and also any legacy line containing SCRIPT_PATH.
awk -v cmd="${CRON_CMD}" -v path="${SCRIPT_PATH}" '
  index($0, cmd) == 0 && index($0, path) == 0 { print }
' "${CURRENT_CRON}" > "${TMP_CRON}"

crontab "${TMP_CRON}"
echo "uninstalled cron entries for: ${SCRIPT_PATH}"
