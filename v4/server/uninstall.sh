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

TMP_USER_CRON="$(mktemp)"
TMP_ROOT_CRON="$(mktemp)"
CURRENT_USER_CRON="$(mktemp)"
CURRENT_ROOT_CRON="$(mktemp)"
trap 'rm -f "${TMP_USER_CRON}" "${TMP_ROOT_CRON}" "${CURRENT_USER_CRON}" "${CURRENT_ROOT_CRON}"' EXIT

crontab -l 2>/dev/null > "${CURRENT_USER_CRON}" || true
if [[ "${EUID}" -eq 0 ]]; then
  crontab -l -u root 2>/dev/null > "${CURRENT_ROOT_CRON}" || true
else
  sudo crontab -l -u root 2>/dev/null > "${CURRENT_ROOT_CRON}" || true
fi

# Remove exact command entry and also any legacy line containing SCRIPT_PATH.
awk -v cmd="${CRON_CMD}" -v path="${SCRIPT_PATH}" '
  index($0, cmd) == 0 && index($0, path) == 0 { print }
' "${CURRENT_USER_CRON}" > "${TMP_USER_CRON}"

awk -v cmd="${CRON_CMD}" -v path="${SCRIPT_PATH}" '
  index($0, cmd) == 0 && index($0, path) == 0 { print }
' "${CURRENT_ROOT_CRON}" > "${TMP_ROOT_CRON}"

crontab "${TMP_USER_CRON}"
if [[ "${EUID}" -eq 0 ]]; then
  crontab -u root "${TMP_ROOT_CRON}"
else
  sudo crontab -u root "${TMP_ROOT_CRON}"
fi

echo "uninstalled cron entries for: ${SCRIPT_PATH} (user + root)"
