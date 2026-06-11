#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SERVICE_NAME="auth-monitor-notify"
SERVICE_DEST="${HOME}/.config/systemd/user/${SERVICE_NAME}.service"

PYTHON_BIN="${PYTHON_BIN:-${BASE_DIR}/.venv/bin/python3}"
if [[ ! -x "${PYTHON_BIN}" ]]; then
    PYTHON_BIN="$(command -v python3)"
fi

ENV_FILE="${AUTH_MONITOR_ENV_FILE:-${BASE_DIR}/.env}"

mkdir -p "${HOME}/.config/systemd/user"

sed \
    -e "s|__PYTHON__|${PYTHON_BIN}|g" \
    -e "s|__BASE_DIR__|${BASE_DIR}|g" \
    -e "s|__ENV_FILE__|${ENV_FILE}|g" \
    "${SCRIPT_DIR}/auth-monitor-notify.service" \
    > "${SERVICE_DEST}"

echo "installed ${SERVICE_DEST}"

systemctl --user daemon-reload
systemctl --user enable "${SERVICE_NAME}.service"
systemctl --user restart "${SERVICE_NAME}.service"

echo "service status:"
systemctl --user status "${SERVICE_NAME}.service" --no-pager || true
