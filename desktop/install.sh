#!/usr/bin/env bash
# authmon v5 desktop install — notify-send notifier + terminal monitor
# Run as regular user (no sudo needed).
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/.local/share/authmon"
SERVICE_DIR="${HOME}/.config/systemd/user"
ENV_FILE="${HOME}/.config/authmon/env"

echo "== copying scripts"
mkdir -p "${INSTALL_DIR}"
cp "${SCRIPT_DIR}/notify-blocked-ips.py"       "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/monitor-firewall-activity.py" "${INSTALL_DIR}/"
chmod +x "${INSTALL_DIR}"/*.py

echo "== env file"
mkdir -p "$(dirname "${ENV_FILE}")"
if [[ ! -f "${ENV_FILE}" ]]; then
  cat > "${ENV_FILE}" << 'EOF'
# authmon v5 desktop secrets
# Copy values from /etc/authmon/env on the target server, or ask the admin.
AUTHMON_MQTT_PASSWORD=change-me
AUTHMON_EVENT_HMAC=change-me
# Optional: override config path (default: /etc/authmon/config.json)
# AUTHMON_CONFIG=/etc/authmon/config.json
EOF
  chmod 600 "${ENV_FILE}"
  echo "created ${ENV_FILE} — EDIT IT before starting (set real secrets)"
else
  echo "${ENV_FILE} already exists — skipping"
fi

echo "== systemd user service"
mkdir -p "${SERVICE_DIR}"
cp "${SCRIPT_DIR}/authmon-notify.service" "${SERVICE_DIR}/"
systemctl --user daemon-reload
systemctl --user enable --now authmon-notify.service
echo "service enabled"

echo ""
echo "Done. Check status: systemctl --user status authmon-notify"
echo "Monitor terminal: python3 ${INSTALL_DIR}/monitor-firewall-activity.py"
