#!/usr/bin/env bash
set -euo pipefail

# authmon v5 installer (Debian/Ubuntu). Installs to /opt/authmon/v5 and wires
# systemd units. Replaces v4's cron + pgrep/kill + lockfile approach.
#
# Usage:
#   sudo ./install.sh agent      # detector + agent (every node)
#   sudo ./install.sh api        # border API (broker node only)
#   sudo ./install.sh all

ROLE="${1:-agent}"
SRC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-/opt/authmon/v5}"
ENV_FILE="/etc/authmon/env"
CONFIG_FILE="/etc/authmon/config.json"

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run as root (sudo)" >&2
  exit 1
fi

if [[ ! -f /etc/debian_version ]]; then
  echo "error: this installer supports Debian/Ubuntu only" >&2
  exit 1
fi

echo "== dependencies"
need_pkgs=()
command -v python3 >/dev/null || need_pkgs+=(python3)
command -v ipset   >/dev/null || need_pkgs+=(ipset)
python3 -c "import paho.mqtt.client" 2>/dev/null || need_pkgs+=(python3-paho-mqtt)
if [[ ${#need_pkgs[@]} -gt 0 ]]; then
  apt-get update -y
  apt-get install -y "${need_pkgs[@]}"
fi

# --- v4 teardown ------------------------------------------------------------
# v5 replaces the v4 cron + pgrep/kill + lockfile approach. Older boxes still
# carry the v4 listener / border-api in root+user crontab and as live processes,
# which crash-loop once the old broker is gone. Remove them best-effort so v5
# and v4 never coexist. Never fails the install.
remove_v4_legacy() {
  echo "== v4 teardown (best-effort)"
  local v4_scripts=(
    "listen-to-mosquitto.py"
    "security-v4/api.py"
    "7-iptables-agent.py"
  )
  local v4_locks=(
    "/var/run/auth-monitor-border-api.lock"
    "/var/run/auth-monitor-mqtt-listener.lock"
    "/var/run/auth-monitor-iptables-agent.lock"
  )

  # Strip matching lines from root + invoking-user crontabs.
  local who
  for who in root "${SUDO_USER:-}"; do
    [[ -z "${who}" ]] && continue
    local current tmp pat
    current="$(crontab -l -u "${who}" 2>/dev/null || true)"
    [[ -z "${current}" ]] && continue
    tmp="${current}"
    for pat in "${v4_scripts[@]}" "/var/log/nw-monitor.log"; do
      tmp="$(printf '%s\n' "${tmp}" | grep -F -v "${pat}" || true)"
    done
    if [[ "${tmp}" != "${current}" ]]; then
      printf '%s\n' "${tmp}" | crontab -u "${who}" - || true
      echo "  cleaned v4 cron entries for user=${who}"
    fi
  done

  # Kill any live v4 processes.
  local script
  for script in "${v4_scripts[@]}"; do
    if pkill -f "${script}" 2>/dev/null; then
      echo "  killed running v4 process: ${script}"
    fi
  done

  # Drop stale lockfiles.
  local lock
  for lock in "${v4_locks[@]}"; do
    if [[ -e "${lock}" ]]; then
      rm -f "${lock}" && echo "  removed lockfile: ${lock}"
    fi
  done
}
remove_v4_legacy || true

echo "== files"
mkdir -p "${INSTALL_DIR}" /etc/authmon /var/lib/authmon /var/log/authmon
cp -r "${SRC_DIR}/authmon" "${SRC_DIR}/agent" "${SRC_DIR}/detector" "${SRC_DIR}/api" "${INSTALL_DIR}/"
chmod 750 /var/lib/authmon /var/log/authmon

if [[ ! -f "${CONFIG_FILE}" ]]; then
  cp "${SRC_DIR}/config/config.example.json" "${CONFIG_FILE}"
  echo "created ${CONFIG_FILE} — EDIT IT (mqtt.host at minimum) before starting"
fi
chmod 640 "${CONFIG_FILE}"

if [[ ! -f "${ENV_FILE}" ]]; then
  cp "${SRC_DIR}/.env.example" "${ENV_FILE}"
fi
chmod 600 "${ENV_FILE}"
chown root:root "${ENV_FILE}"

echo "== secret validation"
set -a; . "${ENV_FILE}"; set +a
for var in AUTHMON_MQTT_PASSWORD AUTHMON_EVENT_HMAC; do
  value="${!var:-}"
  if [[ -z "${value}" || "${value}" == "change-me" ]]; then
    echo "error: ${var} not set in ${ENV_FILE}. Set real secrets and re-run." >&2
    exit 1
  fi
done
if [[ "${ROLE}" == "api" || "${ROLE}" == "all" ]]; then
  if [[ -z "${AUTHMON_API_KEY:-}" || "${AUTHMON_API_KEY:-}" == "change-me" ]]; then
    echo "error: AUTHMON_API_KEY not set in ${ENV_FILE} (required for api role)" >&2
    exit 1
  fi
fi

echo "== config validation"
AUTHMON_CONFIG="${CONFIG_FILE}" python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/authmon/v5")
from authmon.config import load_config, ConfigError
try:
    cfg = load_config()
except ConfigError as exc:
    print(f"error: {exc}", file=sys.stderr)
    sys.exit(1)
print(f"config ok: node_id={cfg['node_id']} broker={cfg['mqtt']['host']}:{cfg['mqtt']['port']} tls={cfg['mqtt']['tls']}")
PY

echo "== systemd"
if [[ "${ROLE}" == "agent" || "${ROLE}" == "all" ]]; then
  cp "${SRC_DIR}/systemd/authmon-agent.service" /etc/systemd/system/
  cp "${SRC_DIR}/systemd/authmon-detector.service" /etc/systemd/system/
  cp "${SRC_DIR}/systemd/authmon-detector.timer" /etc/systemd/system/
fi
if [[ "${ROLE}" == "api" || "${ROLE}" == "all" ]]; then
  cp "${SRC_DIR}/systemd/authmon-api.service" /etc/systemd/system/
  if [[ ! -d /opt/authmon-venv ]]; then
    apt-get install -y python3-venv
    python3 -m venv /opt/authmon-venv
    /opt/authmon-venv/bin/pip install --quiet fastapi 'uvicorn[standard]' paho-mqtt
  fi
fi
systemctl daemon-reload

if [[ "${ROLE}" == "agent" || "${ROLE}" == "all" ]]; then
  systemctl enable --now authmon-agent.service authmon-detector.timer
  echo "agent + detector enabled"
fi
if [[ "${ROLE}" == "api" || "${ROLE}" == "all" ]]; then
  systemctl enable --now authmon-api.service
  echo "border api enabled (127.0.0.1:${AUTHMON_API_PORT:-8741})"
fi

echo "== done. logs: /var/log/authmon/  status: systemctl status authmon-agent"
