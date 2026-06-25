#!/usr/bin/env bash
# authmon v5 deploy script for the ZeeCred fleet.
#
# Reads servers.json from jk-structure, rsyncs source to each firewall node,
# and runs install.sh with the correct role (agent or all).
#
# Also deploys fw-monitor/index.html to fw-monitor.inovacaosistemas.com.br.
#
# Usage:
#   ./deploy-zeecred.sh [options]
#
# Options:
#   --servers <path>       Path to servers.json  (default: ZeeCred2/jk-structure/servers.json)
#   --remote-path <path>   Remote staging dir     (default: /home/devops/authmon-v5/)
#   --services <a,b,...>   Filter to listed services (e.g. management,api)
#   --skip-fw-monitor      Skip fw-monitor deploy
#   --best-effort          Skip unreachable hosts and continue
#   --verbose              Detailed logs
#   --help

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

SERVERS_JSON="${SERVERS_JSON:-/home/esteban/Sync/Projects/YouBR/ZeeCred2/jk-structure/servers.json}"
REMOTE_PATH="${REMOTE_PATH:-/home/devops/authmon-v5/}"
MANAGEMENT_SERVICES="${MANAGEMENT_SERVICES:-management}"
FW_MONITOR_HOST="${FW_MONITOR_HOST:-fw-monitor.inovacaosistemas.com.br}"
FW_MONITOR_USER="${FW_MONITOR_USER:-esteban}"
FW_MONITOR_DEST="${FW_MONITOR_DEST:-/var/www/fw-monitor/index.html}"

BEST_EFFORT=false
SKIP_FW_MONITOR=false
SERVICES_FILTER=""
VERBOSE=false

usage() {
  grep '^#' "$0" | sed 's/^# \?//' | tail -n +2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --servers)    SERVERS_JSON="$2"; shift ;;
    --remote-path) REMOTE_PATH="$2"; shift ;;
    --services)   SERVICES_FILTER="$2"; shift ;;
    --skip-fw-monitor) SKIP_FW_MONITOR=true ;;
    --best-effort) BEST_EFFORT=true ;;
    --verbose)    VERBOSE=true ;;
    --help|-h)    usage; exit 0 ;;
    *) echo "error: unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

vlog() { [[ "$VERBOSE" == "true" ]] && echo "[verbose] $*" || true; }

if [[ ! -f "$SERVERS_JSON" ]]; then
  echo "error: servers.json not found at ${SERVERS_JSON}" >&2
  exit 1
fi

# ── Parse server entries from servers.json ────────────────────────────────────
mapfile -t SERVER_ENTRIES < <(python3 - "${SERVERS_JSON}" <<'PY'
import json, sys
from pathlib import Path

cfg = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))

def resolve(service, env, seen=None):
    seen = seen or set()
    key = f"{service}/{env}"
    if key in seen: raise ValueError(f"cyclic ref: {key}")
    seen.add(key)
    block = cfg.get(service, {})
    if env not in block: raise ValueError(f"unknown: {key}")
    merged = dict(block.get("_vars_", {}))
    merged.update(block[env])
    user = str(merged.get("user", "devops"))
    ip   = str(merged.get("ip", ""))
    if not ip: raise ValueError(f"no ip for {key}")
    jumps = []
    through = str(merged.get("through", "")).strip()
    if through:
        t = through.lstrip("/")
        if "/" not in t: raise ValueError(f"bad through: {through}")
        ts, te = t.split("/", 1)
        hop = resolve(ts, te, seen)
        jumps.extend(hop["jumps"])
        jumps.append(f"{hop['user']}@{hop['ip']}")
    return {"user": user, "ip": ip, "jumps": jumps, "merged": merged}

for svc, block in cfg.items():
    if not isinstance(block, dict) or svc.startswith("_"): continue
    for alias, entry in block.items():
        if alias.startswith("_") or not isinstance(entry, dict): continue
        try:
            r = resolve(svc, alias)
        except ValueError as e:
            print(f"warn: skip {svc}/{alias}: {e}", file=__import__("sys").stderr)
            continue
        m = r["merged"]
        void_fw = str(m.get("void_firewall", "")).lower()
        sync    = str(m.get("sync", "")).lower()
        if void_fw in ("1","true","yes"): continue
        if sync in ("0","false","no"):    continue
        jumps_str = ",".join(r["jumps"])
        print(f"{svc}|{alias}|{r['ip']}|{r['user']}|{jumps_str}")
PY
)

if [[ "${#SERVER_ENTRIES[@]}" -eq 0 ]]; then
  echo "error: no server entries found in ${SERVERS_JSON}" >&2
  exit 1
fi

is_management() {
  local svc="$1" token
  IFS=',' read -ra tokens <<<"${MANAGEMENT_SERVICES}"
  for token in "${tokens[@]}"; do
    [[ "$(echo "$token" | xargs)" == "$svc" ]] && return 0
  done
  return 1
}

is_selected() {
  local svc="$1"
  [[ -z "$SERVICES_FILTER" ]] && return 0
  local token
  IFS=',' read -ra tokens <<<"$SERVICES_FILTER"
  for token in "${tokens[@]}"; do
    [[ "$(echo "$token" | xargs)" == "$svc" ]] && return 0
  done
  return 1
}

RSYNC_ARGS=(
  -rva
  --exclude "__pycache__/"
  --exclude ".venv/"
  --exclude ".git/"
  --exclude ".gitignore"
  --exclude "config/config.json"
  --exclude ".credentials/"
  --exclude ".hypothesis/"
  --exclude "*.pyc"
  --exclude ".env"
  --exclude ".env.*"
  --exclude "v4/"
  --exclude "desktop/"
  --exclude "docs/"
  --exclude "tests/"
  --exclude "fw-monitor/"
  --exclude "deploy-zeecred.sh"
  --exclude "*.bak"
)

FAILED=()
SUCCESS_COUNT=0
SKIPPED_COUNT=0

# ── Per-node loop ─────────────────────────────────────────────────────────────
for entry in "${SERVER_ENTRIES[@]}"; do
  IFS='|' read -r svc alias ip user jumps <<<"$entry"
  label="${svc}/${alias} (${ip})"

  if ! is_selected "$svc"; then
    echo "skip: ${label} reason=service_filtered"
    SKIPPED_COUNT=$((SKIPPED_COUNT+1)); continue
  fi

  ssh_opts=()
  rsync_ssh="ssh"
  if [[ -n "$jumps" ]]; then
    ssh_opts=(-J "$jumps")
    rsync_ssh="ssh -J ${jumps}"
  fi

  if [[ "$BEST_EFFORT" == "true" ]]; then
    if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "${ssh_opts[@]}" "${user}@${ip}" true 2>/dev/null; then
      echo "skip: ${label} reason=unreachable"
      SKIPPED_COUNT=$((SKIPPED_COUNT+1)); continue
    fi
  fi

  # Role: management nodes run all (api + agent + geo-enricher); others run agent
  if is_management "$svc"; then
    role="all"
  else
    role="agent"
  fi

  echo "━━━ ${label} role=${role}"

  # rsync source
  if ! rsync "${RSYNC_ARGS[@]}" -e "${rsync_ssh}" \
      "${SCRIPT_DIR}/" "${user}@${ip}:${REMOTE_PATH}"; then
    echo "error: rsync failed for ${label}" >&2
    FAILED+=("${label}|rsync"); continue
  fi

  # install
  remote_cmd="cd $(printf '%q' "${REMOTE_PATH%/}") && sudo ./install.sh ${role}"
  if ! ssh "${ssh_opts[@]}" "${user}@${ip}" "bash -lc $(printf '%q' "$remote_cmd")"; then
    echo "error: install.sh failed for ${label}" >&2
    FAILED+=("${label}|install"); continue
  fi

  echo "ok: ${label}"
  SUCCESS_COUNT=$((SUCCESS_COUNT+1))
done

# ── fw-monitor deploy ─────────────────────────────────────────────────────────
if [[ "$SKIP_FW_MONITOR" == "false" ]]; then
  echo "━━━ fw-monitor → ${FW_MONITOR_HOST}:${FW_MONITOR_DEST}"
  src="${SCRIPT_DIR}/fw-monitor/index.html"
  if [[ ! -f "$src" ]]; then
    echo "warn: fw-monitor/index.html not found, skipping" >&2
  else
    if cat "$src" | ssh "${FW_MONITOR_USER}@${FW_MONITOR_HOST}" \
        "sudo tee $(printf '%q' "${FW_MONITOR_DEST}") > /dev/null"; then
      echo "ok: fw-monitor deployed"
    else
      echo "error: fw-monitor deploy failed" >&2
      FAILED+=("fw-monitor|deploy")
    fi
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "done: success=${SUCCESS_COUNT} skipped=${SKIPPED_COUNT} failed=${#FAILED[@]}"
if [[ "${#FAILED[@]}" -gt 0 ]]; then
  for f in "${FAILED[@]}"; do echo "failed: ${f}"; done >&2
  exit 1
fi
