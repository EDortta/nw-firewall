#!/usr/bin/env python3
"""Configuration loading and validation.

Hard rule of v5: secrets NEVER live in the config file. The loader refuses to
start if a "password", "secret" or "hmac" value is found inline in config.json
(this is what allowed the v4 credential leak into git history).
"""
from __future__ import annotations

import json
import os
import socket
from pathlib import Path


class ConfigError(ValueError):
    pass


DEFAULT_CONFIG_PATH = os.getenv("AUTHMON_CONFIG", "/etc/authmon/config.json")

_FORBIDDEN_INLINE_KEYS = {"password", "secret", "hmac_secret", "api_key", "token"}

DEFAULTS: dict = {
    "node_id": "",
    "mqtt": {
        "host": "",
        "port": 8883,
        "tls": True,
        "tls_ca": "",            # empty = system CA bundle
        "tls_insecure": False,   # never set true outside a lab
        "username": "",
        "password_env": "AUTHMON_MQTT_PASSWORD",
        "topic": "authmon/v5/events",
        "qos": 1,
        "keepalive": 60,
    },
    "security": {
        "hmac_env": "AUTHMON_EVENT_HMAC",
        "hmac_previous_env": "AUTHMON_EVENT_HMAC_PREVIOUS",  # rotation support
        "max_event_age_seconds": 300,
    },
    "enforcement": {
        "backend": "ipset",           # ipset | iptables (fallback)
        "set_prefix": "authmon5",
        "chain": "INPUT",
        "target": "DROP",
        "default_ttl_seconds": 7 * 24 * 3600,
        "max_blocks_per_minute": 30,
        "max_sync_entries": 2000,
        "never_block": [],            # extra IPs/CIDRs beyond the automatic guard
        "allowlist": [],              # IPs/CIDRs that are never blocked and unblock on sight
    },
    "detection": {
        "nginx_access_logs": ["/var/log/nginx/access.log"],
        "auth_log": "/var/log/auth.log",
        "http_404_burst_threshold": 12,
        "http_404_window_seconds": 120,
        "bad_status_threshold": 25,
        "unique_path_threshold": 15,
        "bad_status_window_seconds": 600,
        "auth_fail_threshold": 6,
        "auth_fail_window_seconds": 300,
        "immediate_block_paths": [],
        "high_risk_paths": [],
        "ignore_path_patterns": ["/status", "/health", "/api/health/"],
        "ignore_ips": [],
    },
    "state": {
        "db_path": "/var/lib/authmon/authmon.db",
        "seen_events_retention_days": 14,
    },
    "sync": {
        "heartbeat_interval_seconds": 300,
        "state_sync_interval_seconds": 3600,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _reject_inline_secrets(node, path: str = "") -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            key_l = str(key).lower()
            if key_l in _FORBIDDEN_INLINE_KEYS and isinstance(value, str) and value.strip():
                raise ConfigError(
                    f"inline secret found at config key '{path}{key}'. "
                    "v5 refuses inline secrets: move it to the environment "
                    "(see *_env keys) and delete it from the config file."
                )
            _reject_inline_secrets(value, f"{path}{key}.")
    elif isinstance(node, list):
        for item in node:
            _reject_inline_secrets(item, path)


def load_config(path: str | Path | None = None) -> dict:
    cfg_path = Path(path or DEFAULT_CONFIG_PATH)
    try:
        raw = json.loads(cfg_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {cfg_path}")
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config file is not valid JSON: {cfg_path}: {exc}")

    if not isinstance(raw, dict):
        raise ConfigError("config root must be a JSON object")

    _reject_inline_secrets(raw)
    cfg = _deep_merge(DEFAULTS, raw)

    if not str(cfg["mqtt"]["host"]).strip():
        raise ConfigError("mqtt.host is required")
    if not str(cfg["mqtt"]["topic"]).strip():
        raise ConfigError("mqtt.topic is required")

    if not str(cfg.get("node_id", "")).strip():
        cfg["node_id"] = socket.gethostname()

    return cfg


def load_secret(env_name: str, *, required: bool = True) -> str:
    value = os.getenv(env_name, "").strip()
    if required and not value:
        raise ConfigError(f"required secret missing from environment: {env_name}")
    if value and value.lower() in {"change-me", "changeme", "todo"}:
        raise ConfigError(f"placeholder value in {env_name}; set a real secret")
    return value


def load_hmac_secrets(cfg: dict) -> list[str]:
    """Current secret first, previous secret second (key rotation)."""
    sec = cfg["security"]
    secrets = [load_secret(str(sec["hmac_env"]))]
    previous = load_secret(str(sec["hmac_previous_env"]), required=False)
    if previous and previous not in secrets:
        secrets.append(previous)
    return secrets
