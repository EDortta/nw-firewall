#!/usr/bin/env python3

import ipaddress
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.getenv("ALLOWED_COUNTRIES_CONFIG", str(SCRIPT_DIR / "config" / "config.json")))
GEO_DIR = Path(os.getenv("IPINFO_OUTPUT_DIR", str(SCRIPT_DIR / "db")))

NGINX_ACCESS_LOG = os.getenv("NGINX_ACCESS_LOG", "/var/log/nginx/access.log")
NGINX_TAIL_LINES = int(os.getenv("LOG_TAIL_LINES", "5500"))
AUTH_LOG_PATH = os.getenv("AUTH_LOG_PATH", "/var/log/auth.log")
AUTH_TAIL_LINES = int(os.getenv("AUTH_LOG_TAIL_LINES", "5500"))

DETECTORS = (
    os.getenv("DETECTOR1_PATH", str(SCRIPT_DIR / "1-detect-malicious-activity-in-log.py")),
    os.getenv("DETECTOR2_PATH", str(SCRIPT_DIR / "2-detect-auth-sessions.py")),
)

AUTH_PATTERNS = (
    re.compile(r"sshd\[\d+\]:\s+Invalid user\s+.+\s+from\s+(?P<host>\S+)", re.IGNORECASE),
    re.compile(r"sshd\[\d+\]:\s+Failed password for\s+.+\s+from\s+(?P<host>\S+)", re.IGNORECASE),
)


def normalize_ip(value: str) -> str | None:
    candidate = value.strip().strip("[]")
    if not candidate:
        return None

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def read_tail(path: str, tail_lines: int) -> list[str]:
    with open(path, "rb") as f:
        return [line.decode("utf-8", "ignore").strip() for line in f.readlines()[-tail_lines:]]


def load_ips_from_nginx_log(path: str, tail_lines: int) -> set[str]:
    try:
        lines = read_tail(path, tail_lines)
    except (FileNotFoundError, PermissionError, OSError):
        return set()

    ips = set()
    for line in lines:
        if not line:
            continue

        first = line.split(" ", 1)[0]
        ip = normalize_ip(first)
        if ip:
            ips.add(ip)

    return ips


def load_ips_from_auth_log(path: str, tail_lines: int) -> set[str]:
    try:
        lines = read_tail(path, tail_lines)
    except (FileNotFoundError, PermissionError, OSError):
        return set()

    ips = set()
    for line in lines:
        if "sshd" not in line:
            continue

        for pattern in AUTH_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue

            ip = normalize_ip(match.group("host"))
            if ip:
                ips.add(ip)
            break

    return ips


def run_detector(script_path: str) -> tuple[set[str], str | None]:
    try:
        proc = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return set(), f"{script_path}: failed to execute ({exc})"

    ips = set()
    for line in proc.stdout.splitlines():
        ip = normalize_ip(line)
        if ip:
            ips.add(ip)

    if proc.returncode != 0:
        stderr = proc.stderr.strip() or f"exit code {proc.returncode}"
        return ips, f"{script_path}: {stderr}"

    return ips, None


def load_allowed_countries(config_path: Path) -> set[str]:
    with open(config_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    raw_values = payload.get("allowed_countries", [])
    if not isinstance(raw_values, list):
        raise ValueError("allowed_countries must be a list")

    allowed = {str(value).strip().upper() for value in raw_values if str(value).strip()}
    if not allowed:
        raise ValueError("allowed_countries is empty")

    return allowed


def load_country_for_ip(ip: str, geo_dir: Path) -> str | None:
    json_path = geo_dir / f"{ip}.json"
    if not json_path.exists():
        return None

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    country = payload.get("country")
    if not country:
        return None

    return str(country).strip().upper() or None


def sort_ips(ips: set[str]) -> list[str]:
    return sorted(ips, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))))


def main() -> None:
    try:
        allowed_countries = load_allowed_countries(CONFIG_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        sys.exit(1)

    detected_ips: set[str] = set()
    errors: list[str] = []

    # Include direct log parsing so low-volume probes are not skipped by detector thresholds.
    detected_ips.update(load_ips_from_nginx_log(NGINX_ACCESS_LOG, NGINX_TAIL_LINES))
    detected_ips.update(load_ips_from_auth_log(AUTH_LOG_PATH, AUTH_TAIL_LINES))

    for detector in DETECTORS:
        ips, error = run_detector(detector)
        detected_ips.update(ips)
        if error:
            errors.append(error)

    not_allowed_ips = []
    not_allowed_country_counts: Counter[str] = Counter()
    missing_geo_count = 0

    for ip in sort_ips(detected_ips):
        country = load_country_for_ip(ip, GEO_DIR)
        if not country:
            missing_geo_count += 1
            continue

        if country not in allowed_countries:
            not_allowed_ips.append(ip)
            not_allowed_country_counts[country] += 1

    for ip in not_allowed_ips:
        print(ip)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)

    print(
        (
            f"# detected={len(detected_ips)} "
            f"outside_allowed={len(not_allowed_ips)} "
            f"missing_geo={missing_geo_count}"
        ),
        file=sys.stderr,
    )

    for country, count in sorted(not_allowed_country_counts.items(), key=lambda item: (-item[1], item[0])):
        print(f"#    country={country} count={count}", file=sys.stderr)


if __name__ == "__main__":
    main()
