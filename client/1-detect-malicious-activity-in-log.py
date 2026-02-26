#!/usr/bin/env python3

import os
import re
from collections import defaultdict
from urllib.parse import unquote

LOG_FILE_PATH = os.getenv("NGINX_ACCESS_LOG", "/var/log/nginx/access.log")
TAIL_LINES = int(os.getenv("LOG_TAIL_LINES", "5500"))

# Mark high-volume noisy clients as abusive only when behavior looks like scanning.
BURST_BAD_STATUS_THRESHOLD = int(os.getenv("BURST_BAD_STATUS_THRESHOLD", "25"))
BURST_UNIQUE_PATH_THRESHOLD = int(os.getenv("BURST_UNIQUE_PATH_THRESHOLD", "15"))

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d{3})\s+\S+\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

TRAVERSAL_PATTERN = re.compile(r'(?:^|/)\.\.(?:/|\\\\|$)')

# Common sensitive files/locations probed by scanners.
SENSITIVE_TARGET_HINTS = (
    "/.env",
    ".aws/credentials",
    "/id_rsa",
    "/etc/passwd",
    "/proc/self/environ",
    "/.git/",
    "/wp-admin",
    "/wp-login.php",
)

SCANNER_UA_HINTS = (
    "shodan",
    "zgrab",
    "masscan",
    "nmap",
    "sqlmap",
    "nikto",
    "nessus",
    "gobuster",
    "dirbuster",
    "nuclei",
)

# Known app path with occasional expected 400 polling noise.
BENIGN_NOISY_PATH_PREFIXES = (
    "/monitor-service/socket.io/",
)


def is_benign_noisy_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in BENIGN_NOISY_PATH_PREFIXES)


def looks_like_path_traversal(raw_target: str, decoded_target: str) -> bool:
    if TRAVERSAL_PATTERN.search(decoded_target):
        return True

    # Catch heavily encoded traversal attempts like %2e%2e%2f and mixed variants.
    raw_lower = raw_target.lower()
    if "%2e%2e" in raw_lower or "..%2f" in raw_lower or "%2f.." in raw_lower:
        return True

    return False


def is_sensitive_probe(decoded_target: str) -> bool:
    return any(hint in decoded_target for hint in SENSITIVE_TARGET_HINTS)


def is_scanner_user_agent(ua: str) -> bool:
    ua_lower = ua.lower()
    return any(hint in ua_lower for hint in SCANNER_UA_HINTS)


def main() -> None:
    malicious_ips = set()
    bad_status_count = defaultdict(int)
    unique_paths = defaultdict(set)

    try:
        with open(LOG_FILE_PATH, "rb") as file:
            lines = file.readlines()[-TAIL_LINES:]
    except (FileNotFoundError, PermissionError):
        return

    for raw_line in lines:
        line = raw_line.decode("utf-8", "ignore").strip()
        if not line:
            continue

        match = LOG_PATTERN.match(line)
        if not match:
            continue

        ip = match.group("ip")
        raw_target = match.group("target")
        status = int(match.group("status"))
        ua = match.group("ua")

        decoded_target = unquote(raw_target).lower()
        benign_noisy_path = is_benign_noisy_path(decoded_target)

        if status >= 400 and not benign_noisy_path:
            bad_status_count[ip] += 1
            unique_paths[ip].add(decoded_target)

        traversal = looks_like_path_traversal(raw_target, decoded_target)
        sensitive_probe = is_sensitive_probe(decoded_target)
        scanner_ua = is_scanner_user_agent(ua)

        # Strong signals: traversal/sensitive probe, or scanner UA making failed probes.
        if traversal or sensitive_probe:
            malicious_ips.add(ip)
            continue

        if scanner_ua and status >= 400 and not benign_noisy_path:
            malicious_ips.add(ip)
            continue

    # Catch high-volume scanning behavior even without explicit traversal signatures.
    for ip, count in bad_status_count.items():
        if count >= BURST_BAD_STATUS_THRESHOLD and len(unique_paths[ip]) >= BURST_UNIQUE_PATH_THRESHOLD:
            malicious_ips.add(ip)

    for ip in sorted(malicious_ips, key=lambda addr: list(map(int, addr.split(".")))):
        print(ip)


if __name__ == "__main__":
    main()
