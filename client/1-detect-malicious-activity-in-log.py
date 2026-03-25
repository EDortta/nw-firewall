#!/usr/bin/env python3

import ipaddress
import os
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
from urllib.parse import unquote

LOG_FILE_PATH = os.getenv("NGINX_ACCESS_LOG", "/var/log/nginx/access.log")
TAIL_LINES = int(os.getenv("LOG_TAIL_LINES", "5500"))

# Core rule requested for v4: burst of HTTP 404s from same IP in time window.
HTTP_404_BURST_THRESHOLD = int(os.getenv("HTTP_404_BURST_THRESHOLD", "12"))
HTTP_404_WINDOW_SECONDS = int(os.getenv("HTTP_404_WINDOW_SECONDS", "120"))

# Secondary scanning behavior signals.
BURST_BAD_STATUS_THRESHOLD = int(os.getenv("BURST_BAD_STATUS_THRESHOLD", "25"))
BURST_UNIQUE_PATH_THRESHOLD = int(os.getenv("BURST_UNIQUE_PATH_THRESHOLD", "15"))

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d{3})\s+\S+\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

TRAVERSAL_PATTERN = re.compile(r'(?:^|/)\.\.(?:/|\\\\|$)')
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
BENIGN_NOISY_PATH_PREFIXES = (
    "/monitor-service/socket.io/",
)


def is_benign_noisy_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in BENIGN_NOISY_PATH_PREFIXES)


def looks_like_path_traversal(raw_target: str, decoded_target: str) -> bool:
    if TRAVERSAL_PATTERN.search(decoded_target):
        return True
    raw_lower = raw_target.lower()
    return "%2e%2e" in raw_lower or "..%2f" in raw_lower or "%2f.." in raw_lower


def is_sensitive_probe(decoded_target: str) -> bool:
    return any(hint in decoded_target for hint in SENSITIVE_TARGET_HINTS)


def is_scanner_user_agent(ua: str) -> bool:
    ua_lower = ua.lower()
    return any(hint in ua_lower for hint in SCANNER_UA_HINTS)


def parse_nginx_ts(raw: str) -> datetime | None:
    # Example: 12/Mar/2026:10:11:12 +0000
    try:
        return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def main() -> None:
    malicious_ips = set()
    bad_status_count = defaultdict(int)
    unique_paths = defaultdict(set)
    bad_404_by_ip: dict[str, deque[datetime]] = defaultdict(deque)

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
        ts = parse_nginx_ts(match.group("ts"))
        raw_target = match.group("target")
        status = int(match.group("status"))
        ua = match.group("ua")

        decoded_target = unquote(raw_target).lower()
        benign_noisy_path = is_benign_noisy_path(decoded_target)

        if status >= 400 and not benign_noisy_path:
            bad_status_count[ip] += 1
            unique_paths[ip].add(decoded_target)

        # Explicit v4 rule: 404 burst in short window marks risk.
        if status == 404 and ts is not None and not benign_noisy_path:
            q = bad_404_by_ip[ip]
            q.append(ts)
            cutoff = ts - timedelta(seconds=HTTP_404_WINDOW_SECONDS)
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= HTTP_404_BURST_THRESHOLD:
                malicious_ips.add(ip)

        traversal = looks_like_path_traversal(raw_target, decoded_target)
        sensitive_probe = is_sensitive_probe(decoded_target)
        scanner_ua = is_scanner_user_agent(ua)

        if traversal or sensitive_probe:
            malicious_ips.add(ip)
            continue

        if scanner_ua and status >= 400 and not benign_noisy_path:
            malicious_ips.add(ip)
            continue

    for ip, count in bad_status_count.items():
        if count >= BURST_BAD_STATUS_THRESHOLD and len(unique_paths[ip]) >= BURST_UNIQUE_PATH_THRESHOLD:
            malicious_ips.add(ip)

    sorted_ips = sorted(
        malicious_ips,
        key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))),
    )
    for ip in sorted_ips:
        print(ip)


if __name__ == "__main__":
    main()
