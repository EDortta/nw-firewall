#!/usr/bin/env python3

import ipaddress
import os
import re
from collections import defaultdict

AUTH_LOG_PATH = os.getenv("AUTH_LOG_PATH", "/var/log/auth.log")
TAIL_LINES = int(os.getenv("AUTH_LOG_TAIL_LINES", "5500"))
MIN_EVENTS_PER_IP = int(os.getenv("AUTH_MIN_EVENTS_PER_IP", "5"))

# Example events:
# sshd[123]: Invalid user admin from 203.0.113.10 port 51422
# sshd[123]: Failed password for root from 203.0.113.10 port 51422 ssh2
# sshd[123]: Failed password for invalid user test from 203.0.113.10 port 51422 ssh2
PATTERNS = (
    re.compile(r"sshd\[\d+\]:\s+Invalid user\s+.+\s+from\s+(?P<host>\S+)", re.IGNORECASE),
    re.compile(r"sshd\[\d+\]:\s+Failed password for\s+.+\s+from\s+(?P<host>\S+)", re.IGNORECASE),
)


def normalize_ip(candidate: str) -> str | None:
    value = candidate.strip().strip("[]")

    # If a port gets attached (rare), drop it safely.
    if value.count(":") == 1 and "." in value:
        host, _, maybe_port = value.partition(":")
        if maybe_port.isdigit():
            value = host

    if "%" in value:
        value = value.split("%", 1)[0]

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def read_tail(path: str, tail_lines: int) -> list[str]:
    with open(path, "rb") as f:
        return [line.decode("utf-8", "ignore").strip() for line in f.readlines()[-tail_lines:]]


def main() -> None:
    event_count_by_ip = defaultdict(int)

    try:
        lines = read_tail(AUTH_LOG_PATH, TAIL_LINES)
    except (FileNotFoundError, PermissionError):
        return

    for line in lines:
        if "sshd" not in line:
            continue

        for pattern in PATTERNS:
            match = pattern.search(line)
            if not match:
                continue

            ip = normalize_ip(match.group("host"))
            if ip:
                event_count_by_ip[ip] += 1
            break

    offenders = [ip for ip, count in event_count_by_ip.items() if count >= MIN_EVENTS_PER_IP]

    offenders.sort(key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))))
    for ip in offenders:
        print(ip)


if __name__ == "__main__":
    main()
