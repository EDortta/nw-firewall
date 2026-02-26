#!/usr/bin/env python3

import ipaddress
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("BLOCKED_IPS_DB_PATH", str(SCRIPT_DIR / "db" / "blocked_ips.db")))
OUTPUT_DIR = Path(os.getenv("IPINFO_OUTPUT_DIR", str(SCRIPT_DIR / "db")))
IPINFO_BASE_URL = os.getenv("IPINFO_BASE_URL", "https://ipinfo.io")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "").strip()
TIMEOUT_SECONDS = float(os.getenv("IPINFO_TIMEOUT_SECONDS", "10"))
REFRESH_EXISTING = os.getenv("GEO_REFRESH", "0").strip().lower() in {"1", "true", "yes"}


def normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def load_blocked_ips(db_path: Path) -> list[str]:
    if not db_path.exists():
        return []

    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT DISTINCT ip FROM blocked_ips WHERE ip IS NOT NULL AND ip <> ''")
    rows = cur.fetchall()
    cur.close()
    con.close()

    ips = set()
    for (raw_ip,) in rows:
        ip = normalize_ip(raw_ip)
        if ip:
            ips.add(ip)

    return sorted(ips, key=lambda ip: (ipaddress.ip_address(ip).version, int(ipaddress.ip_address(ip))))


def build_ipinfo_url(ip: str) -> str:
    if not IPINFO_TOKEN:
        return f"{IPINFO_BASE_URL.rstrip('/')}/{ip}/json"

    query = urllib.parse.urlencode({"token": IPINFO_TOKEN})
    return f"{IPINFO_BASE_URL.rstrip('/')}/{ip}/json?{query}"


def fetch_geo_info(ip: str) -> dict | None:
    url = build_ipinfo_url(ip)

    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8", "ignore")
            payload = json.loads(body)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"warn: failed to fetch geo info for {ip}: {exc}", file=sys.stderr)
        return None

    if isinstance(payload, dict) and "readme" in payload:
        payload.pop("readme", None)

    payload["ip"] = ip
    payload["fetched_at"] = datetime.now(timezone.utc).isoformat()
    payload["source"] = "ipinfo.io"
    return payload


def save_ip_json(ip: str, payload: dict) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    file_path = OUTPUT_DIR / f"{ip}.json"
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)


def main() -> None:
    ips = load_blocked_ips(DB_PATH)
    if not ips:
        return

    created_count = 0
    skipped_count = 0

    for ip in ips:
        output_file = OUTPUT_DIR / f"{ip}.json"
        if output_file.exists() and not REFRESH_EXISTING:
            skipped_count += 1
            continue

        payload = fetch_geo_info(ip)
        if payload is None:
            continue

        save_ip_json(ip, payload)
        created_count += 1

    print(f"processed={len(ips)} created_or_updated={created_count} skipped_existing={skipped_count}")


if __name__ == "__main__":
    main()
