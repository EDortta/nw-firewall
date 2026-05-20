#!/usr/bin/env python3

import ipaddress
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
DB_PATH = Path(os.getenv("BLOCKED_IPS_DB_PATH", str(BASE_DIR / "db" / "blocked_ips.db")))
ACTION = os.getenv("BLOCKED_IPS_ACTION", "block")

DETECTORS = (
    (
        os.getenv("DETECTOR1_PATH", str(SCRIPT_DIR / "1-detect-malicious-activity-in-log.py")),
        "malicious web activity",
    ),
    (
        os.getenv("DETECTOR2_PATH", str(SCRIPT_DIR / "2-detect-auth-sessions.py")),
        "ssh invalid user or bad password",
    ),
)


def normalize_ip(value: str) -> str | None:
    candidate = value.strip().strip("[]")
    if not candidate:
        return None

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


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


def ensure_schema(con: sqlite3.Connection) -> None:
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip text,
            reason text,
            action text,
            timestamp text
        )
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ip_blocked_ips ON blocked_ips (ip)
        """
    )
    con.commit()
    cur.close()


def merge_reason(old_reason: str | None, new_reason: str) -> str:
    parts = set()

    if old_reason:
        parts.update(item.strip() for item in old_reason.split(";") if item.strip())

    if new_reason:
        parts.update(item.strip() for item in new_reason.split(";") if item.strip())

    return "; ".join(sorted(parts))


def upsert_ips(ip_reasons: dict[str, set[str]]) -> tuple[list[str], list[str]]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    con = sqlite3.connect(DB_PATH)
    ensure_schema(con)
    cur = con.cursor()

    now = datetime.now(timezone.utc).isoformat()
    inserted = []
    updated = []

    for ip in sorted(ip_reasons, key=lambda x: (ipaddress.ip_address(x).version, int(ipaddress.ip_address(x)))):
        joined_reason = "; ".join(sorted(ip_reasons[ip]))

        cur.execute("SELECT reason FROM blocked_ips WHERE ip=?", (ip,))
        row = cur.fetchone()
        if row is None:
            cur.execute(
                "INSERT INTO blocked_ips (ip, reason, action, timestamp) VALUES (?, ?, ?, ?)",
                (ip, joined_reason, ACTION, now),
            )
            inserted.append(ip)
        else:
            reason = merge_reason(row[0], joined_reason)
            # Do NOT update timestamp: the watermark in 6-block-ips.py relies on the
            # original insertion time. Refreshing it here would re-publish on every
            # detector run (detector re-reads the same log tail each minute).
            cur.execute(
                "UPDATE blocked_ips SET reason=? WHERE ip=?",
                (reason, ip),
            )
            updated.append(ip)

    con.commit()
    cur.close()
    con.close()

    return inserted, updated


def main() -> None:
    ip_reasons: dict[str, set[str]] = {}
    errors = []

    for script_path, reason in DETECTORS:
        ips, error = run_detector(script_path)
        if error:
            errors.append(error)

        for ip in ips:
            ip_reasons.setdefault(ip, set()).add(reason)

    inserted, updated = upsert_ips(ip_reasons)

    # Print newly inserted IPs so callers can chain firewall actions.
    for ip in inserted:
        print(ip)

    if errors:
        for err in errors:
            print(err, file=sys.stderr)


if __name__ == "__main__":
    main()
