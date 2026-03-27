#!/usr/bin/env python3
import argparse
import ipaddress
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CLIENT_MANAGER = BASE_DIR / "client" / "8-manage-ip-lists.py"
DB_PATH = BASE_DIR / "db" / "blocked_ips.db"
WHITELIST_PATH = BASE_DIR / "db" / "whitelist.json"
GRAYLIST_PATH = BASE_DIR / "db" / "graylist.json"


def normalize_ip(value: str) -> str | None:
    candidate = value.strip().strip("[]")
    if not candidate:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def load_ip_set(path: Path, key_name: str) -> set[str]:
    if not path.exists():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return set()

    if isinstance(payload, list):
        raw = payload
    elif isinstance(payload, dict):
        raw = payload.get(key_name) or payload.get("ips") or []
    else:
        raw = []

    out: set[str] = set()
    for item in raw:
        ip = normalize_ip(str(item))
        if ip:
            out.add(ip)
    return out


def save_ip_set(path: Path, key_name: str, ips: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(ips, key=lambda v: (ipaddress.ip_address(v).version, int(ipaddress.ip_address(v))))
    path.write_text(json.dumps({key_name: ordered}, indent=2) + "\n", encoding="utf-8")


def load_last_actions(db_path: Path) -> dict[str, str]:
    if not db_path.exists():
        return {}

    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute(
        """
        SELECT ip, action
        FROM blocked_ips
        WHERE ip IS NOT NULL
          AND TRIM(ip) <> ''
        ORDER BY timestamp DESC
        """
    )
    rows = cur.fetchall()
    cur.close()
    con.close()

    out: dict[str, str] = {}
    for ip, action in rows:
        ipn = normalize_ip(str(ip))
        if not ipn or ipn in out:
            continue
        out[ipn] = str(action or "").strip().lower()
    return out


def gather_ips(ip_args: list[str], file_path: str | None) -> list[str]:
    values: list[str] = []
    for item in ip_args:
        values.append(item)

    if file_path:
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"ip file not found: {p}")
        for line in p.read_text(encoding="utf-8").splitlines():
            part = line.split("#", 1)[0].strip()
            if part:
                values.append(part)

    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        ip = normalize_ip(raw)
        if not ip:
            print(f"warn: invalid ip skipped: {raw}", file=sys.stderr)
            continue
        if ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out


def run_client_manager(command: str, ip: str, reason: str) -> tuple[bool, str]:
    cmd = [str(CLIENT_MANAGER), command, ip]
    if reason:
        cmd.extend(["--reason", reason])
    try:
        proc = subprocess.run(cmd, check=False, text=True, capture_output=True)
    except Exception as exc:
        return False, str(exc)

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or f"exit={proc.returncode}").strip()
        return False, detail
    return True, (proc.stdout or "ok").strip()


def cmd_query(ips: list[str]) -> int:
    whitelist = load_ip_set(WHITELIST_PATH, "whitelist")
    graylist = load_ip_set(GRAYLIST_PATH, "graylist")
    last_actions = load_last_actions(DB_PATH)

    if not ips:
        ips = sorted(set(last_actions) | whitelist | graylist, key=lambda v: (ipaddress.ip_address(v).version, int(ipaddress.ip_address(v))))

    if not ips:
        print("no ips found")
        return 0

    print("ip,status,last_action")
    for ip in ips:
        action = last_actions.get(ip, "")
        if ip in whitelist:
            status = "whitelist"
        elif ip in graylist:
            status = "graylist"
        elif action == "block":
            status = "blacklist"
        elif action == "unblock":
            status = "unblocked"
        else:
            status = "unknown"
        print(f"{ip},{status},{action}")
    return 0


def cmd_blacklist(ips: list[str], reason: str) -> int:
    gray = load_ip_set(GRAYLIST_PATH, "graylist")
    changed = 0
    failed = 0
    for ip in ips:
        if ip in gray:
            gray.discard(ip)
        ok, detail = run_client_manager("blacklist", ip, reason or "manual blacklist")
        if ok:
            changed += 1
            print(f"blacklist ok ip={ip}")
        else:
            failed += 1
            print(f"blacklist fail ip={ip} detail={detail}", file=sys.stderr)
    save_ip_set(GRAYLIST_PATH, "graylist", gray)
    print(f"summary action=blacklist total={len(ips)} ok={changed} failed={failed}")
    return 1 if failed else 0


def cmd_whitelist(ips: list[str], reason: str) -> int:
    gray = load_ip_set(GRAYLIST_PATH, "graylist")
    changed = 0
    failed = 0
    for ip in ips:
        if ip in gray:
            gray.discard(ip)
        ok, detail = run_client_manager("whitelist", ip, reason or "manual whitelist")
        if ok:
            changed += 1
            print(f"whitelist ok ip={ip}")
        else:
            failed += 1
            print(f"whitelist fail ip={ip} detail={detail}", file=sys.stderr)
    save_ip_set(GRAYLIST_PATH, "graylist", gray)
    print(f"summary action=whitelist total={len(ips)} ok={changed} failed={failed}")
    return 1 if failed else 0


def cmd_graylist(ips: list[str], reason: str) -> int:
    gray = load_ip_set(GRAYLIST_PATH, "graylist")
    changed = 0
    failed = 0
    for ip in ips:
        ok, detail = run_client_manager("remove", ip, reason or "manual graylist")
        if not ok:
            failed += 1
            print(f"graylist fail ip={ip} detail={detail}", file=sys.stderr)
            continue
        gray.add(ip)
        changed += 1
        print(f"graylist ok ip={ip}")
    save_ip_set(GRAYLIST_PATH, "graylist", gray)
    print(f"summary action=graylist total={len(ips)} ok={changed} failed={failed}")
    return 1 if failed else 0


def cmd_remove(ips: list[str], reason: str) -> int:
    gray = load_ip_set(GRAYLIST_PATH, "graylist")
    changed = 0
    failed = 0
    for ip in ips:
        gray.discard(ip)
        ok, detail = run_client_manager("remove", ip, reason or "manual remove")
        if ok:
            changed += 1
            print(f"remove ok ip={ip}")
        else:
            failed += 1
            print(f"remove fail ip={ip} detail={detail}", file=sys.stderr)
    save_ip_set(GRAYLIST_PATH, "graylist", gray)
    print(f"summary action=remove total={len(ips)} ok={changed} failed={failed}")
    return 1 if failed else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Query and manage white/black/gray lists for one or many IPs")
    parser.add_argument("command", choices=["query", "whitelist", "blacklist", "graylist", "remove"])
    parser.add_argument("ips", nargs="*", help="IPv4/IPv6 values")
    parser.add_argument("--file", dest="file_path", default="", help="text file with one IP per line")
    parser.add_argument("--reason", default="", help="reason for write actions")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        ips = gather_ips(args.ips, args.file_path or None)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.command == "query":
        return cmd_query(ips)

    if not ips:
        print("error: provide at least one ip (arg or --file)", file=sys.stderr)
        return 2

    if args.command == "blacklist":
        return cmd_blacklist(ips, args.reason)
    if args.command == "whitelist":
        return cmd_whitelist(ips, args.reason)
    if args.command == "graylist":
        return cmd_graylist(ips, args.reason)
    if args.command == "remove":
        return cmd_remove(ips, args.reason)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
