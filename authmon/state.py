#!/usr/bin/env python3
"""SQLite state: blocks (with TTL), outbox, replay dedupe, decisions audit,
log offsets and allowlist.

WAL mode + busy_timeout so the agent daemon and the detector timer can share
the database safely.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

DDL = """
CREATE TABLE IF NOT EXISTS blocks (
  ip          TEXT PRIMARY KEY,
  reason      TEXT NOT NULL DEFAULT '',
  source      TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  active      INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_blocks_active_expires ON blocks(active, expires_at);

CREATE TABLE IF NOT EXISTS outbox (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  event_json   TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  applied_at   TEXT,
  published_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(published_at) WHERE published_at IS NULL;

CREATE TABLE IF NOT EXISTS seen_events (
  event_id TEXT PRIMARY KEY,
  seen_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ts       TEXT NOT NULL,
  ip       TEXT NOT NULL,
  action   TEXT NOT NULL,
  reason   TEXT NOT NULL,
  detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_decisions_ip_ts ON decisions(ip, ts);

CREATE TABLE IF NOT EXISTS log_offsets (
  path   TEXT PRIMARY KEY,
  inode  INTEGER NOT NULL,
  offset INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS signals (
  id   INTEGER PRIMARY KEY AUTOINCREMENT,
  ip   TEXT NOT NULL,
  kind TEXT NOT NULL,
  ts   TEXT NOT NULL,
  path TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_signals_ip_kind_ts ON signals(ip, kind, ts);

CREATE TABLE IF NOT EXISTS allowlist (
  ip       TEXT PRIMARY KEY,
  reason   TEXT NOT NULL DEFAULT '',
  added_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS peer_ips (
  node_id      TEXT NOT NULL,
  ip           TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'active',
  added_at     TEXT NOT NULL,
  retire_after TEXT,
  PRIMARY KEY (node_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_peer_ips_ip ON peer_ips(ip);
"""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(DDL)
    conn.commit()
    return conn


# --- blocks -----------------------------------------------------------------

def upsert_block(conn, *, ip: str, reason: str, source: str, ttl_seconds: int) -> None:
    now = datetime.now(timezone.utc)
    expires = (now + timedelta(seconds=ttl_seconds)).isoformat()
    conn.execute(
        """
        INSERT INTO blocks(ip, reason, source, created_at, expires_at, active)
        VALUES(?, ?, ?, ?, ?, 1)
        ON CONFLICT(ip) DO UPDATE SET
          reason=excluded.reason, source=excluded.source,
          expires_at=excluded.expires_at, active=1
        """,
        (ip, reason, source, now.isoformat(), expires),
    )
    conn.commit()


def deactivate_block(conn, ip: str) -> bool:
    cur = conn.execute("UPDATE blocks SET active=0 WHERE ip=? AND active=1", (ip,))
    conn.commit()
    return cur.rowcount > 0


def get_active_block(conn, ip: str) -> dict | None:
    row = conn.execute(
        "SELECT ip, reason, source, created_at, expires_at FROM blocks WHERE ip=? AND active=1",
        (ip,),
    ).fetchone()
    if not row:
        return None
    return {"ip": row[0], "reason": row[1], "source": row[2], "created_at": row[3], "expires_at": row[4]}


def list_active_blocks(conn, now_iso: str | None = None) -> list[dict]:
    now_iso = now_iso or utc_now_iso()
    rows = conn.execute(
        "SELECT ip, reason, expires_at FROM blocks WHERE active=1 AND expires_at > ? ORDER BY ip",
        (now_iso,),
    ).fetchall()
    return [{"ip": r[0], "reason": r[1], "expires_at": r[2]} for r in rows]


def list_expired_blocks(conn, now_iso: str | None = None) -> list[str]:
    now_iso = now_iso or utc_now_iso()
    rows = conn.execute(
        "SELECT ip FROM blocks WHERE active=1 AND expires_at <= ?", (now_iso,)
    ).fetchall()
    return [r[0] for r in rows]


# --- outbox -----------------------------------------------------------------

def outbox_add(conn, event: dict) -> None:
    conn.execute(
        "INSERT INTO outbox(event_json, created_at) VALUES(?, ?)",
        (json.dumps(event, separators=(",", ":"), sort_keys=True), utc_now_iso()),
    )
    conn.commit()


def outbox_pending(conn, limit: int = 200) -> list[tuple[int, dict, bool]]:
    rows = conn.execute(
        "SELECT id, event_json, applied_at FROM outbox WHERE published_at IS NULL ORDER BY id LIMIT ?",
        (limit,),
    ).fetchall()
    out = []
    for row_id, raw, applied_at in rows:
        try:
            out.append((row_id, json.loads(raw), applied_at is not None))
        except json.JSONDecodeError:
            conn.execute("UPDATE outbox SET published_at=? WHERE id=?", (utc_now_iso(), row_id))
            conn.commit()
    return out


def outbox_mark_applied(conn, row_id: int) -> None:
    conn.execute("UPDATE outbox SET applied_at=? WHERE id=?", (utc_now_iso(), row_id))
    conn.commit()


def outbox_mark_published(conn, row_id: int) -> None:
    conn.execute("UPDATE outbox SET published_at=? WHERE id=?", (utc_now_iso(), row_id))
    conn.commit()


# --- replay dedupe ----------------------------------------------------------

def has_seen(conn, event_id: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM seen_events WHERE event_id=?", (event_id,)).fetchone())


def mark_seen(conn, event_id: str) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO seen_events(event_id, seen_at) VALUES(?, ?)",
        (event_id, utc_now_iso()),
    )
    conn.commit()


def prune_seen(conn, retention_days: int) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
    cur = conn.execute("DELETE FROM seen_events WHERE seen_at < ?", (cutoff,))
    conn.commit()
    return cur.rowcount


# --- decisions audit --------------------------------------------------------

def record_decision(conn, *, ip: str, action: str, reason: str, detail: str = "") -> None:
    conn.execute(
        "INSERT INTO decisions(ts, ip, action, reason, detail) VALUES(?, ?, ?, ?, ?)",
        (utc_now_iso(), ip, action, reason, detail),
    )
    conn.commit()


# --- log offsets ------------------------------------------------------------

def get_offset(conn, path: str) -> tuple[int, int] | None:
    row = conn.execute("SELECT inode, offset FROM log_offsets WHERE path=?", (path,)).fetchone()
    return (row[0], row[1]) if row else None


def save_offset(conn, path: str, inode: int, offset: int) -> None:
    conn.execute(
        """
        INSERT INTO log_offsets(path, inode, offset) VALUES(?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset
        """,
        (path, inode, offset),
    )
    conn.commit()


# --- detection signals ------------------------------------------------------

def add_signal(conn, *, ip: str, kind: str, ts_iso: str, path: str = "") -> None:
    conn.execute(
        "INSERT INTO signals(ip, kind, ts, path) VALUES(?, ?, ?, ?)", (ip, kind, ts_iso, path)
    )


def count_signals(conn, *, ip: str, kind: str, since_iso: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM signals WHERE ip=? AND kind=? AND ts >= ?", (ip, kind, since_iso)
    ).fetchone()
    return int(row[0])


def count_unique_paths(conn, *, ip: str, since_iso: str) -> int:
    row = conn.execute(
        "SELECT COUNT(DISTINCT path) FROM signals WHERE ip=? AND ts >= ? AND path <> ''",
        (ip, since_iso),
    ).fetchone()
    return int(row[0])


def prune_signals(conn, max_age_seconds: int) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)).isoformat()
    cur = conn.execute("DELETE FROM signals WHERE ts < ?", (cutoff,))
    conn.commit()
    return cur.rowcount


# --- allowlist --------------------------------------------------------------

def allowlist_ips(conn) -> list[str]:
    return [r[0] for r in conn.execute("SELECT ip FROM allowlist ORDER BY ip").fetchall()]


def allowlist_add(conn, ip: str, reason: str = "") -> None:
    conn.execute(
        "INSERT OR REPLACE INTO allowlist(ip, reason, added_at) VALUES(?, ?, ?)",
        (ip, reason, utc_now_iso()),
    )
    conn.commit()


def allowlist_remove(conn, ip: str) -> bool:
    cur = conn.execute("DELETE FROM allowlist WHERE ip=?", (ip,))
    conn.commit()
    return cur.rowcount > 0


# --- peer IPs ---------------------------------------------------------------

def peer_ip_upsert(conn, node_id: str, ip: str, status: str = "active",
                   retire_after: str | None = None) -> None:
    conn.execute(
        """
        INSERT INTO peer_ips(node_id, ip, status, added_at, retire_after)
        VALUES(?, ?, ?, ?, ?)
        ON CONFLICT(node_id, ip) DO UPDATE SET
          status=excluded.status, retire_after=excluded.retire_after
        """,
        (node_id, ip, status, utc_now_iso(), retire_after),
    )
    conn.commit()


def peer_ip_retire(conn, ip: str, retain_seconds: int) -> None:
    """Mark all active entries for this IP as retiring with a deadline."""
    retire_after = (
        datetime.now(timezone.utc) + timedelta(seconds=retain_seconds)
    ).isoformat()
    conn.execute(
        "UPDATE peer_ips SET status='retiring', retire_after=? WHERE ip=? AND status='active'",
        (retire_after, ip),
    )
    conn.commit()


def peer_ip_cancel_retirement(conn, ip: str) -> None:
    """Called when another node claims a retiring IP — keep it protected."""
    conn.execute(
        "UPDATE peer_ips SET status='active', retire_after=NULL WHERE ip=? AND status='retiring'",
        (ip,),
    )
    conn.commit()


def peer_ip_get_active(conn, node_id: str) -> str | None:
    """Return the current active IP for a node, or None."""
    row = conn.execute(
        "SELECT ip FROM peer_ips WHERE node_id=? AND status='active' LIMIT 1",
        (node_id,),
    ).fetchone()
    return row[0] if row else None


def peer_ip_protected_set(conn) -> set[str]:
    """All IPs that should be protected: active + retiring not yet expired."""
    now = utc_now_iso()
    rows = conn.execute(
        """
        SELECT ip FROM peer_ips
        WHERE status='active'
           OR (status='retiring' AND retire_after > ?)
        """,
        (now,),
    ).fetchall()
    return {r[0] for r in rows}


def peer_ip_prune(conn) -> int:
    now = utc_now_iso()
    cur = conn.execute(
        "DELETE FROM peer_ips WHERE status='retiring' AND retire_after <= ?", (now,)
    )
    conn.commit()
    return cur.rowcount
