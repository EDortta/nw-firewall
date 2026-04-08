#!/usr/bin/env python3
from __future__ import annotations

import json
import sqlite3
from pathlib import Path


DDL = """
CREATE TABLE IF NOT EXISTS ip_state (
  ip TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  score INTEGER NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  blocked_until TEXT NOT NULL,
  source_server TEXT NOT NULL,
  reasons_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS ip_events (
  event_id TEXT PRIMARY KEY,
  ip TEXT NOT NULL,
  reason TEXT NOT NULL,
  score INTEGER NOT NULL,
  observed_at TEXT NOT NULL,
  origin_server TEXT NOT NULL,
  raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS seen_messages (
  event_id TEXT PRIMARY KEY,
  seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  event_id TEXT,
  action TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  raw_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_ip_state_blocked_until ON ip_state(blocked_until);
CREATE INDEX IF NOT EXISTS idx_ip_decisions_ip_time ON ip_decisions(ip, created_at);
"""


def connect(db_path: str) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(DDL)
    conn.commit()
    return conn


def mark_seen(conn: sqlite3.Connection, event_id: str, seen_at: str) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO seen_messages(event_id, seen_at) VALUES(?, ?)",
        (event_id, seen_at),
    )
    conn.commit()


def has_seen(conn: sqlite3.Connection, event_id: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM seen_messages WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    return bool(row)


def upsert_ip_state(
    conn: sqlite3.Connection,
    *,
    ip: str,
    status: str,
    score: int,
    first_seen: str,
    last_seen: str,
    blocked_until: str,
    source_server: str,
    reasons: list[str],
) -> None:
    conn.execute(
        """
        INSERT INTO ip_state(ip, status, score, first_seen, last_seen, blocked_until, source_server, reasons_json)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
          status=excluded.status,
          score=excluded.score,
          last_seen=excluded.last_seen,
          blocked_until=excluded.blocked_until,
          source_server=excluded.source_server,
          reasons_json=excluded.reasons_json
        """,
        (ip, status, score, first_seen, last_seen, blocked_until, source_server, json.dumps(reasons)),
    )
    conn.commit()


def delete_ip_state(conn: sqlite3.Connection, ip: str) -> None:
    conn.execute("DELETE FROM ip_state WHERE ip = ?", (ip,))
    conn.commit()


def get_ip_state(conn: sqlite3.Connection, ip: str) -> dict | None:
    row = conn.execute(
        "SELECT ip, status, score, first_seen, last_seen, blocked_until, source_server, reasons_json FROM ip_state WHERE ip = ?",
        (ip,),
    ).fetchone()
    if not row:
        return None
    reasons: list[str]
    try:
        reasons = json.loads(row[7]) if row[7] else []
    except Exception:
        reasons = []
    return {
        "ip": row[0],
        "status": row[1],
        "score": int(row[2]),
        "first_seen": row[3],
        "last_seen": row[4],
        "blocked_until": row[5],
        "source_server": row[6],
        "reasons": reasons,
    }


def list_expired_blocks(conn: sqlite3.Connection, now_iso: str) -> list[str]:
    rows = conn.execute(
        "SELECT ip FROM ip_state WHERE status='blocked' AND blocked_until <= ?",
        (now_iso,),
    ).fetchall()
    return [str(r[0]) for r in rows]


def record_event(conn: sqlite3.Connection, event: dict) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO ip_events(event_id, ip, reason, score, observed_at, origin_server, raw_json)
        VALUES(?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(event.get("event_id", "")),
            str(event.get("ip", "")),
            ",".join(event.get("reasons", [])),
            int(event.get("score", 0)),
            str(event.get("observed_at", "")),
            str(event.get("origin_server", "")),
            json.dumps(event, separators=(",", ":"), sort_keys=True),
        ),
    )
    conn.commit()


def record_decision(
    conn: sqlite3.Connection,
    *,
    ip: str,
    event_id: str,
    action: str,
    reason: str,
    created_at: str,
    raw: dict | None = None,
) -> None:
    conn.execute(
        "INSERT INTO ip_decisions(ip, event_id, action, reason, created_at, raw_json) VALUES(?, ?, ?, ?, ?, ?)",
        (
            ip,
            event_id,
            action,
            reason,
            created_at,
            json.dumps(raw or {}, separators=(",", ":"), sort_keys=True),
        ),
    )
    conn.commit()
