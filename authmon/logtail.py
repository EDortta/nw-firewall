#!/usr/bin/env python3
"""Stateful, rotation-safe log tailing.

v4 re-read the last N lines of each log on every cron run, which both
re-processed old lines (masked only by dedup heuristics downstream) and lost
lines under burst (> N lines/minute). v5 tracks (inode, offset) per file in
the state DB and reads exactly the new bytes once.
"""
from __future__ import annotations

import os
import sqlite3

from . import state

MAX_BYTES_PER_READ = 32 * 1024 * 1024  # safety valve against runaway logs


def read_new_lines(conn: sqlite3.Connection, path: str) -> list[str]:
    try:
        stat = os.stat(path)
    except (FileNotFoundError, PermissionError):
        return []

    saved = state.get_offset(conn, path)
    offset = 0
    if saved is not None:
        saved_inode, saved_offset = saved
        # Same file and not truncated → resume; otherwise the file rotated or
        # was truncated, start from the beginning of the new file.
        if saved_inode == stat.st_ino and saved_offset <= stat.st_size:
            offset = saved_offset

    if offset == stat.st_size:
        if saved is None or saved != (stat.st_ino, offset):
            state.save_offset(conn, path, stat.st_ino, offset)
        return []

    with open(path, "rb") as f:
        f.seek(offset)
        chunk = f.read(MAX_BYTES_PER_READ)

    # Keep a trailing partial line in the file for the next run.
    last_newline = chunk.rfind(b"\n")
    if last_newline == -1:
        state.save_offset(conn, path, stat.st_ino, offset)
        return []
    consumed = chunk[: last_newline + 1]
    state.save_offset(conn, path, stat.st_ino, offset + len(consumed))

    return [
        line.decode("utf-8", "ignore").strip()
        for line in consumed.splitlines()
        if line.strip()
    ]
