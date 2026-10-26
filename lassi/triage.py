"""SQLite-backed alert triage (ack / note / false positive).

The event log remains the source of truth for *what happened*. This store
keeps the operator's workflow on top of it (who acknowledged a card, what was
false, notes) so a restart or a log replay does not lose that work.

SQLite is intentionally the only new dependency: stdlib, single file, WAL,
no server. A connection is opened per call; the alert feed is capped at 200,
so this is cheap and avoids sharing a connection across threads.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TRIAGE_DB_PATH = Path(os.environ.get("LASSI_TRIAGE_DB", "data/triage.db"))
STATUSES = ("open", "ack", "closed")


def _connect() -> sqlite3.Connection:
    TRIAGE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(TRIAGE_DB_PATH), timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS alert_triage (
               key TEXT PRIMARY KEY,
               status TEXT NOT NULL,
               assignee TEXT NOT NULL DEFAULT '',
               note TEXT NOT NULL DEFAULT '',
               false_positive INTEGER NOT NULL DEFAULT 0,
               updated_at TEXT NOT NULL,
               actor TEXT NOT NULL
           )"""
    )
    return conn


def _row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "key": row["key"],
        "status": row["status"],
        "assignee": row["assignee"],
        "note": row["note"],
        "false_positive": bool(row["false_positive"]),
        "updated_at": row["updated_at"],
        "actor": row["actor"],
    }


def all_entries() -> dict[str, dict[str, Any]]:
    try:
        conn = _connect()
        try:
            rows = conn.execute("SELECT * FROM alert_triage").fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return {}
    return {row["key"]: _row(row) for row in rows}


def get_entry(key: str) -> dict[str, Any] | None:
    key = str(key or "").strip()
    if not key:
        return None
    try:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM alert_triage WHERE key = ?",
                               (key,)).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    return _row(row) if row else None


def upsert(key: str, status: str = "ack", assignee: str = "",
           note: str = "", false_positive: bool = False,
           actor: str = "system") -> dict[str, Any]:
    key = str(key or "").strip()
    if not key or len(key) > 300:
        raise ValueError("invalid alert key")
    status = str(status or "ack").strip().lower()
    if status not in STATUSES:
        raise ValueError("status must be open, ack or closed")
    assignee = str(assignee or "").strip()[:64]
    note = str(note or "").strip()[:500]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn = _connect()
    try:
        conn.execute(
            """INSERT INTO alert_triage
                   (key, status, assignee, note, false_positive, updated_at, actor)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET
                   status = excluded.status,
                   assignee = excluded.assignee,
                   note = excluded.note,
                   false_positive = excluded.false_positive,
                   updated_at = excluded.updated_at,
                   actor = excluded.actor""",
            (key, status, assignee, note, 1 if false_positive else 0, now,
             str(actor or "system")[:64]),
        )
        conn.commit()
    finally:
        conn.close()
    return {"key": key, "status": status, "assignee": assignee, "note": note,
            "false_positive": bool(false_positive), "updated_at": now,
            "actor": str(actor or "system")[:64]}
