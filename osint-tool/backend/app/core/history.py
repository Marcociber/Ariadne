"""
Persistent scan history.

Every completed scan is stored so it can be listed and reopened later.
Uses SQLite by default (zero-config, no server required, works in local mode);
point HISTORY_DB at any path to relocate the database file:

    HISTORY_DB=ariadne_history.db        (default, relative to the working dir)

All operations fail safe: a storage error never breaks a scan.
"""
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

_DB = os.getenv("HISTORY_DB", "ariadne_history.db")
_lock = threading.Lock()
_initialized = False


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB)
    conn.row_factory = sqlite3.Row
    return conn


def _init() -> None:
    global _initialized
    if _initialized:
        return
    with _lock, _conn() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                   id             INTEGER PRIMARY KEY AUTOINCREMENT,
                   created_at     TEXT    NOT NULL,
                   target         TEXT    NOT NULL,
                   target_type    TEXT    NOT NULL,
                   findings_count INTEGER NOT NULL,
                   elapsed_ms     INTEGER NOT NULL,
                   response       TEXT    NOT NULL
               )"""
        )
    _initialized = True


def save(response: dict) -> None:
    """Persist a full scan response (already JSON-serializable)."""
    try:
        _init()
        count = sum(len(r.get("findings", [])) for r in response.get("results", []))
        with _lock, _conn() as conn:
            conn.execute(
                "INSERT INTO scans "
                "(created_at, target, target_type, findings_count, elapsed_ms, response) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    response.get("target", ""),
                    response.get("target_type", ""),
                    count,
                    response.get("total_elapsed_ms", 0),
                    json.dumps(response),
                ),
            )
    except Exception:
        pass


def list_recent(limit: int = 50) -> list[dict]:
    """Return recent scans (newest first) without the heavy response blob."""
    try:
        _init()
        with _lock, _conn() as conn:
            rows = conn.execute(
                "SELECT id, created_at, target, target_type, findings_count, elapsed_ms "
                "FROM scans ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [dict(row) for row in rows]
    except Exception:
        return []


def get(scan_id: int) -> dict | None:
    """Return the full stored response for a scan id, or None."""
    try:
        _init()
        with _lock, _conn() as conn:
            row = conn.execute(
                "SELECT response FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        return json.loads(row["response"]) if row else None
    except Exception:
        return None
