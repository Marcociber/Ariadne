"""
Persistent scan history.

Every completed scan is stored so it can be listed and reopened later.
SQLite by default (zero-config, no server); point HISTORY_DB at any path.

Fixed from the first version:

  * connections are now CLOSED. `with sqlite3.connect(...) as conn` manages the
    transaction, not the file handle, so descriptors were leaked to the GC.
  * indexes on `created_at` and `target`, plus real pagination (limit+offset).
  * RETENTION: the table used to grow without bound while storing the full
    JSON of every scan (hundreds of KB for a domain with crt.sh data).
  * failures are logged instead of `except Exception: pass`, which made a
    read-only database look exactly like an empty one.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from contextlib import closing
from datetime import UTC, datetime, timedelta

from .config import settings
from .logging import get_logger

log = get_logger("history")

_lock = threading.Lock()
_initialized = False


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.history_db, timeout=5.0)
    conn.row_factory = sqlite3.Row
    # WAL lets readers work while a scan is being written.
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init() -> None:
    global _initialized
    if _initialized:
        return
    with _lock, closing(_connect()) as conn, conn:
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target, target_type)")
    _initialized = True


def _prune(conn: sqlite3.Connection) -> None:
    """Enforce the retention policy (age first, then row count)."""
    if settings.history_retention_days > 0:
        cutoff = (datetime.now(UTC) - timedelta(days=settings.history_retention_days)).isoformat(
            timespec="seconds"
        )
        conn.execute("DELETE FROM scans WHERE created_at < ?", (cutoff,))
    if settings.history_max_rows > 0:
        conn.execute(
            "DELETE FROM scans WHERE id NOT IN " "(SELECT id FROM scans ORDER BY id DESC LIMIT ?)",
            (settings.history_max_rows,),
        )


def save(response: dict) -> None:
    """Persist a full scan response (already JSON-serializable)."""
    try:
        _init()
        count = sum(len(r.get("findings", [])) for r in response.get("results", []))
        with _lock, closing(_connect()) as conn, conn:
            conn.execute(
                "INSERT INTO scans "
                "(created_at, target, target_type, findings_count, elapsed_ms, response) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    datetime.now(UTC).isoformat(timespec="seconds"),
                    response.get("target", ""),
                    response.get("target_type", ""),
                    count,
                    response.get("total_elapsed_ms", 0),
                    json.dumps(response),
                ),
            )
            _prune(conn)
    except Exception as exc:
        log.warning("history.save_failed", error=str(exc), db=settings.history_db)


async def save_async(response: dict) -> None:
    """Write the history row off the event loop.

    The orchestrator used to call the blocking `save()` straight from a
    coroutine, so every scan stalled the loop for the duration of the write.
    """
    await asyncio.to_thread(save, response)


def list_recent(limit: int = 50, offset: int = 0) -> list[dict]:
    """Return stored scans (newest first) without the heavy response blob."""
    try:
        _init()
        with _lock, closing(_connect()) as conn:
            rows = conn.execute(
                "SELECT id, created_at, target, target_type, findings_count, elapsed_ms "
                "FROM scans ORDER BY id DESC LIMIT ? OFFSET ?",
                (max(1, min(limit, 500)), max(0, offset)),
            ).fetchall()
        return [dict(row) for row in rows]
    except Exception as exc:
        log.warning("history.list_failed", error=str(exc), db=settings.history_db)
        return []


def count() -> int:
    """Total number of stored scans (for pagination in the UI)."""
    try:
        _init()
        with _lock, closing(_connect()) as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()
        return int(row["n"]) if row else 0
    except Exception as exc:
        log.warning("history.count_failed", error=str(exc))
        return 0


def get(scan_id: int) -> dict | None:
    """Return the full stored response for a scan id, or None."""
    try:
        _init()
        with _lock, closing(_connect()) as conn:
            row = conn.execute("SELECT response FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return json.loads(row["response"]) if row else None
    except Exception as exc:
        log.warning("history.get_failed", scan_id=scan_id, error=str(exc))
        return None


def delete(scan_id: int) -> bool:
    """Remove one stored scan. Returns True when a row was deleted."""
    try:
        _init()
        with _lock, closing(_connect()) as conn, conn:
            cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cur.rowcount > 0
    except Exception as exc:
        log.warning("history.delete_failed", scan_id=scan_id, error=str(exc))
        return False
