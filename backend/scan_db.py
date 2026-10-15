import sys
sys.stdout.reconfigure(encoding='utf-8')

import sqlite3
import json
import uuid
import os
from contextlib import contextmanager
from datetime import datetime
from typing import Optional
from database import DB_PATH


# ── Connection factory ─────────────────────────────────────────
@contextmanager
def _db():
    """Opens a connection, commits on success, rolls back on error, always closes."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # WAL + busy timeout: avoid "database is locked" when a background scan
    # writes while the API reads concurrently.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Migration (safe, idempotent) ───────────────────────────────
def _migrate():
    with _db() as conn:
        # Guard: only migrate if the scans table already exists (init_db runs first)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        if "scans" not in tables:
            return
        existing = {row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()}
        if "progress"      not in existing:
            conn.execute("ALTER TABLE scans ADD COLUMN progress      INTEGER DEFAULT 0")
        if "error_message" not in existing:
            conn.execute("ALTER TABLE scans ADD COLUMN error_message TEXT")
        if "results_json"  not in existing:
            conn.execute("ALTER TABLE scans ADD COLUMN results_json  TEXT")
        if "user_id"       not in existing:
            conn.execute("ALTER TABLE scans ADD COLUMN user_id       TEXT")
        # Create the user_id index here (not in init_db) so it is built only
        # after the column is guaranteed to exist on pre-ownership-model DBs.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans (user_id)")


# ── CRUD ──────────────────────────────────────────────────────
def create_scan(target_name: str, target_type: str = "simulation",
                user_id: Optional[str] = None) -> str:
    scan_id = str(uuid.uuid4())[:8]
    with _db() as conn:
        conn.execute("""
            INSERT INTO scans (scan_id, user_id, target_name, target_type, status, created_at, progress)
            VALUES (?, ?, ?, ?, 'pending', ?, 0)
        """, (scan_id, user_id, target_name, target_type, datetime.now().isoformat()))
    return scan_id


def update_scan(scan_id: str, **fields):
    if not fields:
        return
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    with _db() as conn:
        conn.execute(
            f"UPDATE scans SET {set_clause} WHERE scan_id = ?",
            [*fields.values(), scan_id]
        )


def get_scan(scan_id: str) -> Optional[dict]:
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["results"] = json.loads(d["results_json"]) if d.get("results_json") else None
    return d


def list_scans(user_id: Optional[str] = None, limit: int = 50, offset: int = 0) -> list:
    """Lists scans, newest first. If user_id is given, only that user's scans."""
    limit  = max(1, min(limit, 200))   # clamp to a sane page size
    offset = max(0, offset)
    with _db() as conn:
        if user_id is None:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (user_id, limit, offset),
            ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d["results"] = json.loads(d["results_json"]) if d.get("results_json") else None
        result.append(d)
    return result


def count_scans_this_month(user_id: str) -> int:
    """Number of scans the user created since the start of the current month.
    Uses naive-local time to match how created_at is stored (datetime.now())."""
    month_start = datetime.now().replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    ).isoformat()
    with _db() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM scans WHERE user_id = ? AND created_at >= ?",
            (user_id, month_start),
        ).fetchone()[0]


def fail_interrupted_scans() -> int:
    """On startup, any scan still 'pending'/'running' was killed by a restart.
    Mark them failed so the UI doesn't show a perpetual 'running' state."""
    with _db() as conn:
        cur = conn.execute(
            "UPDATE scans SET status = 'failed', "
            "error_message = 'Interrupted by a server restart' "
            "WHERE status IN ('pending', 'running')"
        )
        return cur.rowcount


def delete_scan(scan_id: str):
    with _db() as conn:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scans    WHERE scan_id = ?", (scan_id,))


def count_scans() -> int:
    with _db() as conn:
        return conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]


def count_running_scans() -> int:
    with _db() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM scans WHERE status = 'running'"
        ).fetchone()[0]


def save_findings(scan_id: str, results: list):
    """Persists individual findings after a scan completes."""
    with _db() as conn:
        conn.executemany("""
            INSERT INTO findings
                (scan_id, category, attack, response, score, severity, reason, behavior_changed, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            (
                scan_id,
                r.get("category", ""),
                r.get("attack",   "")[:500],
                r.get("response", "")[:500],
                r.get("score",    0),
                r.get("severity", "SAFE"),
                r.get("reason",   "")[:300],
                1 if r.get("behavior_changed") else 0,
                r.get("confidence", "LOW"),
            )
            for r in results
        ])

        # Update global stats
        summary = {}
        if results:
            conn.execute("""
                UPDATE global_stats SET
                    total_scans         = total_scans + 1,
                    total_attacks_fired = total_attacks_fired + ?,
                    total_criticals     = total_criticals + ?,
                    total_vulns_found   = total_vulns_found + ?,
                    avg_security_score  = (SELECT AVG(security_score) FROM scans WHERE status = 'complete'),
                    last_updated        = ?
                WHERE id = 1
            """, (
                len(results),
                sum(1 for r in results if r.get("severity") == "CRITICAL"),
                sum(1 for r in results if r.get("severity") in ("CRITICAL", "HIGH")),
                datetime.now().isoformat(),
            ))


# _migrate() is called from api.py startup event AFTER init_db() creates tables
