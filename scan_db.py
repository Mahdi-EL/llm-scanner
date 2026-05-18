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
        existing = {row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()}
        if "progress"      not in existing:
            conn.execute("ALTER TABLE scans ADD COLUMN progress      INTEGER DEFAULT 0")
        if "error_message" not in existing:
            conn.execute("ALTER TABLE scans ADD COLUMN error_message TEXT")
        if "results_json"  not in existing:
            conn.execute("ALTER TABLE scans ADD COLUMN results_json  TEXT")


# ── CRUD ──────────────────────────────────────────────────────
def create_scan(target_name: str, target_type: str = "simulation") -> str:
    scan_id = str(uuid.uuid4())[:8]
    with _db() as conn:
        conn.execute("""
            INSERT INTO scans (scan_id, target_name, target_type, status, created_at, progress)
            VALUES (?, ?, ?, 'pending', ?, 0)
        """, (scan_id, target_name, target_type, datetime.now().isoformat()))
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


def list_scans() -> list:
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC"
        ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d["results"] = json.loads(d["results_json"]) if d.get("results_json") else None
        result.append(d)
    return result


def delete_scan(scan_id: str):
    with _db() as conn:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scans    WHERE scan_id = ?", (scan_id,))


def count_scans() -> int:
    with _db() as conn:
        return conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]


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


# ── Init ──────────────────────────────────────────────────────
_migrate()
