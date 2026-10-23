"""Scan records: create, update, list, and the views the API returns.

Internal rows hold secrets (the encrypted target key) and large blobs
(results, checkpoints). public_scan() is the only shape the API returns.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

import scoring
from db import transaction, utcnow

ACTIVE = ("pending", "running")

# Columns update_scan() may write. Field names are code, never user input,
# but the whitelist keeps the f-string SQL safe regardless.
_WRITABLE = {
    "status", "progress", "error_message", "results_json", "json_path", "pdf_path",
    "html_path", "md_path", "security_score", "total_attacks", "critical_count",
    "high_count", "medium_count", "low_count", "safe_count", "completed_at",
    "duration_seconds", "config_json", "api_key_enc", "checkpoint_json",
    "completed_attacks", "current_category", "started_at", "model", "grade",
    "error_count", "llm_calls", "target_id", "schedule_id", "tokens_in", "tokens_out", "graded_by_rules", "created_by",
}

# What list endpoints return: summary columns only, never results or secrets.
_LIST_COLUMNS = (
    "scan_id, user_id, target_name, target_type, status, progress, completed_attacks, "
    "total_attacks, current_category, security_score, grade, critical_count, high_count, "
    "medium_count, low_count, safe_count, error_count, created_at, started_at, completed_at, "
    "duration_seconds, error_message, model, target_id, schedule_id, created_by"
)


def new_scan_id() -> str:
    return uuid.uuid4().hex


def create_scan(target_name: str, target_type: str = "simulation", user_id: Optional[str] = None,
                config: Optional[dict] = None, api_key_enc: Optional[str] = None,
                total_attacks: int = 0, model: Optional[str] = None,
                target_id: Optional[str] = None, schedule_id: Optional[str] = None) -> str:
    scan_id = new_scan_id()
    with transaction() as conn:
        conn.execute("""
            INSERT INTO scans (scan_id, user_id, target_name, target_type, status, created_at, progress,
                               config_json, api_key_enc, total_attacks, model, target_id, schedule_id)
            VALUES (?, ?, ?, ?, 'pending', ?, 0, ?, ?, ?, ?, ?, ?)
        """, (scan_id, user_id, target_name, target_type, utcnow(),
              json.dumps(config or {}), api_key_enc, total_attacks, model, target_id, schedule_id))
    return scan_id


def update_scan(scan_id: str, **fields):
    if not fields:
        return
    unknown = set(fields) - _WRITABLE
    if unknown:
        raise ValueError(f"Unknown scan fields: {sorted(unknown)}")
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    with transaction() as conn:
        conn.execute(f"UPDATE scans SET {set_clause} WHERE scan_id = ?", [*fields.values(), scan_id])


def status_of(scan_id: str) -> Optional[str]:
    """Just the status (None if the scan is gone): cheap enough to ask while a scan runs."""
    with transaction() as conn:
        row = conn.execute("SELECT status FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    return row["status"] if row else None


def get_scan(scan_id: str) -> Optional[dict]:
    """Full internal row, with results parsed. Never return this to a client as-is."""
    with transaction() as conn:
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["results"] = json.loads(d["results_json"]) if d.get("results_json") else None
    return d


def summary_of(scan: dict) -> dict:
    return {
        "security_score": scan.get("security_score") or 0,
        "grade"         : scan.get("grade") or (scoring.grade(scan.get("security_score") or 0)
                                                if scan.get("status") == "complete" else None),
        "critical"      : scan.get("critical_count") or 0,
        "high"          : scan.get("high_count") or 0,
        "medium"        : scan.get("medium_count") or 0,
        "low"           : scan.get("low_count") or 0,
        "safe"          : scan.get("safe_count") or 0,
        "errors"        : scan.get("error_count") or 0,
    }


def public_scan(scan: dict, include_results: bool = False) -> dict:
    """The scan as the API shows it: no secrets, no raw blobs."""
    out = {k: scan.get(k) for k in _LIST_COLUMNS.replace(" ", "").split(",")}
    out["summary"] = summary_of(scan)
    config = scan.get("config_json")
    if config:
        try:
            cfg = json.loads(config)
            out["config"] = {k: cfg.get(k) for k in ("target_type", "model", "api_url", "categories",
                                                     "baseline_question", "input_field", "output_field")
                             if cfg.get(k) is not None}
            out["config"]["has_system_prompt"] = bool(cfg.get("system_prompt"))
            out["config"]["retest"] = bool(cfg.get("attacks"))
            out["config"]["quick"] = bool(cfg.get("quick")) and not cfg.get("attacks")
            if "with_key" in cfg:          # scans from before October 2026 don't say
                out["config"]["with_key"] = bool(cfg["with_key"])
        except (TypeError, ValueError):
            pass
    if include_results:
        out["results"] = scan.get("results")
    return out


def list_scans(user_id: str, limit: int = 50, offset: int = 0, status: Optional[str] = None,
               target_name: Optional[str] = None) -> list:
    """Newest first, summary columns only."""
    limit, offset = max(1, min(limit, 200)), max(0, offset)
    where, args = ["user_id = ?"], [user_id]
    if status:
        where.append("status = ?")
        args.append(status)
    if target_name:
        where.append("target_name = ?")
        args.append(target_name)
    with transaction() as conn:
        rows = conn.execute(
            f"SELECT {_LIST_COLUMNS} FROM scans WHERE {' AND '.join(where)} "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?", (*args, limit, offset)).fetchall()
    return [{**dict(r), "summary": summary_of(dict(r))} for r in rows]


def count_user_scans(user_id: str, status: Optional[str] = None, target_name: Optional[str] = None) -> int:
    where, args = ["user_id = ?"], [user_id]
    if status:
        where.append("status = ?")
        args.append(status)
    if target_name:
        where.append("target_name = ?")
        args.append(target_name)
    with transaction() as conn:
        return conn.execute(f"SELECT COUNT(*) FROM scans WHERE {' AND '.join(where)}", args).fetchone()[0]


def user_scan_stats(user_id: str) -> dict:
    """Totals over all of a user's finished scans (the dashboard only loads the latest page)."""
    with transaction() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS completed, AVG(security_score) AS avg_score, "
            "COALESCE(SUM(critical_count), 0) AS critical, "
            "COALESCE(SUM(CASE WHEN COALESCE(critical_count, 0) = 0 AND COALESCE(high_count, 0) = 0 "
            "THEN 1 ELSE 0 END), 0) AS clean "
            "FROM scans WHERE user_id = ? AND status = 'complete'", (user_id,)).fetchone()
    return {"completed": row["completed"], "critical": row["critical"], "clean": row["clean"],
            "avg_score": None if row["avg_score"] is None else round(row["avg_score"])}


def count_scans_this_month(user_id: str) -> int:
    """Scans created since the start of the current month (UTC) that count toward the quota, deleted
    ones included. A scan that failed or was cancelled before its first attack doesn't count."""
    month_start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    with transaction() as conn:
        live = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE user_id = ? AND created_at >= ? "
            "AND NOT (status IN ('failed', 'cancelled') AND COALESCE(completed_attacks, 0) = 0)",
            (user_id, month_start.isoformat(timespec="seconds"))).fetchone()[0]
        deleted = conn.execute("SELECT count FROM deleted_scan_usage WHERE user_id = ? AND month = ?",
                               (user_id, month_start.strftime("%Y-%m"))).fetchone()
    return live + (deleted[0] if deleted else 0)


def count_scans() -> int:
    with transaction() as conn:
        return conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]


def count_active_for_user(user_id: str) -> int:
    with transaction() as conn:
        return conn.execute("SELECT COUNT(*) FROM scans WHERE user_id = ? AND status IN ('pending', 'running')",
                            (user_id,)).fetchone()[0]


def count_running_scans() -> int:
    """Scans waiting or running: both use capacity."""
    with transaction() as conn:
        return conn.execute("SELECT COUNT(*) FROM scans WHERE status IN ('pending', 'running')").fetchone()[0]


def active_scan_ids() -> list:
    """Scans to resume after a restart, oldest first."""
    with transaction() as conn:
        rows = conn.execute("SELECT scan_id FROM scans WHERE status IN ('pending', 'running') "
                            "ORDER BY created_at").fetchall()
    return [r["scan_id"] for r in rows]


def fail_interrupted_scans() -> int:
    """Marks every pending/running scan as failed (used when resuming isn't possible)."""
    with transaction() as conn:
        cur = conn.execute("UPDATE scans SET status = 'failed', "
                           "error_message = 'Interrupted by a server restart' "
                           "WHERE status IN ('pending', 'running')")
        return cur.rowcount


def delete_scan(scan_id: str):
    with transaction() as conn:
        row = conn.execute("SELECT user_id, created_at, status, completed_attacks FROM scans WHERE scan_id = ?",
                           (scan_id,)).fetchone()
        if row and row["user_id"] and (row["status"] == "complete" or (row["completed_attacks"] or 0) > 0):
            # it used the month's quota: deleting it mustn't give the scan back
            conn.execute("INSERT INTO deleted_scan_usage (user_id, month, count) VALUES (?, ?, 1) "
                         "ON CONFLICT(user_id, month) DO UPDATE SET count = count + 1",
                         (row["user_id"], (row["created_at"] or "")[:7]))
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM share_links WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))


def user_scan_ids(user_id: str) -> list:
    with transaction() as conn:
        return [r["scan_id"] for r in conn.execute("SELECT scan_id FROM scans WHERE user_id = ?", (user_id,))]


def previous_complete_scan(user_id: str, target_name: str, before_scan_id: str,
                           schedule_id: Optional[str] = None) -> Optional[dict]:
    """The latest finished scan of the same target before this one (for comparisons and alerts),
    or with schedule_id, the previous finished run of that schedule."""
    with transaction() as conn:
        ref = conn.execute("SELECT id FROM scans WHERE scan_id = ?", (before_scan_id,)).fetchone()
        if not ref:
            return None
        # id, not created_at: timestamps are to the second, so two scans can share one
        same_schedule = " AND schedule_id = ?" if schedule_id else ""
        row = conn.execute(
            "SELECT scan_id FROM scans WHERE user_id = ? AND target_name = ? AND status = 'complete' "
            f"AND id < ?{same_schedule} ORDER BY id DESC LIMIT 1",
            (user_id, target_name, ref["id"], *([schedule_id] if schedule_id else []))).fetchone()
    return get_scan(row["scan_id"]) if row else None


def save_findings(scan_id: str, results: list):
    """Stores individual findings (truncated) for analytics, plus the global counters."""
    with transaction() as conn:
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        conn.executemany("""
            INSERT INTO findings
                (scan_id, category, attack, response, score, severity, reason, behavior_changed, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            (scan_id, r.get("category", ""), (r.get("attack") or "")[:500], (r.get("response") or "")[:500],
             r.get("score", 0), r.get("severity", "SAFE"), (r.get("reason") or "")[:300],
             1 if r.get("behavior_changed") else 0, r.get("confidence", "LOW"))
            for r in results
        ])
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
            """, (len(results),
                  sum(1 for r in results if r.get("severity") == "CRITICAL"),
                  sum(1 for r in results if r.get("severity") in ("CRITICAL", "HIGH")),
                  utcnow()))


def _migrate():
    """Kept for older callers: migrations now run in database.init_db()."""
    import database
    database.init_db()
