"""Saved targets, scan schedules, custom attack prompts and share links."""
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import vault
from auth_db import token_hash
from db import parse_ts, transaction, utcnow

TARGET_FIELDS = ("target_type", "api_url", "model", "system_prompt", "baseline_question",
                 "input_field", "output_field", "categories")
FREQUENCIES = {"daily": timedelta(days=1), "weekly": timedelta(days=7)}
MAX_PROMPTS = 200


# ── Saved targets ─────────────────────────────────────────────
def _target_out(row) -> dict:
    cfg = json.loads(row["config_json"] or "{}")
    return {"id": row["id"], "name": row["name"], "config": cfg, "has_key": bool(row["api_key_enc"]),
            "created_at": row["created_at"], "updated_at": row["updated_at"]}


def create_target(user_id: str, name: str, cfg: dict, api_key: Optional[str]) -> dict:
    target_id = uuid.uuid4().hex
    clean = {k: cfg[k] for k in TARGET_FIELDS if cfg.get(k) not in (None, "", [])}
    with transaction() as conn:
        conn.execute("INSERT INTO targets (id, user_id, name, config_json, api_key_enc, created_at, updated_at) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (target_id, user_id, name, json.dumps(clean), vault.encrypt(api_key), utcnow(), utcnow()))
    return get_target(user_id, target_id)


def list_targets(user_id: str) -> list:
    with transaction() as conn:
        rows = conn.execute("SELECT * FROM targets WHERE user_id = ? ORDER BY updated_at DESC", (user_id,))
        return [_target_out(r) for r in rows]


def get_target(user_id: str, target_id: str, with_key: bool = False) -> Optional[dict]:
    with transaction() as conn:
        row = conn.execute("SELECT * FROM targets WHERE id = ? AND user_id = ?", (target_id, user_id)).fetchone()
    if not row:
        return None
    out = _target_out(row)
    if with_key:
        out["api_key"] = vault.decrypt(row["api_key_enc"])
    return out


def update_target(user_id: str, target_id: str, name: Optional[str] = None,
                  cfg: Optional[dict] = None, api_key: Optional[str] = None) -> Optional[dict]:
    """api_key: None keeps the stored key, "" removes it, any other value replaces it."""
    current = get_target(user_id, target_id)
    if not current:
        return None
    new_cfg = current["config"]
    if cfg is not None:
        new_cfg = {k: cfg[k] for k in TARGET_FIELDS if cfg.get(k) not in (None, "", [])}
    with transaction() as conn:
        conn.execute("UPDATE targets SET name = ?, config_json = ?, updated_at = ? WHERE id = ? AND user_id = ?",
                     (name or current["name"], json.dumps(new_cfg), utcnow(), target_id, user_id))
        if api_key is not None:
            conn.execute("UPDATE targets SET api_key_enc = ? WHERE id = ? AND user_id = ?",
                         (vault.encrypt(api_key), target_id, user_id))
    return get_target(user_id, target_id)


def delete_target(user_id: str, target_id: str) -> bool:
    with transaction() as conn:
        conn.execute("DELETE FROM schedules WHERE target_id = ? AND user_id = ?", (target_id, user_id))
        conn.execute("DELETE FROM gateway_events WHERE target_id = ? AND user_id = ?", (target_id, user_id))
        return conn.execute("DELETE FROM targets WHERE id = ? AND user_id = ?",
                            (target_id, user_id)).rowcount > 0


# ── Schedules ─────────────────────────────────────────────────
def next_run(frequency: str, after: Optional[datetime] = None) -> str:
    after = after or datetime.now(timezone.utc)
    return (after + FREQUENCIES[frequency]).isoformat(timespec="seconds")


def create_schedule(user_id: str, target_id: str, frequency: str, categories: Optional[list],
                    alert_drop: int) -> dict:
    schedule_id = uuid.uuid4().hex
    with transaction() as conn:
        conn.execute("INSERT INTO schedules (id, user_id, target_id, frequency, categories, alert_drop, "
                     "next_run_at, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
                     (schedule_id, user_id, target_id, frequency, json.dumps(categories or []),
                      alert_drop, next_run(frequency), utcnow()))
    return get_schedule(user_id, schedule_id)


def _schedule_out(row) -> dict:
    d = dict(row)
    d["categories"] = json.loads(d.get("categories") or "[]")
    d["enabled"] = bool(d["enabled"])
    return d


def list_schedules(user_id: str) -> list:
    with transaction() as conn:
        rows = conn.execute("SELECT * FROM schedules WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
        return [_schedule_out(r) for r in rows]


def get_schedule(user_id: str, schedule_id: str) -> Optional[dict]:
    with transaction() as conn:
        row = conn.execute("SELECT * FROM schedules WHERE id = ? AND user_id = ?",
                           (schedule_id, user_id)).fetchone()
    return _schedule_out(row) if row else None


def update_schedule(user_id: str, schedule_id: str, **fields) -> Optional[dict]:
    allowed = {k: v for k, v in fields.items()
               if k in ("frequency", "alert_drop", "enabled", "categories") and v is not None}
    if "categories" in allowed:
        allowed["categories"] = json.dumps(allowed["categories"])
    if "enabled" in allowed:
        allowed["enabled"] = 1 if allowed["enabled"] else 0
    if "frequency" in allowed:
        allowed["next_run_at"] = next_run(allowed["frequency"])
    if allowed:
        sets = ", ".join(f"{k} = ?" for k in allowed)
        with transaction() as conn:
            conn.execute(f"UPDATE schedules SET {sets} WHERE id = ? AND user_id = ?",
                         (*allowed.values(), schedule_id, user_id))
    return get_schedule(user_id, schedule_id)


def delete_schedule(user_id: str, schedule_id: str) -> bool:
    with transaction() as conn:
        return conn.execute("DELETE FROM schedules WHERE id = ? AND user_id = ?",
                            (schedule_id, user_id)).rowcount > 0


def due_schedules(now: Optional[datetime] = None) -> list:
    now = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    with transaction() as conn:
        rows = conn.execute("SELECT * FROM schedules WHERE enabled = 1 AND next_run_at <= ?", (now,))
        return [_schedule_out(r) for r in rows]


def claim_schedule(schedule: dict) -> bool:
    """Moves a due schedule to its next run. Only one caller can win the claim, so two
    processes (a rolling deploy, several workers) never start the same run twice."""
    with transaction() as conn:
        claimed = conn.execute("UPDATE schedules SET last_run_at = ?, next_run_at = ? "
                               "WHERE id = ? AND next_run_at = ? AND enabled = 1",
                               (utcnow(), next_run(schedule["frequency"]), schedule["id"],
                                schedule["next_run_at"])).rowcount
    return claimed == 1


def record_schedule_scan(schedule_id: str, scan_id: str):
    with transaction() as conn:
        conn.execute("UPDATE schedules SET last_scan_id = ? WHERE id = ?", (scan_id, schedule_id))


# ── Custom attack prompts ─────────────────────────────────────
def list_prompts(user_id: str) -> list:
    with transaction() as conn:
        rows = conn.execute("SELECT id, category, prompt, created_at FROM custom_prompts "
                            "WHERE user_id = ? ORDER BY created_at", (user_id,))
        return [dict(r) for r in rows]


def add_prompt(user_id: str, category: str, prompt: str) -> Optional[dict]:
    prompt_id = uuid.uuid4().hex
    with transaction() as conn:
        # One statement, so parallel requests can't both pass the count.
        added = conn.execute(
            "INSERT INTO custom_prompts (id, user_id, category, prompt, created_at) "
            "SELECT ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM custom_prompts WHERE user_id = ?) < ?",
            (prompt_id, user_id, category, prompt, utcnow(), user_id, MAX_PROMPTS)).rowcount
    if not added:
        return None
    return {"id": prompt_id, "category": category, "prompt": prompt}


def delete_prompt(user_id: str, prompt_id: str) -> bool:
    with transaction() as conn:
        return conn.execute("DELETE FROM custom_prompts WHERE id = ? AND user_id = ?",
                            (prompt_id, user_id)).rowcount > 0


# ── Share links ───────────────────────────────────────────────
def create_share(user_id: str, scan_id: str, days: int) -> dict:
    token = secrets.token_urlsafe(24)
    expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds")
    with transaction() as conn:
        conn.execute("DELETE FROM share_links WHERE scan_id = ? AND user_id = ?", (scan_id, user_id))
        conn.execute("INSERT INTO share_links (token_hash, scan_id, user_id, expires_at, created_at) "
                     "VALUES (?, ?, ?, ?, ?)", (token_hash(token), scan_id, user_id, expires, utcnow()))
    return {"token": token, "expires_at": expires}


def resolve_share(token: str) -> Optional[dict]:
    """{"scan_id", "expires_at"} for a live share link, else None."""
    with transaction() as conn:
        row = conn.execute("SELECT scan_id, expires_at FROM share_links WHERE token_hash = ?",
                           (token_hash(token),)).fetchone()
    if not row or parse_ts(row["expires_at"]) < datetime.now(timezone.utc):
        return None
    return {"scan_id": row["scan_id"], "expires_at": row["expires_at"]}


def list_shares(user_id: str) -> list:
    """The user's share links (only a hash of each token is stored, so no URLs)."""
    with transaction() as conn:
        rows = conn.execute("SELECT scan_id, expires_at, created_at FROM share_links WHERE user_id = ? "
                            "ORDER BY created_at DESC", (user_id,)).fetchall()
    return [dict(r) for r in rows]


def share_expiry(user_id: str, scan_id: str) -> Optional[str]:
    """When the scan's share link expires, or None if it has no live link."""
    with transaction() as conn:
        row = conn.execute("SELECT expires_at FROM share_links WHERE scan_id = ? AND user_id = ?",
                           (scan_id, user_id)).fetchone()
    if not row or parse_ts(row["expires_at"]) < datetime.now(timezone.utc):
        return None
    return row["expires_at"]


# ── Triage: false positives and accepted risks ────────────────
TRIAGE_STATUSES = ("false_positive", "accepted_risk")


def finding_key(category: str, attack: str) -> str:
    """Stable id for an attack against a target, the same in every scan of it."""
    return hashlib.sha256(f"{category or ''}\x00{attack or ''}".encode()).hexdigest()[:32]


def triage_for(user_id: str, target_name: str) -> dict:
    """{finding_key: {"status", "note", "created_at", "decided_by"}} for one target."""
    with transaction() as conn:
        rows = conn.execute("SELECT finding_key, status, note, created_at, decided_by FROM finding_triage "
                            "WHERE user_id = ? AND target_name = ?", (user_id, target_name)).fetchall()
    return {r["finding_key"]: {"status": r["status"], "note": r["note"], "created_at": r["created_at"],
                               "decided_by": r["decided_by"]} for r in rows}


def set_triage(user_id: str, target_name: str, key: str, status: Optional[str], note: Optional[str] = None,
               decided_by: Optional[str] = None):
    """Marks a finding (status None or "open" clears the mark). decided_by: who made the call."""
    with transaction() as conn:
        if status in TRIAGE_STATUSES:
            conn.execute("INSERT INTO finding_triage (user_id, target_name, finding_key, status, note, created_at, "
                         "decided_by) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(user_id, target_name, finding_key) "
                         "DO UPDATE SET status = excluded.status, note = excluded.note, "
                         "created_at = excluded.created_at, decided_by = excluded.decided_by",
                         (user_id, target_name, key, status, note, utcnow(), decided_by))
        else:
            conn.execute("DELETE FROM finding_triage WHERE user_id = ? AND target_name = ? AND finding_key = ?",
                         (user_id, target_name, key))


def list_triage(user_id: str) -> list:
    with transaction() as conn:
        rows = conn.execute("SELECT target_name, finding_key, status, note, created_at, decided_by FROM finding_triage "
                            "WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
    return [dict(r) for r in rows]


def apply_triage(user_id: str, target_name: str, results: list) -> list:
    """The results with findings marked false positive or accepted risk counted as SAFE (score 0);
    each keeps what it was in "triage"."""
    marks = triage_for(user_id, target_name)
    if not marks:
        return results
    out = []
    for r in results:
        mark = marks.get(finding_key(r.get("category", ""), r.get("attack", "")))
        if mark and r.get("severity") not in ("SAFE", "ERROR", None):
            r = {**r, "severity": "SAFE", "score": 0,
                 "triage": {**mark, "severity": r.get("severity"), "score": r.get("score")}}
        out.append(r)
    return out


def revoke_share(user_id: str, scan_id: str) -> bool:
    with transaction() as conn:
        return conn.execute("DELETE FROM share_links WHERE scan_id = ? AND user_id = ?",
                            (scan_id, user_id)).rowcount > 0
