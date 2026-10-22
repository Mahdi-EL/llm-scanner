"""Business rules shared by the API and the scheduler: quotas and starting a scan."""
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

import auth_db
import config
import detectors
import netguard
import payment
import runner
import scan_db
import store
import vault
from attacks.prompts import ATTACK_PROMPTS
from db import transaction
from scanner import build_attack_list

log = logging.getLogger("llmscanner.services")

MAX_ACTIVE_PER_USER = 2      # pending + running scans one user may have at once
MAX_QUEUED_TOTAL    = 25     # pending + running scans across everyone

# Checking the limits and inserting the scan happen together, one request at a time;
# otherwise parallel requests all pass the check before any of them is inserted.
_admission = threading.Lock()


class ScanRejected(Exception):
    """A scan can't start. status is the HTTP status the API should answer with."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def quota(user: dict) -> dict:
    limit = payment.plan_limit(user.get("plan", "free"))
    used = scan_db.count_scans_this_month(user["id"])
    return {"plan": user.get("plan", "free"), "limit": limit, "used": used,
            "remaining": None if limit is None else max(0, limit - used)}


def check_can_scan(user: dict, *, already_inserted: bool = False) -> None:
    """Raises ScanRejected when the user can't start a scan. already_inserted: the new scan is
    in the database already and counts toward the limits, so they may be reached but not passed."""
    if config.REQUIRE_EMAIL_VERIFICATION and not user.get("email_verified"):
        raise ScanRejected(403, "Please confirm your email address before running scans.")
    over = 1 if already_inserted else 0
    q = quota(user)
    if q["limit"] is not None and q["used"] - over >= q["limit"]:
        raise ScanRejected(402, f"You've used all {q['limit']} scans of the {str(q['plan']).title()} plan "
                                "this month. Upgrade your plan to run more scans.")
    if scan_db.count_running_scans() - over >= MAX_QUEUED_TOTAL:
        raise ScanRejected(429, "The scanner is at capacity right now. Please retry in a few minutes.")
    with_user = scan_db.count_active_for_user(user["id"]) - over
    if with_user >= MAX_ACTIVE_PER_USER:
        raise ScanRejected(429, f"You already have {with_user} scans running. Wait for one to finish.")


def queue_scan(user: dict, cfg: dict, api_key: Optional[str] = None, *,
               target_name: str, target_id: Optional[str] = None,
               schedule_id: Optional[str] = None, include_custom_prompts: bool = True) -> str:
    """Validates, stores and queues a scan. Returns its scan_id or raises ScanRejected."""
    check_can_scan(user)          # fail fast; checked again below, atomically with the insert

    target_type = cfg.get("target_type", "simulation")
    if target_type in ("openai_compatible", "custom_rest"):
        if not cfg.get("api_url"):
            raise ScanRejected(400, "This target type needs an API URL")
    if cfg.get("api_url"):
        try:
            netguard.check_url(cfg["api_url"])
        except netguard.UnsafeURLError as e:
            raise ScanRejected(400, f"Target URL rejected: {e}")

    attacks = cfg.get("attacks") or None
    if attacks is not None:
        if len(attacks) > 2000 or any(len(a) != 2 or len(str(a[1])) > 4000 for a in attacks):
            raise ScanRejected(400, "Invalid attack list")
    categories = cfg.get("categories") or None
    if categories and not attacks:
        unknown = [c for c in categories if c not in ATTACK_PROMPTS]
        if unknown:
            raise ScanRejected(400, f"Unknown attack categories: {', '.join(unknown)}")

    cfg = {k: v for k, v in cfg.items() if v not in (None, "", [])}
    if target_type in ("simulation", "groq"):
        cfg["canary"] = detectors.make_canary()
    if include_custom_prompts and not attacks:
        prompts = store.list_prompts(user["id"])
        if prompts:
            cfg["custom_prompts"] = [{"category": p["category"], "prompt": p["prompt"]} for p in prompts]

    from target import HISTORY_TYPES
    planned = attacks if attacks else build_attack_list(categories, with_history=target_type in HISTORY_TYPES,
                                                         quick=bool(cfg.get("quick")))
    total = len(planned) + len(cfg.get("custom_prompts") or [])
    with _admission:
        check_can_scan(user)
        scan_id = scan_db.create_scan(
            target_name, target_type, user_id=user["id"], config=cfg,
            api_key_enc=vault.encrypt(api_key), total_attacks=total, model=cfg.get("model"),
            target_id=target_id, schedule_id=schedule_id,
        )
        try:                      # another process may have inserted at the same moment
            check_can_scan(user, already_inserted=True)
        except ScanRejected:
            scan_db.delete_scan(scan_id)
            raise
    auth_db.increment_scan_count(user["id"])
    runner.submit(scan_id)
    log.info("Scan %s queued for user %s (%s, %d attacks)", scan_id, user["id"], target_type, total)
    return scan_id


# ── AI firewall allowance ─────────────────────────────────────
class FirewallRejected(ScanRejected):
    """A firewall check can't run: not in the plan (402) or today's checks are used up (429)."""


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def firewall_usage(user: dict) -> dict:
    """{"used", "limit"}: firewall checks used today (UTC) and the plan's daily allowance."""
    with transaction() as conn:
        row = conn.execute("SELECT count FROM firewall_usage WHERE user_id = ? AND day = ?",
                           (user["id"], _today())).fetchone()
    return {"used": row[0] if row else 0, "limit": payment.firewall_limit(user.get("plan", "free"))}


def use_remediation(user: dict) -> None:
    """Counts one hardened-prompt suggestion against today's allowance, or raises ScanRejected(429)."""
    limit = payment.remediation_limit(user.get("plan", "free"))
    day = _today()
    with transaction() as conn:
        if conn.execute("INSERT INTO remediation_usage (user_id, day, count) VALUES (?, ?, 0) "
                        "ON CONFLICT(user_id, day) DO NOTHING", (user["id"], day)).rowcount:
            old = (datetime.now(timezone.utc) - timedelta(days=35)).strftime("%Y-%m-%d")
            conn.execute("DELETE FROM remediation_usage WHERE user_id = ? AND day < ?", (user["id"], old))
        counted = conn.execute("UPDATE remediation_usage SET count = count + 1 "
                               "WHERE user_id = ? AND day = ? AND count < ?", (user["id"], day, limit)).rowcount
    if not counted:
        raise ScanRejected(429, f"You've asked for {limit} hardened prompts today, your plan's daily limit. "
                                "It resets at midnight UTC.")


def refund_remediation(user: dict) -> None:
    """Gives back today's last suggestion when the model provider failed to produce it."""
    with transaction() as conn:
        conn.execute("UPDATE remediation_usage SET count = count - 1 WHERE user_id = ? AND day = ? AND count > 0",
                     (user["id"], _today()))


def use_firewall(user: dict, checks: int) -> dict:
    """Counts `checks` against today's allowance. Returns {"used", "limit"} or raises FirewallRejected."""
    limit = payment.firewall_limit(user.get("plan", "free"))
    if not limit:
        raise FirewallRejected(402, "The AI firewall isn't included in your plan. Upgrade to use it.")
    day = _today()
    with transaction() as conn:
        if conn.execute("INSERT INTO firewall_usage (user_id, day, count) VALUES (?, ?, 0) "
                        "ON CONFLICT(user_id, day) DO NOTHING", (user["id"], day)).rowcount:
            old = (datetime.now(timezone.utc) - timedelta(days=35)).strftime("%Y-%m-%d")
            conn.execute("DELETE FROM firewall_usage WHERE user_id = ? AND day < ?", (user["id"], old))
        counted = conn.execute("UPDATE firewall_usage SET count = count + ? "
                               "WHERE user_id = ? AND day = ? AND count + ? <= ?",
                               (checks, user["id"], day, checks, limit)).rowcount
        used = conn.execute("SELECT count FROM firewall_usage WHERE user_id = ? AND day = ?",
                            (user["id"], day)).fetchone()[0]
    if not counted:
        raise FirewallRejected(429, f"Daily AI firewall limit reached ({limit:,} checks). "
                                    "It resets at midnight UTC.")
    return {"used": used, "limit": limit}
