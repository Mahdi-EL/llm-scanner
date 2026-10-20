"""What happens after a scan ends: emails, signed webhooks and regression alerts.

Webhook requests carry two headers so receivers can trust them:
  X-LLMScanner-Event:     scan.completed | scan.failed | scan.regression | ping
  X-LLMScanner-Signature: t=<unix time>,v1=<hex HMAC-SHA256 of "<t>.<raw body>">
The HMAC key is the user's webhook secret (shown once in Settings).
"""
import hashlib
import hmac
import json
import logging
import os
import time

import analysis
import config
import email_service
import netguard
import scan_db
from auth_db import get_user_by_id

log = logging.getLogger("llmscanner.notify")


def sign(secret: str, body: bytes, timestamp: int) -> str:
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={mac}"


def verify_signature(secret: str, body: bytes, header: str, tolerance: int = 300) -> bool:
    """Reference check for receivers (and our tests)."""
    try:
        parts = dict(item.split("=", 1) for item in header.split(","))
        timestamp = int(parts["t"])
    except (ValueError, KeyError):
        return False
    if abs(time.time() - timestamp) > tolerance:
        return False
    return hmac.compare_digest(sign(secret, body, timestamp), header)


def send_webhook(user: dict, event: str, payload: dict) -> bool:
    url = user.get("webhook_url")
    if not url:
        return False
    body = json.dumps({"event": event, **payload}, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "LLMScanner-Webhook/1.0",
               "X-LLMScanner-Event": event}
    if user.get("webhook_secret"):
        headers["X-LLMScanner-Signature"] = sign(user["webhook_secret"], body, int(time.time()))
    try:
        response = netguard.safe_post(url, data=body, headers=headers, timeout=5)
        ok = 200 <= response.status_code < 300
        if not ok:
            log.warning("Webhook %s answered %s", event, response.status_code)
        return ok
    except Exception:
        log.warning("Webhook %s to user %s failed", event, user.get("id"), exc_info=True)
        return False


def _payload(scan: dict) -> dict:
    return {
        "scan_id"       : scan["scan_id"],
        "target_name"   : scan["target_name"],
        "status"        : scan["status"],
        "security_score": scan.get("security_score") or 0,
        "grade"         : scan.get("grade"),
        "critical"      : scan.get("critical_count") or 0,
        "high"          : scan.get("high_count") or 0,
        "medium"        : scan.get("medium_count") or 0,
        "low"           : scan.get("low_count") or 0,
        "errors"        : scan.get("error_count") or 0,
        "created_at"    : scan.get("created_at"),
        "completed_at"  : scan.get("completed_at"),
        "report_url"    : f"{config.APP_URL}/results/{scan['scan_id']}",
    }


def _can_email(user: dict) -> bool:
    """Only email confirmed addresses, so nobody can sign up with someone else's to spam them."""
    return bool(user.get("email") and user.get("email_verified"))


def scan_finished(scan_id: str, alert_drop: int = None) -> None:
    """Best-effort notifications once a scan completes or fails. Never raises."""
    try:
        scan = scan_db.get_scan(scan_id)
        user = get_user_by_id(scan.get("user_id")) if scan else None
        if not user:
            return
        if scan["status"] == "complete":
            if _can_email(user):
                email_service.send_scan_complete(
                    user["email"], scan["target_name"], scan.get("security_score") or 0, scan_id,
                    grade=scan.get("grade"), critical=scan.get("critical_count") or 0,
                    high=scan.get("high_count") or 0)
            send_webhook(user, "scan.completed", _payload(scan))
            if alert_drop is not None:
                _regression_alert(user, scan, alert_drop)
        elif scan["status"] == "failed":
            if _can_email(user) and scan.get("schedule_id"):
                email_service.send_scan_failed(user["email"], scan["target_name"], scan_id,
                                               scan.get("error_message") or "Unknown error")
            send_webhook(user, "scan.failed", {**_payload(scan), "error": scan.get("error_message")})
    except Exception:
        log.warning("Notifications for scan %s failed", scan_id, exc_info=True)


def _results(scan: dict) -> list:
    data = scan.get("results")
    if not data and scan.get("json_path") and os.path.exists(scan["json_path"]):
        with open(scan["json_path"], encoding="utf-8") as f:
            data = json.load(f)
    return (data or {}).get("results", []) if isinstance(data, dict) else []


def _regression_alert(user: dict, scan: dict, alert_drop: int) -> None:
    """Compares a scheduled run with the schedule's previous run. The score only counts when both ran
    the same attacks (a re-test or a narrower manual scan isn't a baseline); new criticals are attacks
    both runs tried that are critical now and weren't before."""
    previous = scan_db.previous_complete_scan(user["id"], scan["target_name"], scan["scan_id"],
                                              schedule_id=scan.get("schedule_id"))
    if not previous:
        return
    diff = analysis.diff_findings(_results(previous), _results(scan))
    old, new = previous.get("security_score") or 0, scan.get("security_score") or 0
    dropped = diff["same_attacks"] and old - new >= alert_drop
    new_critical = sum(1 for f in diff["introduced"] if f.get("severity") == "CRITICAL")
    if dropped or new_critical:
        if _can_email(user):
            email_service.send_score_drop(user["email"], scan["target_name"], old, new,
                                          scan["scan_id"], new_critical)
        send_webhook(user, "scan.regression", {**_payload(scan), "previous_scan_id": previous["scan_id"],
                                               "previous_score": old, "new_critical": new_critical})
