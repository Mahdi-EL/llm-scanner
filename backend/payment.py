"""Plans and Stripe billing.

PLANS is the single source of truth: the API's quotas, the /api/plans
endpoint and the Pricing page all read it. When a plan has a Stripe price
ID, the displayed amount comes from Stripe itself, so it always matches
what customers are charged.

Webhook events update the user's plan when a checkout completes, a
subscription changes, or it's cancelled. Event IDs are recorded so a
retried webhook is only applied once.
"""
import logging
import os
import sqlite3
import time
from typing import Optional

import config
from db import transaction, utcnow

log = logging.getLogger("llmscanner.billing")


def _limit(env_name: str, default: int) -> int:
    try:
        return int(os.getenv(env_name, str(default)))
    except ValueError:
        return default


_FREE_SCANS   = _limit("FREE_SCAN_LIMIT", 10)
_PRO_SCANS    = _limit("PRO_SCAN_LIMIT", 200)
# AI firewall checks per day. Each check uses the server's Groq quota (14,400 requests a day per guard
# model on Groq's free tier), so keep these well under it.
_FREE_FIREWALL       = _limit("FREE_FIREWALL_DAILY", 20)
_PRO_FIREWALL        = _limit("PRO_FIREWALL_DAILY", 2000)
_ENTERPRISE_FIREWALL = _limit("ENTERPRISE_FIREWALL_DAILY", 20000)


def _firewall_feature(checks: int, prefix: str) -> list:
    return [f"{prefix} ({checks:,} checks a day)"] if checks else []


PLANS = {
    "free": {
        "name"          : "Free",
        "amount"        : 0,
        "currency"      : "eur",
        "interval"      : "month",
        "price_id"      : None,
        "scan_limit"    : _FREE_SCANS,
        "firewall_daily": _FREE_FIREWALL,
        "features"      : [f"{_FREE_SCANS:,} scans per month", "All 22 attack categories",
                           "PDF, HTML and Markdown reports", "API keys for CI, the SDK and VS Code",
                           *_firewall_feature(_FREE_FIREWALL, "Try the AI firewall")],
    },
    "pro": {
        "name"          : "Pro",
        "amount"        : 4900,     # cents; replaced by the Stripe price when configured
        "currency"      : "eur",
        "interval"      : "month",
        "price_id"      : os.getenv("STRIPE_PRO_PRICE_ID", ""),
        "scan_limit"    : _PRO_SCANS,
        "firewall_daily": _PRO_FIREWALL,
        "features"      : [f"{_PRO_SCANS:,} scans per month", "Everything in Free",
                           "Scheduled scans and alerts", *_firewall_feature(_PRO_FIREWALL, "AI firewall API"),
                           "Email support"],
    },
    "enterprise": {
        "name"          : "Enterprise",
        "amount"        : 19900,
        "currency"      : "eur",
        "interval"      : "month",
        "price_id"      : os.getenv("STRIPE_ENTERPRISE_PRICE_ID", ""),
        "scan_limit"    : None,     # unlimited
        "firewall_daily": _ENTERPRISE_FIREWALL,
        "features"      : ["Unlimited scans", "Everything in Pro",
                           *_firewall_feature(_ENTERPRISE_FIREWALL, "AI firewall API"), "Priority support"],
    },
}


def plan_limit(plan: str) -> Optional[int]:
    """Monthly scan limit for a plan (None = unlimited). Unknown plans get the free limit."""
    return PLANS.get(plan, PLANS["free"])["scan_limit"]


def firewall_limit(plan: str) -> int:
    """AI firewall checks per day for a plan (0 = not included)."""
    return PLANS.get(plan, PLANS["free"])["firewall_daily"]


def _stripe():
    """The stripe module, configured. Raises if no key is set."""
    import stripe as _stripe_mod
    if not config.STRIPE_SECRET_KEY:
        raise ValueError("Payments are not configured")
    _stripe_mod.api_key = config.STRIPE_SECRET_KEY
    return _stripe_mod


_price_cache = {}


def _live_price(price_id: str) -> Optional[dict]:
    """Amount/currency/interval from Stripe, cached for 10 minutes."""
    cached = _price_cache.get(price_id)
    if cached and time.time() - cached[0] < 600:
        return cached[1]
    try:
        price = _stripe().Price.retrieve(price_id)
        info = {"amount": price["unit_amount"], "currency": price["currency"],
                "interval": (price.get("recurring") or {}).get("interval", "month")}
    except Exception:
        log.warning("Couldn't load Stripe price %s; showing the default amount", price_id, exc_info=True)
        info = None
    _price_cache[price_id] = (time.time(), info)
    return info


def billing_enabled() -> bool:
    return bool(config.STRIPE_SECRET_KEY)


def get_plans_public() -> dict:
    """Plan info for the Pricing page, without internal Stripe IDs."""
    out = {}
    for key, plan in PLANS.items():
        entry = {k: plan[k] for k in ("name", "amount", "currency", "interval", "features", "scan_limit",
                                      "firewall_daily")}
        if plan["price_id"] and billing_enabled():
            live = _live_price(plan["price_id"])
            if live:
                entry.update(live)
        entry["purchasable"] = bool(plan["price_id"]) and billing_enabled()
        entry["trial_days"]  = config.STRIPE_TRIAL_DAYS if entry["purchasable"] else 0
        out[key] = entry
    return out


def create_checkout_session(plan: str, user: dict) -> dict:
    """Stripe Checkout for a subscription. Returns {"url", "session_id"} or {"error"}."""
    if plan not in PLANS or not PLANS[plan]["price_id"]:
        return {"error": f"The '{plan}' plan can't be bought online"}
    try:
        stripe = _stripe()
        metadata = {"user_id": user["id"], "plan": plan}
        params = {
            "mode"               : "subscription",
            "line_items"         : [{"price": PLANS[plan]["price_id"], "quantity": 1}],
            "client_reference_id": user["id"],
            "metadata"           : metadata,
            "subscription_data"  : {"metadata": metadata},
            "success_url"        : f"{config.APP_URL}/settings?payment=success&session_id={{CHECKOUT_SESSION_ID}}",
            "cancel_url"         : f"{config.APP_URL}/pricing?payment=cancelled",
            "allow_promotion_codes": True,
        }
        if config.STRIPE_TRIAL_DAYS > 0:
            params["subscription_data"]["trial_period_days"] = config.STRIPE_TRIAL_DAYS
        if user.get("stripe_customer_id"):
            params["customer"] = user["stripe_customer_id"]
        else:
            params["customer_email"] = user["email"]
        session = stripe.checkout.Session.create(**params)
        return {"url": session.url, "session_id": session.id}
    except Exception:
        log.exception("Stripe checkout failed for user %s", user.get("id"))
        return {"error": "Payment provider error. Please try again later."}


def create_portal_session(user: dict) -> dict:
    """Stripe's hosted page where customers update cards, see invoices or cancel."""
    if not user.get("stripe_customer_id"):
        return {"error": "No billing account yet"}
    try:
        session = _stripe().billing_portal.Session.create(
            customer=user["stripe_customer_id"], return_url=f"{config.APP_URL}/settings")
        return {"url": session.url}
    except Exception:
        log.exception("Stripe portal failed for user %s", user.get("id"))
        return {"error": "Payment provider error. Please try again later."}


def cancel_subscription(subscription_id: str) -> None:
    """Cancels immediately (used when an account is deleted). Best effort."""
    if not subscription_id or not billing_enabled():
        return
    try:
        _stripe().Subscription.cancel(subscription_id)
    except Exception:
        log.warning("Couldn't cancel subscription %s", subscription_id, exc_info=True)


def _first_time(event_id: str, event_type: str) -> bool:
    """Records the event; False if we've already processed it."""
    try:
        with transaction() as conn:
            conn.execute("INSERT INTO stripe_events (event_id, type, processed_at) VALUES (?, ?, ?)",
                         (event_id, event_type, utcnow()))
        return True
    except sqlite3.IntegrityError:
        return False


def forget_event(event_id: str) -> None:
    """Un-records an event whose processing failed, so Stripe's retry is handled."""
    with transaction() as conn:
        conn.execute("DELETE FROM stripe_events WHERE event_id = ?", (event_id,))


def _subscription_plan(sub: dict) -> Optional[str]:
    """The plan a subscription pays for: from its current price (portal plan switches
    change the price but not the metadata), falling back to the metadata."""
    items = ((sub.get("items") or {}).get("data") or [])
    price_ids = {((item.get("price") or {}).get("id")) for item in items}
    for name, plan in PLANS.items():
        if plan["price_id"] and plan["price_id"] in price_ids:
            return name
    return (sub.get("metadata") or {}).get("plan")


def handle_webhook(payload: bytes, sig_header: str) -> dict:
    """Verifies a Stripe webhook and returns what changed.

    Returns {"type", "user_id", "plan", "customer_id", "subscription_id"}
    with plan=None when the plan shouldn't change, or {"error": ...}.
    """
    if not config.STRIPE_WEBHOOK_SECRET:
        return {"error": "Webhook secret not configured"}
    try:
        event = _stripe().Webhook.construct_event(payload, sig_header, config.STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        return {"error": f"Invalid webhook: {type(e).__name__}"}

    if not _first_time(event["id"], event["type"]):
        return {"type": "duplicate", "handled": False}

    obj = event["data"]["object"]
    metadata = obj.get("metadata") or {}
    result = {"type": event["type"], "event_id": event["id"], "user_id": metadata.get("user_id"), "plan": None,
              "customer_id": obj.get("customer"), "subscription_id": None}

    if event["type"] == "checkout.session.completed":
        result["user_id"] = metadata.get("user_id") or obj.get("client_reference_id")
        result["subscription_id"] = obj.get("subscription")
        if obj.get("payment_status") in ("paid", "no_payment_required"):
            result["plan"] = metadata.get("plan")
    elif event["type"] in ("customer.subscription.created", "customer.subscription.updated"):
        result["subscription_id"] = obj.get("id")
        status = obj.get("status")
        if status in ("active", "trialing"):
            result["plan"] = _subscription_plan(obj)
        elif status in ("canceled", "unpaid", "incomplete_expired"):
            result["plan"] = "free"
            result["subscription_id"] = ""
            result["ended_subscription"] = obj.get("id")
    elif event["type"] == "customer.subscription.deleted":
        result["plan"] = "free"
        result["subscription_id"] = ""
        result["ended_subscription"] = obj.get("id")
    elif event["type"] == "invoice.payment_failed":
        result["payment_failed"] = True
    else:
        result["handled"] = False

    if result["plan"] and result["plan"] not in PLANS:
        result["plan"] = None
    return result
