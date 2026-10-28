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
# "Suggest a hardened prompt" runs on the server's model key, so it has a daily allowance too.
_REMEDIATION_DAILY = {"free": _limit("FREE_REMEDIATION_DAILY", 10), "pro": _limit("PRO_REMEDIATION_DAILY", 100),
                      "enterprise": _limit("ENTERPRISE_REMEDIATION_DAILY", 500)}


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
        "features"      : [f"{_FREE_SCANS:,} scans per month",
                           "Quick scans across all 22 attack categories" if config.FREE_QUICK_SCANS_ONLY
                           else "All 22 attack categories",
                           "PDF, HTML and Markdown reports", "API keys for CI, the SDK and VS Code",
                           *_firewall_feature(_FREE_FIREWALL, "Try the AI firewall")],
    },
    "pro": {
        "name"          : "Pro",
        "amount"        : 4900,     # cents; replaced by the Stripe price when configured
        "currency"      : "eur",
        "interval"      : "month",
        "price_id"      : os.getenv("STRIPE_PRO_PRICE_ID", ""),
        "yearly_price_id": os.getenv("STRIPE_PRO_YEARLY_PRICE_ID", ""),
        "scan_limit"    : _PRO_SCANS,
        "firewall_daily": _PRO_FIREWALL,
        "features"      : [f"{_PRO_SCANS:,} scans per month", "Everything in Free",
                           *(["Full scans: every attack in the library"] if config.FREE_QUICK_SCANS_ONLY else []),
                           f"Up to {config.PRO_SEATS} people per workspace",
                           "Scheduled scans and alerts", "Evidence reports for audits and security reviews", "Your brand on reports",
                           *_firewall_feature(_PRO_FIREWALL, "AI firewall API"),
                           "Email support"],
    },
    "enterprise": {
        "name"          : "Enterprise",
        "amount"        : 19900,
        "currency"      : "eur",
        "interval"      : "month",
        "price_id"      : os.getenv("STRIPE_ENTERPRISE_PRICE_ID", ""),
        "yearly_price_id": os.getenv("STRIPE_ENTERPRISE_YEARLY_PRICE_ID", ""),
        "scan_limit"    : None,     # unlimited
        "firewall_daily": _ENTERPRISE_FIREWALL,
        "features"      : ["Unlimited scans", "Everything in Pro", "Unlimited people per workspace",
                           *_firewall_feature(_ENTERPRISE_FIREWALL, "AI firewall API"), "Priority support"],
    },
}


def plan_limit(plan: str) -> Optional[int]:
    """Monthly scan limit for a plan (None = unlimited). Unknown plans get the free limit."""
    return PLANS.get(plan, PLANS["free"])["scan_limit"]


def remediation_limit(plan: str) -> int:
    """Hardened-prompt suggestions per day for a plan."""
    return _REMEDIATION_DAILY.get(plan, _REMEDIATION_DAILY["free"])


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
        entry["yearly"] = None
        if plan.get("yearly_price_id") and billing_enabled():
            live = _live_price(plan["yearly_price_id"])
            if live:
                entry["yearly"] = {"amount": live["amount"], "currency": live["currency"], "interval": "year"}
        out[key] = entry
    return out


def _price_ids(plan: dict) -> set:
    return {p for p in (plan.get("price_id"), plan.get("yearly_price_id")) if p}


_LIVE_STATUSES = ("active", "trialing", "past_due")


def _switch_subscription(stripe, user: dict, plan: str, price_id: str) -> dict:
    """Moves an existing subscription to another price (prorated) instead of starting a second one.
    {} when there is no live subscription to switch, so the caller opens a normal checkout."""
    sub_id = user.get("stripe_subscription_id")
    if not sub_id:
        return {}
    try:
        sub = stripe.Subscription.retrieve(sub_id)
    except Exception as e:
        if getattr(e, "code", None) == "resource_missing":
            return {}
        raise
    if sub.get("status") not in _LIVE_STATUSES:
        return {}
    # the item that pays for the plan: a subscription can carry others (an add-on set up in the
    # Stripe dashboard, say), and swapping one of those for the plan's price would bill twice
    items = (sub.get("items") or {}).get("data") or []
    plan_prices = set().union(*(_price_ids(p) for p in PLANS.values()))
    item = next((i for i in items if (i.get("price") or {}).get("id") in plan_prices), items[0] if items else None)
    if not item:
        return {}
    if (item.get("price") or {}).get("id") == price_id:
        return {"error": "You're already on this plan"}
    stripe.Subscription.modify(sub_id, items=[{"id": item["id"], "price": price_id}],
                               proration_behavior="create_prorations",
                               metadata={"user_id": user["id"], "plan": plan})
    # customer.subscription.updated then sets the plan, from the new price
    return {"url": f"{config.APP_URL}/settings?payment=updated", "updated": True}


def create_checkout_session(plan: str, user: dict, interval: str = "month") -> dict:
    """Stripe Checkout for a subscription. Returns {"url", "session_id"}, or {"url", "updated"} when an
    existing subscription was switched to this plan, or {"error"}."""
    if plan not in PLANS or not PLANS[plan]["price_id"]:
        return {"error": f"The '{plan}' plan can't be bought online"}
    price_id = PLANS[plan]["yearly_price_id"] if interval == "year" else PLANS[plan]["price_id"]
    if not price_id:
        return {"error": f"The '{plan}' plan has no yearly price"}
    try:
        stripe = _stripe()
        switched = _switch_subscription(stripe, user, plan, price_id)
        if switched:
            return switched
        metadata = {"user_id": user["id"], "plan": plan}
        params = {
            "mode"               : "subscription",
            "line_items"         : [{"price": price_id, "quantity": 1}],
            "client_reference_id": user["id"],
            "metadata"           : metadata,
            "subscription_data"  : {"metadata": metadata},
            "success_url"        : f"{config.APP_URL}/settings?payment=success&session_id={{CHECKOUT_SESSION_ID}}",
            "cancel_url"         : f"{config.APP_URL}/pricing?payment=cancelled",
            "allow_promotion_codes": True,
        }
        if config.STRIPE_TRIAL_DAYS > 0 and not user.get("stripe_customer_id"):
            # one trial per customer: anyone who has paid before (and so has a customer) pays now
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


def cancel_subscription(subscription_id: str) -> bool:
    """Cancels immediately (used when an account is deleted). False if Stripe refused or was
    unreachable; a subscription that is already gone counts as cancelled."""
    if not subscription_id or not billing_enabled():
        return True
    stripe = _stripe()
    try:
        stripe.Subscription.cancel(subscription_id)
        return True
    except Exception as e:
        if getattr(e, "code", None) == "resource_missing":
            return True
        log.warning("Couldn't cancel subscription %s", subscription_id, exc_info=True)
        return False


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
        if _price_ids(plan) & price_ids:
            return name
    return (sub.get("metadata") or {}).get("plan")


def _subscription_interval(sub: dict) -> Optional[str]:
    """"month" or "year": how often the subscription's plan is billed (None when it can't tell)."""
    items = (sub.get("items") or {}).get("data") or []
    for item in items:
        price_id = (item.get("price") or {}).get("id")
        for plan in PLANS.values():
            if price_id and price_id == plan.get("yearly_price_id"):
                return "year"
            if price_id and price_id == plan.get("price_id"):
                return "month"
    for item in items:
        interval = (((item.get("price") or {}).get("recurring")) or {}).get("interval")
        if interval in ("month", "year"):
            return interval
    return None


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
              "customer_id": obj.get("customer"), "subscription_id": None, "created": event.get("created")}

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
            result["interval"] = _subscription_interval(obj)
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
