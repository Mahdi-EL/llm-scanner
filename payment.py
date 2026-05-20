import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
from typing import Optional

STRIPE_SECRET_KEY       = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET   = os.getenv("STRIPE_WEBHOOK_SECRET", "")
APP_URL                 = os.getenv("APP_URL", "https://llmscanner.vercel.app")

# Price IDs — set in Railway env vars after creating products in Stripe dashboard
PLANS = {
    "pro": {
        "name"      : "Pro",
        "price_id"  : os.getenv("STRIPE_PRO_PRICE_ID", ""),
        "amount"    : 4900,   # cents
        "currency"  : "eur",
        "interval"  : "month",
        "features"  : ["Unlimited scans", "PDF reports", "API access", "Priority support"],
    },
    "enterprise": {
        "name"      : "Enterprise",
        "price_id"  : os.getenv("STRIPE_ENTERPRISE_PRICE_ID", ""),
        "amount"    : 19900,
        "currency"  : "eur",
        "interval"  : "month",
        "features"  : ["Everything in Pro", "White-label", "Custom integrations", "SLA", "Dedicated support"],
    },
}


def _stripe():
    """Returns stripe module, raises if key missing."""
    import stripe as _stripe
    if not STRIPE_SECRET_KEY:
        raise ValueError("STRIPE_SECRET_KEY not configured")
    _stripe.api_key = STRIPE_SECRET_KEY
    return _stripe


def create_checkout_session(plan: str, customer_email: str, user_id: str) -> dict:
    """
    Creates a Stripe Checkout session for the given plan.
    Returns { "url": "...", "session_id": "..." } or { "error": "..." }.
    """
    if plan not in PLANS:
        return {"error": f"Unknown plan: {plan}"}

    price_id = PLANS[plan]["price_id"]
    if not price_id:
        return {"error": f"Stripe price ID not configured for plan '{plan}'"}

    try:
        stripe  = _stripe()
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode                ="subscription",
            customer_email      =customer_email,
            line_items=[{
                "price"   : price_id,
                "quantity": 1,
            }],
            metadata    ={ "user_id": user_id, "plan": plan },
            success_url =f"{APP_URL}/?payment=success&plan={plan}",
            cancel_url  =f"{APP_URL}/pricing?payment=cancelled",
        )
        return {
            "url"       : session.url,
            "session_id": session.id,
        }
    except Exception as e:
        return {"error": str(e)}


def handle_webhook(payload: bytes, sig_header: str) -> dict:
    """
    Processes a Stripe webhook event.
    Returns { "type": "...", "user_id": "...", "plan": "..." } or { "error": "..." }.
    """
    if not STRIPE_WEBHOOK_SECRET:
        return {"error": "Webhook secret not configured"}

    try:
        stripe = _stripe()
        event  = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        return {"error": str(e)}

    evt_type = event["type"]

    if evt_type == "checkout.session.completed":
        session = event["data"]["object"]
        return {
            "type"   : "payment_success",
            "user_id": session["metadata"].get("user_id"),
            "plan"   : session["metadata"].get("plan"),
            "email"  : session.get("customer_email"),
        }

    if evt_type == "customer.subscription.deleted":
        sub = event["data"]["object"]
        return {
            "type"   : "subscription_cancelled",
            "user_id": sub["metadata"].get("user_id"),
        }

    return {"type": evt_type, "handled": False}


def get_plans_public() -> dict:
    """Returns plan info without internal Stripe IDs."""
    return {
        key: {
            "name"    : p["name"],
            "amount"  : p["amount"],
            "currency": p["currency"],
            "interval": p["interval"],
            "features": p["features"],
        }
        for key, p in PLANS.items()
    }
