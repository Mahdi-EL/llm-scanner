"""Creates what billing needs in a Stripe account and prints the settings to copy.

    STRIPE_SECRET_KEY=sk_test_... python backend/stripe_setup.py --api-url https://your-api.example.com

It creates (or finds, when run again) a product per paid plan with a monthly and a yearly price,
and a webhook endpoint for the events the API handles. Prices are found again by their lookup
keys, so running it twice changes nothing. Run it with a test key first; then with the live key.
"""
import argparse
import os
import sys

PLANS = {"pro": ("LLM Scanner Pro", 4900), "enterprise": ("LLM Scanner Enterprise", 19900)}
WEBHOOK_EVENTS = ["checkout.session.completed", "customer.subscription.created",
                  "customer.subscription.updated", "customer.subscription.deleted", "invoice.payment_failed"]


def _lookup_key(plan: str, interval: str) -> str:
    return f"llmscanner_{plan}_{interval}"


def _existing_price(stripe, lookup_key: str):
    found = stripe.Price.list(lookup_keys=[lookup_key], active=True, limit=1)["data"]
    return found[0] if found else None


def _product_for(stripe, plan: str, name: str, known_product_id=None):
    if known_product_id:
        return known_product_id
    for product in stripe.Product.list(active=True, limit=100).auto_paging_iter():
        if (product.get("metadata") or {}).get("llmscanner_plan") == plan:
            return product["id"]
    return stripe.Product.create(name=name, metadata={"llmscanner_plan": plan})["id"]


def ensure_prices(stripe, currency: str, amounts: dict, yearly_months: int) -> dict:
    """{plan: {"month": price_id, "year": price_id}}, creating what is missing."""
    out = {}
    for plan, (name, _) in PLANS.items():
        monthly = amounts[plan]
        product_id, ids = None, {}
        for interval, amount in (("month", monthly), ("year", monthly * yearly_months)):
            price = _existing_price(stripe, _lookup_key(plan, interval))
            if price:
                product_id = product_id or (price["product"] if isinstance(price["product"], str)
                                            else price["product"]["id"])
                if price["unit_amount"] != amount or price["currency"] != currency:
                    print(f"  note: {plan}/{interval} already exists at {price['unit_amount'] / 100:.2f} "
                          f"{price['currency'].upper()}; left as it is")
            else:
                product_id = _product_for(stripe, plan, name, product_id)
                price = stripe.Price.create(product=product_id, unit_amount=amount, currency=currency,
                                            recurring={"interval": interval},
                                            lookup_key=_lookup_key(plan, interval))
                print(f"  created {plan} {interval}ly price: {amount / 100:.2f} {currency.upper()}")
            ids[interval] = price["id"]
        out[plan] = ids
    return out


def ensure_webhook(stripe, api_url: str):
    """(endpoint_id, signing secret or None). Stripe shows a secret only when the endpoint is created."""
    url = api_url.rstrip("/") + "/api/stripe-webhook"
    for endpoint in stripe.WebhookEndpoint.list(limit=100).auto_paging_iter():
        if endpoint["url"] == url:
            missing = set(WEBHOOK_EVENTS) - set(endpoint.get("enabled_events") or [])
            if missing and "*" not in (endpoint.get("enabled_events") or []):
                stripe.WebhookEndpoint.modify(endpoint["id"],
                                              enabled_events=sorted(set(endpoint["enabled_events"]) | missing))
                print(f"  added {len(missing)} event(s) to the existing webhook")
            return endpoint["id"], None
    endpoint = stripe.WebhookEndpoint.create(url=url, enabled_events=WEBHOOK_EVENTS,
                                             description="LLM Scanner plans and billing")
    print(f"  created webhook endpoint {url}")
    return endpoint["id"], endpoint.get("secret")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--api-url", required=True, help="public URL of the API, e.g. https://api.example.com")
    parser.add_argument("--currency", default="eur")
    parser.add_argument("--pro", type=int, default=PLANS["pro"][1], help="Pro monthly price in cents")
    parser.add_argument("--enterprise", type=int, default=PLANS["enterprise"][1],
                        help="Enterprise monthly price in cents")
    parser.add_argument("--yearly-months", type=int, default=10,
                        help="a yearly price costs this many months (10 = two months free)")
    args = parser.parse_args(argv)

    key = os.getenv("STRIPE_SECRET_KEY", "")
    if not key.startswith(("sk_test_", "sk_live_", "rk_test_", "rk_live_")):
        print("Set STRIPE_SECRET_KEY to your Stripe secret key (sk_test_... first).", file=sys.stderr)
        return 2
    import stripe
    stripe.api_key = key
    mode = "LIVE" if "_live_" in key else "test"
    print(f"Setting up Stripe billing in {mode} mode\n")
    prices = ensure_prices(stripe, args.currency.lower(), {"pro": args.pro, "enterprise": args.enterprise},
                           args.yearly_months)
    _, secret = ensure_webhook(stripe, args.api_url)

    print("\nSet these on the API server (Railway → Variables, or .env):\n")
    print(f"STRIPE_SECRET_KEY={key[:12]}...   (the key you just used)")
    print(f"STRIPE_WEBHOOK_SECRET={secret or '<existing endpoint: copy its signing secret from Developers → Webhooks>'}")
    print(f"STRIPE_PRO_PRICE_ID={prices['pro']['month']}")
    print(f"STRIPE_PRO_YEARLY_PRICE_ID={prices['pro']['year']}")
    print(f"STRIPE_ENTERPRISE_PRICE_ID={prices['enterprise']['month']}")
    print(f"STRIPE_ENTERPRISE_YEARLY_PRICE_ID={prices['enterprise']['year']}")
    print("STRIPE_TRIAL_DAYS=14            # optional: first-time customers only")
    print("\nThen turn on the customer portal (Settings → Billing → Customer portal) so customers can")
    print("update cards and cancel, and buy a plan once with a test card (4242 4242 4242 4242).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
