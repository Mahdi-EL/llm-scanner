import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import hashlib
import hmac
import time
import urllib.request
import urllib.error
from datetime import datetime
from database import DB_PATH
import sqlite3


# ── Webhook Events ────────────────────────────────────────────
WEBHOOK_EVENTS = {
    "scan.completed"    : "Fired when a scan completes",
    "scan.failed"       : "Fired when a scan fails",
    "critical.found"    : "Fired when critical vulnerability found",
    "score.dropped"     : "Fired when security score drops",
    "quota.warning"     : "Fired when 80% quota used",
    "quota.exceeded"    : "Fired when quota exceeded",
    "user.created"      : "Fired when new user added",
    "tenant.upgraded"   : "Fired when tenant upgrades plan",
}


# ── Webhook Manager ───────────────────────────────────────────
class WebhookManager:
    """
    Manages webhook subscriptions and deliveries.
    Sends HTTP POST requests to registered URLs
    when events occur.
    """

    def __init__(self):
        self._ensure_tables()

    def _ensure_tables(self):
        """Creates webhook tables."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        # Webhooks table
        c.execute("""
            CREATE TABLE IF NOT EXISTS webhooks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                webhook_id  TEXT UNIQUE NOT NULL,
                tenant_id   TEXT NOT NULL,
                url         TEXT NOT NULL,
                secret      TEXT NOT NULL,
                events      TEXT NOT NULL,
                is_active   INTEGER DEFAULT 1,
                created_at  TEXT NOT NULL,
                last_fired  TEXT,
                total_fired INTEGER DEFAULT 0
            )
        """)

        # Webhook deliveries table
        c.execute("""
            CREATE TABLE IF NOT EXISTS webhook_deliveries (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                webhook_id  TEXT NOT NULL,
                event       TEXT NOT NULL,
                payload     TEXT NOT NULL,
                status_code INTEGER,
                success     INTEGER DEFAULT 0,
                duration_ms INTEGER,
                error       TEXT,
                delivered_at TEXT NOT NULL
            )
        """)

        conn.commit()
        conn.close()

    def register(
        self,
        tenant_id,
        url,
        events=None,
        secret=None
    ):
        """
        Registers a new webhook endpoint.
        Returns webhook_id and secret.
        """
        import secrets as sec

        webhook_id = f"wh_{sec.token_hex(8)}"
        secret     = secret or sec.token_urlsafe(32)
        events     = events or list(WEBHOOK_EVENTS.keys())

        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT INTO webhooks (
                webhook_id, tenant_id, url, secret,
                events, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            webhook_id,
            tenant_id,
            url,
            secret,
            json.dumps(events),
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()

        print(f"  Webhook registered !")
        print(f"  ID     : {webhook_id}")
        print(f"  URL    : {url}")
        print(f"  Events : {', '.join(events)}")
        print(f"  Secret : {secret}")
        print(f"  Use secret to verify webhook signatures")

        return webhook_id, secret

    def unregister(self, webhook_id, tenant_id):
        """Removes a webhook."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            UPDATE webhooks SET is_active = 0
            WHERE webhook_id = ? AND tenant_id = ?
        """, (webhook_id, tenant_id))

        conn.commit()
        conn.close()
        print(f"  Webhook {webhook_id} unregistered")

    def _get_webhooks_for_event(self, tenant_id, event):
        """Gets all active webhooks for a tenant and event."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("""
            SELECT * FROM webhooks
            WHERE tenant_id = ? AND is_active = 1
        """, (tenant_id,))

        webhooks = []
        for row in c.fetchall():
            webhook = dict(row)
            events  = json.loads(webhook["events"])
            if event in events or "*" in events:
                webhooks.append(webhook)

        conn.close()
        return webhooks

    def _sign_payload(self, payload, secret):
        """
        Creates HMAC signature for webhook payload.
        Receivers can verify authenticity with this signature.
        """
        signature = hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"sha256={signature}"

    def _deliver(self, webhook, event, payload_dict):
        """Delivers a webhook to its URL."""
        payload_str = json.dumps(payload_dict)
        signature   = self._sign_payload(payload_str, webhook["secret"])

        headers = {
            "Content-Type"        : "application/json",
            "X-LLMScanner-Event"  : event,
            "X-LLMScanner-Sign"   : signature,
            "X-LLMScanner-Delivery": webhook["webhook_id"],
            "User-Agent"          : "LLMScanner-Webhook/2.0"
        }

        start = time.time()
        try:
            req  = urllib.request.Request(
                webhook["url"],
                data   =payload_str.encode(),
                headers=headers,
                method ="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                status_code = response.status
                success     = 200 <= status_code < 300

        except urllib.error.HTTPError as e:
            status_code = e.code
            success     = False
        except Exception as e:
            status_code = 0
            success     = False

        duration_ms = int((time.time() - start) * 1000)

        # Record delivery
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT INTO webhook_deliveries (
                webhook_id, event, payload, status_code,
                success, duration_ms, delivered_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            webhook["webhook_id"],
            event,
            payload_str[:1000],
            status_code,
            1 if success else 0,
            duration_ms,
            datetime.now().isoformat()
        ))

        c.execute("""
            UPDATE webhooks
            SET total_fired = total_fired + 1,
                last_fired  = ?
            WHERE webhook_id = ?
        """, (datetime.now().isoformat(), webhook["webhook_id"]))

        conn.commit()
        conn.close()

        status = "✅" if success else "❌"
        print(
            f"  {status} Webhook delivered to {webhook['url'][:50]} "
            f"({status_code}, {duration_ms}ms)"
        )

        return success

    def fire(self, tenant_id, event, data=None):
        """
        Fires a webhook event for a tenant.
        Sends to all registered webhooks that subscribe to this event.
        """
        if event not in WEBHOOK_EVENTS:
            print(f"Unknown event: {event}")
            return 0

        webhooks = self._get_webhooks_for_event(tenant_id, event)

        if not webhooks:
            return 0

        payload = {
            "event"     : event,
            "tenant_id" : tenant_id,
            "timestamp" : datetime.now().isoformat(),
            "data"      : data or {}
        }

        print(f"\n  Firing webhook: {event}")
        print(f"  Subscribers: {len(webhooks)}")

        delivered = 0
        for webhook in webhooks:
            if self._deliver(webhook, event, payload):
                delivered += 1

        return delivered

    def fire_scan_completed(self, tenant_id, scan_data):
        """Convenience method for scan.completed event."""
        return self.fire(tenant_id, "scan.completed", {
            "scan_id"       : scan_data.get("scan_id"),
            "target_name"   : scan_data.get("target_name"),
            "security_score": scan_data.get("summary", {}).get(
                "security_score", 0
            ),
            "critical"      : scan_data.get("summary", {}).get("critical", 0),
            "high"          : scan_data.get("summary", {}).get("high", 0),
            "pdf_path"      : scan_data.get("pdf_path"),
        })

    def fire_critical_found(self, tenant_id, finding):
        """Convenience method for critical.found event."""
        return self.fire(tenant_id, "critical.found", {
            "category"  : finding.get("category"),
            "attack"    : finding.get("attack", "")[:100],
            "reason"    : finding.get("reason", ""),
            "score"     : finding.get("score", 0),
        })

    def fire_quota_warning(self, tenant_id, used, limit):
        """Convenience method for quota.warning event."""
        return self.fire(tenant_id, "quota.warning", {
            "scans_used" : used,
            "scans_limit": limit,
            "percentage" : round((used / limit) * 100),
        })

    def get_delivery_history(self, webhook_id, limit=20):
        """Gets delivery history for a webhook."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("""
            SELECT * FROM webhook_deliveries
            WHERE webhook_id = ?
            ORDER BY delivered_at DESC
            LIMIT ?
        """, (webhook_id, limit))

        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return rows

    def get_tenant_webhooks(self, tenant_id):
        """Gets all webhooks for a tenant."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("""
            SELECT * FROM webhooks
            WHERE tenant_id = ? AND is_active = 1
            ORDER BY created_at DESC
        """, (tenant_id,))

        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return rows

    def print_webhook_stats(self, tenant_id):
        """Prints webhook statistics."""
        webhooks = self.get_tenant_webhooks(tenant_id)

        print(f"\n  Webhooks for tenant {tenant_id}")
        print(f"  {'='*50}")

        for wh in webhooks:
            events  = json.loads(wh["events"])
            history = self.get_delivery_history(wh["webhook_id"], 5)
            success = sum(1 for h in history if h["success"])

            print(f"\n  [{wh['webhook_id']}]")
            print(f"  URL         : {wh['url']}")
            print(f"  Events      : {', '.join(events[:3])}...")
            print(f"  Total Fired : {wh['total_fired']}")
            print(f"  Last Fired  : {wh.get('last_fired', 'Never')}")
            print(f"  Recent      : {success}/{len(history)} successful")


# ── Verify Webhook Signature ──────────────────────────────────
def verify_webhook_signature(payload, signature, secret):
    """
    Verifies a webhook signature.
    Call this in your webhook receiver to verify authenticity.

    Usage in your app :
        is_valid = verify_webhook_signature(
            payload   = request.body,
            signature = request.headers["X-LLMScanner-Sign"],
            secret    = "your_webhook_secret"
        )
    """
    expected = hmac.new(
        secret.encode(),
        payload.encode() if isinstance(payload, str) else payload,
        hashlib.sha256
    ).hexdigest()
    expected_sig = f"sha256={expected}"
    return hmac.compare_digest(expected_sig, signature)


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Webhook Manager"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Register
    p_reg = subparsers.add_parser("register")
    p_reg.add_argument("tenant_id")
    p_reg.add_argument("url")
    p_reg.add_argument("--events", nargs="+",
        default=list(WEBHOOK_EVENTS.keys()))

    # List events
    subparsers.add_parser("events")

    # Test fire
    p_fire = subparsers.add_parser("test")
    p_fire.add_argument("tenant_id")
    p_fire.add_argument("event")

    # Stats
    p_stats = subparsers.add_parser("stats")
    p_stats.add_argument("tenant_id")

    args    = parser.parse_args()
    manager = WebhookManager()

    if args.command == "register":
        manager.register(args.tenant_id, args.url, args.events)

    elif args.command == "events":
        print("\n  Available Webhook Events :")
        for event, desc in WEBHOOK_EVENTS.items():
            print(f"  {event:<25} — {desc}")

    elif args.command == "test":
        manager.fire(args.tenant_id, args.event, {
            "test": True,
            "message": "This is a test webhook"
        })

    elif args.command == "stats":
        manager.print_webhook_stats(args.tenant_id)

    else:
        parser.print_help()