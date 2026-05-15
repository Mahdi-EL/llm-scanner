import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import hashlib
from datetime import datetime, timedelta
from database import DB_PATH
import sqlite3


# ── Audit Event Types ─────────────────────────────────────────
AUDIT_EVENTS = {
    # Authentication
    "auth.login"          : "User logged in",
    "auth.logout"         : "User logged out",
    "auth.login_failed"   : "Failed login attempt",
    "auth.token_created"  : "JWT token created",
    "auth.token_expired"  : "JWT token expired",

    # Scans
    "scan.created"        : "New scan started",
    "scan.completed"      : "Scan completed",
    "scan.failed"         : "Scan failed",
    "scan.deleted"        : "Scan deleted",
    "scan.downloaded"     : "Report downloaded",

    # Tenants
    "tenant.created"      : "New tenant created",
    "tenant.updated"      : "Tenant settings updated",
    "tenant.plan_changed" : "Tenant plan changed",
    "tenant.deleted"      : "Tenant deleted",

    # Users
    "user.created"        : "New user created",
    "user.role_changed"   : "User role changed",
    "user.deleted"        : "User deleted",
    "user.permission_changed": "User permission changed",

    # API
    "api.key_created"     : "API key created",
    "api.key_revoked"     : "API key revoked",
    "api.rate_limited"    : "Request rate limited",

    # Security
    "security.xss_blocked": "XSS attempt blocked",
    "security.injection"  : "Injection attempt detected",
    "security.brute_force": "Brute force detected",

    # Webhooks
    "webhook.created"     : "Webhook registered",
    "webhook.deleted"     : "Webhook unregistered",
    "webhook.fired"       : "Webhook event fired",
    "webhook.failed"      : "Webhook delivery failed",

    # Reports
    "report.generated"    : "Report generated",
    "report.exported"     : "Report exported",

    # Settings
    "settings.updated"    : "Settings updated",
    "branding.updated"    : "Branding updated",
}

# Risk levels for events
RISK_LEVELS = {
    "auth.login_failed"   : "HIGH",
    "security.xss_blocked": "HIGH",
    "security.injection"  : "HIGH",
    "security.brute_force": "CRITICAL",
    "api.key_revoked"     : "MEDIUM",
    "tenant.deleted"      : "HIGH",
    "user.deleted"        : "MEDIUM",
    "scan.deleted"        : "LOW",
    "auth.login"          : "INFO",
    "scan.created"        : "INFO",
    "scan.completed"      : "INFO",
}


# ── Audit Logger ──────────────────────────────────────────────
class AuditLogger:
    """
    Comprehensive audit trail system.
    Records all important actions in LLM Scanner.
    """

    def __init__(self):
        self._ensure_tables()

    def _ensure_tables(self):
        """Creates audit tables."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id    TEXT UNIQUE NOT NULL,
                event_type  TEXT NOT NULL,
                tenant_id   TEXT,
                user_id     TEXT,
                ip_address  TEXT,
                user_agent  TEXT,
                resource_id TEXT,
                resource_type TEXT,
                action      TEXT NOT NULL,
                result      TEXT DEFAULT 'success',
                details     TEXT,
                risk_level  TEXT DEFAULT 'INFO',
                duration_ms INTEGER,
                created_at  TEXT NOT NULL
            )
        """)

        # Audit summary table
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_summary (
                id              INTEGER PRIMARY KEY,
                total_events    INTEGER DEFAULT 0,
                high_risk_events INTEGER DEFAULT 0,
                failed_logins   INTEGER DEFAULT 0,
                blocked_attacks INTEGER DEFAULT 0,
                last_updated    TEXT
            )
        """)

        c.execute(
            "INSERT OR IGNORE INTO audit_summary (id) VALUES (1)"
        )

        conn.commit()
        conn.close()

    def log(
        self,
        event_type,
        action,
        tenant_id  =None,
        user_id    =None,
        ip_address =None,
        user_agent =None,
        resource_id=None,
        resource_type=None,
        result     ="success",
        details    =None,
        duration_ms=None
    ):
        """
        Logs an audit event.
        Returns the event_id.
        """
        import secrets

        if event_type not in AUDIT_EVENTS:
            event_type = "settings.updated"

        event_id   = f"evt_{secrets.token_hex(8)}"
        risk_level = RISK_LEVELS.get(event_type, "INFO")

        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT INTO audit_log (
                event_id, event_type, tenant_id, user_id,
                ip_address, user_agent, resource_id, resource_type,
                action, result, details, risk_level,
                duration_ms, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_id,
            event_type,
            tenant_id,
            user_id,
            ip_address,
            user_agent,
            resource_id,
            resource_type,
            action,
            result,
            json.dumps(details) if details else None,
            risk_level,
            duration_ms,
            datetime.now().isoformat()
        ))

        # Update summary
        c.execute("""
            UPDATE audit_summary SET
                total_events     = total_events + 1,
                high_risk_events = high_risk_events + ?,
                failed_logins    = failed_logins + ?,
                blocked_attacks  = blocked_attacks + ?,
                last_updated     = ?
            WHERE id = 1
        """, (
            1 if risk_level in ("HIGH", "CRITICAL") else 0,
            1 if event_type == "auth.login_failed" else 0,
            1 if "security" in event_type else 0,
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()

        return event_id

    # ── Convenience Methods ───────────────────────────────────

    def log_login(self, user_id, ip_address, success=True, tenant_id=None):
        """Logs a login attempt."""
        return self.log(
            event_type ="auth.login" if success else "auth.login_failed",
            action     =f"User {user_id} login {'succeeded' if success else 'failed'}",
            tenant_id  =tenant_id,
            user_id    =user_id,
            ip_address =ip_address,
            result     ="success" if success else "failed"
        )

    def log_scan(
        self, scan_id, target_name, tenant_id=None,
        user_id=None, ip_address=None
    ):
        """Logs a scan creation."""
        return self.log(
            event_type   ="scan.created",
            action       =f"Scan started for {target_name}",
            tenant_id    =tenant_id,
            user_id      =user_id,
            ip_address   =ip_address,
            resource_id  =scan_id,
            resource_type="scan",
            details      ={"target_name": target_name}
        )

    def log_scan_complete(
        self, scan_id, score, critical_count,
        tenant_id=None, duration_ms=None
    ):
        """Logs scan completion."""
        return self.log(
            event_type    ="scan.completed",
            action        =f"Scan {scan_id} completed — Score: {score}%",
            tenant_id     =tenant_id,
            resource_id   =scan_id,
            resource_type ="scan",
            details       ={
                "security_score": score,
                "critical_count": critical_count
            },
            duration_ms   =duration_ms
        )

    def log_download(
        self, scan_id, format_type, tenant_id=None,
        user_id=None, ip_address=None
    ):
        """Logs report download."""
        return self.log(
            event_type   ="scan.downloaded",
            action       =f"Report downloaded: {scan_id} ({format_type})",
            tenant_id    =tenant_id,
            user_id      =user_id,
            ip_address   =ip_address,
            resource_id  =scan_id,
            resource_type="report",
            details      ={"format": format_type}
        )

    def log_security_event(
        self, event_type, details, ip_address=None, tenant_id=None
    ):
        """Logs a security event."""
        return self.log(
            event_type =event_type,
            action     =AUDIT_EVENTS.get(event_type, event_type),
            tenant_id  =tenant_id,
            ip_address =ip_address,
            result     ="blocked",
            details    =details
        )

    def log_tenant_action(
        self, action, tenant_id, details=None, user_id=None
    ):
        """Logs a tenant-related action."""
        return self.log(
            event_type   ="tenant.updated",
            action       =action,
            tenant_id    =tenant_id,
            user_id      =user_id,
            resource_id  =tenant_id,
            resource_type="tenant",
            details      =details
        )

    # ── Query Methods ─────────────────────────────────────────

    def get_events(
        self,
        tenant_id  =None,
        event_type =None,
        risk_level =None,
        hours      =24,
        limit      =100
    ):
        """Gets audit events with filters."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        since = (
            datetime.now() - timedelta(hours=hours)
        ).isoformat()

        query  = "SELECT * FROM audit_log WHERE created_at > ?"
        params = [since]

        if tenant_id:
            query  += " AND tenant_id = ?"
            params.append(tenant_id)

        if event_type:
            query  += " AND event_type = ?"
            params.append(event_type)

        if risk_level:
            query  += " AND risk_level = ?"
            params.append(risk_level)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        c.execute(query, params)
        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return rows

    def get_security_events(self, hours=24):
        """Gets high-risk security events."""
        return self.get_events(
            risk_level="HIGH", hours=hours
        ) + self.get_events(
            risk_level="CRITICAL", hours=hours
        )

    def get_tenant_audit(self, tenant_id, hours=168):
        """Gets full audit trail for a tenant."""
        return self.get_events(
            tenant_id=tenant_id, hours=hours
        )

    def get_summary(self):
        """Gets audit summary statistics."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("SELECT * FROM audit_summary WHERE id = 1")
        summary = dict(c.fetchone() or {})

        # Event counts by type (last 24h)
        since = (datetime.now() - timedelta(hours=24)).isoformat()
        c.execute("""
            SELECT event_type, COUNT(*) as count
            FROM audit_log
            WHERE created_at > ?
            GROUP BY event_type
            ORDER BY count DESC
            LIMIT 10
        """, (since,))
        summary["top_events_24h"] = {
            row["event_type"]: row["count"]
            for row in c.fetchall()
        }

        # Unique IPs
        c.execute("""
            SELECT COUNT(DISTINCT ip_address) as count
            FROM audit_log WHERE created_at > ?
        """, (since,))
        row = c.fetchone()
        summary["unique_ips_24h"] = row["count"] if row else 0

        conn.close()
        return summary

    def export_audit_log(
        self,
        tenant_id=None,
        hours=720,  # 30 days
        output_path=None
    ):
        """Exports audit log to JSON file."""
        events = self.get_events(
            tenant_id=tenant_id,
            hours    =hours,
            limit    =10000
        )

        output = output_path or \
                 f"results/audit_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        os.makedirs("results", exist_ok=True)

        data = {
            "exported_at" : datetime.now().isoformat(),
            "tenant_id"   : tenant_id,
            "period_hours": hours,
            "total_events": len(events),
            "events"      : events
        }

        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"  Audit log exported : {output}")
        print(f"  Total events       : {len(events)}")
        return output

    def generate_audit_report(self, tenant_id=None):
        """Generates a human-readable audit report."""
        summary = self.get_summary()
        events  = self.get_events(
            tenant_id=tenant_id, hours=168, limit=1000
        )

        high_risk = [
            e for e in events
            if e["risk_level"] in ("HIGH", "CRITICAL")
        ]

        print(f"\n  {'='*60}")
        print(f"  AUDIT TRAIL REPORT")
        if tenant_id:
            print(f"  Tenant : {tenant_id}")
        print(f"  Period : Last 7 days")
        print(f"  {'='*60}")
        print(f"\n  Summary :")
        print(f"    Total events       : {summary.get('total_events', 0)}")
        print(f"    High risk events   : {summary.get('high_risk_events', 0)}")
        print(f"    Failed logins      : {summary.get('failed_logins', 0)}")
        print(f"    Blocked attacks    : {summary.get('blocked_attacks', 0)}")
        print(f"    Unique IPs (24h)   : {summary.get('unique_ips_24h', 0)}")

        if high_risk:
            print(f"\n  High Risk Events ({len(high_risk)}) :")
            for e in high_risk[:10]:
                print(
                    f"    [{e['risk_level']:<8}] "
                    f"{e['event_type']:<30} "
                    f"{e['created_at'][:16]}"
                )

        top_events = summary.get("top_events_24h", {})
        if top_events:
            print(f"\n  Top Events (last 24h) :")
            for event_type, count in list(top_events.items())[:5]:
                desc = AUDIT_EVENTS.get(event_type, event_type)
                print(f"    {count:>5}x {desc}")

        print(f"\n  {'='*60}\n")


# ── Audit Middleware ──────────────────────────────────────────
def add_audit_middleware(app):
    """
    Adds audit logging middleware to FastAPI.
    Automatically logs all API requests.
    """
    import time as time_module
    from fastapi import Request

    logger = AuditLogger()

    @app.middleware("http")
    async def audit_middleware(request: Request, call_next):
        start     = time_module.time()
        ip        = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("User-Agent", "")

        response  = await call_next(request)

        duration_ms = int((time_module.time() - start) * 1000)
        method      = request.method
        path        = str(request.url.path)

        # Only log important endpoints
        important = [
            "/scan", "/auth", "/download",
            "/tenant", "/user", "/webhook"
        ]
        if any(imp in path for imp in important):
            event_type = "scan.created" if "/scan" in path else \
                         "auth.login" if "/auth" in path else \
                         "scan.downloaded" if "/download" in path else \
                         "settings.updated"

            logger.log(
                event_type =event_type,
                action     =f"{method} {path}",
                ip_address =ip,
                user_agent =user_agent,
                result     ="success" if response.status_code < 400 else "failed",
                details    ={"status_code": response.status_code},
                duration_ms=duration_ms
            )

        return response

    return app


# ── Global Audit Logger ───────────────────────────────────────
_global_logger = None


def get_audit_logger():
    """Returns the global audit logger (singleton)."""
    global _global_logger
    if _global_logger is None:
        _global_logger = AuditLogger()
    return _global_logger


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Audit Trail"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Report
    p_report = subparsers.add_parser("report")
    p_report.add_argument("--tenant", default=None)

    # Export
    p_export = subparsers.add_parser("export")
    p_export.add_argument("--tenant", default=None)
    p_export.add_argument("--hours",  type=int, default=720)
    p_export.add_argument("--output", default=None)

    # Events
    p_events = subparsers.add_parser("events")
    p_events.add_argument("--tenant", default=None)
    p_events.add_argument("--type",   default=None)
    p_events.add_argument("--risk",   default=None)
    p_events.add_argument("--hours",  type=int, default=24)
    p_events.add_argument("--limit",  type=int, default=20)

    # Test
    subparsers.add_parser("test")

    # List event types
    subparsers.add_parser("list-events")

    args   = parser.parse_args()
    logger = AuditLogger()

    if args.command == "report":
        logger.generate_audit_report(args.tenant)

    elif args.command == "export":
        logger.export_audit_log(
            tenant_id  =args.tenant,
            hours      =args.hours,
            output_path=args.output
        )

    elif args.command == "events":
        events = logger.get_events(
            tenant_id =args.tenant,
            event_type=args.type,
            risk_level=args.risk,
            hours     =args.hours,
            limit     =args.limit
        )
        print(f"\n  Audit Events ({len(events)}) :")
        print(f"  {'='*70}")
        for e in events:
            print(
                f"  [{e['risk_level']:<8}] "
                f"{e['event_type']:<30} "
                f"{e['created_at'][:16]} "
                f"{e['ip_address'] or 'N/A'}"
            )

    elif args.command == "test":
        print("  Testing audit logger...")

        logger.log_login("admin", "127.0.0.1", True)
        print("  ✅ Login logged")

        logger.log_login("hacker", "1.2.3.4", False)
        print("  ✅ Failed login logged")

        logger.log_scan("scan_001", "Banking App", "ten_abc")
        print("  ✅ Scan logged")

        logger.log_security_event(
            "security.xss_blocked",
            {"payload": "<script>alert(1)</script>"},
            "1.2.3.4"
        )
        print("  ✅ Security event logged")

        logger.generate_audit_report()

    elif args.command == "list-events":
        print(f"\n  Available Audit Events ({len(AUDIT_EVENTS)}) :")
        for event_type, desc in AUDIT_EVENTS.items():
            risk = RISK_LEVELS.get(event_type, "INFO")
            print(f"  [{risk:<8}] {event_type:<35} — {desc}")

    else:
        parser.print_help()
        