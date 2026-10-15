import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import hashlib
import secrets
from datetime import datetime
from database import init_db, DB_PATH
import sqlite3


# ── Tenant Plans ──────────────────────────────────────────────
PLANS = {
    "starter": {
        "name"           : "Starter",
        "price_monthly"  : 49,
        "scans_per_month": 5,
        "max_users"      : 1,
        "features"       : [
            "basic_scan",
            "pdf_report",
            "html_report"
        ]
    },
    "pro": {
        "name"           : "Pro",
        "price_monthly"  : 99,
        "scans_per_month": 50,
        "max_users"      : 5,
        "features"       : [
            "basic_scan",
            "deep_scan",
            "pdf_report",
            "html_report",
            "markdown_report",
            "auto_discovery",
            "compare_scans",
            "monitoring"
        ]
    },
    "agency": {
        "name"           : "Agency",
        "price_monthly"  : 299,
        "scans_per_month": -1,  # Unlimited
        "max_users"      : -1,  # Unlimited
        "features"       : [
            "basic_scan",
            "deep_scan",
            "pdf_report",
            "html_report",
            "markdown_report",
            "auto_discovery",
            "compare_scans",
            "monitoring",
            "custom_branding",
            "api_access",
            "priority_support",
            "webhook_notifications",
            "audit_trail"
        ]
    }
}


# ── Tenant Manager ────────────────────────────────────────────
class TenantManager:
    """
    Manages multiple tenants (customers) in LLM Scanner.
    Each tenant has their own isolated data and settings.
    """

    def __init__(self):
        init_db()
        self._ensure_tenant_tables()

    def _ensure_tenant_tables(self):
        """Creates tenant-specific tables if not exist."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        # Tenants table
        c.execute("""
            CREATE TABLE IF NOT EXISTS tenants (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id     TEXT UNIQUE NOT NULL,
                company_name  TEXT NOT NULL,
                email         TEXT UNIQUE NOT NULL,
                plan          TEXT DEFAULT 'starter',
                api_key       TEXT UNIQUE NOT NULL,
                api_key_hash  TEXT NOT NULL,
                scans_used    INTEGER DEFAULT 0,
                scans_limit   INTEGER DEFAULT 5,
                is_active     INTEGER DEFAULT 1,
                created_at    TEXT NOT NULL,
                expires_at    TEXT,
                settings      TEXT DEFAULT '{}'
            )
        """)

        # Tenant users table
        c.execute("""
            CREATE TABLE IF NOT EXISTS tenant_users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id   TEXT NOT NULL,
                username    TEXT NOT NULL,
                email       TEXT NOT NULL,
                role        TEXT DEFAULT 'viewer',
                password_hash TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                last_login  TEXT,
                UNIQUE(tenant_id, username)
            )
        """)

        # Tenant scans table
        c.execute("""
            CREATE TABLE IF NOT EXISTS tenant_scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id   TEXT NOT NULL,
                scan_id     TEXT NOT NULL,
                created_at  TEXT NOT NULL
            )
        """)

        conn.commit()
        conn.close()

    def create_tenant(
        self,
        company_name,
        email,
        plan="starter"
    ):
        """
        Creates a new tenant account.
        Returns tenant_id and api_key.
        """
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        try:
            # Generate IDs
            tenant_id    = f"ten_{secrets.token_hex(8)}"
            api_key      = f"lls_{secrets.token_urlsafe(32)}"
            api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            plan_data    = PLANS.get(plan, PLANS["starter"])
            scans_limit  = plan_data["scans_per_month"]

            c.execute("""
                INSERT INTO tenants (
                    tenant_id, company_name, email,
                    plan, api_key, api_key_hash,
                    scans_limit, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tenant_id,
                company_name,
                email,
                plan,
                api_key,
                api_key_hash,
                scans_limit,
                datetime.now().isoformat()
            ))

            conn.commit()

            print(f"\n  Tenant created !")
            print(f"  Company   : {company_name}")
            print(f"  Plan      : {plan}")
            print(f"  Tenant ID : {tenant_id}")
            print(f"  API Key   : {api_key}")
            print(f"  Save the API key — it won't be shown again !")

            return tenant_id, api_key

        except sqlite3.IntegrityError as e:
            print(f"  Error creating tenant : {e}")
            return None, None
        finally:
            conn.close()

    def get_tenant_by_api_key(self, api_key):
        """Gets tenant by API key."""
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("""
            SELECT * FROM tenants
            WHERE api_key_hash = ? AND is_active = 1
        """, (api_key_hash,))

        row = c.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_tenant(self, tenant_id):
        """Gets tenant by ID."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute(
            "SELECT * FROM tenants WHERE tenant_id = ?",
            (tenant_id,)
        )
        row = c.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_all_tenants(self):
        """Gets all tenants."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("SELECT * FROM tenants ORDER BY created_at DESC")
        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return rows

    def check_scan_quota(self, tenant_id):
        """
        Checks if tenant has remaining scan quota.
        Returns (allowed, remaining, limit)
        """
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return False, 0, 0

        limit = tenant["scans_limit"]

        # Unlimited plan
        if limit == -1:
            return True, -1, -1

        used      = tenant["scans_used"]
        remaining = limit - used

        return remaining > 0, remaining, limit

    def increment_scan_count(self, tenant_id):
        """Increments scan count for tenant."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            UPDATE tenants
            SET scans_used = scans_used + 1
            WHERE tenant_id = ?
        """, (tenant_id,))

        conn.commit()
        conn.close()

    def record_tenant_scan(self, tenant_id, scan_id):
        """Records a scan for a tenant."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT INTO tenant_scans (tenant_id, scan_id, created_at)
            VALUES (?, ?, ?)
        """, (tenant_id, scan_id, datetime.now().isoformat()))

        conn.commit()
        conn.close()
        self.increment_scan_count(tenant_id)

    def get_tenant_scans(self, tenant_id):
        """Gets all scans for a tenant."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("""
            SELECT ts.*, s.security_score, s.status, s.target_name
            FROM tenant_scans ts
            LEFT JOIN scans s ON ts.scan_id = s.scan_id
            WHERE ts.tenant_id = ?
            ORDER BY ts.created_at DESC
        """, (tenant_id,))

        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return rows

    def has_feature(self, tenant_id, feature):
        """Checks if tenant's plan includes a feature."""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return False

        plan      = tenant.get("plan", "starter")
        plan_data = PLANS.get(plan, PLANS["starter"])
        features  = plan_data.get("features", [])

        return feature in features

    def upgrade_plan(self, tenant_id, new_plan):
        """Upgrades tenant to a new plan."""
        if new_plan not in PLANS:
            print(f"Invalid plan: {new_plan}")
            return False

        conn      = sqlite3.connect(DB_PATH)
        c         = conn.cursor()
        plan_data = PLANS[new_plan]

        c.execute("""
            UPDATE tenants
            SET plan = ?, scans_limit = ?
            WHERE tenant_id = ?
        """, (new_plan, plan_data["scans_per_month"], tenant_id))

        conn.commit()
        conn.close()

        print(f"  Tenant {tenant_id} upgraded to {new_plan}")
        return True

    def reset_monthly_quota(self, tenant_id):
        """Resets monthly scan quota for tenant."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            UPDATE tenants SET scans_used = 0
            WHERE tenant_id = ?
        """, (tenant_id,))

        conn.commit()
        conn.close()

    def add_user(
        self,
        tenant_id,
        username,
        email,
        password,
        role="viewer"
    ):
        """Adds a user to a tenant."""
        conn          = sqlite3.connect(DB_PATH)
        c             = conn.cursor()
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        try:
            c.execute("""
                INSERT INTO tenant_users (
                    tenant_id, username, email,
                    role, password_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                tenant_id, username, email,
                role, password_hash, datetime.now().isoformat()
            ))
            conn.commit()
            print(f"  User {username} added to tenant {tenant_id}")
            return True
        except sqlite3.IntegrityError:
            print(f"  User {username} already exists")
            return False
        finally:
            conn.close()

    def get_tenant_users(self, tenant_id):
        """Gets all users for a tenant."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("""
            SELECT id, tenant_id, username, email, role, created_at
            FROM tenant_users WHERE tenant_id = ?
        """, (tenant_id,))

        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return rows

    def print_tenant_info(self, tenant_id):
        """Prints full tenant info."""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            print(f"Tenant not found: {tenant_id}")
            return

        plan_data = PLANS.get(tenant["plan"], {})
        allowed, remaining, limit = self.check_scan_quota(tenant_id)
        users  = self.get_tenant_users(tenant_id)
        scans  = self.get_tenant_scans(tenant_id)

        print(f"\n  {'='*50}")
        print(f"  TENANT INFO")
        print(f"  {'='*50}")
        print(f"  Company   : {tenant['company_name']}")
        print(f"  Email     : {tenant['email']}")
        print(f"  Plan      : {tenant['plan'].upper()}")
        print(f"  Price     : {plan_data.get('price_monthly', 0)}€/month")
        print(f"  Scans     : {tenant['scans_used']} / "
              f"{'∞' if limit == -1 else limit}")
        print(f"  Remaining : {'∞' if limit == -1 else remaining}")
        print(f"  Users     : {len(users)}")
        print(f"  Total Scans: {len(scans)}")
        print(f"  Active    : {'Yes' if tenant['is_active'] else 'No'}")
        print(f"  Created   : {tenant['created_at'][:10]}")
        print()
        print(f"  Features  :")
        for feature in plan_data.get("features", []):
            print(f"    ✅ {feature}")
        print(f"  {'='*50}\n")

    def global_stats(self):
        """Returns global stats across all tenants."""
        tenants = self.get_all_tenants()

        stats = {
            "total_tenants"  : len(tenants),
            "active_tenants" : sum(1 for t in tenants if t["is_active"]),
            "total_scans"    : sum(t["scans_used"] for t in tenants),
            "by_plan"        : {},
            "mrr"            : 0
        }

        for tenant in tenants:
            plan = tenant["plan"]
            if plan not in stats["by_plan"]:
                stats["by_plan"][plan] = 0
            stats["by_plan"][plan] += 1
            stats["mrr"] += PLANS.get(plan, {}).get("price_monthly", 0)

        return stats

    def print_global_stats(self):
        """Prints global business stats."""
        stats = self.global_stats()

        print(f"\n  {'='*50}")
        print(f"  LLM SCANNER — BUSINESS STATS")
        print(f"  {'='*50}")
        print(f"  Total Tenants  : {stats['total_tenants']}")
        print(f"  Active Tenants : {stats['active_tenants']}")
        print(f"  Total Scans    : {stats['total_scans']}")
        print(f"  MRR            : {stats['mrr']}€/month")
        print(f"  ARR            : {stats['mrr'] * 12}€/year")
        print()
        print(f"  By Plan :")
        for plan, count in stats["by_plan"].items():
            price = PLANS.get(plan, {}).get("price_monthly", 0)
            print(f"    {plan:<10} : {count} tenants × {price}€")
        print(f"  {'='*50}\n")


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Tenant Manager"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Create tenant
    p_create = subparsers.add_parser("create")
    p_create.add_argument("--company", required=True)
    p_create.add_argument("--email",   required=True)
    p_create.add_argument("--plan",    default="starter",
        choices=list(PLANS.keys()))

    # Info
    p_info = subparsers.add_parser("info")
    p_info.add_argument("tenant_id")

    # Stats
    subparsers.add_parser("stats")

    # List
    subparsers.add_parser("list")

    # Upgrade
    p_upgrade = subparsers.add_parser("upgrade")
    p_upgrade.add_argument("tenant_id")
    p_upgrade.add_argument("plan", choices=list(PLANS.keys()))

    args    = parser.parse_args()
    manager = TenantManager()

    if args.command == "create":
        manager.create_tenant(args.company, args.email, args.plan)

    elif args.command == "info":
        manager.print_tenant_info(args.tenant_id)

    elif args.command == "stats":
        manager.print_global_stats()

    elif args.command == "list":
        tenants = manager.get_all_tenants()
        print(f"\n  All Tenants ({len(tenants)}) :")
        for t in tenants:
            print(
                f"  [{t['plan'].upper():<8}] "
                f"{t['company_name']:<25} "
                f"{t['scans_used']} scans"
            )

    elif args.command == "upgrade":
        manager.upgrade_plan(args.tenant_id, args.plan)

    else:
        parser.print_help()
        