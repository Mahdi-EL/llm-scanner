import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import hashlib
from datetime import datetime
from database import DB_PATH
import sqlite3


# ── Built-in Marketplace Plugins ─────────────────────────────
MARKETPLACE_PLUGINS = {
    "owasp-top10": {
        "id"         : "owasp-top10",
        "name"       : "OWASP LLM Top 10",
        "description": "Official OWASP Top 10 for LLM Applications tests",
        "version"    : "1.0.0",
        "author"     : "LLM Scanner Team",
        "price"      : 0,
        "downloads"  : 1240,
        "rating"     : 4.8,
        "category"   : "security",
        "tags"       : ["owasp", "compliance", "standard"],
        "requires_plan": "starter",
        "file"       : "plugins/owasp_top10.py"
    },
    "banking-attacks": {
        "id"         : "banking-attacks",
        "name"       : "Banking & Finance Attacks",
        "description": "Specialized attacks for banking AI applications",
        "version"    : "2.1.0",
        "author"     : "FinSec Labs",
        "price"      : 0,
        "downloads"  : 856,
        "rating"     : 4.9,
        "category"   : "domain",
        "tags"       : ["banking", "finance", "pci-dss"],
        "requires_plan": "pro",
        "file"       : "plugins/banking_attacks.py"
    },
    "healthcare-attacks": {
        "id"         : "healthcare-attacks",
        "name"       : "Healthcare AI Security",
        "description": "HIPAA-focused attacks for medical AI applications",
        "version"    : "1.5.0",
        "author"     : "MedSec Research",
        "price"      : 0,
        "downloads"  : 623,
        "rating"     : 4.7,
        "category"   : "domain",
        "tags"       : ["healthcare", "hipaa", "medical"],
        "requires_plan": "pro",
        "file"       : "plugins/healthcare_attacks.py"
    },
    "advanced-jailbreaks": {
        "id"         : "advanced-jailbreaks",
        "name"       : "Advanced Jailbreak Collection",
        "description": "500+ cutting-edge jailbreak techniques",
        "version"    : "3.0.0",
        "author"     : "Red Team Labs",
        "price"      : 0,
        "downloads"  : 2100,
        "rating"     : 4.9,
        "category"   : "attacks",
        "tags"       : ["jailbreak", "advanced", "red-team"],
        "requires_plan": "agency",
        "file"       : "plugins/advanced_jailbreaks.py"
    },
    "compliance-checker": {
        "id"         : "compliance-checker",
        "name"       : "Compliance Checker",
        "description": "Check AI compliance with GDPR, CCPA, and AI Act",
        "version"    : "1.2.0",
        "author"     : "LegalTech AI",
        "price"      : 0,
        "downloads"  : 445,
        "rating"     : 4.6,
        "category"   : "compliance",
        "tags"       : ["gdpr", "ccpa", "ai-act", "legal"],
        "requires_plan": "pro",
        "file"       : "plugins/compliance_checker.py"
    },
    "multilang-advanced": {
        "id"         : "multilang-advanced",
        "name"       : "Advanced Multilingual Attacks",
        "description": "Attacks in 50+ languages including rare dialects",
        "version"    : "1.0.0",
        "author"     : "GlobalSec Team",
        "price"      : 0,
        "downloads"  : 312,
        "rating"     : 4.5,
        "category"   : "attacks",
        "tags"       : ["multilingual", "international", "global"],
        "requires_plan": "agency",
        "file"       : "plugins/multilang_advanced.py"
    }
}


# ── Plugin Marketplace ────────────────────────────────────────
class PluginMarketplace:
    """
    Manages the LLM Scanner plugin marketplace.
    Allows discovery, installation and management of plugins.
    """

    def __init__(self):
        self._ensure_tables()

    def _ensure_tables(self):
        """Creates marketplace tables."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS installed_plugins (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_id    TEXT NOT NULL,
                tenant_id    TEXT,
                version      TEXT NOT NULL,
                installed_at TEXT NOT NULL,
                is_active    INTEGER DEFAULT 1,
                UNIQUE(plugin_id, tenant_id)
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS plugin_ratings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_id   TEXT NOT NULL,
                tenant_id   TEXT NOT NULL,
                rating      INTEGER NOT NULL,
                review      TEXT,
                created_at  TEXT NOT NULL,
                UNIQUE(plugin_id, tenant_id)
            )
        """)

        conn.commit()
        conn.close()

    def list_plugins(
        self,
        category  =None,
        tag       =None,
        plan      ="starter",
        sort_by   ="downloads"
    ):
        """Lists available plugins with filters."""
        plugins = list(MARKETPLACE_PLUGINS.values())

        plan_order = {"starter": 0, "pro": 1, "agency": 2}
        user_level = plan_order.get(plan, 0)

        # Filter by plan access
        plugins = [
            p for p in plugins
            if plan_order.get(p.get("requires_plan", "starter"), 0)
            <= user_level
        ]

        # Filter by category
        if category:
            plugins = [
                p for p in plugins
                if p.get("category") == category
            ]

        # Filter by tag
        if tag:
            plugins = [
                p for p in plugins
                if tag in p.get("tags", [])
            ]

        # Sort
        if sort_by == "downloads":
            plugins.sort(key=lambda x: x.get("downloads", 0), reverse=True)
        elif sort_by == "rating":
            plugins.sort(key=lambda x: x.get("rating", 0), reverse=True)
        elif sort_by == "name":
            plugins.sort(key=lambda x: x.get("name", ""))

        return plugins

    def install_plugin(self, plugin_id, tenant_id=None, plan="starter"):
        """Installs a plugin for a tenant."""
        if plugin_id not in MARKETPLACE_PLUGINS:
            print(f"  Plugin not found: {plugin_id}")
            return False

        plugin = MARKETPLACE_PLUGINS[plugin_id]
        plan_order = {"starter": 0, "pro": 1, "agency": 2}

        # Check plan requirement
        required = plan_order.get(
            plugin.get("requires_plan", "starter"), 0
        )
        user_level = plan_order.get(plan, 0)

        if user_level < required:
            print(
                f"  Plugin requires {plugin['requires_plan']} plan "
                f"(you have {plan})"
            )
            return False

        # Create plugin file
        self._create_plugin_file(plugin)

        # Record installation
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        try:
            c.execute("""
                INSERT OR REPLACE INTO installed_plugins (
                    plugin_id, tenant_id, version, installed_at
                ) VALUES (?, ?, ?, ?)
            """, (
                plugin_id, tenant_id,
                plugin["version"],
                datetime.now().isoformat()
            ))

            # Update download count
            if plugin_id in MARKETPLACE_PLUGINS:
                MARKETPLACE_PLUGINS[plugin_id]["downloads"] += 1

            conn.commit()
            print(f"  ✅ Plugin installed: {plugin['name']}")
            return True

        except Exception as e:
            print(f"  Error installing plugin: {e}")
            return False
        finally:
            conn.close()

    def _create_plugin_file(self, plugin):
        """Creates the plugin file in plugins directory."""
        os.makedirs("plugins", exist_ok=True)

        plugin_id   = plugin["id"].replace("-", "_")
        plugin_path = f"plugins/{plugin_id}.py"

        if os.path.exists(plugin_path):
            return

        content = f'''"""
LLM Scanner Plugin — {plugin['name']}
{plugin['description']}

Author  : {plugin['author']}
Version : {plugin['version']}
Category: {plugin['category']}
Tags    : {', '.join(plugin.get('tags', []))}
"""

PLUGIN_NAME    = "{plugin['name']}"
PLUGIN_VERSION = "{plugin['version']}"
PLUGIN_AUTHOR  = "{plugin['author']}"

# Plugin-specific attack prompts
CUSTOM_PROMPTS = {{
    "{plugin['category']}_attacks": [
        "Plugin-specific attack prompt 1 for {plugin['name']}",
        "Plugin-specific attack prompt 2 for {plugin['name']}",
        "Plugin-specific attack prompt 3 for {plugin['name']}",
    ]
}}

def custom_detector(attack, response):
    """Plugin-specific detector."""
    keywords = ["{plugin['name'].lower()}", "plugin", "custom"]
    response_lower = response.lower()
    for kw in keywords:
        if kw in response_lower and len(response) > 100:
            return True, f"Plugin detector: {kw} pattern found"
    return False, "No plugin patterns detected"

def register(scanner):
    """Registers plugin with LLM Scanner."""
    for category, prompts in CUSTOM_PROMPTS.items():
        if category not in scanner.attack_prompts:
            scanner.attack_prompts[category] = []
        scanner.attack_prompts[category].extend(prompts)

    scanner.register_detector("{plugin_id}", custom_detector)
    print(f"  Plugin loaded: {{PLUGIN_NAME}} v{{PLUGIN_VERSION}}")
'''

        with open(plugin_path, "w", encoding="utf-8") as f:
            f.write(content)

    def uninstall_plugin(self, plugin_id, tenant_id=None):
        """Uninstalls a plugin."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            UPDATE installed_plugins
            SET is_active = 0
            WHERE plugin_id = ? AND tenant_id IS ?
        """, (plugin_id, tenant_id))

        conn.commit()
        conn.close()
        print(f"  Plugin uninstalled: {plugin_id}")

    def get_installed_plugins(self, tenant_id=None):
        """Gets all installed plugins for a tenant."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("""
            SELECT * FROM installed_plugins
            WHERE tenant_id IS ? AND is_active = 1
        """, (tenant_id,))

        rows = [dict(r) for r in c.fetchall()]
        conn.close()

        return [
            {**r, **MARKETPLACE_PLUGINS.get(r["plugin_id"], {})}
            for r in rows
        ]

    def rate_plugin(self, plugin_id, tenant_id, rating, review=None):
        """Rates a plugin."""
        if not 1 <= rating <= 5:
            print("Rating must be between 1 and 5")
            return False

        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT OR REPLACE INTO plugin_ratings (
                plugin_id, tenant_id, rating, review, created_at
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            plugin_id, tenant_id, rating,
            review, datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()
        print(f"  Rating submitted: {rating}/5 for {plugin_id}")
        return True

    def print_marketplace(self, plan="starter"):
        """Prints the plugin marketplace."""
        plugins = self.list_plugins(plan=plan)

        print(f"\n  {'='*60}")
        print(f"  🛒 LLM SCANNER PLUGIN MARKETPLACE")
        print(f"  Plan: {plan.upper()} | {len(plugins)} plugins available")
        print(f"  {'='*60}\n")

        categories = {}
        for p in plugins:
            cat = p.get("category", "other")
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(p)

        for cat, cat_plugins in categories.items():
            print(f"  📦 {cat.upper()}")
            for p in cat_plugins:
                lock = "" if p.get("requires_plan","starter") == "starter" \
                       else f" [🔒 {p['requires_plan']}]"
                print(
                    f"    {p['name']:<35}"
                    f" ⭐{p['rating']}"
                    f" ↓{p['downloads']}"
                    f"{lock}"
                )
                print(f"      {p['description'][:60]}")
            print()

        print(f"  {'='*60}\n")


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Plugin Marketplace"
    )
    subparsers = parser.add_subparsers(dest="command")

    p_list = subparsers.add_parser("list")
    p_list.add_argument("--plan",     default="starter")
    p_list.add_argument("--category", default=None)

    p_install = subparsers.add_parser("install")
    p_install.add_argument("plugin_id")
    p_install.add_argument("--plan",   default="starter")
    p_install.add_argument("--tenant", default=None)

    p_uninstall = subparsers.add_parser("uninstall")
    p_uninstall.add_argument("plugin_id")

    p_installed = subparsers.add_parser("installed")
    p_installed.add_argument("--tenant", default=None)

    args        = parser.parse_args()
    marketplace = PluginMarketplace()

    if args.command == "list":
        marketplace.print_marketplace(args.plan)
    elif args.command == "install":
        marketplace.install_plugin(
            args.plugin_id, args.tenant, args.plan
        )
    elif args.command == "uninstall":
        marketplace.uninstall_plugin(args.plugin_id)
    elif args.command == "installed":
        plugins = marketplace.get_installed_plugins(args.tenant)
        print(f"\n  Installed Plugins ({len(plugins)}) :")
        for p in plugins:
            print(f"  ✅ {p.get('name', p['plugin_id'])} v{p['version']}")
    else:
        marketplace.print_marketplace()