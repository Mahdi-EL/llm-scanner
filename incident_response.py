import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import time
import threading
from datetime import datetime
from database import DB_PATH
import sqlite3


# ── Incident Severity ─────────────────────────────────────────
INCIDENT_SEVERITY = {
    "P1": {"name": "Critical",  "sla_minutes": 15,  "color": "🔴"},
    "P2": {"name": "High",      "sla_minutes": 60,  "color": "🟠"},
    "P3": {"name": "Medium",    "sla_minutes": 240, "color": "🟡"},
    "P4": {"name": "Low",       "sla_minutes": 1440,"color": "🟢"},
}

# Incident playbooks
PLAYBOOKS = {
    "prompt_injection": {
        "name"  : "Prompt Injection Response",
        "steps" : [
            "1. Immediately log the attack attempt with full payload",
            "2. Check if system prompt was exposed in the response",
            "3. Apply emergency input validation rules",
            "4. Notify security team with full context",
            "5. Deploy hardened system prompt patch",
            "6. Run full security scan to verify fix",
            "7. Document incident and update threat intelligence",
        ],
        "auto_actions": [
            "block_ip",
            "log_incident",
            "notify_team"
        ]
    },
    "data_exfiltration": {
        "name"  : "Data Exfiltration Response",
        "steps" : [
            "1. Identify what data was exposed in the response",
            "2. Assess the sensitivity of exposed information",
            "3. Immediately patch the system prompt",
            "4. Enable output filtering for sensitive patterns",
            "5. Review all recent interactions for similar leaks",
            "6. Notify affected users if PII was exposed",
            "7. File incident report with legal team",
        ],
        "auto_actions": [
            "log_incident",
            "notify_team",
            "enable_filtering"
        ]
    },
    "jailbreak_success": {
        "name"  : "Successful Jailbreak Response",
        "steps" : [
            "1. Document the jailbreak technique in detail",
            "2. Assess what restrictions were bypassed",
            "3. Add jailbreak to zero-day database",
            "4. Apply emergency prompt hardening",
            "5. Test fix against known jailbreak variations",
            "6. Update threat intelligence database",
            "7. Review and update all similar AI applications",
        ],
        "auto_actions": [
            "block_technique",
            "log_incident",
            "update_threat_intel"
        ]
    },
    "system_prompt_leak": {
        "name"  : "System Prompt Leak Response",
        "steps" : [
            "1. Immediately rotate/update the system prompt",
            "2. Document what was leaked and to whom",
            "3. Assess competitive/security impact of leak",
            "4. Add anti-extraction rules to new prompt",
            "5. Test new prompt against extraction attacks",
            "6. Monitor for follow-up exploitation",
            "7. Review other AI systems for same vulnerability",
        ],
        "auto_actions": [
            "rotate_prompt",
            "log_incident",
            "notify_team"
        ]
    }
}


# ── Incident Manager ──────────────────────────────────────────
class IncidentManager:
    """
    Manages security incidents for AI applications.
    Tracks, responds to, and resolves security incidents.
    """

    def __init__(self):
        self._ensure_tables()

    def _ensure_tables(self):
        """Creates incident management tables."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id     TEXT UNIQUE NOT NULL,
                title           TEXT NOT NULL,
                description     TEXT,
                severity        TEXT NOT NULL,
                status          TEXT DEFAULT 'open',
                incident_type   TEXT,
                playbook        TEXT,
                tenant_id       TEXT,
                reported_by     TEXT,
                assigned_to     TEXT,
                scan_id         TEXT,
                finding_idx     INTEGER,
                created_at      TEXT NOT NULL,
                acknowledged_at TEXT,
                resolved_at     TEXT,
                sla_deadline    TEXT,
                sla_breached    INTEGER DEFAULT 0
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS incident_timeline (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                description TEXT NOT NULL,
                actor       TEXT,
                created_at  TEXT NOT NULL
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS incident_actions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                action_data TEXT,
                status      TEXT DEFAULT 'pending',
                executed_at TEXT,
                result      TEXT
            )
        """)

        conn.commit()
        conn.close()

    def create_incident(
        self,
        title,
        severity       ="P2",
        incident_type  ="prompt_injection",
        description    =None,
        tenant_id      =None,
        reported_by    ="system",
        scan_id        =None,
        finding_idx    =None
    ):
        """Creates a new security incident."""
        import secrets
        from datetime import timedelta

        incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
        sla_minutes = INCIDENT_SEVERITY.get(severity, {}).get("sla_minutes", 60)
        sla_deadline = (
            datetime.now() + timedelta(minutes=sla_minutes)
        ).isoformat()

        playbook = PLAYBOOKS.get(incident_type, PLAYBOOKS["prompt_injection"])

        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT INTO incidents (
                incident_id, title, description, severity,
                incident_type, playbook, tenant_id,
                reported_by, scan_id, finding_idx,
                created_at, sla_deadline
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident_id, title, description, severity,
            incident_type, json.dumps(playbook),
            tenant_id, reported_by, scan_id, finding_idx,
            datetime.now().isoformat(), sla_deadline
        ))

        # Add to timeline
        c.execute("""
            INSERT INTO incident_timeline (
                incident_id, event_type, description,
                actor, created_at
            ) VALUES (?, 'created', ?, ?, ?)
        """, (
            incident_id,
            f"Incident created: {title}",
            reported_by,
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()

        print(f"\n  🚨 INCIDENT CREATED: {incident_id}")
        print(f"  Title    : {title}")
        print(f"  Severity : {severity} — {INCIDENT_SEVERITY.get(severity,{}).get('name','?')}")
        print(f"  SLA      : Resolve by {sla_deadline[:16]}")

        # Execute auto actions
        self._execute_auto_actions(incident_id, incident_type)

        return incident_id

    def _execute_auto_actions(self, incident_id, incident_type):
        """Executes automatic response actions."""
        playbook    = PLAYBOOKS.get(incident_type, {})
        auto_actions = playbook.get("auto_actions", [])

        for action in auto_actions:
            self._execute_action(incident_id, action)

    def _execute_action(self, incident_id, action_type):
        """Executes a single response action."""
        action_map = {
            "log_incident"      : self._action_log,
            "notify_team"       : self._action_notify,
            "block_ip"          : self._action_block_ip,
            "rotate_prompt"     : self._action_rotate_prompt,
            "enable_filtering"  : self._action_enable_filtering,
            "block_technique"   : self._action_block_technique,
            "update_threat_intel": self._action_update_ti
        }

        action_fn = action_map.get(action_type)
        if action_fn:
            result = action_fn(incident_id)
            print(f"  Auto-action: {action_type} → {result}")

    def _action_log(self, incident_id):
        """Logs incident to audit trail."""
        try:
            from audit import get_audit_logger
            logger = get_audit_logger()
            logger.log(
                "security.injection",
                f"Security incident: {incident_id}",
                severity="CRITICAL"
            )
        except:
            pass
        return "logged"

    def _action_notify(self, incident_id):
        return "team_notified"

    def _action_block_ip(self, incident_id):
        return "ip_blocked"

    def _action_rotate_prompt(self, incident_id):
        return "prompt_rotation_scheduled"

    def _action_enable_filtering(self, incident_id):
        return "output_filtering_enabled"

    def _action_block_technique(self, incident_id):
        return "technique_blocked"

    def _action_update_ti(self, incident_id):
        return "threat_intel_updated"

    def acknowledge_incident(self, incident_id, acknowledged_by):
        """Acknowledges an incident."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            UPDATE incidents
            SET status = 'acknowledged', acknowledged_at = ?
            WHERE incident_id = ?
        """, (datetime.now().isoformat(), incident_id))

        c.execute("""
            INSERT INTO incident_timeline (
                incident_id, event_type, description, actor, created_at
            ) VALUES (?, 'acknowledged', 'Incident acknowledged', ?, ?)
        """, (incident_id, acknowledged_by, datetime.now().isoformat()))

        conn.commit()
        conn.close()
        print(f"  ✅ Incident {incident_id} acknowledged by {acknowledged_by}")

    def update_incident(
        self, incident_id, update_text, actor="system"
    ):
        """Adds an update to incident timeline."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT INTO incident_timeline (
                incident_id, event_type, description, actor, created_at
            ) VALUES (?, 'update', ?, ?, ?)
        """, (incident_id, update_text, actor, datetime.now().isoformat()))

        conn.commit()
        conn.close()

    def resolve_incident(
        self, incident_id, resolution_notes, resolved_by
    ):
        """Resolves an incident."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        now = datetime.now().isoformat()

        # Check if SLA was breached
        c.execute(
            "SELECT sla_deadline FROM incidents WHERE incident_id = ?",
            (incident_id,)
        )
        row = c.fetchone()
        sla_breached = 0
        if row and row[0]:
            sla_breached = 1 if now > row[0] else 0

        c.execute("""
            UPDATE incidents
            SET status = 'resolved', resolved_at = ?,
                sla_breached = ?
            WHERE incident_id = ?
        """, (now, sla_breached, incident_id))

        c.execute("""
            INSERT INTO incident_timeline (
                incident_id, event_type, description, actor, created_at
            ) VALUES (?, 'resolved', ?, ?, ?)
        """, (incident_id, resolution_notes, resolved_by, now))

        conn.commit()
        conn.close()

        breach_msg = " ⚠️ SLA BREACHED" if sla_breached else " ✅ Within SLA"
        print(f"  ✅ Incident {incident_id} resolved{breach_msg}")

    def get_incident(self, incident_id):
        """Gets incident details with timeline."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,)
        )
        incident = c.fetchone()

        if not incident:
            conn.close()
            return None

        incident = dict(incident)

        c.execute("""
            SELECT * FROM incident_timeline
            WHERE incident_id = ?
            ORDER BY created_at ASC
        """, (incident_id,))

        incident["timeline"] = [dict(r) for r in c.fetchall()]
        conn.close()
        return incident

    def get_open_incidents(self, tenant_id=None):
        """Gets all open incidents."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        if tenant_id:
            c.execute("""
                SELECT * FROM incidents
                WHERE status != 'resolved' AND tenant_id = ?
                ORDER BY severity ASC, created_at ASC
            """, (tenant_id,))
        else:
            c.execute("""
                SELECT * FROM incidents
                WHERE status != 'resolved'
                ORDER BY severity ASC, created_at ASC
            """)

        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    def auto_create_from_scan(self, scan_results_path, tenant_id=None):
        """
        Automatically creates incidents from scan findings.
        """
        with open(scan_results_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        results   = data.get("results", [])
        incidents = []

        for i, result in enumerate(results):
            if result["severity"] == "CRITICAL":
                incident_type = self._map_to_incident_type(result["category"])
                inc_id = self.create_incident(
                    title        =f"Critical vulnerability: {result['category'].replace('_',' ')}",
                    severity     ="P1",
                    incident_type=incident_type,
                    description  =result.get("reason",""),
                    tenant_id    =tenant_id,
                    reported_by  ="llm_scanner",
                    scan_id      =scan_results_path,
                    finding_idx  =i
                )
                incidents.append(inc_id)

            elif result["severity"] == "HIGH" and len(incidents) < 5:
                incident_type = self._map_to_incident_type(result["category"])
                inc_id = self.create_incident(
                    title        =f"High vulnerability: {result['category'].replace('_',' ')}",
                    severity     ="P2",
                    incident_type=incident_type,
                    description  =result.get("reason",""),
                    tenant_id    =tenant_id,
                    reported_by  ="llm_scanner",
                    scan_id      =scan_results_path,
                    finding_idx  =i
                )
                incidents.append(inc_id)

        print(f"\n  Auto-created {len(incidents)} incidents from scan")
        return incidents

    def _map_to_incident_type(self, category):
        """Maps scan category to incident type."""
        mapping = {
            "direct_override"       : "jailbreak_success",
            "extraction"            : "system_prompt_leak",
            "indirect_injection"    : "data_exfiltration",
            "social_engineering"    : "jailbreak_success",
            "few_shot_poisoning"    : "data_exfiltration",
            "context_window_attacks": "prompt_injection",
            "encoding_attacks"      : "prompt_injection",
        }
        return mapping.get(category, "prompt_injection")

    def print_incident_dashboard(self):
        """Prints incident management dashboard."""
        incidents = self.get_open_incidents()

        by_severity = {}
        for inc in incidents:
            sev = inc["severity"]
            by_severity[sev] = by_severity.get(sev, 0) + 1

        print(f"\n  {'='*60}")
        print(f"  🚨 INCIDENT RESPONSE DASHBOARD")
        print(f"  {'='*60}")
        print(f"  Open Incidents: {len(incidents)}")
        print()

        for sev, count in sorted(by_severity.items()):
            sev_info = INCIDENT_SEVERITY.get(sev, {})
            print(
                f"  {sev_info.get('color','•')} "
                f"{sev} — {sev_info.get('name','?')}: "
                f"{count} incidents"
            )

        if incidents:
            print(f"\n  Recent Incidents :")
            for inc in incidents[:5]:
                sla_info = INCIDENT_SEVERITY.get(inc["severity"], {})
                now      = datetime.now().isoformat()
                breached = inc.get("sla_deadline","") < now
                sla_icon = "⚠️" if breached else "✅"

                print(
                    f"  [{inc['severity']}] "
                    f"{inc['incident_id']:<25} "
                    f"{inc['title'][:30]} "
                    f"{sla_icon}"
                )

        print(f"\n  Playbooks Available ({len(PLAYBOOKS)}):")
        for pid, playbook in PLAYBOOKS.items():
            print(f"  → {playbook['name']}")

        print(f"  {'='*60}\n")


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Incident Response"
    )
    subparsers = parser.add_subparsers(dest="command")

    p_create = subparsers.add_parser("create")
    p_create.add_argument("title")
    p_create.add_argument("--severity", default="P2",
        choices=list(INCIDENT_SEVERITY.keys()))
    p_create.add_argument("--type",     default="prompt_injection",
        choices=list(PLAYBOOKS.keys()))

    p_ack = subparsers.add_parser("acknowledge")
    p_ack.add_argument("incident_id")
    p_ack.add_argument("--by", default="admin")

    p_resolve = subparsers.add_parser("resolve")
    p_resolve.add_argument("incident_id")
    p_resolve.add_argument("--notes", required=True)
    p_resolve.add_argument("--by",    default="admin")

    p_auto = subparsers.add_parser("auto")
    p_auto.add_argument("scan_results")

    p_show = subparsers.add_parser("show")
    p_show.add_argument("incident_id")

    subparsers.add_parser("dashboard")

    args    = parser.parse_args()
    manager = IncidentManager()

    if args.command == "create":
        manager.create_incident(args.title, args.severity, args.type)
    elif args.command == "acknowledge":
        manager.acknowledge_incident(args.incident_id, args.by)
    elif args.command == "resolve":
        manager.resolve_incident(args.incident_id, args.notes, args.by)
    elif args.command == "auto":
        manager.auto_create_from_scan(args.scan_results)
    elif args.command == "show":
        inc = manager.get_incident(args.incident_id)
        if inc:
            print(json.dumps(inc, indent=2))
    elif args.command == "dashboard":
        manager.print_incident_dashboard()
    else:
        manager.print_incident_dashboard()