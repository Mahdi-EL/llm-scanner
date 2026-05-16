import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import time
from datetime import datetime, timedelta
from database import DB_PATH
import sqlite3


# ── Dashboard Data Collector ──────────────────────────────────
class DashboardDataCollector:
    """
    Collects all data needed for the enterprise dashboard.
    Single source of truth for all metrics.
    """

    def collect_all(self):
        """Collects all dashboard data."""
        return {
            "collected_at"    : datetime.now().isoformat(),
            "business"        : self.collect_business_metrics(),
            "technical"       : self.collect_technical_metrics(),
            "security"        : self.collect_security_metrics(),
            "tenants"         : self.collect_tenant_metrics(),
            "top_findings"    : self.collect_top_findings(),
            "recent_activity" : self.collect_recent_activity()
        }

    def collect_business_metrics(self):
        """Collects business KPIs."""
        try:
            from tenants import TenantManager, PLANS
            manager = TenantManager()
            stats   = manager.global_stats()

            return {
                "total_tenants"  : stats["total_tenants"],
                "active_tenants" : stats["active_tenants"],
                "mrr"            : stats["mrr"],
                "arr"            : stats["mrr"] * 12,
                "total_scans"    : stats["total_scans"],
                "by_plan"        : stats["by_plan"],
                "avg_revenue_per_tenant": round(
                    stats["mrr"] / max(stats["active_tenants"], 1), 2
                )
            }
        except Exception as e:
            return {"error": str(e)}

    def collect_technical_metrics(self):
        """Collects technical performance metrics."""
        try:
            from sla_monitor import get_sla_monitor
            monitor  = get_sla_monitor()
            uptime   = monitor.calculate_uptime(24)
            avg_resp = monitor.calculate_avg_response_time(60)
            err_rate = monitor.calculate_error_rate(60)
            p95      = monitor.calculate_p95_response_time(60)
            compliance = monitor.get_compliance_score(24)

            return {
                "uptime_24h"         : uptime,
                "avg_response_ms"    : avg_resp,
                "p95_response_ms"    : p95,
                "error_rate_pct"     : err_rate,
                "sla_compliance_pct" : compliance,
                "active_breaches"    : self._count_active_breaches()
            }
        except Exception as e:
            return {
                "uptime_24h"        : 100.0,
                "avg_response_ms"   : 0,
                "error_rate_pct"    : 0,
                "sla_compliance_pct": 100.0,
                "active_breaches"   : 0
            }

    def collect_security_metrics(self):
        """Collects security metrics."""
        try:
            from audit import get_audit_logger
            logger  = get_audit_logger()
            summary = logger.get_summary()

            return {
                "total_audit_events"  : summary.get("total_events", 0),
                "high_risk_events"    : summary.get("high_risk_events", 0),
                "failed_logins_24h"   : summary.get("failed_logins", 0),
                "blocked_attacks_24h" : summary.get("blocked_attacks", 0),
                "unique_ips_24h"      : summary.get("unique_ips_24h", 0),
                "top_events"          : summary.get("top_events_24h", {})
            }
        except Exception as e:
            return {"error": str(e)}

    def collect_tenant_metrics(self):
        """Collects per-tenant metrics."""
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            c    = conn.cursor()

            c.execute("""
                SELECT
                    t.tenant_id,
                    t.company_name,
                    t.plan,
                    t.scans_used,
                    t.scans_limit,
                    t.is_active,
                    COUNT(ts.id) as total_scans,
                    MAX(ts.created_at) as last_scan
                FROM tenants t
                LEFT JOIN tenant_scans ts ON t.tenant_id = ts.tenant_id
                GROUP BY t.tenant_id
                ORDER BY t.scans_used DESC
                LIMIT 10
            """)

            rows = [dict(row) for row in c.fetchall()]
            conn.close()
            return rows
        except:
            return []

    def collect_top_findings(self):
        """Collects most common vulnerability findings."""
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            c    = conn.cursor()

            c.execute("""
                SELECT
                    category,
                    severity,
                    COUNT(*) as count,
                    AVG(score) as avg_score
                FROM findings
                WHERE severity IN ('CRITICAL', 'HIGH')
                GROUP BY category, severity
                ORDER BY count DESC
                LIMIT 10
            """)

            rows = [dict(row) for row in c.fetchall()]
            conn.close()
            return rows
        except:
            return []

    def collect_recent_activity(self):
        """Collects recent system activity."""
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            c    = conn.cursor()

            c.execute("""
                SELECT
                    s.scan_id,
                    s.target_name,
                    s.status,
                    s.security_score,
                    s.critical_count,
                    s.created_at
                FROM scans s
                ORDER BY s.created_at DESC
                LIMIT 10
            """)

            rows = [dict(row) for row in c.fetchall()]
            conn.close()
            return rows
        except:
            return []

    def _count_active_breaches(self):
        """Counts active SLA breaches."""
        try:
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()
            c.execute(
                "SELECT COUNT(*) FROM sla_breaches WHERE resolved = 0"
            )
            count = c.fetchone()[0]
            conn.close()
            return count
        except:
            return 0


# ── Terminal Dashboard ────────────────────────────────────────
class TerminalDashboard:
    """
    Renders the enterprise dashboard in the terminal.
    """

    # ANSI colors
    RESET  = '\033[0m'
    BOLD   = '\033[1m'
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    GRAY   = '\033[90m'

    def __init__(self):
        self.collector = DashboardDataCollector()

    def clear(self):
        """Clears the terminal."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def render(self, data):
        """Renders the full dashboard."""
        self.clear()
        self._render_header()
        self._render_business(data.get("business", {}))
        self._render_technical(data.get("technical", {}))
        self._render_security(data.get("security", {}))
        self._render_top_findings(data.get("top_findings", []))
        self._render_recent_activity(data.get("recent_activity", []))
        self._render_footer(data.get("collected_at", ""))

    def _render_header(self):
        """Renders dashboard header."""
        print(f"\n{self.BLUE}{self.BOLD}")
        print("  ╔══════════════════════════════════════════════════════════╗")
        print("  ║          🔐 LLM SCANNER — ENTERPRISE DASHBOARD           ║")
        print("  ╚══════════════════════════════════════════════════════════╝")
        print(f"{self.RESET}")

    def _render_business(self, data):
        """Renders business metrics."""
        if not data or "error" in data:
            return

        mrr = data.get("mrr", 0)
        arr = data.get("arr", 0)

        print(f"  {self.CYAN}{self.BOLD}📊 BUSINESS METRICS{self.RESET}")
        print(f"  {'─'*58}")

        metrics = [
            ("Total Tenants",    data.get("total_tenants", 0),    ""),
            ("Active Tenants",   data.get("active_tenants", 0),   ""),
            ("Total Scans",      data.get("total_scans", 0),      ""),
            ("MRR",              f"{mrr}€",                        ""),
            ("ARR",              f"{arr}€",                        ""),
            ("Avg Revenue/Tenant", f"{data.get('avg_revenue_per_tenant', 0)}€", ""),
        ]

        for i in range(0, len(metrics), 3):
            row_metrics = metrics[i:i+3]
            line = "  "
            for name, value, _ in row_metrics:
                value_color = self.GREEN if isinstance(value, str) and \
                              "€" in str(value) else self.WHITE
                line += f"{name}: {value_color}{value}{self.RESET}   "
            print(line)

        # Plan breakdown
        by_plan = data.get("by_plan", {})
        if by_plan:
            plan_str = "  Plans: "
            for plan, count in by_plan.items():
                plan_str += f"{plan.upper()}={count}  "
            print(plan_str)

        print()

    def _render_technical(self, data):
        """Renders technical metrics."""
        print(f"  {self.CYAN}{self.BOLD}⚡ TECHNICAL METRICS{self.RESET}")
        print(f"  {'─'*58}")

        uptime     = data.get("uptime_24h", 100)
        avg_resp   = data.get("avg_response_ms", 0)
        err_rate   = data.get("error_rate_pct", 0)
        compliance = data.get("sla_compliance_pct", 100)
        breaches   = data.get("active_breaches", 0)

        # Uptime
        up_color = self.GREEN if uptime >= 99.9 else \
                   self.YELLOW if uptime >= 99.0 else self.RED
        print(f"  Uptime (24h)    : {up_color}{uptime}%{self.RESET}")

        # Response time
        resp_color = self.GREEN if avg_resp < 200 else \
                     self.YELLOW if avg_resp < 500 else self.RED
        print(f"  Avg Response    : {resp_color}{avg_resp}ms{self.RESET}")

        # Error rate
        err_color = self.GREEN if err_rate < 1 else \
                    self.YELLOW if err_rate < 5 else self.RED
        print(f"  Error Rate      : {err_color}{err_rate}%{self.RESET}")

        # SLA compliance
        sla_color = self.GREEN if compliance >= 99 else \
                    self.YELLOW if compliance >= 95 else self.RED
        print(f"  SLA Compliance  : {sla_color}{compliance}%{self.RESET}")

        # Active breaches
        breach_color = self.GREEN if breaches == 0 else self.RED
        print(
            f"  Active Breaches : "
            f"{breach_color}{breaches}{self.RESET}"
        )
        print()

    def _render_security(self, data):
        """Renders security metrics."""
        print(f"  {self.CYAN}{self.BOLD}🛡️  SECURITY METRICS{self.RESET}")
        print(f"  {'─'*58}")

        high_risk = data.get("high_risk_events", 0)
        failed    = data.get("failed_logins_24h", 0)
        blocked   = data.get("blocked_attacks_24h", 0)
        ips       = data.get("unique_ips_24h", 0)

        risk_color    = self.RED    if high_risk > 10 else \
                        self.YELLOW if high_risk > 0  else self.GREEN
        failed_color  = self.RED    if failed > 5     else \
                        self.YELLOW if failed > 0     else self.GREEN
        blocked_color = self.YELLOW if blocked > 0    else self.GREEN

        print(
            f"  High Risk Events  : "
            f"{risk_color}{high_risk}{self.RESET}"
        )
        print(
            f"  Failed Logins(24h): "
            f"{failed_color}{failed}{self.RESET}"
        )
        print(
            f"  Blocked Attacks   : "
            f"{blocked_color}{blocked}{self.RESET}"
        )
        print(f"  Unique IPs (24h)  : {self.WHITE}{ips}{self.RESET}")
        print()

    def _render_top_findings(self, findings):
        """Renders top vulnerability findings."""
        if not findings:
            return

        print(f"  {self.CYAN}{self.BOLD}🔍 TOP VULNERABILITIES{self.RESET}")
        print(f"  {'─'*58}")

        for f in findings[:5]:
            sev_color = self.RED if f["severity"] == "CRITICAL" \
                        else self.YELLOW
            print(
                f"  {sev_color}[{f['severity']:<8}]{self.RESET}"
                f" {f['category'].replace('_',' '):<25}"
                f" Count:{f['count']:<5}"
                f" AvgScore:{round(f.get('avg_score', 0), 1)}/10"
            )
        print()

    def _render_recent_activity(self, activity):
        """Renders recent scan activity."""
        if not activity:
            return

        print(f"  {self.CYAN}{self.BOLD}📋 RECENT SCANS{self.RESET}")
        print(f"  {'─'*58}")

        for s in activity[:5]:
            score = s.get("security_score", 0)
            score_color = self.GREEN  if score >= 70 else \
                          self.YELLOW if score >= 40 else self.RED
            status_icon = "✅" if s["status"] == "complete" else \
                          "🔄" if s["status"] == "running"  else "❌"

            print(
                f"  {status_icon} "
                f"{s['target_name'][:25]:<25} "
                f"{score_color}{score:>3}%{self.RESET} "
                f"{self.GRAY}{s['created_at'][:16]}{self.RESET}"
            )
        print()

    def _render_footer(self, collected_at):
        """Renders dashboard footer."""
        print(f"  {self.GRAY}{'─'*58}")
        print(
            f"  Last updated: {collected_at[:19]} | "
            f"LLM Scanner Enterprise v2.0.0{self.RESET}\n"
        )

    def run_live(self, refresh_seconds=30):
        """Runs the dashboard in live refresh mode."""
        print(f"  Starting live dashboard (refresh every {refresh_seconds}s)")
        print(f"  Press Ctrl+C to exit")
        time.sleep(2)

        try:
            while True:
                data = self.collector.collect_all()
                self.render(data)
                time.sleep(refresh_seconds)
        except KeyboardInterrupt:
            self.clear()
            print("\n  Dashboard stopped.\n")


# ── HTML Dashboard Generator ──────────────────────────────────
class HTMLDashboardGenerator:
    """
    Generates a static HTML version of the enterprise dashboard.
    """

    def generate(self, data, output_path="results/enterprise_dashboard.html"):
        """Generates HTML dashboard file."""

        business  = data.get("business", {})
        technical = data.get("technical", {})
        security  = data.get("security", {})
        findings  = data.get("top_findings", [])
        activity  = data.get("recent_activity", [])

        mrr       = business.get("mrr", 0)
        arr       = business.get("arr", 0)
        uptime    = technical.get("uptime_24h", 100)
        avg_resp  = technical.get("avg_response_ms", 0)
        err_rate  = technical.get("error_rate_pct", 0)
        compliance= technical.get("sla_compliance_pct", 100)

        findings_html = ""
        for f in findings[:10]:
            sev_color = "#C0392B" if f["severity"] == "CRITICAL" \
                        else "#E67E22"
            findings_html += f"""
            <div class="finding-row">
                <span class="badge" style="background:{sev_color}22;
                      color:{sev_color}">
                    {f['severity']}
                </span>
                <span class="finding-cat">
                    {f['category'].replace('_',' ').title()}
                </span>
                <span class="finding-count">
                    {f['count']} occurrences
                </span>
            </div>"""

        activity_html = ""
        for s in activity[:10]:
            score  = s.get("security_score", 0)
            color  = "#27AE60" if score >= 70 else \
                     "#F1C40F" if score >= 40 else "#C0392B"
            icon   = "✅" if s["status"] == "complete" else \
                     "🔄" if s["status"] == "running"  else "❌"
            activity_html += f"""
            <div class="activity-row">
                <span>{icon}</span>
                <span class="activity-target">
                    {s['target_name'][:30]}
                </span>
                <span style="color:{color};font-weight:700">
                    {score}%
                </span>
                <span class="activity-date">
                    {s['created_at'][:16]}
                </span>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="30">
    <title>LLM Scanner Enterprise Dashboard</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: 'Segoe UI', sans-serif;
            background: #0f1117;
            color: white;
            padding: 20px;
            min-height: 100vh;
        }}
        .header {{
            text-align: center;
            padding: 30px;
            background: linear-gradient(135deg, #1F3864, #2E75B6);
            border-radius: 16px;
            margin-bottom: 24px;
        }}
        .header h1 {{ font-size: 28px; margin-bottom: 8px; }}
        .header p  {{ color: #aaa; font-size: 14px; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 24px;
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
        }}
        .card {{
            background: #1a1d27;
            border: 1px solid #2a2d3a;
            border-radius: 12px;
            padding: 20px;
        }}
        .card h2 {{
            font-size: 14px;
            color: #888;
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .stat-big {{
            font-size: 42px;
            font-weight: 800;
            margin-bottom: 4px;
        }}
        .stat-label {{ color: #888; font-size: 13px; }}
        .metric-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #2a2d3a;
            font-size: 14px;
        }}
        .metric-row:last-child {{ border-bottom: none; }}
        .metric-value {{ font-weight: 700; }}
        .badge {{
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
        }}
        .finding-row, .activity-row {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 0;
            border-bottom: 1px solid #2a2d3a;
            font-size: 13px;
        }}
        .finding-row:last-child,
        .activity-row:last-child {{ border-bottom: none; }}
        .finding-cat {{ flex: 1; color: #ccc; }}
        .finding-count {{ color: #888; font-size: 12px; }}
        .activity-target {{ flex: 1; color: #ccc; }}
        .activity-date {{ color: #888; font-size: 12px; }}
        .footer {{
            text-align: center;
            color: #555;
            font-size: 12px;
            margin-top: 24px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 LLM Scanner Enterprise Dashboard</h1>
        <p>Last updated: {data.get('collected_at', '')[:19]} |
           Auto-refreshes every 30 seconds</p>
    </div>

    <!-- Business Metrics -->
    <div class="grid">
        <div class="card">
            <h2>Monthly Revenue</h2>
            <div class="stat-big" style="color:#27AE60">{mrr}€</div>
            <div class="stat-label">ARR: {arr}€</div>
        </div>
        <div class="card">
            <h2>Active Tenants</h2>
            <div class="stat-big" style="color:#2E75B6">
                {business.get('active_tenants', 0)}
            </div>
            <div class="stat-label">
                Total: {business.get('total_tenants', 0)}
            </div>
        </div>
        <div class="card">
            <h2>Total Scans</h2>
            <div class="stat-big" style="color:#9B59B6">
                {business.get('total_scans', 0)}
            </div>
            <div class="stat-label">All time</div>
        </div>
    </div>

    <!-- Technical + Security -->
    <div class="grid">
        <div class="card">
            <h2>🟢 Uptime (24h)</h2>
            <div class="stat-big" style="color:{'#27AE60' if uptime >= 99.9 else '#F1C40F'}">
                {uptime}%
            </div>
            <div class="stat-label">
                SLA: {compliance}% compliant
            </div>
        </div>
        <div class="card">
            <h2>⚡ Avg Response</h2>
            <div class="stat-big" style="color:{'#27AE60' if avg_resp < 200 else '#E67E22'}">
                {avg_resp}ms
            </div>
            <div class="stat-label">
                Error rate: {err_rate}%
            </div>
        </div>
        <div class="card">
            <h2>🛡️ Security</h2>
            <div class="metric-row">
                <span>High Risk Events</span>
                <span class="metric-value" style="color:#E67E22">
                    {security.get('high_risk_events', 0)}
                </span>
            </div>
            <div class="metric-row">
                <span>Failed Logins</span>
                <span class="metric-value" style="color:#C0392B">
                    {security.get('failed_logins_24h', 0)}
                </span>
            </div>
            <div class="metric-row">
                <span>Blocked Attacks</span>
                <span class="metric-value" style="color:#F1C40F">
                    {security.get('blocked_attacks_24h', 0)}
                </span>
            </div>
        </div>
    </div>

    <!-- Findings + Activity -->
    <div class="grid-2">
        <div class="card">
            <h2>🔍 Top Vulnerabilities</h2>
            {findings_html or '<p style="color:#888">No data yet</p>'}
        </div>
        <div class="card">
            <h2>📋 Recent Scans</h2>
            {activity_html or '<p style="color:#888">No scans yet</p>'}
        </div>
    </div>

    <div class="footer">
        LLM Scanner Enterprise v2.0.0 —
        github.com/Mahdi-EL/llm-scanner
    </div>
</body>
</html>"""

        os.makedirs("results", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"  HTML Dashboard : {output_path}")
        return output_path


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Enterprise Dashboard"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Terminal dashboard
    p_terminal = subparsers.add_parser("terminal")
    p_terminal.add_argument("--refresh", type=int, default=30)
    p_terminal.add_argument("--live",    action="store_true")

    # HTML dashboard
    p_html = subparsers.add_parser("html")
    p_html.add_argument(
        "--output",
        default="results/enterprise_dashboard.html"
    )

    # Snapshot
    subparsers.add_parser("snapshot")

    args      = parser.parse_args()
    collector = DashboardDataCollector()

    if args.command == "terminal":
        dashboard = TerminalDashboard()
        if args.live:
            dashboard.run_live(args.refresh)
        else:
            data = collector.collect_all()
            dashboard.render(data)

    elif args.command == "html":
        data = collector.collect_all()
        gen  = HTMLDashboardGenerator()
        gen.generate(data, args.output)
        print(f"  Open in browser : {args.output}")

    elif args.command == "snapshot":
        data      = collector.collect_all()
        snap_path = f"results/dashboard_snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        os.makedirs("results", exist_ok=True)
        with open(snap_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"  Snapshot saved : {snap_path}")

    else:
        # Default : show terminal dashboard once
        dashboard = TerminalDashboard()
        data      = collector.collect_all()
        dashboard.render(data)