import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import statistics
from datetime import datetime, timedelta
from database import DB_PATH
import sqlite3


# ── Metrics Collector ─────────────────────────────────────────
class MetricsCollector:
    """
    Collects and calculates security metrics
    for executive reporting.
    """

    def __init__(self):
        self.results_dir = "results"

    def _load_scans(self, days=30):
        """Loads scans from the last N days."""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        scans  = []

        for f in os.listdir(self.results_dir):
            if not f.endswith(".json"):
                continue
            if any(x in f for x in [
                "checkpoint","generated","learning",
                "threat","pipeline","training","metrics"
            ]):
                continue

            path = os.path.join(self.results_dir, f)
            try:
                with open(path, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                if "summary" in data:
                    date = data.get("scan_date", "")
                    if date >= cutoff:
                        data["_file"] = f
                        scans.append(data)
            except:
                continue

        return scans

    def calculate_mttr(self):
        """
        Mean Time To Remediate (MTTR).
        Average time between scan and remediation.
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()

            c.execute("""
                SELECT
                    AVG((julianday(resolved_at) - julianday(created_at)) * 24)
                FROM incidents
                WHERE status = 'resolved' AND resolved_at IS NOT NULL
            """)

            row = c.fetchone()
            conn.close()

            if row and row[0]:
                return round(row[0], 1)
            return None
        except:
            return None

    def calculate_vulnerability_density(self, scans):
        """Vulnerabilities per 100 attack prompts."""
        if not scans:
            return 0

        total_attacks = sum(s.get("total_attacks", 0) for s in scans)
        total_vulns   = sum(
            s["summary"].get("critical", 0) +
            s["summary"].get("high", 0)
            for s in scans
        )

        if total_attacks == 0:
            return 0

        return round((total_vulns / total_attacks) * 100, 2)

    def calculate_security_posture_score(self, scans):
        """
        Composite security posture score (0-100).
        Weights: score (40%) + trend (30%) + critical rate (30%)
        """
        if not scans:
            return 0

        scores = [s["summary"]["security_score"] for s in scans]
        avg_score = statistics.mean(scores)

        # Trend component
        if len(scores) >= 2:
            trend = scores[-1] - scores[0]
            trend_score = min(100, max(0, 50 + trend))
        else:
            trend_score = 50

        # Critical rate component
        total_attacks = sum(s.get("total_attacks", 1) for s in scans)
        total_critical = sum(
            s["summary"].get("critical", 0) for s in scans
        )
        critical_rate = (total_critical / total_attacks) * 100
        critical_score = max(0, 100 - (critical_rate * 10))

        composite = (
            avg_score * 0.4 +
            trend_score * 0.3 +
            critical_score * 0.3
        )

        return round(composite, 1)

    def generate_executive_metrics(self):
        """Generates executive-level security metrics."""
        scans   = self._load_scans(days=30)
        mttr    = self.calculate_mttr()
        density = self.calculate_vulnerability_density(scans)
        posture = self.calculate_security_posture_score(scans)

        if scans:
            scores    = [s["summary"]["security_score"] for s in scans]
            avg_score = round(statistics.mean(scores), 1)
            best_score = max(scores)
            worst_score = min(scores)

            total_critical = sum(
                s["summary"].get("critical", 0) for s in scans
            )
            total_high = sum(
                s["summary"].get("high", 0) for s in scans
            )
        else:
            avg_score = worst_score = best_score = 0
            total_critical = total_high = 0

        return {
            "generated_at"        : datetime.now().isoformat(),
            "period_days"         : 30,
            "total_scans"         : len(scans),
            "security_posture"    : posture,
            "avg_security_score"  : avg_score,
            "best_score"          : best_score,
            "worst_score"         : worst_score,
            "total_critical"      : total_critical,
            "total_high"          : total_high,
            "vuln_density"        : density,
            "mttr_hours"          : mttr,
            "grade"               : self._score_to_grade(posture)
        }

    def _score_to_grade(self, score):
        if score >= 90: return "A+"
        elif score >= 80: return "A"
        elif score >= 70: return "B"
        elif score >= 60: return "C"
        elif score >= 50: return "D"
        else: return "F"

    def generate_html_dashboard(
        self,
        output_path="results/metrics_dashboard.html"
    ):
        """Generates an executive metrics HTML dashboard."""
        metrics = self.generate_executive_metrics()
        posture = metrics["security_posture"]
        grade   = metrics["grade"]

        color = "#27AE60" if posture >= 70 else \
                "#F1C40F" if posture >= 50 else "#C0392B"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="60">
    <title>Security Metrics Dashboard</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: 'Segoe UI', sans-serif;
            background: #0f1117;
            color: white;
            padding: 24px;
        }}
        .header {{
            background: linear-gradient(135deg,#1F3864,#2E75B6);
            border-radius: 16px;
            padding: 32px;
            text-align: center;
            margin-bottom: 24px;
        }}
        .header h1 {{ font-size: 28px; margin-bottom: 8px; }}
        .header p  {{ color: #aaa; font-size: 14px; }}
        .posture {{
            display: inline-block;
            padding: 20px 40px;
            background: {color}22;
            border: 3px solid {color};
            border-radius: 16px;
            margin: 16px 0;
        }}
        .posture-score {{
            font-size: 64px;
            font-weight: 900;
            color: {color};
        }}
        .posture-grade {{
            font-size: 24px;
            color: {color};
            font-weight: 700;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .metric-card {{
            background: #1a1d27;
            border: 1px solid #2a2d3a;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 36px;
            font-weight: 800;
            margin-bottom: 8px;
        }}
        .metric-label {{
            color: #888;
            font-size: 13px;
        }}
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
        <h1>📈 Security Metrics Dashboard</h1>
        <p>30-day executive security report — Auto-refreshes every 60s</p>
        <div class="posture">
            <div class="posture-score">{posture}</div>
            <div class="posture-grade">Security Posture — Grade {grade}</div>
        </div>
    </div>

    <div class="grid">
        <div class="metric-card">
            <div class="metric-value" style="color:#2E75B6">
                {metrics['total_scans']}
            </div>
            <div class="metric-label">Total Scans (30d)</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color:{'#27AE60' if metrics['avg_security_score']>=60 else '#C0392B'}">
                {metrics['avg_security_score']}%
            </div>
            <div class="metric-label">Avg Security Score</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color:#C0392B">
                {metrics['total_critical']}
            </div>
            <div class="metric-label">Critical Findings</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color:#E67E22">
                {metrics['total_high']}
            </div>
            <div class="metric-label">High Findings</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color:#9B59B6">
                {metrics['vuln_density']}%
            </div>
            <div class="metric-label">Vuln Density</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color:#27AE60">
                {metrics['best_score']}%
            </div>
            <div class="metric-label">Best Score</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color:#C0392B">
                {metrics['worst_score']}%
            </div>
            <div class="metric-label">Worst Score</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color:#F1C40F">
                {f"{metrics['mttr_hours']}h" if metrics['mttr_hours'] else 'N/A'}
            </div>
            <div class="metric-label">Mean Time to Remediate</div>
        </div>
    </div>

    <div class="footer">
        LLM Scanner — Security Metrics Dashboard —
        Generated: {metrics['generated_at'][:19]}
    </div>
</body>
</html>"""

        os.makedirs("results", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"  Metrics dashboard: {output_path}")
        return output_path

    def print_metrics(self):
        """Prints metrics to terminal."""
        metrics = self.generate_executive_metrics()

        print(f"\n  {'='*60}")
        print(f"  📈 SECURITY METRICS (30-day)")
        print(f"  {'='*60}")
        print(f"  Security Posture  : {metrics['security_posture']} [{metrics['grade']}]")
        print(f"  Total Scans       : {metrics['total_scans']}")
        print(f"  Avg Score         : {metrics['avg_security_score']}%")
        print(f"  Best / Worst      : {metrics['best_score']}% / {metrics['worst_score']}%")
        print(f"  Critical Findings : {metrics['total_critical']}")
        print(f"  High Findings     : {metrics['total_high']}")
        print(f"  Vuln Density      : {metrics['vuln_density']}%")
        mttr = metrics['mttr_hours']
        print(f"  MTTR              : {f'{mttr}h' if mttr else 'N/A'}")
        print(f"  {'='*60}\n")


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Security Metrics Dashboard"
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("metrics")
    p_html = subparsers.add_parser("html")
    p_html.add_argument(
        "--output",
        default="results/metrics_dashboard.html"
    )

    args      = parser.parse_args()
    collector = MetricsCollector()

    if args.command == "html":
        collector.generate_html_dashboard(args.output)
        print(f"  Open: {args.output}")
    else:
        collector.print_metrics()