import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import math
import statistics
from datetime import datetime, timedelta
from database import DB_PATH
import sqlite3


# ── Analytics Engine ──────────────────────────────────────────
class AnalyticsEngine:
    """
    Advanced analytics for LLM Scanner data.
    Provides trends, predictions, and actionable insights.
    """

    def __init__(self):
        self.results_dir = "results"

    def load_all_scans(self):
        """Loads all scan data from results directory."""
        scans = []
        if not os.path.exists(self.results_dir):
            return scans

        for filename in os.listdir(self.results_dir):
            if not filename.endswith(".json"):
                continue
            if any(x in filename for x in [
                "checkpoint", "generated", "learning",
                "zero_day", "threat", "comparison",
                "timeline", "discovery", "hardening"
            ]):
                continue

            path = os.path.join(self.results_dir, filename)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if "summary" in data and "results" in data:
                    data["_filename"] = filename
                    scans.append(data)
            except:
                continue

        return scans

    def calculate_trend(self, values):
        """Calculates trend direction from a series of values."""
        if len(values) < 2:
            return "stable", 0

        n     = len(values)
        x_avg = (n - 1) / 2
        y_avg = sum(values) / n

        num   = sum((i - x_avg) * (v - y_avg) for i, v in enumerate(values))
        denom = sum((i - x_avg) ** 2 for i in range(n))

        slope = num / denom if denom != 0 else 0

        if slope > 1:
            return "improving", round(slope, 2)
        elif slope < -1:
            return "degrading", round(slope, 2)
        else:
            return "stable", round(slope, 2)

    def get_vulnerability_trends(self):
        """Analyzes vulnerability trends across all scans."""
        scans = self.load_all_scans()
        if not scans:
            return {}

        scores       = [s["summary"]["security_score"] for s in scans]
        criticals    = [s["summary"]["critical"]        for s in scans]
        highs        = [s["summary"]["high"]            for s in scans]

        trend_score, slope_score   = self.calculate_trend(scores)
        trend_crit,  slope_crit    = self.calculate_trend(criticals)

        return {
            "total_scans"    : len(scans),
            "avg_score"      : round(statistics.mean(scores), 1),
            "min_score"      : min(scores),
            "max_score"      : max(scores),
            "score_trend"    : trend_score,
            "score_slope"    : slope_score,
            "avg_critical"   : round(statistics.mean(criticals), 1),
            "critical_trend" : trend_crit,
            "total_criticals": sum(criticals),
            "total_highs"    : sum(highs)
        }

    def get_category_analytics(self):
        """Analyzes attack success rates per category."""
        scans = self.load_all_scans()
        if not scans:
            return {}

        category_stats = {}

        for scan in scans:
            for result in scan.get("results", []):
                cat = result.get("category", "unknown")
                sev = result.get("severity", "SAFE")

                if cat not in category_stats:
                    category_stats[cat] = {
                        "total"   : 0,
                        "critical": 0,
                        "high"    : 0,
                        "medium"  : 0,
                        "safe"    : 0,
                        "scores"  : []
                    }

                category_stats[cat]["total"] += 1
                category_stats[cat]["scores"].append(
                    result.get("score", 0)
                )

                if sev == "CRITICAL":
                    category_stats[cat]["critical"] += 1
                elif sev == "HIGH":
                    category_stats[cat]["high"] += 1
                elif sev == "MEDIUM":
                    category_stats[cat]["medium"] += 1
                elif sev == "SAFE":
                    category_stats[cat]["safe"] += 1

        # Calculate success rates
        for cat, stats in category_stats.items():
            total = stats["total"]
            if total > 0:
                stats["success_rate"] = round(
                    (stats["critical"] + stats["high"]) / total * 100, 1
                )
                stats["avg_score"] = round(
                    statistics.mean(stats["scores"]), 1
                )
            else:
                stats["success_rate"] = 0
                stats["avg_score"]    = 0

        return dict(sorted(
            category_stats.items(),
            key=lambda x: x[1].get("success_rate", 0),
            reverse=True
        ))

    def get_time_analytics(self):
        """Analyzes scan frequency and timing patterns."""
        scans = self.load_all_scans()
        if not scans:
            return {}

        # Group by date
        by_date = {}
        for scan in scans:
            date = scan.get("scan_date", "")[:10]
            if date:
                if date not in by_date:
                    by_date[date] = 0
                by_date[date] += 1

        return {
            "total_scans"  : len(scans),
            "scan_days"    : len(by_date),
            "avg_per_day"  : round(
                len(scans) / max(len(by_date), 1), 1
            ),
            "busiest_day"  : max(by_date, key=by_date.get)
                             if by_date else "N/A",
            "by_date"      : dict(sorted(by_date.items()))
        }

    def get_risk_heatmap(self):
        """
        Creates a risk heatmap across categories and severity.
        """
        cat_analytics = self.get_category_analytics()

        heatmap = []
        for cat, stats in list(cat_analytics.items())[:10]:
            heatmap.append({
                "category"    : cat.replace("_", " ").title(),
                "critical_pct": round(
                    stats["critical"] / max(stats["total"], 1) * 100, 1
                ),
                "high_pct"    : round(
                    stats["high"] / max(stats["total"], 1) * 100, 1
                ),
                "success_rate": stats["success_rate"],
                "risk_level"  : "CRITICAL" if stats["success_rate"] > 40
                                else "HIGH" if stats["success_rate"] > 20
                                else "MEDIUM" if stats["success_rate"] > 10
                                else "LOW"
            })

        return heatmap

    def generate_insights(self):
        """Generates actionable insights from analytics data."""
        trends   = self.get_vulnerability_trends()
        cat_data = self.get_category_analytics()

        insights = []

        if not trends:
            return ["Not enough scan data for insights. Run more scans."]

        # Score trend insight
        if trends.get("score_trend") == "degrading":
            insights.append(
                f"⚠️ Security score is DEGRADING "
                f"(slope: {trends['score_slope']}). "
                f"Immediate attention required."
            )
        elif trends.get("score_trend") == "improving":
            insights.append(
                f"✅ Security score is IMPROVING "
                f"(+{abs(trends['score_slope'])} per scan). "
                f"Keep up the remediation work."
            )

        # Most dangerous category
        if cat_data:
            worst_cat = list(cat_data.keys())[0]
            worst     = cat_data[worst_cat]
            insights.append(
                f"🚨 Most vulnerable category: "
                f"{worst_cat.replace('_',' ')} "
                f"({worst['success_rate']}% attack success rate). "
                f"Prioritize hardening this area."
            )

        # Critical count insight
        total_crits = trends.get("total_criticals", 0)
        if total_crits > 10:
            insights.append(
                f"🔴 {total_crits} critical vulnerabilities found "
                f"across all scans. "
                f"Deploy auto-remediation immediately."
            )

        # Positive insight
        avg_score = trends.get("avg_score", 0)
        if avg_score > 60:
            insights.append(
                f"✅ Average security score is {avg_score}% "
                f"which is above the 60% industry baseline."
            )
        else:
            insights.append(
                f"⚠️ Average security score is {avg_score}% "
                f"which is BELOW the 60% industry baseline."
            )

        return insights

    def generate_analytics_report(self, output_path=None):
        """Generates complete analytics report."""
        trends   = self.get_vulnerability_trends()
        cat_data = self.get_category_analytics()
        time_data = self.get_time_analytics()
        heatmap  = self.get_risk_heatmap()
        insights = self.generate_insights()

        report = {
            "generated_at"     : datetime.now().isoformat(),
            "trends"           : trends,
            "category_analytics": cat_data,
            "time_analytics"   : time_data,
            "risk_heatmap"     : heatmap,
            "insights"         : insights
        }

        if output_path:
            os.makedirs("results", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"  Analytics report saved: {output_path}")

        return report

    def print_analytics_report(self):
        """Prints analytics report to terminal."""
        report   = self.generate_analytics_report()
        trends   = report.get("trends", {})
        cat_data = report.get("category_analytics", {})
        insights = report.get("insights", [])

        print(f"\n  {'='*60}")
        print(f"  📊 ADVANCED ANALYTICS REPORT")
        print(f"  {'='*60}")

        print(f"\n  Overall Trends :")
        print(f"    Total Scans   : {trends.get('total_scans', 0)}")
        print(f"    Avg Score     : {trends.get('avg_score', 0)}%")
        print(f"    Score Trend   : {trends.get('score_trend', 'N/A')}")
        print(f"    Total Critical: {trends.get('total_criticals', 0)}")

        print(f"\n  Top Vulnerable Categories :")
        for cat, stats in list(cat_data.items())[:5]:
            rate = stats.get("success_rate", 0)
            bar  = "█" * int(rate / 5)
            print(
                f"    {cat.replace('_',' '):<30}"
                f" {rate:>5.1f}% {bar}"
            )

        print(f"\n  Insights :")
        for insight in insights:
            print(f"    {insight}")

        print(f"\n  {'='*60}\n")


# ── HTML Analytics Generator ──────────────────────────────────
class HTMLAnalyticsGenerator:
    """Generates HTML analytics dashboard."""

    def generate(
        self, report,
        output_path="results/analytics_dashboard.html"
    ):
        """Generates HTML analytics page."""
        trends   = report.get("trends", {})
        heatmap  = report.get("risk_heatmap", [])
        insights = report.get("insights", [])

        heatmap_html = ""
        for item in heatmap[:8]:
            risk_colors = {
                "CRITICAL": "#C0392B",
                "HIGH"    : "#E67E22",
                "MEDIUM"  : "#F1C40F",
                "LOW"     : "#27AE60"
            }
            color = risk_colors.get(item["risk_level"], "#888")
            heatmap_html += f"""
            <div class="heatmap-row">
                <span class="hcat">{item['category']}</span>
                <div class="hbar-container">
                    <div class="hbar"
                         style="width:{item['success_rate']}%;
                                background:{color}">
                    </div>
                </div>
                <span class="hpct">{item['success_rate']}%</span>
            </div>"""

        insights_html = "".join(
            f'<div class="insight">{i}</div>'
            for i in insights
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LLM Scanner Analytics</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: 'Segoe UI', sans-serif;
            background: #0f1117;
            color: white;
            padding: 20px;
        }}
        .header {{
            text-align: center;
            padding: 30px;
            background: linear-gradient(135deg, #1F3864, #2E75B6);
            border-radius: 16px;
            margin-bottom: 24px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: #1a1d27;
            border: 1px solid #2a2d3a;
            border-radius: 12px;
            padding: 20px;
        }}
        .card h3 {{
            color: #888;
            font-size: 12px;
            text-transform: uppercase;
            margin-bottom: 12px;
        }}
        .stat-big {{
            font-size: 36px;
            font-weight: 800;
        }}
        .heatmap-row {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 10px;
        }}
        .hcat {{ width: 200px; font-size: 13px; color: #ccc; }}
        .hbar-container {{
            flex: 1;
            background: #2a2d3a;
            border-radius: 4px;
            height: 20px;
        }}
        .hbar {{
            height: 100%;
            border-radius: 4px;
            min-width: 2px;
        }}
        .hpct {{
            width: 50px;
            text-align: right;
            font-size: 13px;
            color: #888;
        }}
        .insight {{
            padding: 10px 14px;
            background: #1a1d27;
            border: 1px solid #2a2d3a;
            border-radius: 8px;
            margin-bottom: 8px;
            font-size: 14px;
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📊 LLM Scanner Analytics Dashboard</h1>
        <p>Generated: {report.get('generated_at', '')[:19]}</p>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Total Scans</h3>
            <div class="stat-big" style="color:#2E75B6">
                {trends.get('total_scans', 0)}
            </div>
        </div>
        <div class="card">
            <h3>Avg Security Score</h3>
            <div class="stat-big" style="color:{'#27AE60' if trends.get('avg_score',0) >= 60 else '#C0392B'}">
                {trends.get('avg_score', 0)}%
            </div>
        </div>
        <div class="card">
            <h3>Score Trend</h3>
            <div class="stat-big" style="color:#F1C40F">
                {trends.get('score_trend', 'N/A').upper()}
            </div>
        </div>
        <div class="card">
            <h3>Total Criticals</h3>
            <div class="stat-big" style="color:#C0392B">
                {trends.get('total_criticals', 0)}
            </div>
        </div>
    </div>

    <div class="grid-2">
        <div class="card">
            <h3>Attack Success Rate by Category</h3>
            <br>
            {heatmap_html}
        </div>
        <div class="card">
            <h3>AI Insights</h3>
            <br>
            {insights_html}
        </div>
    </div>
</body>
</html>"""

        os.makedirs("results", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"  Analytics dashboard: {output_path}")
        return output_path


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Advanced Analytics"
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("report")
    p_html = subparsers.add_parser("html")
    p_html.add_argument(
        "--output",
        default="results/analytics_dashboard.html"
    )

    p_export = subparsers.add_parser("export")
    p_export.add_argument(
        "--output",
        default="results/analytics_report.json"
    )

    args   = parser.parse_args()
    engine = AnalyticsEngine()

    if args.command == "report":
        engine.print_analytics_report()

    elif args.command == "html":
        report = engine.generate_analytics_report()
        gen    = HTMLAnalyticsGenerator()
        gen.generate(report, args.output)
        print(f"  Open: {args.output}")

    elif args.command == "export":
        engine.generate_analytics_report(args.output)

    else:
        engine.print_analytics_report()
        