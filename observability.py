import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict
from database import DB_PATH
import sqlite3


# ── Metrics Collector ─────────────────────────────────────────
class ObservabilityPlatform:
    """
    Real-time observability for AI security operations.
    Tracks spans, traces, and metrics across all components.
    OpenTelemetry-inspired design.
    """

    def __init__(self):
        self._spans    = []
        self._counters = defaultdict(int)
        self._gauges   = {}
        self._histograms = defaultdict(list)
        self._lock     = threading.Lock()
        self._ensure_tables()

    def _ensure_tables(self):
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS obs_spans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                trace_id    TEXT NOT NULL,
                span_id     TEXT UNIQUE NOT NULL,
                parent_id   TEXT,
                name        TEXT NOT NULL,
                service     TEXT NOT NULL,
                start_time  TEXT NOT NULL,
                end_time    TEXT,
                duration_ms INTEGER,
                status      TEXT DEFAULT 'ok',
                attributes  TEXT,
                events      TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS obs_metrics (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_name TEXT NOT NULL,
                metric_type TEXT NOT NULL,
                value       REAL NOT NULL,
                labels      TEXT,
                recorded_at TEXT NOT NULL
            )
        """)

        conn.commit()
        conn.close()

    # ── Tracing ───────────────────────────────────────────────

    def start_span(self, name, service, trace_id=None, parent_id=None):
        """Starts a new tracing span."""
        import secrets

        span = {
            "span_id"   : f"span_{secrets.token_hex(8)}",
            "trace_id"  : trace_id or f"trace_{secrets.token_hex(8)}",
            "parent_id" : parent_id,
            "name"      : name,
            "service"   : service,
            "start_time": datetime.now().isoformat(),
            "end_time"  : None,
            "duration_ms": None,
            "status"    : "ok",
            "attributes": {},
            "events"    : []
        }

        with self._lock:
            self._spans.append(span)

        return span

    def end_span(self, span, status="ok", error=None):
        """Ends a tracing span."""
        span["end_time"] = datetime.now().isoformat()
        span["status"]   = status

        start = datetime.fromisoformat(span["start_time"])
        end   = datetime.fromisoformat(span["end_time"])
        span["duration_ms"] = int((end - start).total_seconds() * 1000)

        if error:
            span["events"].append({
                "name"      : "error",
                "timestamp" : datetime.now().isoformat(),
                "attributes": {"message": str(error)[:200]}
            })

        self._save_span(span)
        return span

    def add_span_attribute(self, span, key, value):
        """Adds attribute to a span."""
        span["attributes"][key] = value

    def add_span_event(self, span, name, attributes=None):
        """Adds event to a span."""
        span["events"].append({
            "name"      : name,
            "timestamp" : datetime.now().isoformat(),
            "attributes": attributes or {}
        })

    def _save_span(self, span):
        """Saves span to database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()

            c.execute("""
                INSERT OR REPLACE INTO obs_spans (
                    trace_id, span_id, parent_id, name,
                    service, start_time, end_time, duration_ms,
                    status, attributes, events
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                span["trace_id"],
                span["span_id"],
                span["parent_id"],
                span["name"],
                span["service"],
                span["start_time"],
                span["end_time"],
                span["duration_ms"],
                span["status"],
                json.dumps(span["attributes"]),
                json.dumps(span["events"])
            ))

            conn.commit()
            conn.close()
        except:
            pass

    # ── Metrics ───────────────────────────────────────────────

    def increment(self, name, value=1, labels=None):
        """Increments a counter metric."""
        with self._lock:
            self._counters[name] += value
        self._record_metric(name, "counter", value, labels)

    def gauge(self, name, value, labels=None):
        """Sets a gauge metric."""
        with self._lock:
            self._gauges[name] = value
        self._record_metric(name, "gauge", value, labels)

    def histogram(self, name, value, labels=None):
        """Records a histogram observation."""
        with self._lock:
            self._histograms[name].append(value)
            if len(self._histograms[name]) > 1000:
                self._histograms[name] = self._histograms[name][-1000:]
        self._record_metric(name, "histogram", value, labels)

    def _record_metric(self, name, metric_type, value, labels):
        """Records metric to database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()

            c.execute("""
                INSERT INTO obs_metrics (
                    metric_name, metric_type, value,
                    labels, recorded_at
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                name, metric_type, value,
                json.dumps(labels or {}),
                datetime.now().isoformat()
            ))

            conn.commit()
            conn.close()
        except:
            pass

    # ── Queries ───────────────────────────────────────────────

    def get_trace(self, trace_id):
        """Gets all spans for a trace."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("""
            SELECT * FROM obs_spans
            WHERE trace_id = ?
            ORDER BY start_time ASC
        """, (trace_id,))

        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    def get_slow_operations(self, threshold_ms=5000, limit=10):
        """Gets slow operations above threshold."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("""
            SELECT * FROM obs_spans
            WHERE duration_ms > ? AND status = 'ok'
            ORDER BY duration_ms DESC
            LIMIT ?
        """, (threshold_ms, limit))

        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    def get_error_rate(self, service=None, hours=1):
        """Gets error rate for a service."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        since = (datetime.now() - timedelta(hours=hours)).isoformat()

        query  = "SELECT COUNT(*) as total, SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) as errors FROM obs_spans WHERE start_time > ?"
        params = [since]

        if service:
            query  += " AND service = ?"
            params.append(service)

        c.execute(query, params)
        row = c.fetchone()
        conn.close()

        if not row or not row[0]:
            return 0.0

        return round((row[1] or 0) / row[0] * 100, 2)

    def get_service_metrics(self, service, hours=1):
        """Gets metrics for a specific service."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        since = (datetime.now() - timedelta(hours=hours)).isoformat()

        c.execute("""
            SELECT
                COUNT(*) as total_spans,
                AVG(duration_ms) as avg_duration,
                MIN(duration_ms) as min_duration,
                MAX(duration_ms) as max_duration,
                SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) as errors
            FROM obs_spans
            WHERE service = ? AND start_time > ?
        """, (service, since))

        row = c.fetchone()
        conn.close()

        if not row:
            return {}

        return {
            "service"     : service,
            "total_spans" : row[0] or 0,
            "avg_duration": round(row[1] or 0, 1),
            "min_duration": row[2] or 0,
            "max_duration": row[3] or 0,
            "error_count" : row[4] or 0,
            "error_rate"  : round(
                (row[4] or 0) / max(row[0] or 1, 1) * 100, 2
            )
        }

    def get_dashboard_data(self):
        """Gets all observability dashboard data."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        since_1h = (datetime.now() - timedelta(hours=1)).isoformat()

        # Total spans
        c.execute("SELECT COUNT(*) FROM obs_spans WHERE start_time > ?", (since_1h,))
        total_spans = c.fetchone()[0]

        # Error rate
        c.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) as errors
            FROM obs_spans WHERE start_time > ?
        """, (since_1h,))
        row = c.fetchone()
        error_rate = round(
            (row[1] or 0) / max(row[0] or 1, 1) * 100, 2
        ) if row else 0

        # Services
        c.execute("""
            SELECT service, COUNT(*) as count
            FROM obs_spans WHERE start_time > ?
            GROUP BY service
            ORDER BY count DESC
        """, (since_1h,))
        services = {r[0]: r[1] for r in c.fetchall()}

        # Slow operations
        slow_ops = self.get_slow_operations(threshold_ms=3000, limit=5)

        conn.close()

        return {
            "generated_at" : datetime.now().isoformat(),
            "period"       : "1 hour",
            "total_spans"  : total_spans,
            "error_rate"   : error_rate,
            "services"     : services,
            "counters"     : dict(self._counters),
            "gauges"       : dict(self._gauges),
            "slow_ops"     : slow_ops
        }

    def generate_html_dashboard(
        self,
        output_path="results/observability_dashboard.html"
    ):
        """Generates observability HTML dashboard."""
        data     = self.get_dashboard_data()
        services = data.get("services", {})

        services_html = ""
        for svc, count in services.items():
            metrics = self.get_service_metrics(svc, hours=1)
            services_html += f"""
            <div class="service-card">
                <h3>{svc}</h3>
                <div class="svc-metrics">
                    <span>Spans: {count}</span>
                    <span>Avg: {metrics.get('avg_duration', 0)}ms</span>
                    <span>Errors: {metrics.get('error_count', 0)}</span>
                </div>
            </div>"""

        slow_ops_html = ""
        for op in data.get("slow_ops", []):
            slow_ops_html += f"""
            <div class="slow-op">
                <span class="op-name">{op['name']}</span>
                <span class="op-service">{op['service']}</span>
                <span class="op-duration">{op['duration_ms']}ms</span>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="30">
    <title>LLM Scanner Observability</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: 'Segoe UI', sans-serif;
            background: #0f1117;
            color: white;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg,#1F3864,#2E75B6);
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 20px;
            text-align: center;
        }}
        .grid-4 {{
            display: grid;
            grid-template-columns: repeat(4,1fr);
            gap: 16px;
            margin-bottom: 20px;
        }}
        .metric-card {{
            background: #1a1d27;
            border: 1px solid #2a2d3a;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        .metric-big {{
            font-size: 36px;
            font-weight: 800;
            margin-bottom: 8px;
        }}
        .metric-label {{ color:#888; font-size:13px; }}
        .section {{
            background: #1a1d27;
            border: 1px solid #2a2d3a;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
        }}
        .section h2 {{ font-size:16px; color:#2E75B6; margin-bottom:16px; }}
        .service-card {{
            background: #0f1117;
            border: 1px solid #2a2d3a;
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 8px;
        }}
        .service-card h3 {{ font-size:14px; margin-bottom:8px; }}
        .svc-metrics {{
            display: flex;
            gap: 16px;
            font-size: 12px;
            color: #888;
        }}
        .slow-op {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 0;
            border-bottom: 1px solid #2a2d3a;
            font-size: 13px;
        }}
        .op-name    {{ flex:1; }}
        .op-service {{ color:#888; width:100px; }}
        .op-duration {{ color:#E67E22; font-weight:700; width:80px; text-align:right; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>👁️ LLM Scanner Observability Platform</h1>
        <p>Real-time monitoring — Auto-refreshes every 30s</p>
        <p>Period: {data['period']} | Generated: {data['generated_at'][:19]}</p>
    </div>

    <div class="grid-4">
        <div class="metric-card">
            <div class="metric-big" style="color:#2E75B6">
                {data['total_spans']}
            </div>
            <div class="metric-label">Total Spans</div>
        </div>
        <div class="metric-card">
            <div class="metric-big" style="color:{'#27AE60' if data['error_rate']<1 else '#C0392B'}">
                {data['error_rate']}%
            </div>
            <div class="metric-label">Error Rate</div>
        </div>
        <div class="metric-card">
            <div class="metric-big" style="color:#9B59B6">
                {len(data['services'])}
            </div>
            <div class="metric-label">Active Services</div>
        </div>
        <div class="metric-card">
            <div class="metric-big" style="color:#F1C40F">
                {len(data.get('slow_ops', []))}
            </div>
            <div class="metric-label">Slow Operations</div>
        </div>
    </div>

    <div class="section">
        <h2>🔧 Active Services</h2>
        {services_html or '<p style="color:#888">No service data yet</p>'}
    </div>

    <div class="section">
        <h2>🐢 Slow Operations (&gt;3s)</h2>
        {slow_ops_html or '<p style="color:#888">No slow operations detected</p>'}
    </div>
</body>
</html>"""

        os.makedirs("results", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"  Observability dashboard: {output_path}")
        return output_path

    def print_dashboard(self):
        """Prints observability data to terminal."""
        data = self.get_dashboard_data()

        print(f"\n  {'='*60}")
        print(f"  👁️  OBSERVABILITY PLATFORM")
        print(f"  {'='*60}")
        print(f"  Period       : {data['period']}")
        print(f"  Total Spans  : {data['total_spans']}")
        print(f"  Error Rate   : {data['error_rate']}%")
        print(f"  Services     : {len(data['services'])}")

        if data["services"]:
            print(f"\n  Services :")
            for svc, count in data["services"].items():
                print(f"    {svc:<25} {count} spans")

        counters = data.get("counters", {})
        if counters:
            print(f"\n  Counters :")
            for name, value in list(counters.items())[:5]:
                print(f"    {name:<30} {value}")

        print(f"  {'='*60}\n")


# ── Instrument Scanner ────────────────────────────────────────
def instrument_scan(target, attack, category, obs_platform):
    """
    Runs a single attack with full observability instrumentation.
    """
    from analysis import analyze_response, calculate_final_severity

    span = obs_platform.start_span(
        "attack_execution",
        "scanner",
    )
    obs_platform.add_span_attribute(span, "category", category)
    obs_platform.add_span_attribute(span, "attack_length", len(attack))

    try:
        response = target.send(attack)
        obs_platform.add_span_event(span, "response_received")
        obs_platform.histogram("response_length", len(response))

        score, severity, reason = analyze_response(attack, response)
        final_sev, final_score  = calculate_final_severity(
            score, False, "LOW"
        )

        obs_platform.add_span_attribute(span, "severity", final_sev)
        obs_platform.increment(f"severity.{final_sev.lower()}")

        if final_sev in ("CRITICAL", "HIGH"):
            obs_platform.add_span_event(span, "vulnerability_found", {
                "severity": final_sev,
                "category": category
            })

        obs_platform.end_span(span)
        return {
            "category"        : category,
            "attack"          : attack,
            "response"        : response,
            "score"           : final_score,
            "severity"        : final_sev,
            "reason"          : reason,
            "behavior_changed": False,
            "confidence"      : "MEDIUM"
        }

    except Exception as e:
        obs_platform.end_span(span, status="error", error=e)
        obs_platform.increment("scan.errors")
        raise e


# ── Global Platform ───────────────────────────────────────────
_platform = None

def get_observability_platform():
    """Returns global observability platform."""
    global _platform
    if _platform is None:
        _platform = ObservabilityPlatform()
    return _platform


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Observability Platform"
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("dashboard")
    p_html = subparsers.add_parser("html")
    p_html.add_argument(
        "--output",
        default="results/observability_dashboard.html"
    )

    p_trace = subparsers.add_parser("trace")
    p_trace.add_argument("trace_id")

    p_slow = subparsers.add_parser("slow")
    p_slow.add_argument("--threshold", type=int, default=3000)

    args = parser.parse_args()
    obs  = ObservabilityPlatform()

    if args.command == "html":
        obs.generate_html_dashboard(args.output)
    elif args.command == "trace":
        spans = obs.get_trace(args.trace_id)
        print(f"\n  Trace: {args.trace_id}")
        for span in spans:
            print(
                f"  [{span['service']}] "
                f"{span['name']} — "
                f"{span['duration_ms']}ms "
                f"[{span['status']}]"
            )
    elif args.command == "slow":
        slow = obs.get_slow_operations(args.threshold)
        print(f"\n  Slow operations (>{args.threshold}ms):")
        for op in slow:
            print(
                f"  {op['name']} — "
                f"{op['duration_ms']}ms — "
                f"{op['service']}"
            )
    else:
        obs.print_dashboard()