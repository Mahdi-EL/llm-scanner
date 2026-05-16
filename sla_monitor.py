import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import time
import threading
import statistics
from datetime import datetime, timedelta
from database import DB_PATH
import sqlite3


# ── SLA Definitions ───────────────────────────────────────────
SLA_DEFINITIONS = {
    "api_uptime": {
        "name"       : "API Uptime",
        "target"     : 99.9,
        "unit"       : "%",
        "description": "API must be available 99.9% of the time",
        "check_interval_seconds": 60
    },
    "scan_duration": {
        "name"       : "Scan Duration",
        "target"     : 900,  # 15 minutes in seconds
        "unit"       : "seconds",
        "description": "Scans must complete within 15 minutes",
        "check_interval_seconds": 300
    },
    "api_response_time": {
        "name"       : "API Response Time",
        "target"     : 200,  # ms
        "unit"       : "ms",
        "description": "API responses must be under 200ms",
        "check_interval_seconds": 30
    },
    "error_rate": {
        "name"       : "Error Rate",
        "target"     : 1.0,  # max 1%
        "unit"       : "%",
        "description": "Error rate must stay below 1%",
        "check_interval_seconds": 60
    },
    "report_generation": {
        "name"       : "Report Generation",
        "target"     : 30,  # seconds
        "unit"       : "seconds",
        "description": "Reports must generate within 30 seconds",
        "check_interval_seconds": 300
    }
}

# SLA tiers per plan
SLA_TIERS = {
    "starter": {
        "api_uptime"        : 99.0,
        "scan_duration"     : 1800,  # 30 minutes
        "api_response_time" : 500,
        "error_rate"        : 5.0,
        "report_generation" : 60
    },
    "pro": {
        "api_uptime"        : 99.5,
        "scan_duration"     : 900,   # 15 minutes
        "api_response_time" : 300,
        "error_rate"        : 2.0,
        "report_generation" : 30
    },
    "agency": {
        "api_uptime"        : 99.9,
        "scan_duration"     : 600,   # 10 minutes
        "api_response_time" : 200,
        "error_rate"        : 1.0,
        "report_generation" : 15
    }
}


# ── SLA Metric ────────────────────────────────────────────────
class SLAMetric:
    """Represents a single SLA measurement."""

    def __init__(
        self,
        metric_name,
        value,
        target,
        unit,
        tenant_id=None
    ):
        self.metric_name = metric_name
        self.value       = value
        self.target      = target
        self.unit        = unit
        self.tenant_id   = tenant_id
        self.timestamp   = datetime.now().isoformat()
        self.is_breached = self._check_breach()

    def _check_breach(self):
        """Checks if SLA is breached."""
        if self.metric_name == "api_uptime":
            return self.value < self.target
        elif self.metric_name == "error_rate":
            return self.value > self.target
        else:
            return self.value > self.target

    @property
    def status(self):
        return "BREACHED" if self.is_breached else "OK"

    @property
    def deviation(self):
        return round(abs(self.value - self.target), 2)

    def to_dict(self):
        return {
            "metric_name": self.metric_name,
            "value"      : self.value,
            "target"     : self.target,
            "unit"       : self.unit,
            "status"     : self.status,
            "is_breached": self.is_breached,
            "deviation"  : self.deviation,
            "timestamp"  : self.timestamp,
            "tenant_id"  : self.tenant_id
        }


# ── SLA Monitor ───────────────────────────────────────────────
class SLAMonitor:
    """
    Monitors SLA compliance for LLM Scanner.
    Tracks uptime, response times, error rates, scan durations.
    """

    def __init__(self):
        self._ensure_tables()
        self._running      = False
        self._thread       = None
        self._request_log  = []
        self._error_log    = []
        self._scan_log     = []
        self._lock         = threading.Lock()

    def _ensure_tables(self):
        """Creates SLA tables."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS sla_measurements (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_name  TEXT NOT NULL,
                value        REAL NOT NULL,
                target       REAL NOT NULL,
                unit         TEXT NOT NULL,
                status       TEXT NOT NULL,
                is_breached  INTEGER DEFAULT 0,
                deviation    REAL DEFAULT 0,
                tenant_id    TEXT,
                measured_at  TEXT NOT NULL
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS sla_breaches (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                breach_id    TEXT UNIQUE NOT NULL,
                metric_name  TEXT NOT NULL,
                value        REAL NOT NULL,
                target       REAL NOT NULL,
                severity     TEXT DEFAULT 'WARNING',
                tenant_id    TEXT,
                resolved     INTEGER DEFAULT 0,
                detected_at  TEXT NOT NULL,
                resolved_at  TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS sla_uptime_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                is_up        INTEGER NOT NULL,
                response_ms  INTEGER,
                error        TEXT,
                checked_at   TEXT NOT NULL
            )
        """)

        conn.commit()
        conn.close()

    # ── Recording Methods ─────────────────────────────────────

    def record_request(self, duration_ms, is_error=False, tenant_id=None):
        """Records an API request for SLA tracking."""
        with self._lock:
            self._request_log.append({
                "duration_ms": duration_ms,
                "is_error"   : is_error,
                "tenant_id"  : tenant_id,
                "timestamp"  : time.time()
            })
            # Keep last 1000 requests
            if len(self._request_log) > 1000:
                self._request_log = self._request_log[-1000:]

    def record_scan_duration(self, duration_seconds, tenant_id=None):
        """Records a scan duration for SLA tracking."""
        with self._lock:
            self._scan_log.append({
                "duration" : duration_seconds,
                "tenant_id": tenant_id,
                "timestamp": time.time()
            })
            if len(self._scan_log) > 500:
                self._scan_log = self._scan_log[-500:]

    def record_uptime_check(self, is_up, response_ms=None, error=None):
        """Records an uptime check result."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT INTO sla_uptime_log (is_up, response_ms, error, checked_at)
            VALUES (?, ?, ?, ?)
        """, (
            1 if is_up else 0,
            response_ms,
            error,
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()

    # ── Calculation Methods ───────────────────────────────────

    def calculate_uptime(self, hours=24):
        """Calculates uptime percentage over the last N hours."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        since = (
            datetime.now() - timedelta(hours=hours)
        ).isoformat()

        c.execute("""
            SELECT
                COUNT(*) as total,
                SUM(is_up) as up_count
            FROM sla_uptime_log
            WHERE checked_at > ?
        """, (since,))

        row = c.fetchone()
        conn.close()

        if not row or not row[0]:
            return 100.0  # No data = assume up

        total    = row[0]
        up_count = row[1] or 0
        return round((up_count / total) * 100, 3)

    def calculate_avg_response_time(self, minutes=60):
        """Calculates average API response time."""
        with self._lock:
            cutoff  = time.time() - (minutes * 60)
            recent  = [
                r["duration_ms"]
                for r in self._request_log
                if r["timestamp"] > cutoff
            ]

        if not recent:
            return 0.0

        return round(statistics.mean(recent), 2)

    def calculate_error_rate(self, minutes=60):
        """Calculates API error rate percentage."""
        with self._lock:
            cutoff  = time.time() - (minutes * 60)
            recent  = [
                r for r in self._request_log
                if r["timestamp"] > cutoff
            ]

        if not recent:
            return 0.0

        errors = sum(1 for r in recent if r["is_error"])
        return round((errors / len(recent)) * 100, 2)

    def calculate_avg_scan_duration(self, hours=24):
        """Calculates average scan duration."""
        with self._lock:
            cutoff  = time.time() - (hours * 3600)
            recent  = [
                s["duration"]
                for s in self._scan_log
                if s["timestamp"] > cutoff
            ]

        if not recent:
            return 0.0

        return round(statistics.mean(recent), 2)

    def calculate_p95_response_time(self, minutes=60):
        """Calculates 95th percentile response time."""
        with self._lock:
            cutoff  = time.time() - (minutes * 60)
            recent  = sorted([
                r["duration_ms"]
                for r in self._request_log
                if r["timestamp"] > cutoff
            ])

        if not recent:
            return 0.0

        idx = int(len(recent) * 0.95)
        return recent[min(idx, len(recent) - 1)]

    # ── Measurement Methods ───────────────────────────────────

    def measure_all(self, tenant_id=None):
        """
        Takes all SLA measurements.
        Returns list of SLAMetric objects.
        """
        plan   = self._get_tenant_plan(tenant_id)
        limits = SLA_TIERS.get(plan, SLA_TIERS["pro"])

        measurements = [
            SLAMetric(
                "api_uptime",
                self.calculate_uptime(24),
                limits["api_uptime"],
                "%",
                tenant_id
            ),
            SLAMetric(
                "api_response_time",
                self.calculate_avg_response_time(60),
                limits["api_response_time"],
                "ms",
                tenant_id
            ),
            SLAMetric(
                "error_rate",
                self.calculate_error_rate(60),
                limits["error_rate"],
                "%",
                tenant_id
            ),
            SLAMetric(
                "scan_duration",
                self.calculate_avg_scan_duration(24),
                limits["scan_duration"],
                "seconds",
                tenant_id
            ),
        ]

        # Save measurements
        self._save_measurements(measurements)

        # Check for breaches
        for m in measurements:
            if m.is_breached:
                self._record_breach(m)

        return measurements

    def _save_measurements(self, measurements):
        """Saves measurements to database."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        for m in measurements:
            c.execute("""
                INSERT INTO sla_measurements (
                    metric_name, value, target, unit,
                    status, is_breached, deviation,
                    tenant_id, measured_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                m.metric_name,
                m.value,
                m.target,
                m.unit,
                m.status,
                1 if m.is_breached else 0,
                m.deviation,
                m.tenant_id,
                m.timestamp
            ))

        conn.commit()
        conn.close()

    def _record_breach(self, metric):
        """Records an SLA breach."""
        import secrets

        breach_id = f"breach_{secrets.token_hex(6)}"
        severity  = "CRITICAL" if metric.deviation > 10 else "WARNING"

        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT OR IGNORE INTO sla_breaches (
                breach_id, metric_name, value, target,
                severity, tenant_id, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            breach_id,
            metric.metric_name,
            metric.value,
            metric.target,
            severity,
            metric.tenant_id,
            metric.timestamp
        ))

        conn.commit()
        conn.close()

        print(
            f"\n  🚨 SLA BREACH DETECTED !"
            f"\n  Metric  : {metric.metric_name}"
            f"\n  Value   : {metric.value}{metric.unit}"
            f"\n  Target  : {metric.target}{metric.unit}"
            f"\n  Severity: {severity}"
        )

    def _get_tenant_plan(self, tenant_id):
        """Gets tenant plan."""
        if not tenant_id:
            return "pro"
        try:
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()
            c.execute(
                "SELECT plan FROM tenants WHERE tenant_id = ?",
                (tenant_id,)
            )
            row = c.fetchone()
            conn.close()
            return row[0] if row else "pro"
        except:
            return "pro"

    # ── Historical Analysis ───────────────────────────────────

    def get_sla_history(self, metric_name=None, hours=168):
        """Gets historical SLA measurements."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        since = (
            datetime.now() - timedelta(hours=hours)
        ).isoformat()

        if metric_name:
            c.execute("""
                SELECT * FROM sla_measurements
                WHERE metric_name = ? AND measured_at > ?
                ORDER BY measured_at DESC
            """, (metric_name, since))
        else:
            c.execute("""
                SELECT * FROM sla_measurements
                WHERE measured_at > ?
                ORDER BY measured_at DESC
            """, (since,))

        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return rows

    def get_breach_history(self, hours=720):
        """Gets historical SLA breaches."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        since = (
            datetime.now() - timedelta(hours=hours)
        ).isoformat()

        c.execute("""
            SELECT * FROM sla_breaches
            WHERE detected_at > ?
            ORDER BY detected_at DESC
        """, (since,))

        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return rows

    def get_compliance_score(self, hours=24):
        """
        Calculates overall SLA compliance score.
        Returns percentage of measurements that met SLA.
        """
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        since = (
            datetime.now() - timedelta(hours=hours)
        ).isoformat()

        c.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN is_breached = 0 THEN 1 ELSE 0 END) as compliant
            FROM sla_measurements
            WHERE measured_at > ?
        """, (since,))

        row = c.fetchone()
        conn.close()

        if not row or not row[0]:
            return 100.0

        return round((row[1] / row[0]) * 100, 1)

    # ── Reporting ─────────────────────────────────────────────

    def generate_sla_report(self, tenant_id=None):
        """Generates a comprehensive SLA report."""
        measurements   = self.measure_all(tenant_id)
        breaches       = self.get_breach_history(hours=720)
        compliance     = self.get_compliance_score()
        uptime         = self.calculate_uptime(720)  # 30 days

        print(f"\n  {'='*60}")
        print(f"  SLA MONITORING REPORT")
        if tenant_id:
            print(f"  Tenant : {tenant_id}")
        print(f"  {'='*60}")
        print(f"\n  Overall Compliance : {compliance}%")
        print(f"  30-Day Uptime      : {uptime}%")
        print(f"  Total Breaches     : {len(breaches)}")
        print()
        print(f"  Current Measurements :")
        print(f"  {'-'*50}")

        for m in measurements:
            status_icon = "✅" if not m.is_breached else "🚨"
            print(
                f"  {status_icon} {m.metric_name:<25}"
                f" {m.value:>8.1f}{m.unit:<10}"
                f" (target: {m.target}{m.unit})"
            )

        if breaches:
            print(f"\n  Recent Breaches :")
            print(f"  {'-'*50}")
            for b in breaches[:5]:
                resolved = "✅ RESOLVED" if b["resolved"] else "🔴 ACTIVE"
                print(
                    f"  {resolved} {b['metric_name']:<25}"
                    f" {b['detected_at'][:16]}"
                )

        print(f"\n  SLA Tiers :")
        print(f"  {'-'*50}")
        for plan, limits in SLA_TIERS.items():
            print(f"  {plan.upper()} :")
            print(f"    Uptime    : {limits['api_uptime']}%")
            print(f"    Response  : {limits['api_response_time']}ms")
            print(f"    Error Rate: {limits['error_rate']}%")

        print(f"\n  {'='*60}\n")

        return {
            "compliance"    : compliance,
            "uptime"        : uptime,
            "breaches"      : len(breaches),
            "measurements"  : [m.to_dict() for m in measurements]
        }

    # ── Background Monitor ────────────────────────────────────

    def start(self, check_interval=60):
        """Starts background SLA monitoring."""
        self._running = True

        def loop():
            print(f"  SLA Monitor started")
            while self._running:
                try:
                    # Simulate uptime check
                    start     = time.time()
                    is_up     = True  # Replace with real health check
                    elapsed   = int((time.time() - start) * 1000)

                    self.record_uptime_check(is_up, elapsed)
                    self.measure_all()

                except Exception as e:
                    print(f"  SLA Monitor error: {e}")
                    self.record_uptime_check(False, error=str(e))

                time.sleep(check_interval)

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stops background monitoring."""
        self._running = False
        print("  SLA Monitor stopped")

    def simulate_load(self, requests=100):
        """
        Simulates API load for testing.
        Generates realistic request patterns.
        """
        import random

        print(f"  Simulating {requests} API requests...")

        for i in range(requests):
            # Simulate response time (mostly fast, some slow)
            if random.random() < 0.9:
                duration = random.gauss(80, 30)  # avg 80ms
            else:
                duration = random.gauss(400, 100)  # occasional slow

            duration = max(10, duration)
            is_error = random.random() < 0.02  # 2% error rate

            self.record_request(int(duration), is_error)

        # Simulate some scan durations
        for _ in range(10):
            duration = random.gauss(300, 60)  # avg 5 minutes
            self.record_scan_duration(max(60, duration))

        print(f"  Simulation complete")
        print(f"  Avg response time : {self.calculate_avg_response_time()}ms")
        print(f"  Error rate        : {self.calculate_error_rate()}%")


# ── Global SLA Monitor ────────────────────────────────────────
_global_monitor = None


def get_sla_monitor():
    """Returns global SLA monitor (singleton)."""
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = SLAMonitor()
    return _global_monitor


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — SLA Monitor"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Report
    p_report = subparsers.add_parser("report")
    p_report.add_argument("--tenant", default=None)

    # Start monitor
    p_start = subparsers.add_parser("start")
    p_start.add_argument("--interval", type=int, default=60)

    # Simulate
    p_sim = subparsers.add_parser("simulate")
    p_sim.add_argument("--requests", type=int, default=100)

    # History
    p_hist = subparsers.add_parser("history")
    p_hist.add_argument("--metric", default=None)
    p_hist.add_argument("--hours",  type=int, default=24)

    # Tiers
    subparsers.add_parser("tiers")

    args    = parser.parse_args()
    monitor = SLAMonitor()

    if args.command == "report":
        monitor.generate_sla_report(args.tenant)

    elif args.command == "start":
        monitor.start(args.interval)
        print("  SLA Monitor running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            monitor.stop()

    elif args.command == "simulate":
        monitor.simulate_load(args.requests)
        monitor.generate_sla_report()

    elif args.command == "history":
        history = monitor.get_sla_history(args.metric, args.hours)
        print(f"\n  SLA History ({len(history)} measurements) :")
        for h in history[:20]:
            icon = "✅" if not h["is_breached"] else "🚨"
            print(
                f"  {icon} {h['metric_name']:<25}"
                f" {h['value']:>8.1f}{h['unit']}"
                f" {h['measured_at'][:16]}"
            )

    elif args.command == "tiers":
        print(f"\n  SLA Tiers :")
        for plan, limits in SLA_TIERS.items():
            print(f"\n  {plan.upper()} :")
            for metric, value in limits.items():
                defn = SLA_DEFINITIONS.get(metric, {})
                unit = defn.get("unit", "")
                print(f"    {metric:<20} : {value}{unit}")

    else:
        parser.print_help()