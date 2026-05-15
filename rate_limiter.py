import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import time
import threading
from datetime import datetime
from collections import defaultdict
from database import DB_PATH
import sqlite3


# ── Plan Limits ───────────────────────────────────────────────
PLAN_LIMITS = {
    "starter": {
        "requests_per_minute" : 20,
        "requests_per_hour"   : 100,
        "requests_per_day"    : 500,
        "scans_per_day"       : 2,
        "concurrent_scans"    : 1,
        "max_payload_mb"      : 1,
        "websocket_connections": 1
    },
    "pro": {
        "requests_per_minute" : 100,
        "requests_per_hour"   : 1000,
        "requests_per_day"    : 10000,
        "scans_per_day"       : 10,
        "concurrent_scans"    : 3,
        "max_payload_mb"      : 5,
        "websocket_connections": 5
    },
    "agency": {
        "requests_per_minute" : 500,
        "requests_per_hour"   : 10000,
        "requests_per_day"    : 100000,
        "scans_per_day"       : -1,  # Unlimited
        "concurrent_scans"    : 10,
        "max_payload_mb"      : 20,
        "websocket_connections": 20
    },
    "default": {
        "requests_per_minute" : 10,
        "requests_per_hour"   : 50,
        "requests_per_day"    : 200,
        "scans_per_day"       : 1,
        "concurrent_scans"    : 1,
        "max_payload_mb"      : 1,
        "websocket_connections": 1
    }
}


# ── Token Bucket ──────────────────────────────────────────────
class TokenBucket:
    """
    Token bucket algorithm for rate limiting.
    Tokens refill at a constant rate.
    Requests consume tokens.
    """

    def __init__(self, capacity, refill_rate):
        self.capacity    = capacity
        self.tokens      = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.last_refill = time.time()
        self._lock       = threading.Lock()

    def consume(self, tokens=1):
        """
        Tries to consume tokens.
        Returns True if allowed, False if rate limited.
        """
        with self._lock:
            self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True, self.tokens
            return False, self.tokens

    def _refill(self):
        """Refills tokens based on elapsed time."""
        now     = time.time()
        elapsed = now - self.last_refill
        refill  = elapsed * self.refill_rate

        self.tokens      = min(self.capacity, self.tokens + refill)
        self.last_refill = now

    @property
    def remaining(self):
        """Returns remaining tokens."""
        self._refill()
        return int(self.tokens)


# ── Sliding Window Counter ────────────────────────────────────
class SlidingWindowCounter:
    """
    Sliding window rate limiter.
    Counts requests in the last N seconds.
    """

    def __init__(self, window_seconds, max_requests):
        self.window      = window_seconds
        self.max_requests= max_requests
        self.requests    = []
        self._lock       = threading.Lock()

    def is_allowed(self):
        """
        Checks if request is allowed.
        Returns (allowed, count, reset_time)
        """
        with self._lock:
            now = time.time()

            # Remove old requests outside window
            self.requests = [
                r for r in self.requests
                if now - r < self.window
            ]

            count = len(self.requests)

            if count >= self.max_requests:
                # Calculate reset time
                oldest      = self.requests[0] if self.requests else now
                reset_time  = oldest + self.window
                return False, count, reset_time

            self.requests.append(now)
            return True, count + 1, now + self.window


# ── Advanced Rate Limiter ─────────────────────────────────────
class AdvancedRateLimiter:
    """
    Multi-tier rate limiter that enforces limits
    at minute, hour, and day levels.
    Also enforces concurrent scan limits.
    """

    def __init__(self):
        # {tenant_id: {window: SlidingWindowCounter}}
        self._counters         = defaultdict(dict)
        self._buckets          = defaultdict(dict)
        self._concurrent_scans = defaultdict(int)
        self._lock             = threading.Lock()
        self._ensure_tables()

    def _ensure_tables(self):
        """Creates rate limit tables."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS rate_limit_violations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id   TEXT,
                ip_address  TEXT,
                limit_type  TEXT NOT NULL,
                endpoint    TEXT,
                violated_at TEXT NOT NULL,
                plan        TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS rate_limit_stats (
                id              INTEGER PRIMARY KEY,
                total_allowed   INTEGER DEFAULT 0,
                total_blocked   INTEGER DEFAULT 0,
                last_updated    TEXT
            )
        """)

        c.execute(
            "INSERT OR IGNORE INTO rate_limit_stats (id) VALUES (1)"
        )

        conn.commit()
        conn.close()

    def _get_plan(self, tenant_id):
        """Gets tenant plan from database."""
        if not tenant_id:
            return "default"

        try:
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()
            c.execute(
                "SELECT plan FROM tenants WHERE tenant_id = ?",
                (tenant_id,)
            )
            row = c.fetchone()
            conn.close()
            return row[0] if row else "default"
        except:
            return "default"

    def _get_limits(self, plan):
        """Gets rate limits for a plan."""
        return PLAN_LIMITS.get(plan, PLAN_LIMITS["default"])

    def _get_counter(self, key, window, max_requests):
        """Gets or creates a sliding window counter."""
        with self._lock:
            if key not in self._counters:
                self._counters[key] = {}
            if window not in self._counters[key]:
                self._counters[key][window] = SlidingWindowCounter(
                    window, max_requests
                )
            return self._counters[key][window]

    def check_request(self, tenant_id=None, ip_address=None, endpoint=None):
        """
        Checks if a request is allowed.
        Returns (allowed, headers, reason)
        """
        plan   = self._get_plan(tenant_id)
        limits = self._get_limits(plan)
        key    = tenant_id or ip_address or "anonymous"

        # Check minute limit
        min_counter = self._get_counter(
            f"{key}:minute", 60,
            limits["requests_per_minute"]
        )
        allowed_min, count_min, reset_min = min_counter.is_allowed()

        if not allowed_min:
            self._record_violation(
                tenant_id, ip_address,
                "per_minute", endpoint, plan
            )
            return False, self._build_headers(
                plan, limits, count_min,
                limits["requests_per_minute"],
                reset_min, "per_minute"
            ), "Rate limit exceeded: too many requests per minute"

        # Check hour limit
        hour_counter = self._get_counter(
            f"{key}:hour", 3600,
            limits["requests_per_hour"]
        )
        allowed_hour, count_hour, reset_hour = hour_counter.is_allowed()

        if not allowed_hour:
            self._record_violation(
                tenant_id, ip_address,
                "per_hour", endpoint, plan
            )
            return False, self._build_headers(
                plan, limits, count_hour,
                limits["requests_per_hour"],
                reset_hour, "per_hour"
            ), "Rate limit exceeded: too many requests per hour"

        # Check day limit
        day_counter = self._get_counter(
            f"{key}:day", 86400,
            limits["requests_per_day"]
        )
        allowed_day, count_day, reset_day = day_counter.is_allowed()

        if not allowed_day:
            self._record_violation(
                tenant_id, ip_address,
                "per_day", endpoint, plan
            )
            return False, self._build_headers(
                plan, limits, count_day,
                limits["requests_per_day"],
                reset_day, "per_day"
            ), "Rate limit exceeded: daily limit reached"

        # All checks passed
        self._record_allowed()
        return True, self._build_headers(
            plan, limits, count_min,
            limits["requests_per_minute"],
            reset_min
        ), None

    def check_concurrent_scans(self, tenant_id):
        """Checks if tenant can start another concurrent scan."""
        plan   = self._get_plan(tenant_id)
        limits = self._get_limits(plan)
        max_concurrent = limits["concurrent_scans"]

        with self._lock:
            current = self._concurrent_scans.get(tenant_id, 0)
            if max_concurrent != -1 and current >= max_concurrent:
                return False, current, max_concurrent
            return True, current, max_concurrent

    def increment_concurrent(self, tenant_id):
        """Increments concurrent scan count."""
        with self._lock:
            self._concurrent_scans[tenant_id] = \
                self._concurrent_scans.get(tenant_id, 0) + 1

    def decrement_concurrent(self, tenant_id):
        """Decrements concurrent scan count."""
        with self._lock:
            count = self._concurrent_scans.get(tenant_id, 0)
            self._concurrent_scans[tenant_id] = max(0, count - 1)

    def _build_headers(
        self, plan, limits, current, maximum, reset, limit_type=None
    ):
        """Builds rate limit response headers."""
        remaining = max(0, maximum - current)
        headers   = {
            "X-RateLimit-Plan"     : plan,
            "X-RateLimit-Limit"    : str(maximum),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset"    : str(int(reset)),
            "X-RateLimit-Window"   : limit_type or "per_minute",
            "Retry-After"          : str(int(reset - time.time()))
                                     if remaining == 0 else "0"
        }
        return headers

    def _record_violation(
        self, tenant_id, ip, limit_type, endpoint, plan
    ):
        """Records a rate limit violation."""
        try:
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()

            c.execute("""
                INSERT INTO rate_limit_violations (
                    tenant_id, ip_address, limit_type,
                    endpoint, violated_at, plan
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                tenant_id, ip, limit_type,
                endpoint, datetime.now().isoformat(), plan
            ))

            c.execute("""
                UPDATE rate_limit_stats
                SET total_blocked = total_blocked + 1,
                    last_updated  = ?
                WHERE id = 1
            """, (datetime.now().isoformat(),))

            conn.commit()
            conn.close()
        except:
            pass

    def _record_allowed(self):
        """Records an allowed request."""
        try:
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()

            c.execute("""
                UPDATE rate_limit_stats
                SET total_allowed = total_allowed + 1,
                    last_updated  = ?
                WHERE id = 1
            """, (datetime.now().isoformat(),))

            conn.commit()
            conn.close()
        except:
            pass

    def get_stats(self):
        """Returns rate limiting statistics."""
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            c    = conn.cursor()

            c.execute("SELECT * FROM rate_limit_stats WHERE id = 1")
            stats = dict(c.fetchone() or {})

            c.execute("""
                SELECT limit_type, COUNT(*) as count
                FROM rate_limit_violations
                GROUP BY limit_type
                ORDER BY count DESC
            """)
            violations_by_type = {
                row["limit_type"]: row["count"]
                for row in c.fetchall()
            }

            c.execute("""
                SELECT plan, COUNT(*) as count
                FROM rate_limit_violations
                GROUP BY plan
            """)
            violations_by_plan = {
                row["plan"]: row["count"]
                for row in c.fetchall()
            }

            conn.close()

            stats["violations_by_type"] = violations_by_type
            stats["violations_by_plan"] = violations_by_plan
            return stats
        except:
            return {}

    def print_stats(self):
        """Prints rate limiting statistics."""
        stats = self.get_stats()

        print(f"\n  {'='*50}")
        print(f"  RATE LIMITER STATS")
        print(f"  {'='*50}")
        print(f"  Total Allowed  : {stats.get('total_allowed', 0)}")
        print(f"  Total Blocked  : {stats.get('total_blocked', 0)}")

        violations = stats.get("violations_by_type", {})
        if violations:
            print(f"\n  Violations by type :")
            for vtype, count in violations.items():
                print(f"    {vtype:<15} : {count}")

        by_plan = stats.get("violations_by_plan", {})
        if by_plan:
            print(f"\n  Violations by plan :")
            for plan, count in by_plan.items():
                print(f"    {plan:<10} : {count}")

        print(f"\n  Plan Limits :")
        for plan, limits in PLAN_LIMITS.items():
            if plan == "default":
                continue
            print(
                f"    {plan:<10} : "
                f"{limits['requests_per_minute']}/min "
                f"{limits['requests_per_hour']}/hr "
                f"{limits['requests_per_day']}/day"
            )
        print(f"  {'='*50}\n")

    def print_plan_comparison(self):
        """Prints comparison of all plan limits."""
        print(f"\n  {'='*70}")
        print(f"  RATE LIMIT PLAN COMPARISON")
        print(f"  {'='*70}")

        fields = [
            ("requests_per_minute",  "Req/Minute"),
            ("requests_per_hour",    "Req/Hour"),
            ("requests_per_day",     "Req/Day"),
            ("scans_per_day",        "Scans/Day"),
            ("concurrent_scans",     "Concurrent"),
            ("max_payload_mb",       "Max MB"),
            ("websocket_connections","WebSockets"),
        ]

        plans = ["starter", "pro", "agency"]
        header = f"  {'Limit':<25}"
        for plan in plans:
            header += f"{plan.upper():<15}"
        print(header)
        print(f"  {'-'*70}")

        for field, label in fields:
            row = f"  {label:<25}"
            for plan in plans:
                val = PLAN_LIMITS[plan][field]
                row += f"{'∞' if val == -1 else val:<15}"
            print(row)

        print(f"  {'='*70}\n")


# ── Global Rate Limiter ───────────────────────────────────────
_global_limiter = None


def get_rate_limiter():
    """Returns the global rate limiter (singleton)."""
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = AdvancedRateLimiter()
    return _global_limiter


# ── FastAPI Middleware ────────────────────────────────────────
def add_rate_limit_middleware(app):
    """
    Adds advanced rate limiting middleware to FastAPI.
    """
    from fastapi import Request
    from fastapi.responses import JSONResponse

    limiter = get_rate_limiter()

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        # Extract tenant from header or auth
        tenant_id  = request.headers.get("X-Tenant-ID")
        ip_address = request.client.host if request.client else "unknown"
        endpoint   = str(request.url.path)

        allowed, headers, reason = limiter.check_request(
            tenant_id, ip_address, endpoint
        )

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error"      : "Rate limit exceeded",
                    "reason"     : reason,
                    "retry_after": headers.get("Retry-After", "60"),
                    "upgrade_url": "/pricing"
                },
                headers=headers
            )

        response = await call_next(request)

        # Add rate limit headers to all responses
        for key, value in headers.items():
            response.headers[key] = value

        return response

    return app


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Advanced Rate Limiter"
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("stats",   help="Show rate limit stats")
    subparsers.add_parser("plans",   help="Show plan comparison")
    subparsers.add_parser("compare", help="Compare all plans")

    p_test = subparsers.add_parser("test", help="Test rate limiting")
    p_test.add_argument("--tenant",  default=None)
    p_test.add_argument("--requests", type=int, default=25)

    args    = parser.parse_args()
    limiter = get_rate_limiter()

    if args.command == "stats":
        limiter.print_stats()

    elif args.command in ("plans", "compare"):
        limiter.print_plan_comparison()

    elif args.command == "test":
        print(f"\n  Testing rate limiter with {args.requests} requests...")
        allowed = 0
        blocked = 0

        for i in range(args.requests):
            ok, headers, reason = limiter.check_request(
                args.tenant, f"192.168.1.{i%10}", "/api/v2/scan"
            )
            if ok:
                allowed += 1
            else:
                blocked += 1
                print(f"  Request {i+1} BLOCKED : {reason}")

        print(f"\n  Results :")
        print(f"  Allowed : {allowed}")
        print(f"  Blocked : {blocked}")

    else:
        limiter.print_plan_comparison()
        