import sys
sys.stdout.reconfigure(encoding='utf-8')

import re
import os
import json
import hashlib
import secrets
from datetime import datetime


# ── Input Validation ──────────────────────────────────────────
class InputValidator:
    """
    Validates and sanitizes all user inputs before
    they reach the scanner or API.
    """

    # Known malicious patterns to block
    BLOCKED_PATTERNS = [
        r"<script[^>]*>",           # XSS
        r"javascript:",             # XSS
        r"on\w+\s*=",              # Event handlers
        r"--\s*$",                 # SQL injection
        r";\s*(drop|delete|insert)", # SQL injection
        r"\.\./",                  # Path traversal
        r"etc/passwd",             # Path traversal
        r"cmd\.exe",               # Command injection
        r"/bin/bash",              # Command injection
    ]

    MAX_LENGTHS = {
        "target_name"  : 200,
        "system_prompt": 5000,
        "api_url"      : 500,
        "email"        : 200,
        "scan_id"      : 50
    }

    @classmethod
    def validate_target_name(cls, name):
        """Validates target name input."""
        if not name or not isinstance(name, str):
            raise ValueError("Target name must be a non-empty string")

        name = name.strip()

        if len(name) > cls.MAX_LENGTHS["target_name"]:
            raise ValueError(
                f"Target name too long (max {cls.MAX_LENGTHS['target_name']} chars)"
            )

        if cls._contains_malicious(name):
            raise ValueError("Target name contains invalid characters")

        return name

    @classmethod
    def validate_system_prompt(cls, prompt):
        """Validates system prompt input."""
        if not prompt:
            return None

        if not isinstance(prompt, str):
            raise ValueError("System prompt must be a string")

        prompt = prompt.strip()

        if len(prompt) > cls.MAX_LENGTHS["system_prompt"]:
            raise ValueError(
                f"System prompt too long (max {cls.MAX_LENGTHS['system_prompt']} chars)"
            )

        return prompt

    @classmethod
    def validate_api_url(cls, url):
        """Validates API URL input."""
        if not url:
            return None

        if not isinstance(url, str):
            raise ValueError("API URL must be a string")

        url = url.strip()

        if len(url) > cls.MAX_LENGTHS["api_url"]:
            raise ValueError("API URL too long")

        # Must start with http or https or ws
        if not re.match(r'^(https?|wss?)://', url):
            raise ValueError(
                "API URL must start with http://, https://, or wss://"
            )

        if cls._contains_malicious(url):
            raise ValueError("API URL contains invalid characters")

        return url

    @classmethod
    def validate_email(cls, email):
        """Validates email input."""
        if not email or not isinstance(email, str):
            raise ValueError("Email must be a non-empty string")

        email = email.strip().lower()

        if len(email) > cls.MAX_LENGTHS["email"]:
            raise ValueError("Email too long")

        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ValueError("Invalid email format")

        return email

    @classmethod
    def validate_scan_id(cls, scan_id):
        """Validates scan ID — alphanumeric only."""
        if not scan_id or not isinstance(scan_id, str):
            raise ValueError("Scan ID must be a non-empty string")

        scan_id = scan_id.strip()

        if len(scan_id) > cls.MAX_LENGTHS["scan_id"]:
            raise ValueError("Scan ID too long")

        if not re.match(r'^[a-zA-Z0-9_\-]+$', scan_id):
            raise ValueError("Scan ID contains invalid characters")

        return scan_id

    @classmethod
    def validate_categories(cls, categories):
        """Validates attack categories list."""
        if not categories:
            return None

        from attacks.prompts import ATTACK_PROMPTS
        valid_cats = list(ATTACK_PROMPTS.keys())

        if not isinstance(categories, list):
            raise ValueError("Categories must be a list")

        for cat in categories:
            if cat not in valid_cats:
                raise ValueError(
                    f"Invalid category: {cat}. "
                    f"Valid: {', '.join(valid_cats)}"
                )

        return categories

    @classmethod
    def _contains_malicious(cls, text):
        """Checks if text contains malicious patterns."""
        text_lower = text.lower()
        for pattern in cls.BLOCKED_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True
        return False

    @classmethod
    def sanitize_output(cls, text):
        """
        Sanitizes text for safe HTML output.
        Prevents XSS in reports and dashboard.
        """
        if not isinstance(text, str):
            return str(text)

        replacements = {
            "&" : "&amp;",
            "<" : "&lt;",
            ">" : "&gt;",
            '"' : "&quot;",
            "'" : "&#x27;"
        }

        for char, replacement in replacements.items():
            text = text.replace(char, replacement)

        return text


# ── Rate Limiter ──────────────────────────────────────────────
class RateLimiter:
    """
    Simple in-memory rate limiter.
    Tracks requests per IP address.
    """

    def __init__(self):
        self.requests = {}  # {ip: [timestamps]}

    def is_allowed(self, ip, limit=20, window_seconds=60):
        """
        Returns True if request is allowed.
        Returns False if rate limit exceeded.
        """
        now = datetime.now().timestamp()

        if ip not in self.requests:
            self.requests[ip] = []

        # Remove old requests outside window
        self.requests[ip] = [
            t for t in self.requests[ip]
            if now - t < window_seconds
        ]

        if len(self.requests[ip]) >= limit:
            return False

        self.requests[ip].append(now)
        return True

    def get_usage(self, ip, window_seconds=60):
        """Returns current usage for an IP."""
        now = datetime.now().timestamp()
        if ip not in self.requests:
            return 0
        recent = [
            t for t in self.requests[ip]
            if now - t < window_seconds
        ]
        return len(recent)


# ── Security Logger ───────────────────────────────────────────
class SecurityLogger:
    """
    Logs security events for audit trail.
    """

    LOG_FILE = "results/security_audit.log"

    @classmethod
    def log(cls, event_type, details, ip=None, severity="INFO"):
        """Logs a security event."""
        os.makedirs("results", exist_ok=True)

        entry = {
            "timestamp" : datetime.now().isoformat(),
            "event_type": event_type,
            "severity"  : severity,
            "ip"        : ip or "unknown",
            "details"   : details
        }

        with open(cls.LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    @classmethod
    def log_scan_start(cls, target_name, ip=None):
        cls.log("SCAN_STARTED", {"target": target_name}, ip)

    @classmethod
    def log_scan_complete(cls, scan_id, score, ip=None):
        cls.log("SCAN_COMPLETE", {
            "scan_id": scan_id,
            "score"  : score
        }, ip)

    @classmethod
    def log_invalid_input(cls, field, value, ip=None):
        cls.log("INVALID_INPUT", {
            "field": field,
            "value": str(value)[:50]
        }, ip, severity="WARNING")

    @classmethod
    def log_rate_limit(cls, ip):
        cls.log("RATE_LIMIT_HIT", {}, ip, severity="WARNING")

    @classmethod
    def log_auth_attempt(cls, username, success, ip=None):
        cls.log("AUTH_ATTEMPT", {
            "username": username,
            "success" : success
        }, ip, severity="INFO" if success else "WARNING")

    @classmethod
    def get_recent_events(cls, limit=50):
        """Returns recent security events."""
        if not os.path.exists(cls.LOG_FILE):
            return []

        events = []
        with open(cls.LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    events.append(json.loads(line.strip()))
                except:
                    continue

        return events[-limit:]


# ── Secret Generator ──────────────────────────────────────────
class SecretManager:
    """
    Manages secrets and API keys securely.
    """

    @staticmethod
    def generate_api_key():
        """Generates a secure random API key."""
        return f"lls_{secrets.token_urlsafe(32)}"

    @staticmethod
    def generate_scan_id():
        """Generates a secure random scan ID."""
        return secrets.token_hex(4)

    @staticmethod
    def hash_api_key(api_key):
        """Hashes an API key for storage."""
        return hashlib.sha256(api_key.encode()).hexdigest()

    @staticmethod
    def verify_api_key(plain_key, hashed_key):
        """Verifies an API key against its hash."""
        return hashlib.sha256(
            plain_key.encode()
        ).hexdigest() == hashed_key


# ── Security Headers ──────────────────────────────────────────
SECURITY_HEADERS = {
    "X-Content-Type-Options" : "nosniff",
    "X-Frame-Options"        : "DENY",
    "X-XSS-Protection"       : "1; mode=block",
    "Referrer-Policy"        : "strict-origin-when-cross-origin",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline';"
    )
}


# ── Add Security Headers To FastAPI ───────────────────────────
def add_security_middleware(app):
    """
    Adds security headers to all FastAPI responses.
    Call this in api.py after creating the app.
    """
    from fastapi import Request
    from fastapi.responses import Response

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        return response

    return app


# ── Audit Report ──────────────────────────────────────────────
def generate_security_audit_report():
    """
    Generates a report of security events.
    """
    events  = SecurityLogger.get_recent_events(100)
    by_type = {}

    for event in events:
        etype = event["event_type"]
        if etype not in by_type:
            by_type[etype] = 0
        by_type[etype] += 1

    warnings = [e for e in events if e["severity"] == "WARNING"]

    print("\n" + "=" * 50)
    print("  SECURITY AUDIT REPORT")
    print("=" * 50)
    print(f"  Total events : {len(events)}")
    print(f"  Warnings     : {len(warnings)}")
    print()
    print("  Event breakdown :")
    for etype, count in by_type.items():
        print(f"    {etype:<30} : {count}")

    if warnings:
        print(f"\n  Recent warnings :")
        for w in warnings[-5:]:
            print(f"    [{w['timestamp'][:16]}] {w['event_type']}")

    print("=" * 50)


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "audit":
            generate_security_audit_report()
        elif sys.argv[1] == "generate-key":
            key = SecretManager.generate_api_key()
            print(f"Generated API key : {key}")
        elif sys.argv[1] == "test":
            # Test input validation
            v = InputValidator()
            print("Testing input validation...")

            try:
                v.validate_target_name("<script>alert(1)</script>")
                print("❌ XSS not blocked")
            except ValueError:
                print("✅ XSS blocked")

            try:
                v.validate_email("not-an-email")
                print("❌ Invalid email not blocked")
            except ValueError:
                print("✅ Invalid email blocked")

            try:
                v.validate_api_url("ftp://evil.com")
                print("❌ Invalid URL not blocked")
            except ValueError:
                print("✅ Invalid URL blocked")

            print("\nAll security tests passed !")
    else:
        print("Usage :")
        print("  python security.py audit        → Show audit report")
        print("  python security.py generate-key → Generate API key")
        print("  python security.py test         → Test validation")
        