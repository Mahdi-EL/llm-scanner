"""Central settings for the LLM Scanner backend.

Everything configurable is read from the environment (and a local `.env`)
once, here. Other modules import values from this file instead of calling
os.getenv() themselves, so there is one place to look.
"""
import logging
import os

from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger("llmscanner.config")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# ── Environment ───────────────────────────────────────────────
ENV     = os.getenv("ENV", "development").lower()
IS_PROD = ENV in ("prod", "production") or bool(os.getenv("RAILWAY_ENVIRONMENT"))

# Proxies between the internet and the API (Railway's edge, Heroku's or Render's router: 1). Rate limits key
# on the address that many entries from the right of X-Forwarded-For: each proxy appends what it saw, so
# anything further left was written by the client. 0 = use the connection's own address (no proxy).
_PAAS = any(os.getenv(v) for v in ("RAILWAY_ENVIRONMENT", "DYNO", "RENDER", "FLY_APP_NAME"))
TRUSTED_PROXY_HOPS = _int("TRUSTED_PROXY_HOPS", 1 if _PAAS else 0)

# ── Secrets ───────────────────────────────────────────────────
# Values that appear in docs/examples and must never sign real tokens.
_PLACEHOLDER_SECRETS = {
    "change-me-in-production", "changeme", "change-me", "secret",
    "your-secret-key", "dev-only-insecure-key-do-not-deploy",
}
_DEV_SECRET = "dev-only-insecure-key-do-not-deploy"

SECRET_KEY = os.getenv("SECRET_KEY") or ""
if IS_PROD:
    if not SECRET_KEY or SECRET_KEY.strip().lower() in _PLACEHOLDER_SECRETS:
        raise RuntimeError(
            "SECRET_KEY must be set to a real random value in production. Generate one with: "
            "python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )
    if len(SECRET_KEY) < 32:
        log.warning("SECRET_KEY is shorter than 32 characters; use a longer random value.")
elif not SECRET_KEY:
    SECRET_KEY = _DEV_SECRET
    log.warning("SECRET_KEY is not set; using an insecure development key.")

ACCESS_TOKEN_MINUTES = _int("ACCESS_TOKEN_MINUTES", 30)
REFRESH_TOKEN_DAYS   = _int("REFRESH_TOKEN_DAYS", 30)

# ── Storage ───────────────────────────────────────────────────
DB_PATH     = os.getenv("DB_PATH", "results/llmscanner.db")
DATA_DIR    = os.path.dirname(os.path.abspath(DB_PATH))
REPORTS_DIR = os.getenv("REPORTS_DIR") or os.path.join(DATA_DIR, "reports")

# ── LLM providers ─────────────────────────────────────────────
GROQ_API_KEY   = os.getenv("GROQ_API_KEY")
# Groq retires models; groq_models.resolve() falls back when one disappears.
DEFAULT_MODEL  = os.getenv("DEFAULT_MODEL", "qwen/qwen3.8-27b")
JUDGE_MODEL    = os.getenv("JUDGE_MODEL", "openai/gpt-oss-120b")
JUDGE_FALLBACK_MODEL = os.getenv("JUDGE_FALLBACK_MODEL", "qwen/qwen3.8-27b")
JUDGE_API_KEY  = os.getenv("JUDGE_API_KEY") or GROQ_API_KEY
JUDGE_BASE_URL = os.getenv("JUDGE_BASE_URL") or None
# Short, plain refusals ("I'm sorry, I can't help with that.") that the rule detectors cleared are
# graded SAFE without a judge call: on a well-defended target that's most replies.
JUDGE_SKIP_CLEAR_REFUSALS = _bool("JUDGE_SKIP_CLEAR_REFUSALS", True)
# Groq's reasoning_effort for gpt-oss judges ("low" | "medium" | "high"). Unset = the provider's
# default. "low" spends far fewer (billed) reasoning tokens; check grading quality before using it.
JUDGE_REASONING_EFFORT = (os.getenv("JUDGE_REASONING_EFFORT") or "").strip().lower() or None

# ── Scans ─────────────────────────────────────────────────────
MAX_CONCURRENT_SCANS = _int("MAX_CONCURRENT_SCANS", 3)   # scans running at once
SCAN_CONCURRENCY     = _int("SCAN_CONCURRENCY", 4)       # attacks in flight per scan
TARGET_TIMEOUT       = _int("TARGET_TIMEOUT", 30)        # seconds per target call
MAX_CONSECUTIVE_ERRORS = _int("MAX_CONSECUTIVE_ERRORS", 25)
# A scan where more than this share of attacks couldn't be completed fails instead of
# reporting a score built from the few that worked.
MAX_ERROR_PERCENT    = _int("MAX_ERROR_PERCENT", 50)
# A quick scan runs this many attacks per category, spread from basic to advanced (22 x 5 = 110).
QUICK_SCAN_PER_CATEGORY = _int("QUICK_SCAN_PER_CATEGORY", 5)
# Free accounts run quick scans only (full scans cost ~10x the model calls). Off by default.
FREE_QUICK_SCANS_ONLY = _bool("FREE_QUICK_SCANS_ONLY", False)

# People per workspace on Pro, owner included (Free: 1, Enterprise: no limit).
PRO_SEATS            = _int("PRO_SEATS", 5)
# Free no-signup leak checks (20 attacks each on the server's model key) across all visitors per day.
LEAK_CHECKS_PER_DAY  = _int("LEAK_CHECKS_PER_DAY", 300)

# ── Firewall gateway (/gateway/<target id>/v1) ────────────────
GATEWAY_TIMEOUT      = _int("GATEWAY_TIMEOUT", 120)      # seconds for the model's API to answer
GATEWAY_CONCURRENCY  = _int("GATEWAY_CONCURRENCY", 16)   # gateway requests in flight; the rest queue
GATEWAY_BLOCK_SCORE  = float(os.getenv("GATEWAY_BLOCK_SCORE", "0.8"))   # Prompt Guard score that blocks
GATEWAY_BLOCK_MESSAGE = os.getenv("GATEWAY_BLOCK_MESSAGE") or "I can't help with that request."
# Lets local development scan http://localhost targets. Never enable in production.
ALLOW_PRIVATE_TARGETS = _bool("ALLOW_PRIVATE_TARGETS", False) and not IS_PROD

# ── Web ───────────────────────────────────────────────────────
ALLOWED_ORIGINS = [o.strip() for o in os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:3000").split(",") if o.strip()]
APP_URL    = os.getenv("APP_URL", "https://llmscanner.vercel.app").rstrip("/")
LOG_LEVEL  = os.getenv("LOG_LEVEL", "INFO").upper()
SENTRY_DSN = os.getenv("SENTRY_DSN") or None
REQUIRE_EMAIL_VERIFICATION = _bool("REQUIRE_EMAIL_VERIFICATION", False)

# ── Email ─────────────────────────────────────────────────────
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
FROM_EMAIL     = os.getenv("FROM_EMAIL", "LLM Scanner <noreply@llmscanner.com>")

# ── Payments ──────────────────────────────────────────────────
STRIPE_SECRET_KEY     = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_TRIAL_DAYS     = _int("STRIPE_TRIAL_DAYS", 0)


class Config:
    """Backwards-compatible view for older scripts (cli.py, tests)."""
    GROQ_API_KEY        = GROQ_API_KEY
    DEFAULT_MODEL       = DEFAULT_MODEL
    MAX_TOKENS          = 100
    SLEEP_BETWEEN_CALLS = 0.0
    RESULTS_DIR         = "results"
    API_HOST            = "0.0.0.0"
    API_PORT            = 8000

    @classmethod
    def validate(cls):
        if not cls.GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not found in .env file")
        return True


config = Config()
