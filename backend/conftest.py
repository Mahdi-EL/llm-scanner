"""Pytest bootstrap for the backend.

- Puts backend/ on sys.path so the flat-module imports (`import api`,
  `from analysis import ...`) resolve when pytest runs from the repo root.
- Pins a deterministic, offline test environment (fresh temp DB and report
  folder, throwaway secret, low quota, no background scan workers) BEFORE any
  module reads these env vars at import time.
"""
import os
import sys
import tempfile

_tmp = tempfile.mkdtemp(prefix="llmscanner_pytest_")

os.environ["ENV"] = "development"
os.environ.pop("RAILWAY_ENVIRONMENT", None)
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-prod-0123456789abcdef")
os.environ["FREE_SCAN_LIMIT"] = "2"
os.environ["FREE_FIREWALL_DAILY"] = "5"
os.environ["DB_PATH"] = os.path.join(_tmp, "llmscanner.db")
os.environ["REPORTS_DIR"] = os.path.join(_tmp, "reports")
os.environ["LLMSCANNER_DISABLE_WORKERS"] = "1"
os.environ["RESEND_API_KEY"] = ""
os.environ["STRIPE_SECRET_KEY"] = ""
os.environ["STRIPE_WEBHOOK_SECRET"] = ""
os.environ.setdefault("GROQ_API_KEY", "gsk_test_not_a_real_key")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
