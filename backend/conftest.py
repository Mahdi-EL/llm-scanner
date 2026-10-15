"""Pytest bootstrap for the backend.

- Puts backend/ on sys.path so the flat-module imports (`import api`,
  `from analysis import ...`) resolve when pytest runs from the repo root.
- Pins a deterministic test environment (temp DB, throwaway secret, low quota)
  BEFORE any module reads these env vars at import time.
"""
import os
import sys
import tempfile

os.environ.setdefault("ENV", "development")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-prod")
os.environ.setdefault("FREE_SCAN_LIMIT", "2")
os.environ.setdefault(
    "DB_PATH", os.path.join(tempfile.gettempdir(), "llmscanner_pytest.db")
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
