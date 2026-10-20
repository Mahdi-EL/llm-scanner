"""Database schema and migrations, plus a small admin CLI.

init_db() creates every table and adds any missing column, so it is safe to
run on every startup and on databases created by older versions.

    python backend/database.py stats      # global stats
    python backend/database.py waitlist   # waitlist emails (personal data; never exposed over HTTP)
"""
import logging
import os
import sqlite3
import sys

import config
from db import add_missing_columns, transaction, utcnow

log = logging.getLogger("llmscanner.database")

# Kept for older imports (`from database import DB_PATH`).
DB_PATH = config.DB_PATH


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          TEXT UNIQUE NOT NULL,
    user_id          TEXT,
    target_name      TEXT NOT NULL,
    target_type      TEXT DEFAULT 'simulation',
    status           TEXT DEFAULT 'pending',
    security_score   INTEGER DEFAULT 0,
    total_attacks    INTEGER DEFAULT 0,
    critical_count   INTEGER DEFAULT 0,
    high_count       INTEGER DEFAULT 0,
    medium_count     INTEGER DEFAULT 0,
    low_count        INTEGER DEFAULT 0,
    safe_count       INTEGER DEFAULT 0,
    json_path        TEXT,
    pdf_path         TEXT,
    html_path        TEXT,
    md_path          TEXT,
    created_at       TEXT NOT NULL,
    completed_at     TEXT,
    duration_seconds INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          TEXT NOT NULL,
    category         TEXT NOT NULL,
    attack           TEXT NOT NULL,
    response         TEXT,
    score            INTEGER DEFAULT 0,
    severity         TEXT DEFAULT 'SAFE',
    reason           TEXT,
    behavior_changed INTEGER DEFAULT 0,
    confidence       TEXT DEFAULT 'LOW',
    FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
);
CREATE TABLE IF NOT EXISTS waitlist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT UNIQUE NOT NULL,
    name       TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS global_stats (
    id                  INTEGER PRIMARY KEY,
    total_scans         INTEGER DEFAULT 0,
    total_attacks_fired INTEGER DEFAULT 0,
    total_criticals     INTEGER DEFAULT 0,
    total_vulns_found   INTEGER DEFAULT 0,
    avg_security_score  REAL DEFAULT 0,
    last_updated        TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id                  TEXT PRIMARY KEY,
    username            TEXT UNIQUE NOT NULL,
    email               TEXT UNIQUE NOT NULL,
    hashed_password     TEXT NOT NULL,
    plan                TEXT DEFAULT 'free',
    scans_count         INTEGER DEFAULT 0,
    is_active           INTEGER DEFAULT 1,
    created_at          TEXT NOT NULL,
    reset_token         TEXT,
    reset_token_expires TEXT
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    name         TEXT,
    key_hash     TEXT UNIQUE NOT NULL,
    prefix       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked      INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS stripe_events (
    event_id     TEXT PRIMARY KEY,
    type         TEXT,
    processed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS targets (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    name        TEXT NOT NULL,
    config_json TEXT NOT NULL,
    api_key_enc TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS schedules (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    frequency   TEXT NOT NULL,
    categories  TEXT,
    alert_drop  INTEGER DEFAULT 5,
    next_run_at TEXT NOT NULL,
    last_run_at TEXT,
    last_scan_id TEXT,
    enabled     INTEGER DEFAULT 1,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS custom_prompts (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    category   TEXT NOT NULL,
    prompt     TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS firewall_usage (
    user_id TEXT NOT NULL,
    day     TEXT NOT NULL,
    count   INTEGER DEFAULT 0,
    PRIMARY KEY (user_id, day)
);
CREATE TABLE IF NOT EXISTS leak_checks (
    day   TEXT PRIMARY KEY,
    count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS finding_triage (
    user_id     TEXT NOT NULL,
    target_name TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    status      TEXT NOT NULL,
    note        TEXT,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (user_id, target_name, finding_key)
);
CREATE TABLE IF NOT EXISTS gateway_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT NOT NULL,
    target_id       TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    input_verdict   TEXT,
    output_verdict  TEXT,
    rules           TEXT,
    latency_ms      INTEGER,
    upstream_status INTEGER,
    screened        INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS remediation_usage (
    user_id TEXT NOT NULL,
    day     TEXT NOT NULL,
    count   INTEGER DEFAULT 0,
    PRIMARY KEY (user_id, day)
);
CREATE TABLE IF NOT EXISTS share_links (
    token_hash TEXT PRIMARY KEY,
    scan_id    TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

# Columns added after the first release. add_missing_columns() is idempotent.
SCAN_COLUMNS = {
    "progress"         : "INTEGER DEFAULT 0",
    "error_message"    : "TEXT",
    "results_json"     : "TEXT",
    "user_id"          : "TEXT",
    "config_json"      : "TEXT",
    "api_key_enc"      : "TEXT",
    "checkpoint_json"  : "TEXT",
    "completed_attacks": "INTEGER DEFAULT 0",
    "current_category" : "TEXT",
    "started_at"       : "TEXT",
    "model"            : "TEXT",
    "grade"            : "TEXT",
    "error_count"      : "INTEGER DEFAULT 0",
    "llm_calls"        : "INTEGER DEFAULT 0",
    "target_id"        : "TEXT",
    "schedule_id"      : "TEXT",
    # model tokens billed to this server's keys (judge, plus the target for simulation scans)
    "tokens_in"        : "INTEGER DEFAULT 0",
    "tokens_out"       : "INTEGER DEFAULT 0",
    "graded_by_rules"  : "INTEGER DEFAULT 0",
}
USER_COLUMNS = {
    "webhook_url"           : "TEXT",
    "webhook_secret"        : "TEXT",
    "stripe_customer_id"    : "TEXT",
    "stripe_subscription_id": "TEXT",
    "tokens_valid_after"    : "TEXT",
    "verify_token"          : "TEXT",
    "verify_token_expires"  : "TEXT",
    "report_brand"          : "TEXT",
}


def init_db():
    """Creates all tables and runs migrations. Safe to call on every startup."""
    folder = os.path.dirname(config.DB_PATH)
    if folder:
        os.makedirs(folder, exist_ok=True)

    raw = sqlite3.connect(config.DB_PATH)
    try:
        raw.execute("PRAGMA journal_mode=WAL")   # persistent setting; readers don't block the scan writer
    finally:
        raw.close()

    with transaction() as conn:
        conn.executescript(SCHEMA)
        conn.execute("INSERT OR IGNORE INTO global_stats (id) VALUES (1)")
        add_missing_columns(conn, "scans", SCAN_COLUMNS)

        had_verified = "email_verified" in {r[1] for r in conn.execute("PRAGMA table_info(users)")}
        add_missing_columns(conn, "users", USER_COLUMNS)
        if not had_verified:
            conn.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0")
            conn.execute("UPDATE users SET email_verified = 1")   # existing accounts stay usable

        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans (user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys (user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_gateway_user_time ON gateway_events (user_id, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens (user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_user ON targets (user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_schedules_next ON schedules (enabled, next_run_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_prompts_user ON custom_prompts (user_id)")
        try:    # sign-up checks usernames case-insensitively; this makes the database enforce it too
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_nocase ON users (lower(username))")
        except sqlite3.IntegrityError:
            log.warning("Usernames differing only in case exist; case-insensitive unique index not created")

    import auth_db
    auth_db.migrate_tokens()
    auth_db.seed_admin()


# ── Waitlist and stats (admin CLI) ────────────────────────────
def add_to_waitlist(email, name=None):
    try:
        with transaction() as conn:
            conn.execute("INSERT INTO waitlist (email, name, created_at) VALUES (?, ?, ?)",
                         (email.strip().lower(), name, utcnow()))
        return True
    except sqlite3.IntegrityError:
        return False


def get_waitlist():
    with transaction() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM waitlist ORDER BY created_at DESC")]


def get_global_stats():
    with transaction() as conn:
        stats = dict(conn.execute("SELECT * FROM global_stats WHERE id = 1").fetchone() or {})
        row = conn.execute("SELECT category, AVG(score) AS avg_score FROM findings "
                           "GROUP BY category ORDER BY avg_score DESC LIMIT 1").fetchone()
        stats["most_vulnerable_category"] = row["category"] if row else "N/A"
    return stats


def print_stats():
    stats = get_global_stats()
    print("LLM Scanner database stats")
    print(f"  Total scans         : {stats.get('total_scans', 0)}")
    print(f"  Total attacks fired : {stats.get('total_attacks_fired', 0)}")
    print(f"  Total criticals     : {stats.get('total_criticals', 0)}")
    print(f"  Avg security score  : {round(stats.get('avg_security_score') or 0, 1)}")
    print(f"  Most vulnerable     : {stats.get('most_vulnerable_category', 'N/A')}")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    init_db()
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "stats":
        print_stats()
    elif command == "waitlist":
        entries = get_waitlist()
        print(f"Waitlist ({len(entries)} entries):")
        for entry in entries:
            print(f"  {entry['email']} - {entry['created_at']}")
    else:
        print("Usage: python backend/database.py [stats|waitlist]")
