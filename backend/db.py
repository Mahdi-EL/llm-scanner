"""One SQLite connection helper for the whole backend.

Every module that touches the database goes through `transaction()`, so
pragmas, commit/rollback and closing behave the same everywhere.
"""
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

import config


def utcnow() -> str:
    """Current time as an ISO-8601 UTC string (what we store in the DB)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_ts(value: str) -> datetime:
    """Parses a stored timestamp. Old rows are naive local time; new ones are UTC."""
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.astimezone()          # naive → assume server-local time
    return dt.astimezone(timezone.utc)


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def transaction():
    """Opens a connection, commits on success, rolls back on error, always closes."""
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def columns(conn: sqlite3.Connection, table: str) -> set:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def add_missing_columns(conn: sqlite3.Connection, table: str, wanted: dict) -> None:
    """Idempotent migration helper: ALTER TABLE ... ADD COLUMN for any missing column."""
    existing = columns(conn, table)
    for name, ddl in wanted.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
