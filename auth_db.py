import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import sqlite3
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional
from database import DB_PATH


# ── Schema ────────────────────────────────────────────────────
def init_users_table():
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("""
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
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token      TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()

    # Seed default admin if absent
    existing = c.execute(
        "SELECT id FROM users WHERE username = ?", ("admin",)
    ).fetchone()
    if not existing:
        c.execute("""
            INSERT INTO users (id, username, email, hashed_password, plan, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            str(uuid.uuid4()),
            "admin",
            "admin@llmscanner.com",
            _hash("admin123"),
            "enterprise",
            datetime.now().isoformat()
        ))
        conn.commit()

    conn.close()


# ── Helpers ───────────────────────────────────────────────────
def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _row(cursor, row) -> dict:
    return dict(zip([d[0] for d in cursor.description], row))


# ── User CRUD ─────────────────────────────────────────────────
def create_user(username: str, email: str, password: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    uid  = str(uuid.uuid4())
    try:
        c.execute("""
            INSERT INTO users (id, username, email, hashed_password, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (uid, username, email, _hash(password), datetime.now().isoformat()))
        conn.commit()
        return {"success": True, "user_id": uid}
    except sqlite3.IntegrityError as e:
        field = "username" if "username" in str(e) else "email"
        return {"success": False, "error": f"This {field} is already taken"}
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[dict]:
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    row  = c.execute(
        "SELECT * FROM users WHERE username = ? AND is_active = 1", (username,)
    ).fetchone()
    conn.close()
    return _row(c, row) if row else None


def get_user_by_id(user_id: str) -> Optional[dict]:
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    row  = c.execute(
        "SELECT * FROM users WHERE id = ? AND is_active = 1", (user_id,)
    ).fetchone()
    conn.close()
    return _row(c, row) if row else None


def get_user_by_email(email: str) -> Optional[dict]:
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    row  = c.execute(
        "SELECT * FROM users WHERE email = ? AND is_active = 1", (email,)
    ).fetchone()
    conn.close()
    return _row(c, row) if row else None


def verify_password(plain: str, hashed: str) -> bool:
    return _hash(plain) == hashed


def increment_scan_count(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE users SET scans_count = scans_count + 1 WHERE id = ?", (user_id,)
    )
    conn.commit()
    conn.close()


def update_plan(user_id: str, plan: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE users SET plan = ? WHERE id = ?", (plan, user_id)
    )
    conn.commit()
    conn.close()


# ── Password Reset ────────────────────────────────────────────
def create_reset_token(email: str) -> Optional[str]:
    user = get_user_by_email(email)
    if not user:
        return None
    token   = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(hours=1)).isoformat()
    conn    = sqlite3.connect(DB_PATH)
    conn.execute("""
        UPDATE users SET reset_token = ?, reset_token_expires = ?
        WHERE email = ?
    """, (token, expires, email))
    conn.commit()
    conn.close()
    return token


def consume_reset_token(token: str, new_password: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    row  = c.execute("""
        SELECT id, reset_token_expires FROM users
        WHERE reset_token = ?
    """, (token,)).fetchone()
    if not row:
        conn.close()
        return False
    user_id, expires_str = row
    if datetime.fromisoformat(expires_str) < datetime.now():
        conn.close()
        return False
    c.execute("""
        UPDATE users SET hashed_password = ?, reset_token = NULL, reset_token_expires = NULL
        WHERE id = ?
    """, (_hash(new_password), user_id))
    conn.commit()
    conn.close()
    return True


# ── Refresh Tokens ────────────────────────────────────────────
def create_refresh_token(user_id: str) -> str:
    token   = secrets.token_urlsafe(64)
    expires = (datetime.now() + timedelta(days=30)).isoformat()
    conn    = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO refresh_tokens (token, user_id, expires_at, created_at)
        VALUES (?, ?, ?, ?)
    """, (token, user_id, expires, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return token


def consume_refresh_token(token: str) -> Optional[str]:
    """Validates refresh token, deletes it, returns user_id or None."""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    row  = c.execute("""
        SELECT user_id, expires_at FROM refresh_tokens WHERE token = ?
    """, (token,)).fetchone()
    if not row:
        conn.close()
        return None
    user_id, expires_str = row
    if datetime.fromisoformat(expires_str) < datetime.now():
        conn.close()
        return None
    c.execute("DELETE FROM refresh_tokens WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    return user_id


# ── Init on import ────────────────────────────────────────────
init_users_table()
