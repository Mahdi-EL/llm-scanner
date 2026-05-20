import sys
sys.stdout.reconfigure(encoding='utf-8')

import sqlite3
import hashlib
import secrets
import uuid
import bcrypt as _bcrypt
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Optional
from database import DB_PATH


# ── Password hashing (bcrypt direct — passlib dropped for bcrypt 4+/5+ compat) ─
def _hash(password: str) -> str:
    return _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    # Transparent migration: legacy SHA-256 hashes are 64-char hex strings
    if len(hashed) == 64 and not hashed.startswith("$"):
        return hashlib.sha256(plain.encode()).hexdigest() == hashed
    return _bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

def needs_rehash(hashed: str) -> bool:
    """True if password was stored as SHA-256 and should be upgraded to bcrypt."""
    return len(hashed) == 64 and not hashed.startswith("$")


# ── Connection factory ─────────────────────────────────────────
@contextmanager
def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Schema ────────────────────────────────────────────────────
def init_users_table():
    with _db() as conn:
        conn.execute("""
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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token      TEXT PRIMARY KEY,
                user_id    TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        # Seed default admin if absent — password from env or secure default
        import os as _os
        admin_pwd = _os.getenv("ADMIN_PASSWORD", "")
        if not admin_pwd:
            return  # No admin seeded unless ADMIN_PASSWORD env var is set
        exists = conn.execute(
            "SELECT id FROM users WHERE username = ?", ("admin",)
        ).fetchone()
        if not exists:
            conn.execute("""
                INSERT INTO users (id, username, email, hashed_password, plan, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()),
                "admin",
                _os.getenv("ADMIN_EMAIL", "admin@llmscanner.com"),
                _hash(admin_pwd),
                "enterprise",
                datetime.now().isoformat(),
            ))


# ── User CRUD ─────────────────────────────────────────────────
def create_user(username: str, email: str, password: str) -> dict:
    uid = str(uuid.uuid4())
    try:
        with _db() as conn:
            conn.execute("""
                INSERT INTO users (id, username, email, hashed_password, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (uid, username, email, _hash(password), datetime.now().isoformat()))
        return {"success": True, "user_id": uid}
    except sqlite3.IntegrityError as e:
        field = "username" if "username" in str(e) else "email"
        return {"success": False, "error": f"This {field} is already taken"}


def _get_user(where: str, value: str) -> Optional[dict]:
    with _db() as conn:
        row = conn.execute(
            f"SELECT * FROM users WHERE {where} = ? AND is_active = 1", (value,)
        ).fetchone()
        return dict(row) if row else None


def get_user_by_username(username: str) -> Optional[dict]:
    return _get_user("username", username)

def get_user_by_id(user_id: str) -> Optional[dict]:
    return _get_user("id", user_id)

def get_user_by_email(email: str) -> Optional[dict]:
    return _get_user("email", email)


def upgrade_password(user_id: str, new_bcrypt_hash: str):
    """Replaces a legacy SHA-256 hash with a bcrypt one (called after successful login)."""
    with _db() as conn:
        conn.execute(
            "UPDATE users SET hashed_password = ? WHERE id = ?",
            (new_bcrypt_hash, user_id)
        )


def increment_scan_count(user_id: str):
    with _db() as conn:
        conn.execute(
            "UPDATE users SET scans_count = scans_count + 1 WHERE id = ?", (user_id,)
        )


def update_plan(user_id: str, plan: str):
    with _db() as conn:
        conn.execute(
            "UPDATE users SET plan = ? WHERE id = ?", (plan, user_id)
        )


# ── Password Reset ────────────────────────────────────────────
def create_reset_token(email: str) -> Optional[str]:
    user = get_user_by_email(email)
    if not user:
        return None
    token   = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(hours=1)).isoformat()
    with _db() as conn:
        conn.execute("""
            UPDATE users SET reset_token = ?, reset_token_expires = ?
            WHERE email = ?
        """, (token, expires, email))
    return token


def consume_reset_token(token: str, new_password: str) -> bool:
    with _db() as conn:
        row = conn.execute("""
            SELECT id, reset_token_expires FROM users WHERE reset_token = ?
        """, (token,)).fetchone()
        if not row:
            return False
        if datetime.fromisoformat(row["reset_token_expires"]) < datetime.now():
            return False
        conn.execute("""
            UPDATE users
            SET hashed_password = ?, reset_token = NULL, reset_token_expires = NULL
            WHERE id = ?
        """, (_hash(new_password), row["id"]))
    return True


# ── Refresh Tokens ────────────────────────────────────────────
def create_refresh_token(user_id: str) -> str:
    token   = secrets.token_urlsafe(64)
    expires = (datetime.now() + timedelta(days=30)).isoformat()
    with _db() as conn:
        conn.execute("""
            INSERT INTO refresh_tokens (token, user_id, expires_at, created_at)
            VALUES (?, ?, ?, ?)
        """, (token, user_id, expires, datetime.now().isoformat()))
    return token


def consume_refresh_token(token: str) -> Optional[str]:
    """Validates + deletes refresh token, returns user_id or None."""
    with _db() as conn:
        row = conn.execute("""
            SELECT user_id, expires_at FROM refresh_tokens WHERE token = ?
        """, (token,)).fetchone()
        if not row:
            return None
        if datetime.fromisoformat(row["expires_at"]) < datetime.now():
            return None
        conn.execute("DELETE FROM refresh_tokens WHERE token = ?", (token,))
        return row["user_id"]


# ── Init on import ────────────────────────────────────────────
init_users_table()
