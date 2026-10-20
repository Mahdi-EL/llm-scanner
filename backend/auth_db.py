"""Users, passwords, sessions, API keys and webhooks.

Security notes:
- Passwords use bcrypt (legacy SHA-256 hashes are upgraded at login).
- Refresh, reset and email-verification tokens are stored as SHA-256 hashes,
  so a leaked database doesn't hand out working sessions.
- Changing or resetting a password revokes every refresh token and sets
  tokens_valid_after, which makes older access tokens invalid at once.
- Emails are stored lower-case and compared case-insensitively.
"""
import hashlib
import hmac
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt as _bcrypt

import config
from db import parse_ts, transaction, utcnow

API_KEY_PREFIX = "llmsk_"


# ── Hashing ───────────────────────────────────────────────────
def _hash(password: str) -> str:
    return _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    # Transparent migration: legacy SHA-256 hashes are 64-char hex strings
    if len(hashed) == 64 and not hashed.startswith("$"):
        return hmac.compare_digest(hashlib.sha256(plain.encode()).hexdigest(), hashed)
    encoded = plain.encode("utf-8")
    if len(encoded) > 72:      # bcrypt>=5 raises instead of truncating
        return False
    return _bcrypt.checkpw(encoded, hashed.encode("utf-8"))


def needs_rehash(hashed: str) -> bool:
    """True if password was stored as SHA-256 and should be upgraded to bcrypt."""
    return len(hashed) == 64 and not hashed.startswith("$")


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _expired(stamp: Optional[str]) -> bool:
    return not stamp or parse_ts(stamp) < datetime.now(timezone.utc)


def _in(hours: float = 0, days: float = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours, days=days)).isoformat(timespec="seconds")


# ── Startup tasks (called from database.init_db) ──────────────
def init_users_table():
    """Kept for older callers: the schema now lives in database.init_db()."""
    import database
    database.init_db()


def migrate_tokens():
    """Hashes refresh tokens saved in plain text by older versions (no one is logged out)."""
    with transaction() as conn:
        rows = conn.execute("SELECT token FROM refresh_tokens").fetchall()
        for row in rows:
            raw = row["token"]
            if len(raw) != 64 or any(c not in "0123456789abcdef" for c in raw):
                conn.execute("UPDATE OR IGNORE refresh_tokens SET token = ? WHERE token = ?",
                             (token_hash(raw), raw))
        # Plain-text reset tokens can't be migrated safely; they expire within an hour anyway.
        conn.execute("UPDATE users SET reset_token = NULL, reset_token_expires = NULL "
                     "WHERE reset_token IS NOT NULL AND length(reset_token) != 64")


def seed_admin():
    """Creates the 'admin' user once, only when ADMIN_PASSWORD is set."""
    import os
    password = os.getenv("ADMIN_PASSWORD", "")
    if not password:
        return
    with transaction() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username = 'admin'").fetchone():
            return
        conn.execute(
            "INSERT INTO users (id, username, email, hashed_password, plan, created_at, email_verified) "
            "VALUES (?, 'admin', ?, ?, 'enterprise', ?, 1)",
            (str(uuid.uuid4()), os.getenv("ADMIN_EMAIL", "admin@llmscanner.com").lower(),
             _hash(password), utcnow()))


# ── Users ─────────────────────────────────────────────────────
def create_user(username: str, email: str, password: str, verified: bool = False) -> dict:
    username, email = username.strip(), email.strip().lower()
    with transaction() as conn:
        if conn.execute("SELECT 1 FROM users WHERE lower(username) = lower(?)", (username,)).fetchone():
            return {"success": False, "error": "This username is already taken"}
        if conn.execute("SELECT 1 FROM users WHERE lower(email) = ?", (email,)).fetchone():
            return {"success": False, "error": "This email is already registered"}
        uid = str(uuid.uuid4())
        try:
            conn.execute(
                "INSERT INTO users (id, username, email, hashed_password, created_at, email_verified) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (uid, username, email, _hash(password), utcnow(), 1 if verified else 0))
        except sqlite3.IntegrityError:      # lost a race with a simultaneous sign-up
            return {"success": False, "error": "This username or email is already registered"}
    return {"success": True, "user_id": uid}


def _get_user(where: str, value: str) -> Optional[dict]:
    with transaction() as conn:
        row = conn.execute(f"SELECT * FROM users WHERE {where} AND is_active = 1", (value,)).fetchone()
        return dict(row) if row else None


def get_user_by_username(username: str) -> Optional[dict]:
    return _get_user("username = ?", username) or _get_user("lower(username) = lower(?)", username)


def get_user_by_id(user_id: str) -> Optional[dict]:
    return _get_user("id = ?", user_id) if user_id else None


def get_user_by_email(email: str) -> Optional[dict]:
    return _get_user("lower(email) = lower(?)", email.strip())


def get_user_for_login(identifier: str) -> Optional[dict]:
    """Login accepts a username or an email address."""
    identifier = identifier.strip()
    if "@" in identifier:
        return get_user_by_email(identifier)
    return get_user_by_username(identifier)


def get_user_by_stripe_customer(customer_id: str) -> Optional[dict]:
    return _get_user("stripe_customer_id = ?", customer_id) if customer_id else None


def upgrade_password(user_id: str, new_bcrypt_hash: str):
    """Stores a new hash without ending sessions (used for the SHA-256 → bcrypt upgrade)."""
    with transaction() as conn:
        conn.execute("UPDATE users SET hashed_password = ? WHERE id = ?", (new_bcrypt_hash, user_id))


def set_password(user_id: str, new_password: str):
    """Changes a password and signs the user out everywhere."""
    with transaction() as conn:
        conn.execute("UPDATE users SET hashed_password = ?, reset_token = NULL, "
                     "reset_token_expires = NULL, tokens_valid_after = ? WHERE id = ?",
                     (_hash(new_password), utcnow(), user_id))
        conn.execute("DELETE FROM refresh_tokens WHERE user_id = ?", (user_id,))


def increment_scan_count(user_id: str):
    with transaction() as conn:
        conn.execute("UPDATE users SET scans_count = scans_count + 1 WHERE id = ?", (user_id,))


def update_plan(user_id: str, plan: str):
    with transaction() as conn:
        conn.execute("UPDATE users SET plan = ? WHERE id = ?", (plan, user_id))


def set_stripe_ids(user_id: str, customer_id: Optional[str] = None,
                   subscription_id: Optional[str] = None):
    with transaction() as conn:
        if customer_id:
            conn.execute("UPDATE users SET stripe_customer_id = ? WHERE id = ?", (customer_id, user_id))
        if subscription_id is not None:
            conn.execute("UPDATE users SET stripe_subscription_id = ? WHERE id = ?",
                         (subscription_id or None, user_id))


def mark_email_verified(user_id: str):
    with transaction() as conn:
        conn.execute("UPDATE users SET email_verified = 1, verify_token = NULL, "
                     "verify_token_expires = NULL WHERE id = ?", (user_id,))


def delete_user(user_id: str):
    """Removes the account and everything attached to it except scans (deleted by the caller)."""
    with transaction() as conn:
        for table in ("api_keys", "refresh_tokens", "targets", "schedules", "custom_prompts", "share_links",
                      "firewall_usage", "remediation_usage", "gateway_events", "finding_triage"):
            conn.execute(f"DELETE FROM {table} WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


# ── Password reset ────────────────────────────────────────────
def create_reset_token(email: str) -> Optional[str]:
    user = get_user_by_email(email)
    if not user:
        return None
    token = secrets.token_urlsafe(32)
    with transaction() as conn:
        conn.execute("UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?",
                     (token_hash(token), _in(hours=1), user["id"]))
    return token


def consume_reset_token(token: str, new_password: str) -> bool:
    with transaction() as conn:
        row = conn.execute("SELECT id, reset_token_expires FROM users WHERE reset_token = ?",
                           (token_hash(token),)).fetchone()
    if not row or _expired(row["reset_token_expires"]):
        return False
    set_password(row["id"], new_password)
    return True


# ── Email verification ────────────────────────────────────────
def create_verify_token(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    with transaction() as conn:
        conn.execute("UPDATE users SET verify_token = ?, verify_token_expires = ? WHERE id = ?",
                     (token_hash(token), _in(days=2), user_id))
    return token


def consume_verify_token(token: str) -> Optional[str]:
    with transaction() as conn:
        row = conn.execute("SELECT id, verify_token_expires FROM users WHERE verify_token = ?",
                           (token_hash(token),)).fetchone()
    if not row or _expired(row["verify_token_expires"]):
        return None
    mark_email_verified(row["id"])
    return row["id"]


# ── Refresh tokens (rotated on every use) ─────────────────────
def create_refresh_token(user_id: str) -> str:
    token = secrets.token_urlsafe(48)
    with transaction() as conn:
        conn.execute("INSERT INTO refresh_tokens (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
                     (token_hash(token), user_id, _in(days=config.REFRESH_TOKEN_DAYS), utcnow()))
        # Housekeeping: drop this user's expired tokens.
        conn.execute("DELETE FROM refresh_tokens WHERE user_id = ? AND expires_at < ?", (user_id, utcnow()))
    return token


def consume_refresh_token(token: str) -> Optional[str]:
    """Validates and deletes a refresh token; returns its user_id or None."""
    hashed = token_hash(token)
    with transaction() as conn:
        row = conn.execute("SELECT user_id, expires_at FROM refresh_tokens WHERE token = ?",
                           (hashed,)).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM refresh_tokens WHERE token = ?", (hashed,))
    if _expired(row["expires_at"]):
        return None
    return row["user_id"]


def revoke_refresh_token(token: str):
    with transaction() as conn:
        conn.execute("DELETE FROM refresh_tokens WHERE token = ?", (token_hash(token),))


def revoke_all_sessions(user_id: str):
    with transaction() as conn:
        conn.execute("DELETE FROM refresh_tokens WHERE user_id = ?", (user_id,))
        conn.execute("UPDATE users SET tokens_valid_after = ? WHERE id = ?", (utcnow(), user_id))


# ── API keys (programmatic / CI access) ───────────────────────
def create_api_key(user_id: str, name: str = "") -> dict:
    """Generates a new API key. Returns the FULL key once (only its hash is stored)."""
    raw    = API_KEY_PREFIX + secrets.token_urlsafe(32)
    key_id = str(uuid.uuid4())
    label  = (name or "API key").strip()[:60] or "API key"
    with transaction() as conn:
        conn.execute("INSERT INTO api_keys (id, user_id, name, key_hash, prefix, created_at) "
                     "VALUES (?, ?, ?, ?, ?, ?)",
                     (key_id, user_id, label, token_hash(raw), raw[:14], utcnow()))
    return {"id": key_id, "name": label, "key": raw, "prefix": raw[:14]}


def get_user_by_api_key(key: str) -> Optional[str]:
    """Returns the owning user_id for a valid, non-revoked key (and stamps usage)."""
    if not key or not key.startswith(API_KEY_PREFIX):
        return None
    with transaction() as conn:
        row = conn.execute("SELECT id, user_id, last_used_at FROM api_keys "
                           "WHERE key_hash = ? AND revoked = 0", (token_hash(key),)).fetchone()
        if not row:
            return None
        # Update the timestamp at most once a minute to avoid a write per request.
        if not row["last_used_at"] or \
                (datetime.now(timezone.utc) - parse_ts(row["last_used_at"])).total_seconds() > 60:
            conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (utcnow(), row["id"]))
        return row["user_id"]


def list_api_keys(user_id: str) -> list:
    """Lists the user's keys WITHOUT the secret (prefix only)."""
    with transaction() as conn:
        rows = conn.execute("SELECT id, name, prefix, created_at, last_used_at, revoked FROM api_keys "
                            "WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
    return [dict(r) for r in rows]


def revoke_api_key(user_id: str, key_id: str) -> bool:
    with transaction() as conn:
        cur = conn.execute("UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ?", (key_id, user_id))
        return cur.rowcount > 0


# ── Per-user webhook ──────────────────────────────────────────
def update_webhook(user_id: str, url: Optional[str]) -> Optional[str]:
    """Sets or clears the webhook URL. Returns the signing secret (created on first use)."""
    with transaction() as conn:
        row = conn.execute("SELECT webhook_secret FROM users WHERE id = ?", (user_id,)).fetchone()
        secret = row["webhook_secret"] if row and row["webhook_secret"] else None
        if url and not secret:
            secret = "whsec_" + secrets.token_urlsafe(24)
        conn.execute("UPDATE users SET webhook_url = ?, webhook_secret = ? WHERE id = ?",
                     (url, secret, user_id))
    return secret


def rotate_webhook_secret(user_id: str) -> str:
    secret = "whsec_" + secrets.token_urlsafe(24)
    with transaction() as conn:
        conn.execute("UPDATE users SET webhook_secret = ? WHERE id = ?", (secret, user_id))
    return secret
