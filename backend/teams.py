"""Teams: other people working in your account.

A workspace is an account: its scans, saved targets, keys, plan and quota. The owner (and admins)
invite people by email; each member has a role:

    viewer  reads scans and reports
    member  also runs and manages scans, targets, schedules and custom attacks
    admin   also manages API keys, the webhook, report branding and the team
    owner   also billing and deleting the account (one per workspace: the account itself)

A request acts in another workspace when it carries X-Workspace: <account id> and the signed-in
person is a member there (see api._workspace_user). Personal settings (password, profile, data
export, account deletion) always apply to the person.
"""
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import config
from auth_db import token_hash
from db import parse_ts, transaction, utcnow

ROLES = ("viewer", "member", "admin")
RANK = {"viewer": 0, "member": 1, "admin": 2, "owner": 3}
INVITE_DAYS = 7


class TeamError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def seat_limit(plan: str) -> Optional[int]:
    """People in a workspace, owner included (None = no limit)."""
    return {"free": 1, "pro": config.PRO_SEATS, "enterprise": None}.get(plan or "free", 1)


def role_of(account_id: str, user_id: str) -> Optional[str]:
    if account_id == user_id:
        return "owner"
    with transaction() as conn:
        row = conn.execute("SELECT role FROM memberships WHERE account_id = ? AND user_id = ?",
                           (account_id, user_id)).fetchone()
    return row["role"] if row else None


def members(account_id: str) -> list:
    """The owner, then the members: [{"user_id", "username", "email", "role", "since"}]."""
    with transaction() as conn:
        owner = conn.execute("SELECT id, username, email, created_at FROM users WHERE id = ?", (account_id,)).fetchone()
        rows = conn.execute(
            "SELECT m.user_id, u.username, u.email, m.role, m.created_at FROM memberships m "
            "JOIN users u ON u.id = m.user_id WHERE m.account_id = ? ORDER BY m.created_at", (account_id,)).fetchall()
    out = [{"user_id": owner["id"], "username": owner["username"], "email": owner["email"], "role": "owner",
            "since": owner["created_at"]}] if owner else []
    return out + [{"user_id": r["user_id"], "username": r["username"], "email": r["email"], "role": r["role"],
                   "since": r["created_at"]} for r in rows]


def seated(account_id: str, plan: str) -> Optional[set]:
    """Who has a seat when a workspace has more people than its plan allows (after a downgrade): the owner,
    then members in the order they joined. None when everyone has one."""
    limit = seat_limit(plan)
    if limit is None:
        return None
    with transaction() as conn:
        rows = conn.execute("SELECT user_id FROM memberships WHERE account_id = ? ORDER BY created_at, user_id",
                            (account_id,)).fetchall()
    if len(rows) < limit:
        return None
    return {account_id} | {r["user_id"] for r in rows[:max(0, limit - 1)]}


def has_seat(account: dict, user_id: str) -> bool:
    seats = seated(account["id"], account.get("plan"))
    return seats is None or user_id in seats


def workspaces_of(user_id: str) -> list:
    """Workspaces a person can act in: their own first, then the ones they were invited to ("active" is
    False while the workspace's plan has no seat for them)."""
    with transaction() as conn:
        rows = conn.execute(
            "SELECT u.id, u.username, u.plan, m.role FROM memberships m JOIN users u ON u.id = m.account_id "
            "WHERE m.user_id = ? ORDER BY u.username", (user_id,)).fetchall()
    return [{"id": user_id, "name": "Personal", "role": "owner", "active": True}] + \
           [{"id": r["id"], "name": r["username"], "role": r["role"], "plan": r["plan"] or "free",
             "active": has_seat({"id": r["id"], "plan": r["plan"]}, user_id)} for r in rows]


def pending_invites(account_id: str) -> list:
    now = datetime.now(timezone.utc)
    with transaction() as conn:
        rows = conn.execute("SELECT id, email, role, created_at, expires_at FROM team_invites "
                            "WHERE account_id = ? AND accepted_at IS NULL ORDER BY created_at", (account_id,)).fetchall()
    return [dict(r) for r in rows if parse_ts(r["expires_at"]) > now]


def seats_used(account_id: str) -> int:
    return len(members(account_id)) + len(pending_invites(account_id))


def create_invite(account: dict, email: str, role: str, invited_by: str) -> dict:
    """{"id", "token", "expires_at"}; the token is shown once (only its hash is stored)."""
    email = email.strip().lower()
    if role not in ROLES:
        raise TeamError("Role must be viewer, member or admin")
    limit = seat_limit(account.get("plan"))
    if limit is not None and seats_used(account["id"]) >= limit:
        raise TeamError("Your plan has no free seats: upgrade, or remove a member or invite first." if limit > 1
                        else "Team members are part of the paid plans.", 402)
    if any((m["email"] or "").lower() == email for m in members(account["id"])):
        raise TeamError("That person is already in this workspace", 409)
    token = secrets.token_urlsafe(24)
    invite_id = uuid.uuid4().hex
    expires = (datetime.now(timezone.utc) + timedelta(days=INVITE_DAYS)).isoformat(timespec="seconds")
    with transaction() as conn:
        # a newer invite to the same address replaces the old one
        conn.execute("DELETE FROM team_invites WHERE account_id = ? AND email = ? AND accepted_at IS NULL",
                     (account["id"], email))
        conn.execute("INSERT INTO team_invites (id, account_id, email, role, token_hash, invited_by, created_at, "
                     "expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (invite_id, account["id"], email, role, token_hash(token), invited_by, utcnow(), expires))
    return {"id": invite_id, "token": token, "expires_at": expires, "email": email, "role": role}


def revoke_invite(account_id: str, invite_id: str) -> bool:
    with transaction() as conn:
        return conn.execute("DELETE FROM team_invites WHERE id = ? AND account_id = ? AND accepted_at IS NULL",
                            (invite_id, account_id)).rowcount > 0


def accept_invite(token: str, person: dict) -> str:
    """Joins the invite's workspace and returns its account id. The invite must be for this
    person's email address, so a forwarded or leaked link can't be used by someone else."""
    with transaction() as conn:
        row = conn.execute("SELECT * FROM team_invites WHERE token_hash = ?", (token_hash(token),)).fetchone()
        if not row or row["accepted_at"] or parse_ts(row["expires_at"]) < datetime.now(timezone.utc):
            raise TeamError("This invite link is invalid or has expired. Ask for a new one.", 404)
        if (person.get("email") or "").lower() != row["email"]:
            raise TeamError(f"This invite is for {row['email']}. Sign in with that address to accept it.", 403)
        if not person.get("email_verified"):
            # anyone can sign up with an address they don't own; only a confirmed one proves the invite is theirs
            raise TeamError("Confirm your email address first (use the link we emailed you), then accept the invite.",
                            403)
        if row["account_id"] == person["id"]:
            raise TeamError("You can't join your own workspace", 409)
        account = conn.execute("SELECT plan FROM users WHERE id = ?", (row["account_id"],)).fetchone()
        limit = seat_limit(account["plan"] if account else "free")
        taken = 1 + conn.execute("SELECT COUNT(*) FROM memberships WHERE account_id = ? AND user_id != ?",
                                 (row["account_id"], person["id"])).fetchone()[0]
        if limit is not None and taken >= limit:      # the plan changed since the invite was sent
            raise TeamError("This workspace has no free seat right now. Ask whoever invited you to upgrade "
                            "its plan or free a seat.", 402)
        conn.execute("INSERT INTO memberships (account_id, user_id, role, created_at) VALUES (?, ?, ?, ?) "
                     "ON CONFLICT(account_id, user_id) DO UPDATE SET role = excluded.role",
                     (row["account_id"], person["id"], row["role"], utcnow()))
        conn.execute("UPDATE team_invites SET accepted_at = ? WHERE id = ?", (utcnow(), row["id"]))
    return row["account_id"]


# API keys belong to the workspace, but the person who made one has it. Their keys stop working when
# they leave or become a viewer: a key does what a member can (run scans, change targets, the gateway).
_REVOKE_THEIR_KEYS = "UPDATE api_keys SET revoked = 1 WHERE user_id = ? AND created_by = ? AND revoked = 0"


def set_role(account_id: str, user_id: str, role: str) -> bool:
    if role not in ROLES:
        raise TeamError("Role must be viewer, member or admin")
    with transaction() as conn:
        changed = conn.execute("UPDATE memberships SET role = ? WHERE account_id = ? AND user_id = ?",
                               (role, account_id, user_id)).rowcount > 0
        if changed and role == "viewer":
            conn.execute(_REVOKE_THEIR_KEYS, (account_id, user_id))
    return changed


def remove_member(account_id: str, user_id: str) -> bool:
    with transaction() as conn:
        removed = conn.execute("DELETE FROM memberships WHERE account_id = ? AND user_id = ?",
                               (account_id, user_id)).rowcount > 0
        if removed:
            conn.execute(_REVOKE_THEIR_KEYS, (account_id, user_id))
    return removed


def forget_user(user_id: str) -> None:
    """When an account is deleted: its workspace's team and invites, its own memberships, and the keys
    it made in other workspaces."""
    with transaction() as conn:
        conn.execute("UPDATE api_keys SET revoked = 1 WHERE created_by = ? AND user_id != ?", (user_id, user_id))
        conn.execute("DELETE FROM memberships WHERE account_id = ? OR user_id = ?", (user_id, user_id))
        conn.execute("DELETE FROM team_invites WHERE account_id = ?", (user_id,))
