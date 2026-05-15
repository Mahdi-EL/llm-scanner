import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import hashlib
from datetime import datetime
from database import DB_PATH
import sqlite3


# ── Permissions ───────────────────────────────────────────────
PERMISSIONS = {
    "scan:create"   : "Launch new scans",
    "scan:read"     : "View scan results",
    "scan:delete"   : "Delete scans",
    "report:read"   : "View reports",
    "report:export" : "Download reports",
    "user:create"   : "Create users",
    "user:read"     : "View users",
    "user:delete"   : "Delete users",
    "tenant:read"   : "View tenant settings",
    "tenant:update" : "Update tenant settings",
    "api:access"    : "Use API endpoints",
    "monitor:read"  : "View monitoring data",
    "monitor:create": "Create monitors",
    "audit:read"    : "View audit logs",
}


# ── Roles ─────────────────────────────────────────────────────
ROLES = {
    "admin": {
        "name"       : "Administrator",
        "description": "Full access to everything",
        "permissions": list(PERMISSIONS.keys())  # All permissions
    },
    "manager": {
        "name"       : "Manager",
        "description": "Can manage scans and view reports",
        "permissions": [
            "scan:create",
            "scan:read",
            "report:read",
            "report:export",
            "user:read",
            "tenant:read",
            "api:access",
            "monitor:read",
            "monitor:create",
        ]
    },
    "analyst": {
        "name"       : "Security Analyst",
        "description": "Can run scans and analyze results",
        "permissions": [
            "scan:create",
            "scan:read",
            "report:read",
            "report:export",
            "monitor:read",
            "api:access",
        ]
    },
    "viewer": {
        "name"       : "Viewer",
        "description": "Read-only access to reports",
        "permissions": [
            "scan:read",
            "report:read",
        ]
    }
}


# ── RBAC Manager ──────────────────────────────────────────────
class RBACManager:
    """
    Role-Based Access Control Manager.
    Controls what each user can do in LLM Scanner.
    """

    def __init__(self):
        self._ensure_rbac_tables()

    def _ensure_rbac_tables(self):
        """Creates RBAC tables."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        # Custom roles table
        c.execute("""
            CREATE TABLE IF NOT EXISTS custom_roles (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id   TEXT NOT NULL,
                role_name   TEXT NOT NULL,
                permissions TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                UNIQUE(tenant_id, role_name)
            )
        """)

        # User permissions override table
        c.execute("""
            CREATE TABLE IF NOT EXISTS user_permissions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id   TEXT NOT NULL,
                username    TEXT NOT NULL,
                permission  TEXT NOT NULL,
                granted     INTEGER DEFAULT 1,
                granted_by  TEXT,
                created_at  TEXT NOT NULL,
                UNIQUE(tenant_id, username, permission)
            )
        """)

        conn.commit()
        conn.close()

    def has_permission(self, tenant_id, username, permission):
        """
        Checks if a user has a specific permission.
        Checks role permissions + individual overrides.
        """
        # Get user role
        user = self._get_user(tenant_id, username)
        if not user:
            return False

        role = user.get("role", "viewer")

        # Check role permissions
        role_data    = ROLES.get(role, ROLES["viewer"])
        has_from_role = permission in role_data["permissions"]

        # Check individual overrides
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            SELECT granted FROM user_permissions
            WHERE tenant_id = ? AND username = ? AND permission = ?
        """, (tenant_id, username, permission))

        override = c.fetchone()
        conn.close()

        if override is not None:
            return bool(override[0])

        return has_from_role

    def get_user_permissions(self, tenant_id, username):
        """Gets all permissions for a user."""
        user = self._get_user(tenant_id, username)
        if not user:
            return []

        role      = user.get("role", "viewer")
        role_data = ROLES.get(role, ROLES["viewer"])
        perms     = set(role_data["permissions"])

        # Apply overrides
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            SELECT permission, granted FROM user_permissions
            WHERE tenant_id = ? AND username = ?
        """, (tenant_id, username))

        for perm, granted in c.fetchall():
            if granted:
                perms.add(perm)
            else:
                perms.discard(perm)

        conn.close()
        return list(perms)

    def grant_permission(
        self, tenant_id, username, permission, granted_by=None
    ):
        """Grants a specific permission to a user."""
        if permission not in PERMISSIONS:
            print(f"Unknown permission: {permission}")
            return False

        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT OR REPLACE INTO user_permissions (
                tenant_id, username, permission,
                granted, granted_by, created_at
            ) VALUES (?, ?, ?, 1, ?, ?)
        """, (
            tenant_id, username, permission,
            granted_by, datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()
        print(f"  Granted {permission} to {username}")
        return True

    def revoke_permission(self, tenant_id, username, permission):
        """Revokes a specific permission from a user."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT OR REPLACE INTO user_permissions (
                tenant_id, username, permission,
                granted, created_at
            ) VALUES (?, ?, ?, 0, ?)
        """, (
            tenant_id, username, permission,
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()
        print(f"  Revoked {permission} from {username}")
        return True

    def change_user_role(self, tenant_id, username, new_role):
        """Changes a user's role."""
        if new_role not in ROLES:
            print(f"Unknown role: {new_role}")
            return False

        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            UPDATE tenant_users
            SET role = ?
            WHERE tenant_id = ? AND username = ?
        """, (new_role, tenant_id, username))

        conn.commit()
        conn.close()
        print(f"  {username} role changed to {new_role}")
        return True

    def create_custom_role(
        self, tenant_id, role_name, permissions
    ):
        """Creates a custom role for a tenant."""
        valid_perms = [
            p for p in permissions if p in PERMISSIONS
        ]

        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        try:
            c.execute("""
                INSERT INTO custom_roles (
                    tenant_id, role_name, permissions, created_at
                ) VALUES (?, ?, ?, ?)
            """, (
                tenant_id, role_name,
                json.dumps(valid_perms),
                datetime.now().isoformat()
            ))
            conn.commit()
            print(f"  Custom role created: {role_name}")
            return True
        except sqlite3.IntegrityError:
            print(f"  Role already exists: {role_name}")
            return False
        finally:
            conn.close()

    def _get_user(self, tenant_id, username):
        """Gets a user from the database."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("""
            SELECT * FROM tenant_users
            WHERE tenant_id = ? AND username = ?
        """, (tenant_id, username))

        row = c.fetchone()
        conn.close()
        return dict(row) if row else None

    def print_role_matrix(self):
        """Prints a permission matrix for all roles."""
        print(f"\n  {'='*70}")
        print(f"  ROLE PERMISSION MATRIX")
        print(f"  {'='*70}")

        # Header
        roles_list = list(ROLES.keys())
        header     = f"  {'Permission':<25}"
        for role in roles_list:
            header += f"{role:<12}"
        print(header)
        print(f"  {'-'*70}")

        # Rows
        for perm, desc in PERMISSIONS.items():
            row = f"  {perm:<25}"
            for role in roles_list:
                has = perm in ROLES[role]["permissions"]
                row += f"{'✅':<12}" if has else f"{'❌':<12}"
            print(row)

        print(f"  {'='*70}\n")

    def print_user_permissions(self, tenant_id, username):
        """Prints all permissions for a user."""
        user  = self._get_user(tenant_id, username)
        if not user:
            print(f"User not found: {username}")
            return

        perms = self.get_user_permissions(tenant_id, username)
        role  = user.get("role", "viewer")

        print(f"\n  User : {username}")
        print(f"  Role : {role} — {ROLES.get(role, {}).get('name', '')}")
        print(f"\n  Permissions ({len(perms)}) :")
        for perm in sorted(perms):
            desc = PERMISSIONS.get(perm, "")
            print(f"    ✅ {perm:<20} — {desc}")


# ── Permission Decorator ──────────────────────────────────────
def require_permission(permission):
    """
    Decorator for FastAPI endpoints.
    Checks if user has required permission.
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Extract tenant_id and username from request
            request   = kwargs.get("request")
            tenant_id = getattr(request, "tenant_id", None)
            username  = getattr(request, "username", None)

            if not tenant_id or not username:
                from fastapi import HTTPException
                raise HTTPException(
                    status_code=401,
                    detail="Authentication required"
                )

            rbac = RBACManager()
            if not rbac.has_permission(tenant_id, username, permission):
                from fastapi import HTTPException
                raise HTTPException(
                    status_code=403,
                    detail=f"Permission required: {permission}"
                )

            return await func(*args, **kwargs)
        return wrapper
    return decorator


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — RBAC Manager"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Matrix
    subparsers.add_parser("matrix",
        help="Show permission matrix")

    # Check permission
    p_check = subparsers.add_parser("check")
    p_check.add_argument("tenant_id")
    p_check.add_argument("username")
    p_check.add_argument("permission")

    # Grant permission
    p_grant = subparsers.add_parser("grant")
    p_grant.add_argument("tenant_id")
    p_grant.add_argument("username")
    p_grant.add_argument("permission")

    # Revoke permission
    p_revoke = subparsers.add_parser("revoke")
    p_revoke.add_argument("tenant_id")
    p_revoke.add_argument("username")
    p_revoke.add_argument("permission")

    # Change role
    p_role = subparsers.add_parser("role")
    p_role.add_argument("tenant_id")
    p_role.add_argument("username")
    p_role.add_argument("new_role", choices=list(ROLES.keys()))

    # User permissions
    p_user = subparsers.add_parser("user")
    p_user.add_argument("tenant_id")
    p_user.add_argument("username")

    args = parser.parse_args()
    rbac = RBACManager()

    if args.command == "matrix":
        rbac.print_role_matrix()

    elif args.command == "check":
        result = rbac.has_permission(
            args.tenant_id, args.username, args.permission
        )
        icon = "✅" if result else "❌"
        print(f"{icon} {args.username} "
              f"{'has' if result else 'does NOT have'} "
              f"permission: {args.permission}")

    elif args.command == "grant":
        rbac.grant_permission(
            args.tenant_id, args.username, args.permission
        )

    elif args.command == "revoke":
        rbac.revoke_permission(
            args.tenant_id, args.username, args.permission
        )

    elif args.command == "role":
        rbac.change_user_role(
            args.tenant_id, args.username, args.new_role
        )

    elif args.command == "user":
        rbac.print_user_permissions(args.tenant_id, args.username)

    else:
        rbac.print_role_matrix()
        