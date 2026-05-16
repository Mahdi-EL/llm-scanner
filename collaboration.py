import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import threading
import time
from datetime import datetime
from database import DB_PATH
import sqlite3


# ── Collaboration Manager ─────────────────────────────────────
class CollaborationManager:
    """
    Enables real-time collaboration on security scans.
    Multiple users can view and comment on findings together.
    """

    def __init__(self):
        self._ensure_tables()

    def _ensure_tables(self):
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT UNIQUE NOT NULL,
                scan_id     TEXT NOT NULL,
                tenant_id   TEXT,
                created_by  TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                expires_at  TEXT,
                is_active   INTEGER DEFAULT 1
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS session_participants (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT NOT NULL,
                username    TEXT NOT NULL,
                role        TEXT DEFAULT 'viewer',
                joined_at   TEXT NOT NULL,
                last_active TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS finding_comments (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                comment_id  TEXT UNIQUE NOT NULL,
                session_id  TEXT NOT NULL,
                scan_id     TEXT NOT NULL,
                finding_idx INTEGER NOT NULL,
                username    TEXT NOT NULL,
                comment     TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                edited_at   TEXT,
                is_resolved INTEGER DEFAULT 0
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS finding_tags (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT NOT NULL,
                finding_idx INTEGER NOT NULL,
                tag         TEXT NOT NULL,
                tagged_by   TEXT NOT NULL,
                tagged_at   TEXT NOT NULL,
                UNIQUE(scan_id, finding_idx, tag)
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS finding_assignments (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id      TEXT NOT NULL,
                finding_idx  INTEGER NOT NULL,
                assigned_to  TEXT NOT NULL,
                assigned_by  TEXT NOT NULL,
                status       TEXT DEFAULT 'open',
                due_date     TEXT,
                assigned_at  TEXT NOT NULL,
                UNIQUE(scan_id, finding_idx)
            )
        """)

        conn.commit()
        conn.close()

    def create_session(
        self, scan_id, created_by, tenant_id=None, expires_hours=24
    ):
        """Creates a collaboration session for a scan."""
        import secrets
        from datetime import timedelta

        session_id = f"sess_{secrets.token_hex(8)}"
        expires_at = (
            datetime.now() + timedelta(hours=expires_hours)
        ).isoformat()

        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT INTO scan_sessions (
                session_id, scan_id, tenant_id,
                created_by, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            session_id, scan_id, tenant_id,
            created_by, datetime.now().isoformat(), expires_at
        ))

        # Add creator as admin participant
        c.execute("""
            INSERT INTO session_participants (
                session_id, username, role, joined_at
            ) VALUES (?, ?, 'admin', ?)
        """, (session_id, created_by, datetime.now().isoformat()))

        conn.commit()
        conn.close()

        print(f"  Session created: {session_id}")
        print(f"  Share URL: /collaborate/{session_id}")
        return session_id

    def join_session(self, session_id, username, role="viewer"):
        """Joins an existing collaboration session."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        # Check session exists and is active
        c.execute("""
            SELECT * FROM scan_sessions
            WHERE session_id = ? AND is_active = 1
        """, (session_id,))

        if not c.fetchone():
            conn.close()
            return False

        c.execute("""
            INSERT OR REPLACE INTO session_participants (
                session_id, username, role, joined_at, last_active
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            session_id, username, role,
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()
        print(f"  {username} joined session {session_id}")
        return True

    def add_comment(
        self, session_id, scan_id, finding_idx, username, comment
    ):
        """Adds a comment to a specific finding."""
        import secrets

        comment_id = f"cmt_{secrets.token_hex(6)}"

        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT INTO finding_comments (
                comment_id, session_id, scan_id,
                finding_idx, username, comment, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            comment_id, session_id, scan_id,
            finding_idx, username, comment,
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()
        return comment_id

    def get_comments(self, scan_id, finding_idx=None):
        """Gets all comments for a scan or specific finding."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        if finding_idx is not None:
            c.execute("""
                SELECT * FROM finding_comments
                WHERE scan_id = ? AND finding_idx = ?
                ORDER BY created_at ASC
            """, (scan_id, finding_idx))
        else:
            c.execute("""
                SELECT * FROM finding_comments
                WHERE scan_id = ?
                ORDER BY created_at ASC
            """, (scan_id,))

        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return rows

    def tag_finding(self, scan_id, finding_idx, tag, username):
        """Tags a finding with a label."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        try:
            c.execute("""
                INSERT INTO finding_tags (
                    scan_id, finding_idx, tag,
                    tagged_by, tagged_at
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                scan_id, finding_idx, tag,
                username, datetime.now().isoformat()
            ))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def assign_finding(
        self, scan_id, finding_idx,
        assigned_to, assigned_by, due_date=None
    ):
        """Assigns a finding to a team member for remediation."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT OR REPLACE INTO finding_assignments (
                scan_id, finding_idx, assigned_to,
                assigned_by, due_date, assigned_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_id, finding_idx, assigned_to,
            assigned_by, due_date, datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()
        print(f"  Finding {finding_idx} assigned to {assigned_to}")

    def resolve_finding(self, scan_id, finding_idx, resolved_by):
        """Marks a finding as resolved."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            UPDATE finding_assignments
            SET status = 'resolved'
            WHERE scan_id = ? AND finding_idx = ?
        """, (scan_id, finding_idx))

        conn.commit()
        conn.close()
        print(f"  Finding {finding_idx} resolved by {resolved_by}")

    def get_session_activity(self, session_id):
        """Gets all activity for a session."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("""
            SELECT * FROM session_participants
            WHERE session_id = ?
        """, (session_id,))
        participants = [dict(r) for r in c.fetchall()]

        c.execute("""
            SELECT * FROM scan_sessions
            WHERE session_id = ?
        """, (session_id,))
        session = c.fetchone()

        conn.close()

        if not session:
            return None

        session = dict(session)
        session["participants"] = participants

        return session

    def print_session_status(self, session_id):
        """Prints session status."""
        activity = self.get_session_activity(session_id)
        if not activity:
            print(f"  Session not found: {session_id}")
            return

        print(f"\n  {'='*50}")
        print(f"  COLLABORATION SESSION")
        print(f"  {'='*50}")
        print(f"  Session ID : {session_id}")
        print(f"  Scan ID    : {activity['scan_id']}")
        print(f"  Created by : {activity['created_by']}")
        print(f"  Expires    : {activity.get('expires_at','?')[:16]}")
        print(f"\n  Participants ({len(activity['participants'])}) :")
        for p in activity["participants"]:
            print(
                f"    {p['username']:<20} "
                f"[{p['role']}] "
                f"Joined: {p['joined_at'][:16]}"
            )
        print(f"  {'='*50}\n")


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Collaboration Manager"
    )
    subparsers = parser.add_subparsers(dest="command")

    p_create = subparsers.add_parser("create")
    p_create.add_argument("scan_id")
    p_create.add_argument("--user", required=True)

    p_join = subparsers.add_parser("join")
    p_join.add_argument("session_id")
    p_join.add_argument("--user", required=True)

    p_comment = subparsers.add_parser("comment")
    p_comment.add_argument("session_id")
    p_comment.add_argument("scan_id")
    p_comment.add_argument("--finding", type=int, required=True)
    p_comment.add_argument("--user",    required=True)
    p_comment.add_argument("--text",    required=True)

    p_status = subparsers.add_parser("status")
    p_status.add_argument("session_id")

    args    = parser.parse_args()
    collab  = CollaborationManager()

    if args.command == "create":
        collab.create_session(args.scan_id, args.user)
    elif args.command == "join":
        collab.join_session(args.session_id, args.user)
    elif args.command == "comment":
        collab.add_comment(
            args.session_id, args.scan_id,
            args.finding, args.user, args.text
        )
    elif args.command == "status":
        collab.print_session_status(args.session_id)
    else:
        parser.print_help()