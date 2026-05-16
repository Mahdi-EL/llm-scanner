import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import hashlib
from datetime import datetime
from database import DB_PATH
import sqlite3


# ── Prompt Version Control ────────────────────────────────────
class PromptVersionControl:
    """
    Git-like version control for system prompts.
    Track changes, rollback, compare versions.
    """

    def __init__(self):
        self._ensure_tables()

    def _ensure_tables(self):
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS prompt_versions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                version_id   TEXT UNIQUE NOT NULL,
                prompt_name  TEXT NOT NULL,
                content      TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                version_num  INTEGER NOT NULL,
                message      TEXT,
                author       TEXT,
                is_current   INTEGER DEFAULT 0,
                security_score INTEGER,
                created_at   TEXT NOT NULL
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS prompt_tags (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                version_id  TEXT NOT NULL,
                tag         TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                UNIQUE(version_id, tag)
            )
        """)

        conn.commit()
        conn.close()

    def _hash_content(self, content):
        """Generates hash for prompt content."""
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _get_next_version(self, prompt_name):
        """Gets next version number for a prompt."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            SELECT MAX(version_num) FROM prompt_versions
            WHERE prompt_name = ?
        """, (prompt_name,))

        row = c.fetchone()
        conn.close()
        return (row[0] or 0) + 1

    def commit(
        self,
        prompt_name,
        content,
        message     ="Update prompt",
        author      ="user",
        security_score=None
    ):
        """
        Commits a new version of a prompt.
        """
        import secrets

        version_id  = f"v{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(3)}"
        content_hash = self._hash_content(content)
        version_num  = self._get_next_version(prompt_name)

        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        # Mark previous as not current
        c.execute("""
            UPDATE prompt_versions SET is_current = 0
            WHERE prompt_name = ?
        """, (prompt_name,))

        c.execute("""
            INSERT INTO prompt_versions (
                version_id, prompt_name, content, content_hash,
                version_num, message, author, is_current,
                security_score, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        """, (
            version_id, prompt_name, content, content_hash,
            version_num, message, author, security_score,
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()

        print(f"  ✅ Committed: {version_id}")
        print(f"     Version   : {version_num}")
        print(f"     Message   : {message}")
        print(f"     Hash      : {content_hash}")

        return version_id

    def get_current(self, prompt_name):
        """Gets the current version of a prompt."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("""
            SELECT * FROM prompt_versions
            WHERE prompt_name = ? AND is_current = 1
        """, (prompt_name,))

        row = c.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_version(self, version_id):
        """Gets a specific version."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute(
            "SELECT * FROM prompt_versions WHERE version_id = ?",
            (version_id,)
        )
        row = c.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_history(self, prompt_name, limit=20):
        """Gets version history for a prompt."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute("""
            SELECT * FROM prompt_versions
            WHERE prompt_name = ?
            ORDER BY version_num DESC
            LIMIT ?
        """, (prompt_name, limit))

        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    def rollback(self, prompt_name, version_id):
        """Rolls back to a specific version."""
        version = self.get_version(version_id)
        if not version:
            print(f"  Version not found: {version_id}")
            return False

        if version["prompt_name"] != prompt_name:
            print(f"  Version belongs to different prompt")
            return False

        # Create new version with old content
        new_id = self.commit(
            prompt_name   =prompt_name,
            content       =version["content"],
            message       =f"Rollback to {version_id} (v{version['version_num']})",
            author        ="system"
        )

        print(f"  ✅ Rolled back to v{version['version_num']}")
        print(f"     New version: {new_id}")
        return new_id

    def diff(self, version_id1, version_id2):
        """Shows differences between two versions."""
        v1 = self.get_version(version_id1)
        v2 = self.get_version(version_id2)

        if not v1 or not v2:
            print("  One or both versions not found")
            return

        content1 = v1["content"]
        content2 = v2["content"]

        lines1 = content1.split('\n')
        lines2 = content2.split('\n')

        print(f"\n  DIFF: {version_id1} → {version_id2}")
        print(f"  {'='*50}")

        added   = [l for l in lines2 if l not in lines1]
        removed = [l for l in lines1 if l not in lines2]

        for line in removed[:5]:
            if line.strip():
                print(f"  - {line}")
        for line in added[:5]:
            if line.strip():
                print(f"  + {line}")

        print(f"  {'='*50}")
        print(f"  Added   : {len(added)} lines")
        print(f"  Removed : {len(removed)} lines")

    def tag(self, version_id, tag):
        """Tags a version."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        try:
            c.execute("""
                INSERT INTO prompt_tags (version_id, tag, created_at)
                VALUES (?, ?, ?)
            """, (version_id, tag, datetime.now().isoformat()))
            conn.commit()
            print(f"  Tagged {version_id} as '{tag}'")
        except sqlite3.IntegrityError:
            print(f"  Tag already exists")
        finally:
            conn.close()

    def tag_with_scan(self, version_id, scan_results_path):
        """
        Runs a scan and tags the version with security results.
        """
        with open(scan_results_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        score  = data["summary"]["security_score"]

        # Update security score
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("""
            UPDATE prompt_versions SET security_score = ?
            WHERE version_id = ?
        """, (score, version_id))
        conn.commit()
        conn.close()

        # Tag based on score
        if score >= 70:
            self.tag(version_id, "secure")
        elif score >= 40:
            self.tag(version_id, "moderate")
        else:
            self.tag(version_id, "vulnerable")

        print(f"  Version {version_id} security score: {score}%")

    def print_log(self, prompt_name):
        """Prints git-like log for a prompt."""
        history = self.get_history(prompt_name)

        if not history:
            print(f"  No versions found for: {prompt_name}")
            return

        print(f"\n  Prompt Version Log: {prompt_name}")
        print(f"  {'='*60}")

        for v in history:
            current = " ← CURRENT" if v["is_active"] else ""
            score   = f" [Score: {v['security_score']}%]" \
                      if v.get("security_score") else ""
            print(
                f"\n  v{v['version_num']} {v['version_id']}{current}"
            )
            print(f"  Author  : {v['author']}")
            print(f"  Date    : {v['created_at'][:16]}")
            print(f"  Hash    : {v['content_hash']}")
            print(f"  Message : {v['message']}{score}")

        print(f"\n  {'='*60}\n")

    def list_prompts(self):
        """Lists all tracked prompts."""
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            SELECT prompt_name, MAX(version_num) as versions,
                   MAX(created_at) as last_updated
            FROM prompt_versions
            GROUP BY prompt_name
        """)

        rows = c.fetchall()
        conn.close()

        print(f"\n  Tracked Prompts ({len(rows)}):")
        for name, versions, last_updated in rows:
            print(
                f"  {name:<30} "
                f"v{versions:<5} "
                f"Updated: {last_updated[:16]}"
            )


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Prompt Version Control"
    )
    subparsers = parser.add_subparsers(dest="command")

    p_commit = subparsers.add_parser("commit")
    p_commit.add_argument("prompt_name")
    p_commit.add_argument("content_or_file")
    p_commit.add_argument("--message", default="Update prompt")
    p_commit.add_argument("--author",  default="user")

    p_log = subparsers.add_parser("log")
    p_log.add_argument("prompt_name")

    p_rollback = subparsers.add_parser("rollback")
    p_rollback.add_argument("prompt_name")
    p_rollback.add_argument("version_id")

    p_diff = subparsers.add_parser("diff")
    p_diff.add_argument("version_id1")
    p_diff.add_argument("version_id2")

    p_tag = subparsers.add_parser("tag")
    p_tag.add_argument("version_id")
    p_tag.add_argument("tag")

    subparsers.add_parser("list")

    args = parser.parse_args()
    pvc  = PromptVersionControl()

    if args.command == "commit":
        content = args.content_or_file
        if os.path.exists(content):
            with open(content, "r", encoding="utf-8") as f:
                content = f.read()
        pvc.commit(args.prompt_name, content, args.message, args.author)

    elif args.command == "log":
        pvc.print_log(args.prompt_name)

    elif args.command == "rollback":
        pvc.rollback(args.prompt_name, args.version_id)

    elif args.command == "diff":
        pvc.diff(args.version_id1, args.version_id2)

    elif args.command == "tag":
        pvc.tag(args.version_id, args.tag)

    elif args.command == "list":
        pvc.list_prompts()

    else:
        pvc.list_prompts()