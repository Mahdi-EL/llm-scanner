import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
import secrets
from datetime import datetime
from database import DB_PATH
import sqlite3


# ── Bounty Tiers ──────────────────────────────────────────────
BOUNTY_TIERS = {
    "CRITICAL": {"reward": 500,  "label": "Critical",  "emoji": "🔴"},
    "HIGH"    : {"reward": 200,  "label": "High",       "emoji": "🟠"},
    "MEDIUM"  : {"reward": 50,   "label": "Medium",     "emoji": "🟡"},
    "LOW"     : {"reward": 10,   "label": "Low",        "emoji": "🟢"},
    "NOVEL"   : {"reward": 1000, "label": "Novel Zero-Day", "emoji": "🏆"}
}


# ── Bounty System ─────────────────────────────────────────────
class VulnerabilityBountySystem:
    """
    Manages a vulnerability bounty program for AI systems.
    Tracks submissions, reviews, and rewards.
    """

    def __init__(self):
        self._ensure_tables()

    def _ensure_tables(self):
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS bounty_programs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id  TEXT UNIQUE NOT NULL,
                tenant_id   TEXT,
                name        TEXT NOT NULL,
                description TEXT,
                total_budget INTEGER DEFAULT 0,
                paid_out    INTEGER DEFAULT 0,
                is_active   INTEGER DEFAULT 1,
                created_at  TEXT NOT NULL
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS bounty_submissions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                submission_id   TEXT UNIQUE NOT NULL,
                program_id      TEXT NOT NULL,
                researcher_id   TEXT NOT NULL,
                title           TEXT NOT NULL,
                description     TEXT,
                severity        TEXT NOT NULL,
                category        TEXT,
                attack_prompt   TEXT,
                expected_response TEXT,
                actual_response TEXT,
                is_novel        INTEGER DEFAULT 0,
                status          TEXT DEFAULT 'pending',
                reward_amount   INTEGER DEFAULT 0,
                reviewed_by     TEXT,
                submitted_at    TEXT NOT NULL,
                reviewed_at     TEXT,
                paid_at         TEXT
            )
        """)

        conn.commit()
        conn.close()

    def create_program(
        self,
        name,
        tenant_id=None,
        description=None,
        budget=5000
    ):
        """Creates a new bounty program."""
        program_id = f"BOP-{secrets.token_hex(6).upper()}"

        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT INTO bounty_programs (
                program_id, tenant_id, name, description,
                total_budget, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            program_id, tenant_id, name, description,
            budget, datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()

        print(f"\n  ✅ Bounty Program Created!")
        print(f"  Program ID : {program_id}")
        print(f"  Name       : {name}")
        print(f"  Budget     : ${budget}")
        print(f"\n  Reward Tiers:")
        for tier, info in BOUNTY_TIERS.items():
            print(f"  {info['emoji']} {tier:<10} : ${info['reward']}")

        return program_id

    def submit_vulnerability(
        self,
        program_id,
        researcher_id,
        title,
        severity,
        attack_prompt,
        actual_response,
        category="unknown",
        description=None,
        is_novel=False
    ):
        """Submits a vulnerability report."""
        submission_id = f"SUB-{secrets.token_hex(6).upper()}"
        tier          = BOUNTY_TIERS.get(
            "NOVEL" if is_novel else severity,
            BOUNTY_TIERS["MEDIUM"]
        )
        reward = tier["reward"]

        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()

        c.execute("""
            INSERT INTO bounty_submissions (
                submission_id, program_id, researcher_id,
                title, description, severity, category,
                attack_prompt, actual_response, is_novel,
                reward_amount, submitted_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            submission_id, program_id, researcher_id,
            title, description, severity, category,
            attack_prompt[:500], actual_response[:500],
            1 if is_novel else 0, reward,
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()

        print(f"\n  ✅ Submission Received!")
        print(f"  ID       : {submission_id}")
        print(f"  Severity : {tier['emoji']} {severity}")
        print(f"  Reward   : ${reward}")
        print(f"  Status   : Pending review")

        return submission_id

    def review_submission(
        self,
        submission_id,
        reviewer,
        approved=True,
        custom_reward=None
    ):
        """Reviews and approves/rejects a submission."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute(
            "SELECT * FROM bounty_submissions WHERE submission_id = ?",
            (submission_id,)
        )
        submission = c.fetchone()

        if not submission:
            print(f"  Submission not found: {submission_id}")
            conn.close()
            return False

        submission = dict(submission)
        status     = "approved" if approved else "rejected"
        reward     = custom_reward or (
            submission["reward_amount"] if approved else 0
        )

        c.execute("""
            UPDATE bounty_submissions
            SET status = ?, reviewed_by = ?,
                reviewed_at = ?, reward_amount = ?
            WHERE submission_id = ?
        """, (
            status, reviewer,
            datetime.now().isoformat(), reward,
            submission_id
        ))

        conn.commit()
        conn.close()

        icon = "✅" if approved else "❌"
        print(f"  {icon} Submission {submission_id}: {status.upper()}")
        if approved:
            print(f"  Reward: ${reward}")

        return True

    def get_leaderboard(self, program_id=None):
        """Gets researcher leaderboard."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        query = """
            SELECT
                researcher_id,
                COUNT(*) as submissions,
                SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN status='approved' THEN reward_amount ELSE 0 END) as earnings,
                MAX(severity) as highest_severity
            FROM bounty_submissions
        """
        params = []
        if program_id:
            query  += " WHERE program_id = ?"
            params.append(program_id)

        query += " GROUP BY researcher_id ORDER BY earnings DESC LIMIT 10"

        c.execute(query, params)
        rows = [dict(r) for r in c.fetchall()]
        conn.close()

        print(f"\n  {'='*60}")
        print(f"  💰 BOUNTY LEADERBOARD")
        print(f"  {'='*60}")

        for i, r in enumerate(rows, 1):
            print(
                f"  #{i:<3} {r['researcher_id']:<20} "
                f"${r['earnings']:<8} "
                f"{r['approved']}/{r['submissions']} approved"
            )

        print(f"  {'='*60}\n")
        return rows

    def get_program_stats(self, program_id):
        """Gets program statistics."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c    = conn.cursor()

        c.execute(
            "SELECT * FROM bounty_programs WHERE program_id = ?",
            (program_id,)
        )
        program = c.fetchone()

        c.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN status='approved' THEN reward_amount ELSE 0 END) as paid
            FROM bounty_submissions WHERE program_id = ?
        """, (program_id,))

        stats = dict(c.fetchone())
        conn.close()

        if program:
            prog = dict(program)
            print(f"\n  Program: {prog['name']}")
            print(f"  Budget : ${prog['total_budget']}")
            print(f"  Paid   : ${stats['paid']}")
            print(f"  Remaining: ${prog['total_budget'] - stats['paid']}")
            print(f"  Submissions: {stats['total']}")
            print(f"  Pending  : {stats['pending']}")
            print(f"  Approved : {stats['approved']}")

        return stats


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Vulnerability Bounty System"
    )
    subparsers = parser.add_subparsers(dest="command")

    p_create = subparsers.add_parser("create")
    p_create.add_argument("name")
    p_create.add_argument("--budget", type=int, default=5000)

    p_submit = subparsers.add_parser("submit")
    p_submit.add_argument("program_id")
    p_submit.add_argument("--researcher", required=True)
    p_submit.add_argument("--title",      required=True)
    p_submit.add_argument("--severity",   default="HIGH",
        choices=list(BOUNTY_TIERS.keys()))
    p_submit.add_argument("--attack",     default="Sample attack")
    p_submit.add_argument("--response",   default="Sample response")

    p_review = subparsers.add_parser("review")
    p_review.add_argument("submission_id")
    p_review.add_argument("--reviewer",  default="admin")
    p_review.add_argument("--approve",   action="store_true")
    p_review.add_argument("--reject",    action="store_true")
    p_review.add_argument("--reward",    type=int, default=None)

    p_board = subparsers.add_parser("leaderboard")
    p_board.add_argument("--program", default=None)

    p_stats = subparsers.add_parser("stats")
    p_stats.add_argument("program_id")

    args   = parser.parse_args()
    bounty = VulnerabilityBountySystem()

    if args.command == "create":
        bounty.create_program(args.name, budget=args.budget)
    elif args.command == "submit":
        bounty.submit_vulnerability(
            args.program_id, args.researcher,
            args.title, args.severity,
            args.attack, args.response
        )
    elif args.command == "review":
        approved = not args.reject
        bounty.review_submission(
            args.submission_id, args.reviewer,
            approved, args.reward
        )
    elif args.command == "leaderboard":
        bounty.get_leaderboard(args.program)
    elif args.command == "stats":
        bounty.get_program_stats(args.program_id)
    else:
        parser.print_help()