import sys
sys.stdout.reconfigure(encoding='utf-8')

import sqlite3
import json
import os
from datetime import datetime


# ── Database Path ─────────────────────────────────────────────
DB_PATH = "results/llmscanner.db"


# ── Initialize Database ───────────────────────────────────────
def init_db():
    """
    Creates the database and all tables if they don't exist.
    Called once at startup.
    """
    os.makedirs("results", exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    # ── Scans Table ──────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id         TEXT UNIQUE NOT NULL,
            target_name     TEXT NOT NULL,
            target_type     TEXT DEFAULT 'simulation',
            status          TEXT DEFAULT 'pending',
            security_score  INTEGER DEFAULT 0,
            total_attacks   INTEGER DEFAULT 0,
            critical_count  INTEGER DEFAULT 0,
            high_count      INTEGER DEFAULT 0,
            medium_count    INTEGER DEFAULT 0,
            low_count       INTEGER DEFAULT 0,
            safe_count      INTEGER DEFAULT 0,
            json_path       TEXT,
            pdf_path        TEXT,
            html_path       TEXT,
            md_path         TEXT,
            created_at      TEXT NOT NULL,
            completed_at    TEXT,
            duration_seconds INTEGER DEFAULT 0
        )
    """)

    # ── Findings Table ────────────────────────────────────────
    c.execute("""
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
        )
    """)

    # ── Waitlist Table ────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS waitlist (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT UNIQUE NOT NULL,
            name       TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # ── Stats Table ───────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS global_stats (
            id                  INTEGER PRIMARY KEY,
            total_scans         INTEGER DEFAULT 0,
            total_attacks_fired INTEGER DEFAULT 0,
            total_criticals     INTEGER DEFAULT 0,
            total_vulns_found   INTEGER DEFAULT 0,
            avg_security_score  REAL DEFAULT 0,
            last_updated        TEXT
        )
    """)

    # Insert default stats row
    c.execute("""
        INSERT OR IGNORE INTO global_stats (id) VALUES (1)
    """)

    conn.commit()
    conn.close()
    print(f"Database initialized : {DB_PATH}")


# ── Save Scan ─────────────────────────────────────────────────
def save_scan(scan_data):
    """
    Saves a completed scan to the database.
    scan_data = dict from scans_database in api.py
    """
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    summary = scan_data.get("results", {}).get("summary", {})

    c.execute("""
        INSERT OR REPLACE INTO scans (
            scan_id, target_name, status,
            security_score, total_attacks,
            critical_count, high_count,
            medium_count, low_count, safe_count,
            json_path, pdf_path, html_path, md_path,
            created_at, completed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_data["scan_id"],
        scan_data["target_name"],
        scan_data["status"],
        summary.get("security_score", 0),
        summary.get("total_attacks", 0),
        summary.get("critical", 0),
        summary.get("high", 0),
        summary.get("medium", 0),
        summary.get("low", 0),
        summary.get("safe", 0),
        scan_data.get("json_path"),
        scan_data.get("pdf_path"),
        scan_data.get("html_path"),
        scan_data.get("md_path"),
        scan_data.get("created_at"),
        datetime.now().isoformat()
    ))

    # Save individual findings
    results = scan_data.get("results", {}).get("results", [])
    for r in results:
        c.execute("""
            INSERT INTO findings (
                scan_id, category, attack, response,
                score, severity, reason,
                behavior_changed, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_data["scan_id"],
            r.get("category", ""),
            r.get("attack", "")[:500],
            r.get("response", "")[:500],
            r.get("score", 0),
            r.get("severity", "SAFE"),
            r.get("reason", "")[:300],
            1 if r.get("behavior_changed") else 0,
            r.get("confidence", "LOW")
        ))

    # Update global stats
    c.execute("""
        UPDATE global_stats SET
            total_scans         = total_scans + 1,
            total_attacks_fired = total_attacks_fired + ?,
            total_criticals     = total_criticals + ?,
            total_vulns_found   = total_vulns_found + ?,
            last_updated        = ?
        WHERE id = 1
    """, (
        summary.get("total_attacks", 0),
        summary.get("critical", 0),
        summary.get("critical", 0) + summary.get("high", 0),
        datetime.now().isoformat()
    ))

    # Update average score
    c.execute("""
        UPDATE global_stats SET
            avg_security_score = (
                SELECT AVG(security_score) FROM scans
                WHERE status = 'complete'
            )
        WHERE id = 1
    """)

    conn.commit()
    conn.close()


# ── Get All Scans ─────────────────────────────────────────────
def get_all_scans(limit=50, offset=0):
    """Returns all scans from database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("""
        SELECT * FROM scans
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    """, (limit, offset))

    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows


# ── Get Scan By ID ────────────────────────────────────────────
def get_scan_by_id(scan_id):
    """Returns a specific scan with its findings."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
    scan = c.fetchone()

    if not scan:
        conn.close()
        return None

    scan = dict(scan)

    # Get findings
    c.execute("""
        SELECT * FROM findings
        WHERE scan_id = ?
        ORDER BY score DESC
    """, (scan_id,))

    scan["findings"] = [dict(row) for row in c.fetchall()]
    conn.close()
    return scan


# ── Search Scans ──────────────────────────────────────────────
def search_scans(query):
    """Search scans by target name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("""
        SELECT * FROM scans
        WHERE target_name LIKE ?
        ORDER BY created_at DESC
    """, (f"%{query}%",))

    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows


# ── Get Global Stats ──────────────────────────────────────────
def get_global_stats():
    """Returns global statistics."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT * FROM global_stats WHERE id = 1")
    stats = dict(c.fetchone() or {})

    # Most vulnerable category
    c.execute("""
        SELECT category, AVG(score) as avg_score
        FROM findings
        GROUP BY category
        ORDER BY avg_score DESC
        LIMIT 1
    """)
    row = c.fetchone()
    stats["most_vulnerable_category"] = row["category"] if row else "N/A"

    # Most common severity
    c.execute("""
        SELECT severity, COUNT(*) as count
        FROM findings
        GROUP BY severity
        ORDER BY count DESC
        LIMIT 1
    """)
    row = c.fetchone()
    stats["most_common_severity"] = row["severity"] if row else "N/A"

    conn.close()
    return stats


# ── Add To Waitlist ───────────────────────────────────────────
def add_to_waitlist(email, name=None):
    """Adds email to waitlist."""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    try:
        c.execute("""
            INSERT INTO waitlist (email, name, created_at)
            VALUES (?, ?, ?)
        """, (email, name, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False  # Email already exists


# ── Get Waitlist ──────────────────────────────────────────────
def get_waitlist():
    """Returns all waitlist entries."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT * FROM waitlist ORDER BY created_at DESC")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows


# ── Delete Scan ───────────────────────────────────────────────
def delete_scan_from_db(scan_id):
    """Deletes a scan and its findings."""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    c.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
    c.execute("DELETE FROM scans WHERE scan_id = ?",    (scan_id,))

    conn.commit()
    conn.close()


# ── Print Stats ───────────────────────────────────────────────
def print_stats():
    """Prints global stats in terminal."""
    stats = get_global_stats()

    print("\n" + "=" * 50)
    print("  LLM SCANNER — DATABASE STATS")
    print("=" * 50)
    print(f"  Total scans         : {stats.get('total_scans', 0)}")
    print(f"  Total attacks fired : {stats.get('total_attacks_fired', 0)}")
    print(f"  Total criticals     : {stats.get('total_criticals', 0)}")
    print(f"  Avg security score  : {round(stats.get('avg_security_score', 0), 1)}%")
    print(f"  Most vulnerable     : {stats.get('most_vulnerable_category', 'N/A')}")
    print("=" * 50)


# ── Import Existing JSON Results ──────────────────────────────
def import_existing_results():
    """
    Imports all existing JSON scan results into the database.
    Run this once to migrate existing data.
    """
    results_dir = "results"
    imported    = 0

    for filename in os.listdir(results_dir):
        if not filename.endswith(".json"):
            continue
        if "checkpoint" in filename or "generated" in filename:
            continue
        if "discovery" in filename or "hardening" in filename:
            continue

        path = os.path.join(results_dir, filename)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if "summary" not in data:
                continue

            scan_id = filename.replace(".json", "")
            fake_scan = {
                "scan_id"    : scan_id,
                "target_name": data.get("scan_date", "Imported Scan"),
                "status"     : "complete",
                "results"    : data,
                "created_at" : data.get("scan_date", datetime.now().isoformat()),
                "json_path"  : path,
                "pdf_path"   : path.replace(".json", ".pdf"),
                "html_path"  : path.replace(".json", ".html"),
                "md_path"    : path.replace(".json", ".md"),
            }

            save_scan(fake_scan)
            imported += 1
            print(f"  Imported : {filename}")

        except Exception as e:
            print(f"  Skipped  : {filename} ({e})")

    print(f"\nImported {imported} scan results")


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    init_db()

    if len(sys.argv) > 1:
        if sys.argv[1] == "stats":
            print_stats()
        elif sys.argv[1] == "import":
            import_existing_results()
        elif sys.argv[1] == "waitlist":
            entries = get_waitlist()
            print(f"\nWaitlist ({len(entries)} entries) :")
            for e in entries:
                print(f"  {e['email']} — {e['created_at']}")
    else:
        print("Usage :")
        print("  python database.py stats    → Show global stats")
        print("  python database.py import   → Import existing JSON results")
        print("  python database.py waitlist → Show waitlist")
        