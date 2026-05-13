"""
Shared State Store — SQLite-backed storage for findings, coverage, and cost tracking.
All agents read/write through this interface.
"""

import json
import sqlite3
import os
from datetime import datetime
from config import STATE_DB


def _get_conn():
    conn = sqlite3.connect(STATE_DB, timeout=10)
    conn.row_factory = sqlite3.Row
    # Wait up to 5s if another writer holds the lock (parallel workers)
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_id TEXT UNIQUE NOT NULL,
            category TEXT NOT NULL,
            subcategory TEXT DEFAULT '',
            attack_payload TEXT NOT NULL,
            target_response TEXT DEFAULT '',
            verdict TEXT DEFAULT 'pending',
            severity TEXT DEFAULT 'medium',
            confidence REAL DEFAULT 0.0,
            judge_reasoning TEXT DEFAULT '',
            campaign_id TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            judged_at TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS coverage (
            category TEXT NOT NULL,
            subcategory TEXT NOT NULL DEFAULT '',
            total_attacks INTEGER DEFAULT 0,
            bypasses INTEGER DEFAULT 0,
            defenses INTEGER DEFAULT 0,
            partials INTEGER DEFAULT 0,
            last_tested TEXT DEFAULT '',
            PRIMARY KEY (category, subcategory)
        );

        CREATE TABLE IF NOT EXISTS exploits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            attack_id TEXT UNIQUE NOT NULL,
            category TEXT NOT NULL,
            subcategory TEXT DEFAULT '',
            severity TEXT NOT NULL,
            confidence REAL DEFAULT 0.0,
            attack_sequence TEXT NOT NULL,
            expected_safe_behavior TEXT NOT NULL,
            observed_behavior TEXT NOT NULL,
            judge_reasoning TEXT DEFAULT '',
            fixed INTEGER DEFAULT 0,
            fix_validated INTEGER DEFAULT 0,
            last_regression_verdict TEXT DEFAULT '',
            last_regression_at TEXT DEFAULT '',
            last_regression_reasoning TEXT DEFAULT '',
            confirmed_at TEXT NOT NULL,
            FOREIGN KEY (finding_id) REFERENCES findings(id)
        );

        CREATE TABLE IF NOT EXISTS cost_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent TEXT NOT NULL,
            model TEXT NOT NULL,
            input_tokens INTEGER DEFAULT 0,
            output_tokens INTEGER DEFAULT 0,
            cost_usd REAL DEFAULT 0.0,
            campaign_id TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS campaigns (
            id TEXT PRIMARY KEY,
            category TEXT NOT NULL,
            status TEXT DEFAULT 'running',
            attacks_generated INTEGER DEFAULT 0,
            attacks_successful INTEGER DEFAULT 0,
            total_cost REAL DEFAULT 0.0,
            started_at TEXT NOT NULL,
            finished_at TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exploit_id INTEGER NOT NULL,
            report_text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (exploit_id) REFERENCES exploits(id)
        );
    """)

    # Initialize coverage for every (category, subcategory) from the threat model
    from config import ATTACK_SUBCATEGORIES
    for cat, subs in ATTACK_SUBCATEGORIES.items():
        for sub in subs:
            conn.execute(
                "INSERT OR IGNORE INTO coverage (category, subcategory, total_attacks) VALUES (?, ?, 0)",
                (cat, sub)
            )

    conn.commit()
    conn.close()


# ── Findings ──

def add_finding(attack_id, category, subcategory, attack_payload, target_response, campaign_id=""):
    conn = _get_conn()
    conn.execute(
        """INSERT OR REPLACE INTO findings
           (attack_id, category, subcategory, attack_payload, target_response, campaign_id, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (attack_id, category, subcategory, attack_payload, target_response, campaign_id, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


def update_verdict(attack_id, verdict, severity, confidence, reasoning):
    conn = _get_conn()
    conn.execute(
        """UPDATE findings SET verdict=?, severity=?, confidence=?, judge_reasoning=?, judged_at=?
           WHERE attack_id=?""",
        (verdict, severity, confidence, reasoning, datetime.utcnow().isoformat(), attack_id)
    )
    conn.commit()
    conn.close()


def get_findings(category=None, verdict=None):
    conn = _get_conn()
    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    if category:
        query += " AND category=?"
        params.append(category)
    if verdict:
        query += " AND verdict=?"
        params.append(verdict)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_partial_successes(category=None):
    return get_findings(category=category, verdict="partial")


# ── Coverage ──

def update_coverage(category, subcategory, verdict):
    conn = _get_conn()
    col = {"bypass": "bypasses", "defended": "defenses", "partial": "partials"}.get(verdict, "defenses")
    # Ensure the row exists even if the Red Team invented a new subcategory not in config
    conn.execute(
        "INSERT OR IGNORE INTO coverage (category, subcategory, total_attacks) VALUES (?, ?, 0)",
        (category, subcategory)
    )
    conn.execute(
        f"UPDATE coverage SET total_attacks = total_attacks + 1, {col} = {col} + 1, last_tested = ? "
        "WHERE category = ? AND subcategory = ?",
        (datetime.utcnow().isoformat(), category, subcategory)
    )
    conn.commit()
    conn.close()


def get_coverage():
    """Return one row per (category, subcategory), least-tested first."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM coverage ORDER BY total_attacks ASC, category, subcategory"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_coverage_by_category():
    """Aggregate coverage rolled up to the top-level category."""
    conn = _get_conn()
    rows = conn.execute(
        """SELECT category,
                  SUM(total_attacks) AS total_attacks,
                  SUM(bypasses)      AS bypasses,
                  SUM(defenses)      AS defenses,
                  SUM(partials)      AS partials,
                  MAX(last_tested)   AS last_tested
           FROM coverage
           GROUP BY category
           ORDER BY total_attacks ASC"""
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Exploits ──

def add_exploit(finding_id, attack_id, category, severity, attack_sequence, expected, observed):
    conn = _get_conn()
    conn.execute(
        """INSERT OR REPLACE INTO exploits
           (finding_id, attack_id, category, severity, attack_sequence, expected_safe_behavior, observed_behavior, confirmed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (finding_id, attack_id, category, severity, json.dumps(attack_sequence), expected, observed, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


def promote_finding_to_exploit(attack_id, expected_safe_text, confidence_threshold=0.9):
    """
    Promotion gate (ARCHITECTURE.md §4.2):
    if a finding's verdict is 'bypass' AND confidence >= τ, freeze it into the
    exploits table as an ExploitArtifact. Idempotent — re-promoting the same
    attack_id is a no-op (UNIQUE constraint on attack_id).

    Returns the exploit row id, or None if the finding didn't qualify.
    """
    conn = _get_conn()
    f = conn.execute(
        "SELECT id, attack_id, category, subcategory, severity, confidence, "
        "attack_payload, target_response, judge_reasoning "
        "FROM findings WHERE attack_id=?",
        (attack_id,)
    ).fetchone()
    if not f:
        conn.close()
        return None

    f = dict(f)
    # Get the verdict separately (column name might collide)
    verdict_row = conn.execute("SELECT verdict FROM findings WHERE attack_id=?", (attack_id,)).fetchone()
    verdict = verdict_row["verdict"] if verdict_row else ""

    if verdict != "bypass" or (f.get("confidence") or 0.0) < confidence_threshold:
        conn.close()
        return None

    # Idempotency check
    existing = conn.execute("SELECT id FROM exploits WHERE attack_id=?", (attack_id,)).fetchone()
    if existing:
        conn.close()
        return existing["id"]

    # attack_payload may be JSON-encoded (multi-turn) or plain string
    try:
        seq = json.loads(f["attack_payload"])
        if not isinstance(seq, list):
            seq = [f["attack_payload"]]
    except (json.JSONDecodeError, TypeError):
        seq = [f["attack_payload"]]

    conn.execute(
        """INSERT INTO exploits
           (finding_id, attack_id, category, subcategory, severity, confidence,
            attack_sequence, expected_safe_behavior, observed_behavior,
            judge_reasoning, confirmed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (f["id"], attack_id, f["category"], f.get("subcategory", ""),
         f.get("severity", "high"), f.get("confidence", 0.0),
         json.dumps(seq), expected_safe_text,
         f.get("target_response", ""), f.get("judge_reasoning", ""),
         datetime.utcnow().isoformat())
    )
    exploit_id = conn.execute("SELECT id FROM exploits WHERE attack_id=?", (attack_id,)).fetchone()["id"]
    conn.commit()
    conn.close()
    return exploit_id


def get_exploits(fixed=None):
    conn = _get_conn()
    query = "SELECT * FROM exploits"
    params = []
    if fixed is not None:
        query += " WHERE fixed=?"
        params.append(int(fixed))
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Cost ──

def log_cost(agent, model, input_tokens, output_tokens, cost_usd, campaign_id=""):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO cost_log (agent, model, input_tokens, output_tokens, cost_usd, campaign_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (agent, model, input_tokens, output_tokens, cost_usd, campaign_id, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


def get_total_cost(campaign_id=None):
    conn = _get_conn()
    if campaign_id:
        row = conn.execute("SELECT SUM(cost_usd) as total FROM cost_log WHERE campaign_id=?", (campaign_id,)).fetchone()
    else:
        row = conn.execute("SELECT SUM(cost_usd) as total FROM cost_log").fetchone()
    conn.close()
    return row["total"] or 0.0


# ── Campaigns ──

def create_campaign(campaign_id, category):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO campaigns (id, category, started_at) VALUES (?, ?, ?)",
        (campaign_id, category, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


def finish_campaign(campaign_id, attacks_generated, attacks_successful, total_cost):
    conn = _get_conn()
    conn.execute(
        "UPDATE campaigns SET status='finished', attacks_generated=?, attacks_successful=?, total_cost=?, finished_at=? WHERE id=?",
        (attacks_generated, attacks_successful, total_cost, datetime.utcnow().isoformat(), campaign_id)
    )
    conn.commit()
    conn.close()


# ── Reports ──

def save_report(exploit_id, report_text):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO reports (exploit_id, report_text, created_at) VALUES (?, ?, ?)",
        (exploit_id, report_text, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


# ── Summary ──

def get_summary():
    conn = _get_conn()
    total_findings = conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()["c"]
    total_exploits = conn.execute("SELECT COUNT(*) as c FROM exploits").fetchone()["c"]
    open_exploits = conn.execute("SELECT COUNT(*) as c FROM exploits WHERE fixed=0").fetchone()["c"]
    total_cost = conn.execute("SELECT COALESCE(SUM(cost_usd), 0) as c FROM cost_log").fetchone()["c"]
    coverage = get_coverage()
    conn.close()

    return {
        "total_findings": total_findings,
        "total_exploits": total_exploits,
        "open_exploits": open_exploits,
        "total_cost_usd": round(total_cost, 4),
        "coverage": coverage,
    }


# Initialize on import
init_db()
