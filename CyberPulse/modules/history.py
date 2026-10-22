"""
Investigation History and Audit Log Engine.
Backed by SQLite for persistent SOC lookup records and timeline review.
"""
import sqlite3
import os
import contextlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "investigations.db")


@contextlib.contextmanager
def get_db_connection():
    """Context manager for SQLite connections that guarantees clean closure."""
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    """Initializes the database schema if it doesn't already exist."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ioc TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                vt_malicious INTEGER DEFAULT 0,
                abuse_score INTEGER DEFAULT 0,
                country TEXT DEFAULT 'N/A',
                analyst_notes TEXT DEFAULT ''
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ioc ON investigations(ioc)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON investigations(timestamp)")
        conn.commit()


def save_investigation(
    ioc: str,
    ioc_type: str,
    risk_score: int,
    risk_level: str,
    vt_malicious: int = 0,
    abuse_score: int = 0,
    country: str = "N/A",
    analyst_notes: str = ""
) -> int:
    """Saves a completed IOC investigation into the audit database."""
    init_db()
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO investigations (
                timestamp, ioc, ioc_type, risk_score, risk_level,
                vt_malicious, abuse_score, country, analyst_notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (now_iso, ioc, ioc_type, risk_score, risk_level, vt_malicious, abuse_score, country, analyst_notes))
        conn.commit()
        return cursor.lastrowid


def get_history(limit: int = 100, search_query: str = "") -> List[Dict[str, Any]]:
    """Retrieves recent investigation logs with optional keyword search."""
    try:
        safe_limit = max(1, min(1000, int(limit)))
    except (ValueError, TypeError):
        safe_limit = 100
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if search_query:
            query = f"%{search_query.strip()}%"
            cursor.execute("""
                SELECT * FROM investigations 
                WHERE ioc LIKE ? OR ioc_type LIKE ? OR risk_level LIKE ? OR analyst_notes LIKE ?
                ORDER BY id DESC LIMIT ?
            """, (query, query, query, query, safe_limit))
        else:
            cursor.execute("""
                SELECT * FROM investigations 
                ORDER BY id DESC LIMIT ?
            """, (safe_limit,))
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_history_stats() -> Dict[str, int]:
    """Computes summary statistics across all past investigations."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM investigations")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM investigations WHERE risk_score >= 61")
        high = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM investigations WHERE risk_score BETWEEN 21 AND 60")
        medium = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM investigations WHERE risk_score <= 20")
        low = cursor.fetchone()[0]

        return {
            "total_scans": total,
            "critical_threats": high,
            "suspicious_indicators": medium,
            "benign_assets": low
        }


def clear_history() -> None:
    """Clears all records in the investigation history."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM investigations")
        conn.commit()


def get_investigation_by_id(inv_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single investigation record by ID."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def delete_investigation(inv_id: int) -> bool:
    """Deletes a single investigation record by ID."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM investigations WHERE id = ?", (inv_id,))
        conn.commit()
        return cursor.rowcount > 0

