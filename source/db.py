#!/usr/bin/env python3
"""
Database Security & Parameterized Query Module
File: source/db.py
Primary Responsibility: STUDENT C (Database Security, Testing & Audit Logging)
Enforces:
  - Parameterized queries ONLY (SQL Injection prevention - Section 3.3)
  - Foreign key & CHECK constraint enforcement
  - Environment-based configuration (no hardcoded credentials in repository)
  - Safe error handling (never leaks SQL statements or stack traces)
"""

import os
import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "database" / "university_records.db"
SCHEMA_SQL_PATH = PROJECT_ROOT / "database" / "schema.sql"
SEED_SQL_PATH = PROJECT_ROOT / "database" / "seed-data.sql"


def get_db_connection(db_path=None):
    """
    Create a database connection with foreign keys enabled.
    Reads DB path from environment variable URS_DB_PATH if not explicitly passed.
    """
    target_path = db_path or os.environ.get("URS_DB_PATH", str(DEFAULT_DB_PATH))
    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_database(conn=None, db_path=None):
    """
    Initialize database schema and seed data from database/schema.sql and database/seed-data.sql.
    """
    close_after = False
    if conn is None:
        conn = get_db_connection(db_path)
        close_after = True

    with open(SCHEMA_SQL_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

    with open(SEED_SQL_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

    conn.commit()
    if close_after:
        conn.close()
    return conn


def safe_query_all(conn, sql, params=()):
    """
    Execute a read-only SELECT query using strict parameterized binding (?).
    """
    if not isinstance(params, (tuple, list)):
        raise ValueError("Query parameters must be passed as a tuple or list.")
    cursor = conn.execute(sql, tuple(params))
    return [dict(row) for row in cursor.fetchall()]


def safe_query_one(conn, sql, params=()):
    """
    Execute a read-only SELECT query returning a single record using parameterized binding (?).
    """
    if not isinstance(params, (tuple, list)):
        raise ValueError("Query parameters must be passed as a tuple or list.")
    cursor = conn.execute(sql, tuple(params))
    row = cursor.fetchone()
    return dict(row) if row else None


def safe_execute(conn, sql, params=()):
    """
    Execute an INSERT/UPDATE/DELETE statement using parameterized binding (?).
    Masks internal SQLite errors to prevent leaking SQL statements or schema details.
    """
    if not isinstance(params, (tuple, list)):
        raise ValueError("Query parameters must be passed as a tuple or list.")
    try:
        cursor = conn.execute(sql, tuple(params))
        conn.commit()
        return {"ok": True, "lastrowid": cursor.lastrowid, "rowcount": cursor.rowcount}
    except sqlite3.Error as exc:
        conn.rollback()
        raw_msg = str(exc)
        if "SECURITY VIOLATION" in raw_msg:
            return {
                "ok": False,
                "error": "SECURITY VIOLATION: audit_logs is append-only. Modification or deletion is prohibited.",
            }
        return {
            "ok": False,
            "error": "Operation could not be completed: duplicate or invalid record.",
        }