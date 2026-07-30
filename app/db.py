"""SQLite storage layer + idempotent migration helpers.

Migration philosophy: never DROP, never recreate. Tables are created with
CREATE TABLE IF NOT EXISTS; new columns are added with ALTER TABLE ... ADD COLUMN
only when PRAGMA table_info says they are missing. A schema change therefore
never wipes data, and running an older build against a newer DB is harmless.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterable, Sequence

from . import config

SCHEMA_VERSION = 5

_local = threading.local()

# --------------------------------------------------------------------------
# Base tables (created once, then only ever extended via ensure_column)
# --------------------------------------------------------------------------
TABLES: dict[str, str] = {
    "settings": """
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        )""",
    "assets": """
        CREATE TABLE IF NOT EXISTS assets (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_key     TEXT UNIQUE NOT NULL,
            hostname      TEXT,
            ip_address    TEXT,
            os_name       TEXT,
            os_family     TEXT,
            environment   TEXT,
            department    TEXT,
            application   TEXT,
            system_owner  TEXT,
            owner_email   TEXT,
            business_unit TEXT,
            criticality   TEXT,
            location      TEXT,
            asset_type    TEXT,
            tags          TEXT,
            notes         TEXT,
            first_seen    TEXT,
            last_seen     TEXT,
            created_at    TEXT,
            updated_at    TEXT
        )""",
    "vulns": """
        CREATE TABLE IF NOT EXISTS vulns (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_key       TEXT UNIQUE NOT NULL,
            plugin_id      TEXT,
            title          TEXT,
            severity       TEXT,
            severity_rank  INTEGER,
            cvss_score     REAL,
            cvss_vector    TEXT,
            cve            TEXT,
            category       TEXT,
            subcategory    TEXT,
            product        TEXT,
            vendor         TEXT,
            family         TEXT,
            description    TEXT,
            solution       TEXT,
            exploit_available INTEGER DEFAULT 0,
            exploit_maturity  TEXT,
            patch_available   INTEGER DEFAULT 0,
            classified_by  TEXT,
            classify_rule  TEXT,
            classify_confidence REAL,
            first_seen     TEXT,
            last_seen      TEXT,
            created_at     TEXT,
            updated_at     TEXT
        )""",
    "findings": """
        CREATE TABLE IF NOT EXISTS findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_key     TEXT UNIQUE NOT NULL,
            asset_id        INTEGER NOT NULL REFERENCES assets(id),
            vuln_id         INTEGER NOT NULL REFERENCES vulns(id),
            port            TEXT,
            protocol        TEXT,
            service         TEXT,
            status          TEXT DEFAULT 'open',
            severity        TEXT,
            severity_rank   INTEGER,
            cvss_score      REAL,
            first_detected  TEXT,
            last_detected   TEXT,
            mitigated_date  TEXT,
            closed_date     TEXT,
            reopened_count  INTEGER DEFAULT 0,
            age_days        INTEGER DEFAULT 0,
            days_to_close   INTEGER,
            due_date        TEXT,
            sla_days        INTEGER,
            sla_breached    INTEGER DEFAULT 0,
            first_scan_id   INTEGER,
            last_scan_id    INTEGER,
            mitigation_scan_id INTEGER,
            evidence        TEXT,
            remediation_owner TEXT,
            ticket_ref      TEXT,
            notes           TEXT,
            created_at      TEXT,
            updated_at      TEXT
        )""",
    "scans": """
        CREATE TABLE IF NOT EXISTS scans (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT,
            filename      TEXT,
            kind          TEXT DEFAULT 'scan',
            scanner       TEXT,
            scan_date     TEXT,
            imported_at   TEXT,
            imported_by   TEXT,
            rows_total    INTEGER DEFAULT 0,
            rows_imported INTEGER DEFAULT 0,
            rows_skipped  INTEGER DEFAULT 0,
            assets_touched   INTEGER DEFAULT 0,
            findings_new     INTEGER DEFAULT 0,
            findings_updated INTEGER DEFAULT 0,
            findings_reopened INTEGER DEFAULT 0,
            findings_closed   INTEGER DEFAULT 0,
            status        TEXT DEFAULT 'complete',
            message       TEXT,
            mapping_json  TEXT
        )""",
    "finding_events": """
        CREATE TABLE IF NOT EXISTS finding_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id  INTEGER NOT NULL REFERENCES findings(id),
            event_type  TEXT,
            from_status TEXT,
            to_status   TEXT,
            scan_id     INTEGER,
            actor       TEXT,
            note        TEXT,
            created_at  TEXT
        )""",
    "audit_log": """
        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            entity     TEXT,
            entity_id  INTEGER,
            field      TEXT,
            old_value  TEXT,
            new_value  TEXT,
            actor      TEXT,
            source     TEXT,
            created_at TEXT
        )""",
    "class_rules": """
        CREATE TABLE IF NOT EXISTS class_rules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT,
            priority    INTEGER DEFAULT 100,
            field       TEXT DEFAULT 'haystack',
            pattern     TEXT,
            category    TEXT,
            subcategory TEXT,
            product     TEXT,
            confidence  REAL DEFAULT 0.9,
            enabled     INTEGER DEFAULT 1,
            builtin     INTEGER DEFAULT 0,
            hits        INTEGER DEFAULT 0,
            created_at  TEXT,
            updated_at  TEXT
        )""",
    "sla_policy": """
        CREATE TABLE IF NOT EXISTS sla_policy (
            severity TEXT PRIMARY KEY,
            days     INTEGER
        )""",
    "job_runs": """
        CREATE TABLE IF NOT EXISTS job_runs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            job        TEXT,
            started_at TEXT,
            ended_at   TEXT,
            status     TEXT,
            detail     TEXT
        )""",
    "users": """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            full_name     TEXT,
            email         TEXT,
            role          TEXT DEFAULT 'viewer',
            password_hash TEXT,
            salt          TEXT,
            is_active     INTEGER DEFAULT 1,
            must_change    INTEGER DEFAULT 0,
            created_at    TEXT,
            last_login    TEXT
        )""",
    "sessions": """
        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL REFERENCES users(id),
            created_at TEXT,
            expires_at TEXT,
            client     TEXT
        )""",
    "saved_views": """
        CREATE TABLE IF NOT EXISTS saved_views (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT UNIQUE,
            scope      TEXT,
            filters    TEXT,
            created_at TEXT
        )""",
}

# Columns added after a table first shipped. ensure_column() adds them only if
# absent, so upgrading in place never touches existing rows.
ADDED_COLUMNS: list[tuple[str, str, str]] = [
    ("assets", "manual_fields", "TEXT"),
    ("assets", "risk_score", "REAL DEFAULT 0"),
    ("assets", "open_count", "INTEGER DEFAULT 0"),
    ("findings", "risk_score", "REAL DEFAULT 0"),
    ("findings", "exception_until", "TEXT"),
    ("vulns", "epss_score", "REAL"),
]

INDEXES: list[str] = [
    "CREATE INDEX IF NOT EXISTS ix_findings_status ON findings(status)",
    "CREATE INDEX IF NOT EXISTS ix_findings_asset ON findings(asset_id)",
    "CREATE INDEX IF NOT EXISTS ix_findings_vuln ON findings(vuln_id)",
    "CREATE INDEX IF NOT EXISTS ix_findings_sev ON findings(severity_rank)",
    "CREATE INDEX IF NOT EXISTS ix_findings_first ON findings(first_detected)",
    "CREATE INDEX IF NOT EXISTS ix_findings_last ON findings(last_detected)",
    "CREATE INDEX IF NOT EXISTS ix_assets_dept ON assets(department)",
    "CREATE INDEX IF NOT EXISTS ix_assets_app ON assets(application)",
    "CREATE INDEX IF NOT EXISTS ix_assets_owner ON assets(system_owner)",
    "CREATE INDEX IF NOT EXISTS ix_vulns_cat ON vulns(category)",
    "CREATE INDEX IF NOT EXISTS ix_events_finding ON finding_events(finding_id)",
    "CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions(user_id)",
]

DEFAULT_SLA = {"Critical": 15, "High": 30, "Medium": 60, "Low": 90, "Info": 180}


# --------------------------------------------------------------------------
# Connection handling
# --------------------------------------------------------------------------
def connect(path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or str(config.db_path()), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def get_conn() -> sqlite3.Connection:
    """One connection per thread (FastAPI + APScheduler are multi-threaded)."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = connect()
        _local.conn = conn
    return conn


def reset_thread_conn() -> None:
    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
    _local.conn = None


@contextmanager
def tx(conn: sqlite3.Connection | None = None):
    c = conn or get_conn()
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise


# --------------------------------------------------------------------------
# Idempotent migration helpers
# --------------------------------------------------------------------------
def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def columns_of(conn: sqlite3.Connection, table: str) -> list[str]:
    if not table_exists(conn, table):
        return []
    return [r["name"] for r in conn.execute(f"PRAGMA table_info({table})")]


def ensure_table(conn: sqlite3.Connection, name: str, ddl: str) -> bool:
    """CREATE TABLE IF NOT EXISTS. Returns True if it created the table."""
    existed = table_exists(conn, name)
    conn.execute(ddl)
    return not existed


def ensure_column(conn: sqlite3.Connection, table: str, column: str, decl: str) -> bool:
    """ALTER TABLE ADD COLUMN only when the column is missing. Data-preserving."""
    if not table_exists(conn, table):
        return False
    if column in columns_of(conn, table):
        return False
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
    return True


def ensure_index(conn: sqlite3.Connection, ddl: str) -> None:
    conn.execute(ddl)


def get_setting(key: str, default: str | None = None, conn: sqlite3.Connection | None = None):
    c = conn or get_conn()
    row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str, conn: sqlite3.Connection | None = None) -> None:
    c = conn or get_conn()
    c.execute(
        "INSERT INTO settings(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )
    c.commit()


def init_db(conn: sqlite3.Connection | None = None) -> dict:
    """Create/extend the schema in place. Safe to call on every start."""
    c = conn or get_conn()
    report = {"created": [], "columns_added": [], "schema_version": SCHEMA_VERSION}
    for name, ddl in TABLES.items():
        if ensure_table(c, name, ddl):
            report["created"].append(name)
    for table, col, decl in ADDED_COLUMNS:
        if ensure_column(c, table, col, decl):
            report["columns_added"].append(f"{table}.{col}")
    for ddl in INDEXES:
        ensure_index(c, ddl)
    for sev, days in DEFAULT_SLA.items():
        c.execute("INSERT OR IGNORE INTO sla_policy(severity,days) VALUES(?,?)", (sev, days))
    c.commit()
    set_setting("schema_version", str(SCHEMA_VERSION), c)
    return report


# --------------------------------------------------------------------------
# Small query helpers
# --------------------------------------------------------------------------
def q(sql: str, params: Sequence[Any] = (), conn: sqlite3.Connection | None = None) -> list[dict]:
    c = conn or get_conn()
    return [dict(r) for r in c.execute(sql, params).fetchall()]


def q1(sql: str, params: Sequence[Any] = (), conn: sqlite3.Connection | None = None) -> dict | None:
    rows = q(sql, params, conn)
    return rows[0] if rows else None


def execute(sql: str, params: Sequence[Any] = (), conn: sqlite3.Connection | None = None):
    c = conn or get_conn()
    cur = c.execute(sql, params)
    c.commit()
    return cur


def executemany(sql: str, rows: Iterable[Sequence[Any]], conn: sqlite3.Connection | None = None):
    c = conn or get_conn()
    cur = c.executemany(sql, rows)
    c.commit()
    return cur
