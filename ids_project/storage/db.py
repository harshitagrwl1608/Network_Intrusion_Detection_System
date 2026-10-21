"""
storage/db.py
-------------
Database abstraction layer.
Supports SQLite (default) and PostgreSQL.
Switch backends by setting DB_BACKEND="postgres" and POSTGRES_URL in config/env.

Thread safety:
  - SQLite: uses a threading.Lock around all writes.
  - PostgreSQL: psycopg2 connections are not thread-safe; a new connection is
    created per write call (connection pooling is the right next step).
"""

import sqlite3
import threading
import time
import sys
import os

# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------
_sqlite_lock = threading.Lock()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   REAL    NOT NULL,
    rule_name   TEXT    NOT NULL,
    rule_version TEXT,
    src_ip      TEXT,
    dst_ip      TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    protocol    TEXT,
    detail      TEXT,
    severity    TEXT    DEFAULT 'medium',
    confidence  TEXT    DEFAULT 'heuristic',
    evidence_json TEXT,
    window_start  REAL,
    window_end    REAL,
    country     TEXT,
    country_code TEXT,
    city        TEXT,
    idempotency_key TEXT
);

CREATE TABLE IF NOT EXISTS observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   REAL    NOT NULL,
    message     TEXT    NOT NULL,
    rule_name   TEXT
);

CREATE TABLE IF NOT EXISTS seen_devices (
    mac         TEXT PRIMARY KEY,
    ip          TEXT,
    first_seen  REAL,
    last_seen   REAL,
    vendor      TEXT
);

CREATE TABLE IF NOT EXISTS feedback (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id      INTEGER NOT NULL,
    timestamp     REAL    NOT NULL,
    classification TEXT   NOT NULL,  -- 'true_positive' | 'false_positive'
    analyst_note  TEXT,
    rule_name     TEXT,
    src_ip        TEXT,
    dst_ip        TEXT
);
"""

# PostgreSQL-compatible schema (no AUTOINCREMENT → SERIAL)
SCHEMA_PG = """
CREATE TABLE IF NOT EXISTS alerts (
    id          SERIAL  PRIMARY KEY,
    timestamp   DOUBLE PRECISION NOT NULL,
    rule_name   TEXT    NOT NULL,
    rule_version TEXT,
    src_ip      TEXT,
    dst_ip      TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    protocol    TEXT,
    detail      TEXT,
    severity    TEXT    DEFAULT 'medium',
    confidence  TEXT    DEFAULT 'heuristic',
    evidence_json TEXT,
    window_start  DOUBLE PRECISION,
    window_end    DOUBLE PRECISION,
    country     TEXT,
    country_code TEXT,
    city        TEXT,
    idempotency_key TEXT
);

CREATE TABLE IF NOT EXISTS observations (
    id          SERIAL  PRIMARY KEY,
    timestamp   DOUBLE PRECISION NOT NULL,
    message     TEXT    NOT NULL,
    rule_name   TEXT
);

CREATE TABLE IF NOT EXISTS seen_devices (
    mac         TEXT PRIMARY KEY,
    ip          TEXT,
    first_seen  DOUBLE PRECISION,
    last_seen   DOUBLE PRECISION,
    vendor      TEXT
);

CREATE TABLE IF NOT EXISTS feedback (
    id            SERIAL  PRIMARY KEY,
    alert_id      INTEGER NOT NULL,
    timestamp     DOUBLE PRECISION NOT NULL,
    classification TEXT   NOT NULL,
    analyst_note  TEXT,
    rule_name     TEXT,
    src_ip        TEXT,
    dst_ip        TEXT
);
"""


# ---------------------------------------------------------------------------
# Connection factory
# ---------------------------------------------------------------------------

def get_connection():
    """Return a DB connection based on configured backend."""
    if config.DB_BACKEND == "postgres":
        try:
            import psycopg2
            return psycopg2.connect(config.POSTGRES_URL)
        except ImportError:
            raise RuntimeError("psycopg2 not installed. Run: pip install psycopg2-binary")
    else:
        d = os.path.dirname(config.SQLITE_PATH) or "."
        os.makedirs(d, exist_ok=True)
        conn = sqlite3.connect(config.SQLITE_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn


def init_db(conn):
    """Create tables if they don't exist. Also applies column migrations for upgrades."""
    schema = SCHEMA_PG if config.DB_BACKEND == "postgres" else SCHEMA_SQL
    with _sqlite_lock:
        cur = conn.cursor()
        # Split on semicolons for multi-statement execution
        for stmt in [s.strip() for s in schema.split(";") if s.strip()]:
            cur.execute(stmt)
        conn.commit()
        # ── Column migration: add GeoIP + vendor columns to existing DBs ──
        _migrate_columns(conn, cur)
        conn.commit()
        cur.close()


def _migrate_columns(conn, cur):
    """Add new columns to existing databases without dropping data."""
    migrations = [
        # GeoIP
        ("alerts",       "country",       "TEXT"),
        ("alerts",       "country_code",  "TEXT"),
        ("alerts",       "city",          "TEXT"),
        ("seen_devices", "vendor",        "TEXT"),
        # §3.7 — structured evidence and extended alert schema
        ("alerts",       "rule_version",  "TEXT"),
        ("alerts",       "src_port",      "INTEGER"),
        ("alerts",       "protocol",      "TEXT"),
        ("alerts",       "confidence",    "TEXT"),
        ("alerts",       "evidence_json", "TEXT"),
        ("alerts",       "window_start",  "REAL"),
        ("alerts",       "window_end",    "REAL"),
        ("alerts",       "idempotency_key", "TEXT"),
    ]
    for table, col, col_type in migrations:
        try:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
        except Exception as exc:
            err_msg = str(exc).lower()
            if "duplicate column" not in err_msg and "already exists" not in err_msg:
                import logging as _log
                _log.getLogger(__name__).warning(
                    f"Unexpected migration error ({table}.{col}): {exc}"
                )
    # Create the idempotency index only AFTER the column migration has run.
    # Existing databases may not have idempotency_key yet, so putting the
    # index in the initial schema would fail before _migrate_columns() adds it.
    try:
        if config.DB_BACKEND == "postgres":
            cur.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_idempotency_pg "
                "ON alerts(idempotency_key)"
            )
        else:
            cur.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_idempotency "
                "ON alerts(idempotency_key)"
            )
    except Exception as exc:
        import logging as _log
        _log.getLogger(__name__).warning(
            f"Could not create alerts idempotency index: {exc}"
        )


# ---------------------------------------------------------------------------
# Alert operations
# ---------------------------------------------------------------------------

def write_alert(conn, alert: dict):
    """Insert one alert into the alerts table. Thread-safe and idempotent."""
    sql = """
        INSERT OR IGNORE INTO alerts (
            timestamp, rule_name, rule_version,
            src_ip, dst_ip, src_port, dst_port, protocol,
            detail, severity, confidence,
            evidence_json, window_start, window_end,
            country, country_code, city, idempotency_key
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """ if config.DB_BACKEND == "sqlite" else """
        INSERT INTO alerts (
            timestamp, rule_name, rule_version,
            src_ip, dst_ip, src_port, dst_port, protocol,
            detail, severity, confidence,
            evidence_json, window_start, window_end,
            country, country_code, city, idempotency_key
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (idempotency_key) DO NOTHING
    """
    values = (
        alert.get("timestamp", time.time()),
        alert["rule_name"],
        alert.get("rule_version"),
        alert.get("src_ip"),
        alert.get("dst_ip"),
        alert.get("src_port"),
        alert.get("dst_port"),
        alert.get("protocol"),
        alert.get("detail"),
        alert.get("severity", "medium"),
        alert.get("confidence", "heuristic"),
        alert.get("evidence_json"),
        alert.get("window_start"),
        alert.get("window_end"),
        alert.get("country"),
        alert.get("country_code"),
        alert.get("city"),
        alert.get("idempotency_key") or alert.get("uuid"),
    )
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, values)
        conn.commit()
        cur.close()


def read_recent_alerts(conn, minutes: int = 60) -> list[dict]:
    """Return alerts from the last `minutes` minutes as list of dicts."""
    since = time.time() - (minutes * 60)
    sql = "SELECT * FROM alerts WHERE timestamp >= ? ORDER BY timestamp DESC" \
        if config.DB_BACKEND == "sqlite" \
        else "SELECT * FROM alerts WHERE timestamp >= %s ORDER BY timestamp DESC"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (since,))
        rows = cur.fetchall()
        cur.close()
    return [dict(r) for r in rows]


def read_alerts_range(conn, days: int = 7, limit: int = 5000) -> list[dict]:
    """
    Return alerts from the last `days` days, newest first.
    `limit` caps the result set to avoid huge responses (default 5000 rows).
    """
    since = time.time() - (days * 86400)
    if config.DB_BACKEND == "sqlite":
        sql = "SELECT * FROM alerts WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?"
        params = (since, limit)
    else:
        sql = "SELECT * FROM alerts WHERE timestamp >= %s ORDER BY timestamp DESC LIMIT %s"
        params = (since, limit)
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()
        cur.close()
    return [dict(r) for r in rows]


def read_all_alerts(conn) -> list[dict]:
    sql = "SELECT * FROM alerts ORDER BY timestamp DESC"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()
        cur.close()
    return [dict(r) for r in rows]


def prune_old_alerts(conn, retention_days: int = 7) -> int:
    """
    Delete alerts AND observations older than `retention_days` days.
    Returns total number of rows deleted.
    Set retention_days=0 to skip pruning entirely.
    """
    if retention_days <= 0:
        return 0

    cutoff = time.time() - (retention_days * 86400)
    p = "?" if config.DB_BACKEND == "sqlite" else "%s"

    deleted = 0
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(f"DELETE FROM alerts WHERE timestamp < {p}", (cutoff,))
        deleted += cur.rowcount
        cur.execute(f"DELETE FROM observations WHERE timestamp < {p}", (cutoff,))
        deleted += cur.rowcount
        conn.commit()
        cur.close()
    return deleted



def count_alerts_by_hour(conn, hours: int = 24) -> list[dict]:
    """Return alert counts bucketed by hour for the last N hours. Used by Chart.js."""
    since = time.time() - (hours * 3600)
    if config.DB_BACKEND == "sqlite":
        sql = """
            SELECT CAST((timestamp - ?) / 3600 AS INTEGER) as hour_offset,
                   rule_name, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= ?
            GROUP BY hour_offset, rule_name
            ORDER BY hour_offset
        """
        params = (since, since)
    else:
        sql = """
            SELECT EXTRACT(EPOCH FROM (to_timestamp(timestamp) - to_timestamp(%s))) / 3600 AS hour_offset,
                   rule_name, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= %s
            GROUP BY hour_offset, rule_name
            ORDER BY hour_offset
        """
        params = (since, since)
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()
        cur.close()
    return [dict(r) for r in rows]


def count_alerts_by_day(conn, year: int, month: int) -> list[dict]:
    """
    Return per-day alert counts + max severity for a given year/month.
    Used by the calendar heatmap.
    Returns list of {date_str, count, has_high}.
    """
    import calendar as _cal
    first_day = time.mktime(time.strptime(f"{year}-{month:02d}-01", "%Y-%m-%d"))
    last_day_num = _cal.monthrange(year, month)[1]
    last_day = time.mktime(time.strptime(
        f"{year}-{month:02d}-{last_day_num:02d} 23:59:59", "%Y-%m-%d %H:%M:%S"))

    if config.DB_BACKEND == "sqlite":
        sql = """
            SELECT
                date(timestamp, 'unixepoch', 'localtime') as date_str,
                COUNT(*) as count,
                MAX(CASE WHEN severity='high' THEN 1 ELSE 0 END) as has_high
            FROM alerts
            WHERE timestamp >= ? AND timestamp <= ?
            GROUP BY date_str
            ORDER BY date_str
        """
        params = (first_day, last_day)
    else:
        sql = """
            SELECT
                TO_CHAR(TO_TIMESTAMP(timestamp) AT TIME ZONE 'localtime', 'YYYY-MM-DD') as date_str,
                COUNT(*) as count,
                MAX(CASE WHEN severity='high' THEN 1 ELSE 0 END) as has_high
            FROM alerts
            WHERE timestamp >= %s AND timestamp <= %s
            GROUP BY date_str
            ORDER BY date_str
        """
        params = (first_day, last_day)

    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()
        cur.close()
    return [dict(r) for r in rows]


def read_alerts_for_date(conn, date_str: str) -> list[dict]:
    """
    Return all alerts for a specific date (YYYY-MM-DD), newest first.
    """
    try:
        day_start = time.mktime(time.strptime(f"{date_str} 00:00:00", "%Y-%m-%d %H:%M:%S"))
        day_end   = time.mktime(time.strptime(f"{date_str} 23:59:59", "%Y-%m-%d %H:%M:%S"))
    except ValueError:
        return []
    p = "?" if config.DB_BACKEND == "sqlite" else "%s"
    sql = (f"SELECT * FROM alerts WHERE timestamp >= {p} AND timestamp <= {p} "
           f"ORDER BY timestamp DESC")
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (day_start, day_end))
        rows = cur.fetchall()
        cur.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Observation operations
# ---------------------------------------------------------------------------

def write_observation(conn, message: str, rule_name: str = None):
    sql = "INSERT INTO observations (timestamp, message, rule_name) VALUES (?, ?, ?)" \
        if config.DB_BACKEND == "sqlite" \
        else "INSERT INTO observations (timestamp, message, rule_name) VALUES (%s, %s, %s)"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (time.time(), message, rule_name))
        conn.commit()
        cur.close()


def read_recent_observations(conn, limit: int = 20) -> list[dict]:
    sql = "SELECT * FROM observations ORDER BY timestamp DESC LIMIT ?" \
        if config.DB_BACKEND == "sqlite" \
        else "SELECT * FROM observations ORDER BY timestamp DESC LIMIT %s"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (limit,))
        rows = cur.fetchall()
        cur.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Device tracking
# ---------------------------------------------------------------------------

def upsert_device(conn, mac: str, ip: str, vendor: str = None):
    now = time.time()
    if config.DB_BACKEND == "sqlite":
        sql = """
            INSERT INTO seen_devices (mac, ip, first_seen, last_seen, vendor)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ip=excluded.ip,
                last_seen=excluded.last_seen,
                vendor=COALESCE(excluded.vendor, seen_devices.vendor)
        """
    else:
        sql = """
            INSERT INTO seen_devices (mac, ip, first_seen, last_seen, vendor)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT(mac) DO UPDATE SET
                ip=EXCLUDED.ip,
                last_seen=EXCLUDED.last_seen,
                vendor=COALESCE(EXCLUDED.vendor, seen_devices.vendor)
        """
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (mac, ip, now, now, vendor))
        conn.commit()
        cur.close()


def read_all_devices(conn) -> list[dict]:
    sql = "SELECT * FROM seen_devices ORDER BY last_seen DESC"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()
        cur.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Feedback (analyst TP / FP classification)
# ---------------------------------------------------------------------------

def write_feedback(conn, alert_id: int, classification: str,
                   analyst_note: str = "", rule_name: str = "",
                   src_ip: str = "", dst_ip: str = ""):
    """
    Store analyst feedback on an alert.
    classification: 'true_positive' | 'false_positive'
    Also appends to the flat JSONL feedback file for offline tuning.
    """
    import json as _json
    sql = (
        "INSERT INTO feedback (alert_id, timestamp, classification, analyst_note, rule_name, src_ip, dst_ip) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)"
        if config.DB_BACKEND == "sqlite" else
        "INSERT INTO feedback (alert_id, timestamp, classification, analyst_note, rule_name, src_ip, dst_ip) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)"
    )
    now = time.time()
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (alert_id, now, classification, analyst_note, rule_name, src_ip, dst_ip))
        conn.commit()
        cur.close()

    # Also write to JSONL file for offline rule tuning
    try:
        fb_path = config.FEEDBACK_PATH
        os.makedirs(os.path.dirname(fb_path) if os.path.dirname(fb_path) else ".", exist_ok=True)
        entry = {
            "alert_id": alert_id, "timestamp": now,
            "classification": classification, "analyst_note": analyst_note,
            "rule_name": rule_name, "src_ip": src_ip, "dst_ip": dst_ip,
        }
        with open(fb_path, "a") as f:
            f.write(_json.dumps(entry) + "\n")
    except Exception as e:
        pass  # DB write already succeeded; JSONL is a bonus


def read_feedback(conn, limit: int = 100) -> list[dict]:
    sql = ("SELECT * FROM feedback ORDER BY timestamp DESC LIMIT ?"
           if config.DB_BACKEND == "sqlite"
           else "SELECT * FROM feedback ORDER BY timestamp DESC LIMIT %s")
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (limit,))
        rows = cur.fetchall()
        cur.close()
    return [dict(r) for r in rows]


def feedback_stats(conn) -> dict:
    """Return TP/FP counts per rule for the tuning summary."""
    sql = "SELECT rule_name, classification, COUNT(*) as cnt FROM feedback GROUP BY rule_name, classification"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()
        cur.close()
    stats: dict = {}
    for r in rows:
        d = dict(r)
        rule = d["rule_name"] or "UNKNOWN"
        if rule not in stats:
            stats[rule] = {"true_positive": 0, "false_positive": 0}
        stats[rule][d["classification"]] = d["cnt"]
    return stats
