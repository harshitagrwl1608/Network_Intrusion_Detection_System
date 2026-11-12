"""
ids_project/tests/test_migration_and_fresh_install.py
-----------------------------------------------------
Acceptance tests for database lifecycle, fresh installation, and schema migrations:
1. Fresh installation on SQLite (creates all schemas, indexes, and enables all API routes).
2. Upgrade on existing SQLite database containing pre-migration alerts and feedback
   (preserves historical records, adds correlation columns, creates forensics tables).
3. Idempotency test (re-running migrations does not fail or duplicate columns/indexes).
4. Fresh installation and migration idempotency on live PostgreSQL 18.
"""

import os
import sys
import time
import sqlite3
import pytest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from storage.db import get_connection, init_db, write_alert
from storage.forensics_db import init_forensics_db, save_system_setting, get_system_setting
from dashboard.app import app

EXPECTED_TABLES = {
    "alerts", "seen_devices", "feedback", "network_flows", "packet_events",
    "pcap_segments", "pcap_jobs", "cases", "case_alerts", "case_notes",
    "saved_searches", "traffic_baselines", "traffic_anomalies",
    "notification_outbox", "audit_log", "system_settings"
}


def test_fresh_installation_sqlite(tmp_path):
    """Test deploying NetGuard on a completely empty SQLite database."""
    db_file = str(tmp_path / "fresh_install.db")
    orig_sqlite = config.SQLITE_PATH
    orig_backend = config.DB_BACKEND
    config.DB_BACKEND = "sqlite"
    config.SQLITE_PATH = db_file

    import dashboard.app as d_app
    d_app._db_conn = None

    try:
        # Step 1: Initialize all application schemas
        conn = get_connection()
        init_db(conn)
        init_forensics_db(conn)

        # Step 2: Verify all expected tables exist
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cur.fetchall()}
        missing = EXPECTED_TABLES - tables
        assert not missing, f"Missing expected tables in fresh install: {missing}"

        # Step 3: Verify indexes exist
        cur.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {r[0] for r in cur.fetchall()}
        assert "idx_flows_last_seen" in indexes
        assert "idx_cases_status" in indexes
        cur.close()

        # Step 4: Verify system settings and notification configuration can be saved
        save_system_setting(conn, "test_setting", {"status": "initialized", "version": "2.0"})
        val = get_system_setting(conn, "test_setting")
        assert val == {"status": "initialized", "version": "2.0"}
        conn.close()

        # Step 5: Start dashboard test client and verify core routes respond cleanly
        app.config["TESTING"] = True
        with app.test_client() as client:
            # Query APIs on clean database
            assert client.get("/api/alerts").status_code == 200
            assert client.get("/api/traffic").status_code == 200
            assert client.get("/api/cases").status_code == 200
            assert client.get("/api/notifications/providers").status_code == 200
            assert client.get("/api/baselines").status_code == 200
            assert client.get("/api/anomalies").status_code == 200
            assert client.get("/api/audit-log").status_code == 200

    finally:
        if d_app._db_conn is not None:
            try:
                d_app._db_conn.close()
            except Exception:
                pass
            d_app._db_conn = None
        config.SQLITE_PATH = orig_sqlite
        config.DB_BACKEND = orig_backend


def test_upgrade_existing_database_sqlite(tmp_path):
    """Test running migrations against a legacy database containing historical alerts and feedback."""
    db_file = str(tmp_path / "legacy_v1.db")
    orig_sqlite = config.SQLITE_PATH
    orig_backend = config.DB_BACKEND
    config.DB_BACKEND = "sqlite"
    config.SQLITE_PATH = db_file

    import dashboard.app as d_app
    d_app._db_conn = None

    try:
        # Step 1: Create a legacy database without correlation columns or forensics tables
        raw_conn = sqlite3.connect(db_file)
        cur = raw_conn.cursor()
        cur.execute("""
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT NOT NULL,
                detail TEXT NOT NULL,
                evidence TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE seen_devices (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                vendor TEXT,
                first_seen REAL,
                last_seen REAL,
                packet_count INTEGER DEFAULT 1
            )
        """)
        cur.execute("""
            CREATE TABLE feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                classification TEXT NOT NULL,
                analyst_note TEXT,
                timestamp REAL NOT NULL
            )
        """)

        # Step 2: Seed synthetic historical data
        now = time.time()
        for i in range(1, 6):
            cur.execute("""
                INSERT INTO alerts (timestamp, rule_name, severity, src_ip, dst_ip, src_port, dst_port, protocol, detail)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (now - (100 * i), f"HISTORICAL_RULE_{i}", "medium", f"192.168.1.{10 + i}", "10.0.0.1", 1000 + i, 80, "TCP", f"Historical Alert {i}"))

        cur.execute("""
            INSERT INTO feedback (alert_id, classification, analyst_note, timestamp)
            VALUES (1, 'true_positive', 'Historical analyst reviewed', ?)
        """, (now - 50,))
        raw_conn.commit()
        raw_conn.close()

        # Step 3: Run modern NetGuard database migrations on this legacy database
        conn = get_connection()
        init_db(conn)
        init_forensics_db(conn)

        # Step 4: Verify existing historical records are completely preserved
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM alerts")
        assert cur.fetchone()[0] == 5

        cur.execute("SELECT id, rule_name, detail FROM alerts ORDER BY id ASC")
        rows = cur.fetchall()
        assert rows[0][1] == "HISTORICAL_RULE_1"
        assert rows[4][1] == "HISTORICAL_RULE_5"

        cur.execute("SELECT classification, analyst_note FROM feedback WHERE alert_id = 1")
        fb = cur.fetchone()
        assert fb[0] == "true_positive"
        assert fb[1] == "Historical analyst reviewed"

        # Step 5: Verify new correlation columns have been safely added to alerts
        cur.execute("PRAGMA table_info(alerts)")
        col_names = {r[1] for r in cur.fetchall()}
        for expected_col in ("flow_id", "event_id", "pcap_segment_id", "packet_index", "assigned_case_id", "acknowledged", "status"):
            assert expected_col in col_names, f"Expected migrated column '{expected_col}' in alerts"

        # Step 6: Verify all new forensics tables exist
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cur.fetchall()}
        for t in ("network_flows", "cases", "case_alerts", "case_notes", "notification_outbox"):
            assert t in tables, f"Expected new table '{t}' created by migration"

        # Step 7: Verify migration idempotency (running init_forensics_db a second time must succeed)
        init_forensics_db(conn)
        cur.execute("SELECT COUNT(*) FROM alerts")
        assert cur.fetchone()[0] == 5
        cur.close()
        conn.close()

    finally:
        if d_app._db_conn is not None:
            try:
                d_app._db_conn.close()
            except Exception:
                pass
            d_app._db_conn = None
        config.SQLITE_PATH = orig_sqlite
        config.DB_BACKEND = orig_backend


def test_fresh_installation_and_migration_postgres():
    """Verify fresh schema initialization and migration idempotency on live PostgreSQL 18."""
    pg_url = "postgresql://harshitgarg@127.0.0.1:54333/postgres"
    try:
        import psycopg2
        test_conn = psycopg2.connect(pg_url, connect_timeout=2)
        test_conn.close()
    except Exception:
        pytest.skip("Live PostgreSQL 18 instance on port 54333 is not running")

    orig_backend = config.DB_BACKEND
    orig_url = getattr(config, "POSTGRES_URL", "")
    config.DB_BACKEND = "postgres"
    config.POSTGRES_URL = pg_url

    import dashboard.app as d_app
    d_app._db_conn = None

    try:
        # Step 1: Initialize DB on PostgreSQL
        conn = get_connection()
        init_db(conn)
        init_forensics_db(conn)

        # Step 2: Verify PostgreSQL tables exist
        cur = conn.cursor()
        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
        tables = {r[0] for r in cur.fetchall()}
        missing = EXPECTED_TABLES - tables
        assert not missing, f"Missing tables in PostgreSQL schema: {missing}"

        # Step 3: Verify correlation columns in alerts table
        cur.execute("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'alerts'
        """)
        cols = {r[0] for r in cur.fetchall()}
        for c in ("flow_id", "event_id", "assigned_case_id", "status"):
            assert c in cols, f"Expected column '{c}' in PostgreSQL alerts table"

        # Step 4: Verify idempotency on PostgreSQL
        init_db(conn)
        init_forensics_db(conn)
        cur.close()
        conn.close()

    finally:
        if d_app._db_conn is not None:
            try:
                d_app._db_conn.close()
            except Exception:
                pass
            d_app._db_conn = None
        config.DB_BACKEND = orig_backend
        config.POSTGRES_URL = orig_url

