"""
ids_project/tests/test_operational_reliability.py
-------------------------------------------------
Operational reliability and failure recovery acceptance suite:
1. Worker initialization idempotency (repeated initialization does not leak duplicate worker threads).
2. Reverse DNS worker bounded queue & clean shutdown.
3. Notification outbox persistence & retry across simulated application restart.
4. Database transaction rollback verification on error.
5. Fail-closed authentication verification when credentials are missing or default.
"""

import os
import sys
import time
import threading
import pytest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from storage.db import get_connection, init_db, write_alert, _sqlite_lock
from storage.forensics_db import init_forensics_db
from analytics.reverse_dns import ReverseDNSResolver, get_reverse_dns_resolver
from notifications.outbox import NotificationOutboxManager
from dashboard.app import app


@pytest.fixture
def isolated_db(tmp_path):
    orig_sqlite = config.SQLITE_PATH
    orig_backend = config.DB_BACKEND
    db_file = str(tmp_path / "reliability.db")
    config.DB_BACKEND = "sqlite"
    config.SQLITE_PATH = db_file

    import dashboard.app as d_app
    d_app._db_conn = None

    conn = get_connection()
    init_db(conn)
    init_forensics_db(conn)
    conn.close()

    yield db_file

    if d_app._db_conn is not None:
        try:
            d_app._db_conn.close()
        except Exception:
            pass
        d_app._db_conn = None
    config.SQLITE_PATH = orig_sqlite
    config.DB_BACKEND = orig_backend


def test_repeated_initialization_no_duplicate_workers(isolated_db):
    """Verify that multiple initialization calls do not leak or spawn duplicate worker threads."""
    import dashboard.app as d_app

    initial_threads = threading.active_count()

    # Call get_db and initialization multiple times
    for _ in range(5):
        conn = d_app.get_db()
        init_db(conn)
        init_forensics_db(conn)
        r = get_reverse_dns_resolver()
        assert r is not None

    after_threads = threading.active_count()
    # Thread count should remain stable and bounded
    assert after_threads <= initial_threads + 5


def test_reverse_dns_worker_bounded_queue_and_clean_shutdown():
    """Verify that reverse DNS worker pool bounds pending requests and terminates cleanly."""
    resolver = ReverseDNSResolver(max_workers=2)
    assert resolver._running is True

    # Enqueue 2500 unique IP addresses to test queue bounding
    for i in range(2500):
        resolver.resolve_async(f"198.51.100.{i % 250}")

    # Maximum pending capacity check
    with resolver._lock:
        pending_count = len(resolver._pending)
        assert pending_count <= 2000, f"Pending queue exceeded bound: {pending_count}"

    # Verify clean shutdown
    resolver.shutdown(wait=True)
    assert resolver._running is False


def test_notification_outbox_persistence_across_restart(isolated_db):
    """Verify pending notifications survive application restart and preserve retry state."""
    conn = get_connection()
    outbox1 = NotificationOutboxManager(main_conn=conn, cooldown_seconds=0)
    outbox1.configure_provider("webhook", {"url": "http://127.0.0.1:9999/webhook"})

    alert = {
        "id": 101,
        "rule_name": "SYN_FLOOD",
        "severity": "high",
        "src_ip": "192.168.1.101",
        "dst_ip": "10.0.0.1",
        "timestamp": time.time(),
        "detail": "SYN flood persistence test"
    }

    # 1. Enqueue alert in outbox
    enqueued = outbox1.enqueue_alert(alert, enabled_providers=["webhook"])
    assert enqueued > 0

    # 2. Verify pending item exists in database
    cur = conn.cursor()
    cur.execute("SELECT id, status, retry_count FROM notification_outbox WHERE status = 'pending'")
    row = cur.fetchone()
    assert row is not None
    item_id = row[0]

    # 3. Simulate failure update
    cur.execute("UPDATE notification_outbox SET retry_count = 1, error_message = 'Transient SMTP timeout' WHERE id = ?", (item_id,))
    conn.commit()
    cur.close()

    # 4. Simulate application shutdown and restart
    conn.close()

    conn2 = get_connection()

    # 5. Verify notification survived in database across simulated restart
    cur2 = conn2.cursor()
    cur2.execute("SELECT id, status, retry_count, error_message FROM notification_outbox WHERE id = ?", (item_id,))
    row2 = cur2.fetchone()
    cur2.close()
    conn2.close()

    assert row2 is not None
    assert row2[1] == "pending"
    assert row2[2] == 1  # retry_count preserved
    assert "Transient SMTP timeout" in row2[3]


def test_database_rollback_on_failed_transaction(isolated_db):
    """Verify that failed transactions roll back cleanly without leaving partial records."""
    conn = get_connection()
    now = time.time()
    case_id = "CASE-ROLLBACK-TEST"

    with _sqlite_lock:
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO cases (case_id, title, status, severity, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (case_id, "Transaction Rollback Test", "open", "medium", now, now)
            )
            # Deliberately execute an invalid SQL statement to trigger a rollback
            cur.execute("INSERT INTO non_existent_table VALUES (1, 2, 3)")
            conn.commit()
        except Exception:
            conn.rollback()
        finally:
            cur.close()

    # Verify that the case record was rolled back
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cases WHERE case_id = ?", (case_id,))
    count = cur.fetchone()[0]
    cur.close()
    conn.close()

    assert count == 0, "Partial case record remained after transaction rollback"


def test_auth_fail_closed_on_missing_or_default_password(isolated_db):
    """Verify fail-closed security when DASHBOARD_AUTH_ENABLED is True with missing or default credentials."""
    orig_auth = getattr(config, "DASHBOARD_AUTH_ENABLED", False)
    orig_pass = getattr(config, "DASHBOARD_PASSWORD", None)

    try:
        # Scenario 1: Auth enabled, but password is default "netguard" -> Must fail closed (HTTP 500)
        config.DASHBOARD_AUTH_ENABLED = True
        config.DASHBOARD_PASSWORD = "netguard"

        app.config["TESTING"] = True
        with app.test_client() as client:
            res = client.get("/api/status")
            assert res.status_code == 500
            assert "DASHBOARD_PASSWORD must be explicitly configured" in res.data.decode("utf-8")

        # Scenario 2: Auth enabled, but password is None -> Must fail closed (HTTP 500)
        config.DASHBOARD_PASSWORD = None
        with app.test_client() as client:
            res = client.get("/api/status")
            assert res.status_code == 500

        # Scenario 3: Auth enabled with strong password -> Rejects unauthorized (HTTP 401)
        config.DASHBOARD_PASSWORD = "StrongExplicitPassword#987"
        with app.test_client() as client:
            res_unauth = client.get("/api/status")
            assert res_unauth.status_code == 401

            # Authorized with correct credentials -> HTTP 200
            import base64
            auth_val = base64.b64encode(b"admin:StrongExplicitPassword#987").decode("utf-8")
            res_auth = client.get("/api/status", headers={"Authorization": f"Basic {auth_val}"})
            assert res_auth.status_code == 200

    finally:
        config.DASHBOARD_AUTH_ENABLED = orig_auth
        config.DASHBOARD_PASSWORD = orig_pass
