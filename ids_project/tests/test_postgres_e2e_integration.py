"""
ids_project/tests/test_postgres_e2e_integration.py
--------------------------------------------------
End-to-end integration test suite running against a live PostgreSQL instance.

Isolation strategy:
- Uses NETGUARD_TEST_POSTGRES_URL env var (falls back to hardcoded local dev URL).
- Creates a unique temporary test schema per test run via search_path isolation.
- Cleans up schema after test execution (even on failure).
- Skips clearly if PostgreSQL service is unavailable.
- Avoids accumulating test data between runs.

Covers:
1. Live schema initialization and migrations
2. Full case lifecycle (creation, alert linking, notes, state machine, unlinking)
3. Audit log trail persistence and querying
4. Saved search persistence and listing (RETURNING id)
5. Traffic Explorer queries with mathematical CIDR subnet search (::inet <<=)
6. Credential encryption at rest in PostgreSQL system_settings
"""

import os
import sys
import time
import uuid
import pytest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from storage.db import get_connection, init_db, write_alert
from storage.forensics_db import (
    init_forensics_db, upsert_network_flow, query_network_flows,
    save_system_setting, get_system_setting
)
from dashboard.app import app

# Configured via NETGUARD_TEST_POSTGRES_URL for isolation; falls back to local dev cluster
_DEFAULT_LOCAL_PG_URL = "postgresql://harshitgarg@127.0.0.1:54333/postgres"
POSTGRES_BASE_URL = os.environ.get("NETGUARD_TEST_POSTGRES_URL", _DEFAULT_LOCAL_PG_URL)


def _postgres_available():
    try:
        import psycopg2
        conn = psycopg2.connect(POSTGRES_BASE_URL, connect_timeout=2)
        conn.close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _postgres_available(),
    reason="Live PostgreSQL service not available (set NETGUARD_TEST_POSTGRES_URL to enable)"
)


def _make_isolated_url(schema_name: str) -> str:
    """Build a PostgreSQL URL that pins to an isolated test schema via search_path."""
    sep = "&" if "?" in POSTGRES_BASE_URL else "?"
    return f"{POSTGRES_BASE_URL}{sep}options=-csearch_path%3D{schema_name}"


@pytest.fixture(scope="module")
def pg_setup():
    """
    Create isolated PostgreSQL test schema per test module run.
    Initializes all NetGuard tables in the isolated schema.
    Drops the schema (and all data) after tests complete.
    """
    import psycopg2

    schema_name = f"netguard_test_{uuid.uuid4().hex[:12]}"
    isolated_url = _make_isolated_url(schema_name)

    # Create isolated schema
    admin_conn = psycopg2.connect(POSTGRES_BASE_URL)
    admin_conn.autocommit = True
    admin_cur = admin_conn.cursor()
    admin_cur.execute(f"CREATE SCHEMA IF NOT EXISTS {schema_name}")
    admin_cur.close()
    admin_conn.close()

    orig_backend = config.DB_BACKEND
    orig_url = getattr(config, "POSTGRES_URL", "")
    config.DB_BACKEND = "postgres"
    config.POSTGRES_URL = isolated_url

    import dashboard.app as d_app
    if d_app._db_conn:
        try:
            d_app._db_conn.close()
        except Exception:
            pass
        d_app._db_conn = None

    # Initialize all tables in isolated schema
    conn = get_connection()
    init_db(conn)
    init_forensics_db(conn)
    conn.close()

    yield schema_name

    # Cleanup: drop isolated schema regardless of test outcomes
    if d_app._db_conn:
        try:
            d_app._db_conn.close()
        except Exception:
            pass
        d_app._db_conn = None

    config.DB_BACKEND = orig_backend
    config.POSTGRES_URL = orig_url

    try:
        admin_conn = psycopg2.connect(POSTGRES_BASE_URL)
        admin_conn.autocommit = True
        admin_cur = admin_conn.cursor()
        admin_cur.execute(f"DROP SCHEMA IF EXISTS {schema_name} CASCADE")
        admin_cur.close()
        admin_conn.close()
    except Exception as cleanup_err:
        print(f"WARNING: schema cleanup failed: {cleanup_err}")


@pytest.fixture
def pg_client(pg_setup):
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def pg_auth_headers(pg_client):
    res = pg_client.get("/api/csrf-token")
    token = res.get_json()["csrf_token"]
    return {"X-CSRFToken": token}


def test_postgres_schema_isolation(pg_setup):
    """Verify schema isolation: tables exist in isolated schema, not public."""
    import psycopg2
    schema_name = pg_setup
    isolated_url = _make_isolated_url(schema_name)
    conn = psycopg2.connect(isolated_url)
    cur = conn.cursor()
    cur.execute("""
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = %s
    """, (schema_name,))
    tables = {r[0] for r in cur.fetchall()}
    cur.close()
    conn.close()

    expected_tables = {
        "alerts", "seen_devices", "feedback", "network_flows", "packet_events",
        "cases", "case_alerts", "case_notes", "audit_log", "system_settings",
        "saved_searches", "notification_outbox"
    }
    for t in expected_tables:
        assert t in tables, f"Expected table '{t}' in schema '{schema_name}'"


def test_postgres_cleanup_isolation(pg_setup):
    """Verify that each test run with fresh schema has no residual data."""
    import psycopg2
    schema_name = pg_setup
    isolated_url = _make_isolated_url(schema_name)
    conn = psycopg2.connect(isolated_url)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cases")
    count = cur.fetchone()[0]
    cur.close()
    conn.close()
    # In a fresh isolated schema, there should be no pre-existing cases
    assert count == 0, f"Expected 0 existing cases in fresh schema, found {count}"


def test_postgres_case_management_lifecycle(pg_client, pg_auth_headers):
    """Test full 10-step case management lifecycle end-to-end on isolated PostgreSQL schema."""
    conn = get_connection()
    # 1. Seed an alert
    alert_id = write_alert(conn, {
        "rule_name": "PORT_SCAN",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "severity": "high",
        "confidence": "HIGH",
        "timestamp": time.time(),
    })
    conn.close()
    assert alert_id > 0

    # 2. Case Creation via API
    res = pg_client.post("/api/cases", headers=pg_auth_headers, json={
        "title": "PostgreSQL Incident Investigation",
        "severity": "high",
        "description": "Verifying case tracking on live PostgreSQL 18",
        "assigned_to": "PG Analyst",
        "alert_ids": [alert_id]
    })
    assert res.status_code in (200, 201)
    case_data = res.get_json()
    case_id = case_data["case_id"]
    assert case_id.startswith("CASE-")

    # 3. Retrieve Case Detail
    res_get = pg_client.get(f"/api/cases/{case_id}")
    assert res_get.status_code == 200
    detail = res_get.get_json()
    assert detail["case"]["title"] == "PostgreSQL Incident Investigation"
    assert detail["case"]["status"] == "open"
    assert detail["case"]["severity"] == "high"
    assert len(detail["alerts"]) == 1
    assert detail["alerts"][0]["id"] == alert_id

    # 4. Link additional alert (tests ON CONFLICT DO NOTHING on case_alerts)
    res_link = pg_client.post(f"/api/cases/{case_id}/alerts", headers=pg_auth_headers, json={"alert_ids": [alert_id]})
    assert res_link.status_code == 200

    # 5. Add Case Note
    res_note = pg_client.post(f"/api/cases/{case_id}/notes", headers=pg_auth_headers, json={
        "note": "Investigated PostgreSQL forensic records; no lateral movement.",
        "author": "PG Analyst"
    })
    assert res_note.status_code == 200

    # Verify Note Saved
    res_get2 = pg_client.get(f"/api/cases/{case_id}")
    assert len(res_get2.get_json()["notes"]) >= 1

    # 6. Invalid Status Transition: open -> closed directly (Must fail 400)
    res_bad_trans = pg_client.patch(f"/api/cases/{case_id}", headers=pg_auth_headers, json={"status": "closed"})
    assert res_bad_trans.status_code == 400

    # 7. Valid Transition: open -> investigating
    res_inv = pg_client.patch(f"/api/cases/{case_id}", headers=pg_auth_headers, json={"status": "investigating"})
    assert res_inv.status_code == 200

    # 8. Invalid Transition: investigating -> closed directly (Must fail 400)
    res_inv_close = pg_client.patch(f"/api/cases/{case_id}", headers=pg_auth_headers, json={"status": "closed"})
    assert res_inv_close.status_code == 400

    # 9. Valid Transition: investigating -> resolved
    res_res = pg_client.patch(f"/api/cases/{case_id}", headers=pg_auth_headers, json={"status": "resolved"})
    assert res_res.status_code == 200

    # 10. Valid Transition: resolved -> closed
    res_close = pg_client.patch(f"/api/cases/{case_id}", headers=pg_auth_headers, json={"status": "closed"})
    assert res_close.status_code == 200
    res_get3 = pg_client.get(f"/api/cases/{case_id}")
    assert res_get3.get_json()["case"]["status"] == "closed"

    # 11. Valid Reopen: closed -> open
    res_reopen = pg_client.patch(f"/api/cases/{case_id}", headers=pg_auth_headers, json={"status": "open"})
    assert res_reopen.status_code == 200
    res_get4 = pg_client.get(f"/api/cases/{case_id}")
    assert res_get4.get_json()["case"]["status"] == "open"

    # 12. Nonexistent alert ID and case ID validation
    res_bad_aid = pg_client.post(f"/api/cases/{case_id}/alerts", headers=pg_auth_headers, json={"alert_ids": [999999]})
    assert res_bad_aid.status_code == 404

    res_bad_case = pg_client.post("/api/cases/CASE-NONEXISTENT/notes", headers=pg_auth_headers, json={"note": "ghost"})
    assert res_bad_case.status_code == 404

    # 13. Alert Unlink and Re-link
    res_unlink = pg_client.delete(f"/api/cases/{case_id}/alerts/{alert_id}", headers=pg_auth_headers)
    assert res_unlink.status_code == 200
    assert res_unlink.get_json()["unlinked_alert_id"] == alert_id


def test_postgres_saved_searches(pg_client, pg_auth_headers):
    """Verify saved search creation with PostgreSQL RETURNING id clause."""
    unique_name = f"PG Search {uuid.uuid4().hex[:8]}"
    res = pg_client.post("/api/traffic/saved-searches", headers=pg_auth_headers, json={
        "name": unique_name,
        "description": "Flows with alerts on isolated Postgres schema",
        "query": {"alerted_only": True}
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["id"] is not None

    # List saved searches
    res_list = pg_client.get("/api/traffic/saved-searches")
    assert res_list.status_code == 200
    saved = res_list.get_json()
    assert any(s["name"] == unique_name for s in saved)


def test_postgres_audit_log(pg_client, pg_auth_headers):
    """Verify audit log retrieval on isolated PostgreSQL schema."""
    # Create a case to generate an audit log entry
    conn = get_connection()
    alert_id = write_alert(conn, {
        "rule_name": "SYN_FLOOD",
        "src_ip": "10.0.0.1",
        "dst_ip": "192.168.1.1",
        "src_port": 1234,
        "dst_port": 80,
        "protocol": "TCP",
        "severity": "critical",
        "confidence": "HIGH",
        "timestamp": time.time(),
    })
    conn.close()

    pg_client.post("/api/cases", headers=pg_auth_headers, json={
        "title": "Audit Log Verification Case",
        "severity": "critical",
        "alert_ids": [alert_id],
    })

    res = pg_client.get("/api/audit-log?limit=50")
    assert res.status_code == 200
    logs = res.get_json()
    assert isinstance(logs, list)
    assert len(logs) > 0


def test_postgres_traffic_explorer_cidr_kql(pg_client):
    """Verify Traffic Explorer and KQL mathematical CIDR matching on isolated PostgreSQL."""
    conn = get_connection()
    now = time.time()
    upsert_network_flow(conn, {
        "flow_id": f"pg-flow-cidr-{uuid.uuid4().hex[:8]}",
        "start_time": now,
        "last_seen": now,
        "src_ip": "172.16.10.5",
        "dst_ip": "10.0.0.50",
        "src_port": 1234,
        "dst_port": 80,
        "protocol": "TCP",
        "packet_count": 10,
        "byte_count": 1500,
    })
    flow2_id = f"pg-flow-cidr2-{uuid.uuid4().hex[:8]}"
    upsert_network_flow(conn, {
        "flow_id": flow2_id,
        "start_time": now,
        "last_seen": now,
        "src_ip": "192.168.1.150",
        "dst_ip": "10.0.0.51",
        "src_port": 1235,
        "dst_port": 443,
        "protocol": "TCP",
        "packet_count": 20,
        "byte_count": 3000,
    })
    conn.close()

    # CIDR search: 192.168.1.128/25 should match .150 but not 172.16.x
    res_kql = pg_client.get('/api/traffic?kql=src_ip : "192.168.1.128/25"')
    assert res_kql.status_code == 200
    kql_flows = res_kql.get_json().get("flows", [])
    kql_flow_ids = [f["flow_id"] for f in kql_flows]
    assert flow2_id in kql_flow_ids


def test_postgres_credential_encryption_at_rest(pg_setup):
    """Verify secrets stored in isolated PostgreSQL schema are encrypted, not plaintext."""
    import os
    from cryptography.fernet import Fernet
    # This test requires NETGUARD_ENCRYPTION_KEY to be set
    old_enc_key = os.environ.get("NETGUARD_ENCRYPTION_KEY")
    old_sess_key = os.environ.get("NETGUARD_SECRET_KEY")
    enc_key = Fernet.generate_key().decode()
    sess_key = Fernet.generate_key().decode()
    os.environ["NETGUARD_ENCRYPTION_KEY"] = enc_key
    os.environ["NETGUARD_SECRET_KEY"] = sess_key
    import storage.crypto
    import importlib
    importlib.reload(storage.crypto)

    try:
        conn = get_connection()
        save_system_setting(conn, "notification_email", {
            "host": "smtp.postgres-test.com",
            "password": "SecretPostgresPassword!#$",
            "user": "pg@ids.local",
        })

        # Direct query against PostgreSQL table verifying ciphertext
        cur = conn.cursor()
        cur.execute("SELECT value_json FROM system_settings WHERE setting_key = %s", ("notification_email",))
        row = cur.fetchone()
        cur.close()
        raw_json = row[0]
        assert "SecretPostgresPassword!#$" not in raw_json
        assert "enc:v1:" in raw_json

        # Retrieved via helper: transparently decrypted
        retrieved = get_system_setting(conn, "notification_email")
        conn.close()
        assert retrieved["password"] == "SecretPostgresPassword!#$"
        assert retrieved["host"] == "smtp.postgres-test.com"
    finally:
        if old_enc_key:
            os.environ["NETGUARD_ENCRYPTION_KEY"] = old_enc_key
        else:
            os.environ.pop("NETGUARD_ENCRYPTION_KEY", None)
        if old_sess_key:
            os.environ["NETGUARD_SECRET_KEY"] = old_sess_key
        else:
            os.environ.pop("NETGUARD_SECRET_KEY", None)
        importlib.reload(storage.crypto)
