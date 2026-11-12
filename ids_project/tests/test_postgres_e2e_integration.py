"""
ids_project/tests/test_postgres_e2e_integration.py
--------------------------------------------------
End-to-end integration test suite running against a live PostgreSQL 18 instance.
Verifies all core dashboard routes and storage operations with PostgreSQL:
1. Live schema initialization and migrations
2. Case lifecycle operations:
   - Creation with severity validation
   - Alert linking (ON CONFLICT DO NOTHING)
   - Case notes addition
   - State machine transitions (open -> investigating -> resolved -> closed)
   - Reopening (closed -> open)
   - Invalid status and severity rejection (HTTP 400)
3. Audit log trail persistence and querying
4. Saved search persistence and listing (RETURNING id)
5. Traffic Explorer queries with mathematical CIDR subnet search (::inet <<=)
6. Credential encryption at rest in PostgreSQL system_settings
"""

import os
import sys
import time
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

POSTGRES_TEST_URL = "postgresql://harshitgarg@127.0.0.1:54333/postgres"


def _postgres_available():
    try:
        import psycopg2
        conn = psycopg2.connect(POSTGRES_TEST_URL, connect_timeout=2)
        conn.close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _postgres_available(),
    reason="Live PostgreSQL cluster on 127.0.0.1:54333 is not running"
)


@pytest.fixture(scope="module")
def pg_setup():
    """Configure PostgreSQL backend and initialize schemas on live instance."""
    orig_backend = config.DB_BACKEND
    orig_url = getattr(config, "POSTGRES_URL", "")
    config.DB_BACKEND = "postgres"
    config.POSTGRES_URL = POSTGRES_TEST_URL

    import dashboard.app as d_app
    if d_app._db_conn:
        try:
            d_app._db_conn.close()
        except Exception:
            pass
        d_app._db_conn = None

    conn = get_connection()
    init_db(conn)
    init_forensics_db(conn)
    conn.close()

    yield

    if d_app._db_conn:
        try:
            d_app._db_conn.close()
        except Exception:
            pass
        d_app._db_conn = None

    config.DB_BACKEND = orig_backend
    config.POSTGRES_URL = orig_url


@pytest.fixture
def pg_client(pg_setup):
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_postgres_schema_initialization(pg_setup):
    """Verify live PostgreSQL tables and columns exist."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = 'public'
    """)
    tables = {r[0] for r in cur.fetchall()}
    cur.close()
    conn.close()

    expected_tables = {
        "alerts", "seen_devices", "feedback", "network_flows", "packet_events",
        "cases", "case_alerts", "case_notes", "audit_log", "system_settings",
        "saved_searches", "notification_outbox"
    }
    for t in expected_tables:
        assert t in tables, f"Expected table '{t}' in PostgreSQL schema"


def test_postgres_case_management_lifecycle(pg_client):
    """Test full 10-step case management lifecycle end-to-end on PostgreSQL."""
    conn = get_connection()
    # 1. Seed an alert in PostgreSQL
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
    res = pg_client.post("/api/cases", json={
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
    res_link = pg_client.post(f"/api/cases/{case_id}/alerts", json={"alert_ids": [alert_id]})
    assert res_link.status_code == 200

    # 5. Add Case Note
    res_note = pg_client.post(f"/api/cases/{case_id}/notes", json={
        "note": "Investigated PostgreSQL forensic records; no lateral movement.",
        "author": "PG Analyst"
    })
    assert res_note.status_code == 200

    # Verify Note Saved
    res_get2 = pg_client.get(f"/api/cases/{case_id}")
    assert len(res_get2.get_json()["notes"]) >= 1

    # 6. Invalid Status Transition: open -> closed directly (Must fail 400)
    res_bad_trans = pg_client.patch(f"/api/cases/{case_id}", json={"status": "closed"})
    assert res_bad_trans.status_code == 400

    # 7. Valid Transition: open -> investigating
    res_inv = pg_client.patch(f"/api/cases/{case_id}", json={"status": "investigating"})
    assert res_inv.status_code == 200

    # 8. Valid Transition: investigating -> resolved
    res_res = pg_client.patch(f"/api/cases/{case_id}", json={"status": "resolved"})
    assert res_res.status_code == 200

    # 9. Valid Transition: resolved -> closed
    res_close = pg_client.patch(f"/api/cases/{case_id}", json={"status": "closed"})
    assert res_close.status_code == 200
    res_get3 = pg_client.get(f"/api/cases/{case_id}")
    assert res_get3.get_json()["case"]["status"] == "closed"

    # 10. Valid Reopen: closed -> open
    res_reopen = pg_client.patch(f"/api/cases/{case_id}", json={"status": "open"})
    assert res_reopen.status_code == 200
    res_get4 = pg_client.get(f"/api/cases/{case_id}")
    assert res_get4.get_json()["case"]["status"] == "open"


def test_postgres_saved_searches(pg_client):
    """Verify saved search creation with PostgreSQL RETURNING id clause."""
    res = pg_client.post("/api/traffic/saved-searches", json={
        "name": "Postgres High Risk Flow Search",
        "description": "Flows with alerts on Postgres",
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
    assert any(s["name"] == "Postgres High Risk Flow Search" for s in saved)


def test_postgres_audit_log(pg_client):
    """Verify audit log retrieval on PostgreSQL."""
    res = pg_client.get("/api/audit-log?limit=50")
    assert res.status_code == 200
    logs = res.get_json()
    assert isinstance(logs, list)
    assert len(logs) > 0


def test_postgres_traffic_explorer_cidr_kql(pg_client):
    """Verify Traffic Explorer and KQL mathematical CIDR matching on live PostgreSQL."""
    conn = get_connection()
    now = time.time()
    # Upsert test flows
    upsert_network_flow(conn, {
        "flow_id": "pg-flow-1",
        "start_time": now,
        "last_seen": now,
        "src_ip": "172.16.10.5",
        "dst_ip": "10.0.0.50",
        "src_port": 1234,
        "dst_port": 80,
        "protocol": "TCP",
        "packet_count": 10,
        "byte_count": 1500,
        "dns_query": "internal.service.local",
    })
    upsert_network_flow(conn, {
        "flow_id": "pg-flow-2",
        "start_time": now,
        "last_seen": now,
        "src_ip": "192.168.1.150",
        "dst_ip": "10.0.0.51",
        "src_port": 1235,
        "dst_port": 443,
        "protocol": "TCP",
        "packet_count": 20,
        "byte_count": 3000,
        "dns_query": "secure.bank.com",
    })
    conn.close()

    # Query with CIDR via Traffic Explorer API
    res = pg_client.get("/api/traffic?src_ip=172.16.0.0/16")
    assert res.status_code == 200
    flows = res.get_json().get("flows", [])
    flow_ids = [f["flow_id"] for f in flows]
    assert "pg-flow-1" in flow_ids
    assert "pg-flow-2" not in flow_ids

    # Query with KQL /25 subnet search via Traffic Explorer
    res_kql = pg_client.get('/api/traffic?kql=src_ip : "192.168.1.128/25"')
    assert res_kql.status_code == 200
    kql_flows = res_kql.get_json().get("flows", [])
    kql_flow_ids = [f["flow_id"] for f in kql_flows]
    assert "pg-flow-2" in kql_flow_ids
    assert "pg-flow-1" not in kql_flow_ids


def test_postgres_credential_encryption_at_rest(pg_client):
    """Verify secrets stored in PostgreSQL system_settings are encrypted."""
    conn = get_connection()
    save_system_setting(conn, "notification_email", {
        "host": "smtp.postgres-test.com",
        "password": "SecretPostgresPassword!#$",
        "user": "pg@ids.local",
    })

    # Direct query against PostgreSQL table verifying ciphertext
    cur = conn.cursor()
    cur.execute("SELECT value_json FROM system_settings WHERE setting_key = 'notification_email'")
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
