"""
Unit and integration tests for Case Management Lifecycle.
Verifies CRUD operations, alert linking, status/severity transitions, timeline notes, and audit logging.
"""

import os
import sys
import time
import pytest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from dashboard.app import app
from storage.db import get_connection, init_db
from storage.forensics_db import init_forensics_db
import config


@pytest.fixture(autouse=True)
def setup_isolated_db(tmp_path):
    orig_sqlite = config.SQLITE_PATH
    orig_backend = config.DB_BACKEND
    db_file = str(tmp_path / "test_case.db")
    config.DB_BACKEND = "sqlite"
    config.SQLITE_PATH = db_file

    import dashboard.app as d_app
    d_app._db_conn = None

    conn = get_connection()
    init_db(conn)
    init_forensics_db(conn)
    conn.close()

    yield

    if d_app._db_conn is not None:
        try:
            d_app._db_conn.close()
        except Exception:
            pass
        d_app._db_conn = None

    config.SQLITE_PATH = orig_sqlite
    config.DB_BACKEND = orig_backend


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def auth_headers(client):
    res = client.get("/api/csrf-token")
    token = res.get_json()["csrf_token"]
    return {"X-CSRFToken": token}


@pytest.fixture
def seed_test_alert():
    conn = get_connection()
    now = time.time()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO alerts (timestamp, rule_name, severity, src_ip, dst_ip, src_port, dst_port, protocol, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (now, "PORT_SCAN_TCP", "high", "10.0.0.99", "192.168.1.1", 45678, 80, "TCP", "Port scan alert for case testing")
    )
    aid = cur.lastrowid
    conn.commit()
    cur.close()
    yield aid

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM alerts WHERE id = ?", (aid,))
    conn.commit()
    cur.close()


def test_case_lifecycle_full(client, auth_headers, seed_test_alert):
    aid = seed_test_alert

    # 1. Create Case
    res_create = client.post("/api/cases", headers=auth_headers, json={
        "title": "Suspicious Port Scan on Host 192.168.1.1",
        "severity": "high",
        "assigned_to": "Alice Analyst",
        "description": "Investigating reconnaissance activity targeting internal host.",
        "alert_ids": [aid]
    })
    assert res_create.status_code in (200, 201)
    create_data = res_create.get_json()
    assert create_data["status"] == "ok"
    case_id = create_data["case_id"]
    assert case_id.startswith("CASE-")

    # 2. Retrieve Case Details
    res_get = client.get(f"/api/cases/{case_id}")
    assert res_get.status_code == 200
    case_detail = res_get.get_json()
    assert "case" in case_detail
    assert "alerts" in case_detail
    assert "notes" in case_detail
    c = case_detail["case"]
    assert c["title"] == "Suspicious Port Scan on Host 192.168.1.1"
    assert c["status"] == "open"
    assert c["severity"] == "high"
    assert c["assigned_to"] == "Alice Analyst"
    assert len(case_detail["alerts"]) == 1
    assert case_detail["alerts"][0]["id"] == aid

    # 3. Add Investigation Note
    res_note = client.post(f"/api/cases/{case_id}/notes", headers=auth_headers, json={
        "note": "Host isolated at edge switch; packet capture slice downloaded.",
        "author": "Alice Analyst"
    })
    assert res_note.status_code == 200
    assert res_note.get_json()["status"] == "ok"

    # Verify Note Appears in Case
    res_get2 = client.get(f"/api/cases/{case_id}")
    notes = res_get2.get_json()["notes"]
    assert len(notes) == 1
    assert "Host isolated" in notes[0]["note"]
    assert notes[0]["author"] == "Alice Analyst"

    # 4. Status Transition: Open -> Investigating
    res_trans1 = client.patch(f"/api/cases/{case_id}", headers=auth_headers, json={"status": "investigating"})
    assert res_trans1.status_code == 200
    assert res_trans1.get_json()["status"] == "ok"

    res_get3 = client.get(f"/api/cases/{case_id}")
    assert res_get3.get_json()["case"]["status"] == "investigating"

    # 5. Status Transition: Investigating -> Resolved -> Closed
    res_trans2 = client.patch(f"/api/cases/{case_id}", headers=auth_headers, json={"status": "closed"})
    assert res_trans2.status_code == 200

    res_get4 = client.get(f"/api/cases/{case_id}")
    assert res_get4.get_json()["case"]["status"] == "closed"

    # 6. Audit Trail Verification
    res_audit = client.get("/api/audit-log?limit=10")
    assert res_audit.status_code == 200
    logs = res_audit.get_json()
    case_actions = [l for l in logs if l.get("resource_id") == case_id]
    assert len(case_actions) >= 1


def test_case_invalid_transitions_and_severity(client, auth_headers):
    """Verify that invalid severities and illegal status transitions return HTTP 400."""
    # Invalid severity on creation
    res_bad_sev = client.post("/api/cases", headers=auth_headers, json={
        "title": "Invalid Severity Case",
        "severity": "catastrophic",
    })
    assert res_bad_sev.status_code == 400
    assert "Invalid severity" in res_bad_sev.get_json()["error"]

    # Valid creation
    res_create = client.post("/api/cases", headers=auth_headers, json={
        "title": "State Machine Case",
        "severity": "medium",
    })
    assert res_create.status_code in (200, 201)
    case_id = res_create.get_json()["case_id"]

    # Illegal direct jump: open -> closed (must be investigated first)
    res_illegal_close = client.patch(f"/api/cases/{case_id}", headers=auth_headers, json={"status": "closed"})
    assert res_illegal_close.status_code == 400
    assert "Invalid status transition" in res_illegal_close.get_json()["error"]

    # Illegal direct jump: open -> resolved
    res_illegal_resolve = client.patch(f"/api/cases/{case_id}", headers=auth_headers, json={"status": "resolved"})
    assert res_illegal_resolve.status_code == 400
    assert "Invalid status transition" in res_illegal_resolve.get_json()["error"]

    # Invalid status string
    res_bad_status = client.patch(f"/api/cases/{case_id}", headers=auth_headers, json={"status": "pending"})
    assert res_bad_status.status_code == 400
    assert "Invalid status" in res_bad_status.get_json()["error"]

    # Invalid severity on patch
    res_bad_patch_sev = client.patch(f"/api/cases/{case_id}", headers=auth_headers, json={"severity": "super_urgent"})
    assert res_bad_patch_sev.status_code == 400
    assert "Invalid severity" in res_bad_patch_sev.get_json()["error"]

    # Legal transition: open -> investigating
    res_ok_inv = client.patch(f"/api/cases/{case_id}", headers=auth_headers, json={"status": "investigating"})
    assert res_ok_inv.status_code == 200

    # Legal transition: investigating -> resolved
    res_ok_res = client.patch(f"/api/cases/{case_id}", headers=auth_headers, json={"status": "resolved"})
    assert res_ok_res.status_code == 200

    # Legal transition: resolved -> closed
    res_ok_close = client.patch(f"/api/cases/{case_id}", headers=auth_headers, json={"status": "closed"})
    assert res_ok_close.status_code == 200

    # Legal reopen: closed -> open
    res_reopen = client.patch(f"/api/cases/{case_id}", headers=auth_headers, json={"status": "open"})
    assert res_reopen.status_code == 200
