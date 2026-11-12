"""
Unit and integration tests for Overview Recent Alerts live panel and SSE streaming feed.
"""

import os
import sys
import time
import pytest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from dashboard.app import app
from storage.db import get_connection, write_alert, init_db
from storage.forensics_db import init_forensics_db
import config


@pytest.fixture(autouse=True)
def setup_isolated_db(tmp_path):
    orig_sqlite = config.SQLITE_PATH
    orig_backend = config.DB_BACKEND
    db_file = str(tmp_path / "test_overview.db")
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
def seed_recent_alerts():
    conn = get_connection()
    now = time.time()
    cur = conn.cursor()

    severities = ["critical", "high", "medium", "low"]
    alert_ids = []
    for i, sev in enumerate(severities):
        cur.execute(
            """
            INSERT INTO alerts (timestamp, rule_name, severity, src_ip, dst_ip, src_port, dst_port, protocol, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (now - (i * 10), f"TEST_RULE_{sev.upper()}", sev, f"192.168.1.{10+i}", "10.0.0.1", 10000 + i, 80, "TCP", f"Test alert for {sev}")
        )
        alert_ids.append(cur.lastrowid)

    conn.commit()
    cur.close()
    yield alert_ids

    # Cleanup
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM alerts WHERE rule_name LIKE 'TEST_RULE_%'")
    conn.commit()
    cur.close()


def test_recent_alerts_feed_structure(client, seed_recent_alerts):
    res = client.get("/api/alerts?hours=24")
    assert res.status_code == 200
    alerts = res.get_json()
    assert isinstance(alerts, list)
    assert len(alerts) >= 4

    test_alerts = [a for a in alerts if a.get("rule_name", "").startswith("TEST_RULE_")]
    assert len(test_alerts) == 4

    # Verify severity diversity
    sevs = {a["severity"].lower() for a in test_alerts}
    assert "critical" in sevs
    assert "high" in sevs
    assert "medium" in sevs
    assert "low" in sevs

    # Verify required UI fields exist
    first = test_alerts[0]
    assert "id" in first
    assert "timestamp" in first
    assert "time_str" in first
    assert "rule_name" in first
    assert "severity" in first
    assert "src_ip" in first
    assert "dst_ip" in first
    assert "protocol" in first
    assert "detail" in first


def test_overview_alert_inspection_modal_api(client, seed_recent_alerts):
    aid = seed_recent_alerts[0]
    res = client.get(f"/api/alerts/{aid}")
    assert res.status_code == 200
    data = res.get_json()
    assert data["id"] == aid
    assert "rule_name" in data
    assert "packet_context" in data or "evidence" in data


def test_sse_stream_endpoint(client):
    with app.test_request_context("/api/stream"):
        from dashboard.app import api_stream
        res = api_stream()
        assert res.mimetype == "text/event-stream"
        assert res.headers.get("Cache-Control") == "no-cache"
