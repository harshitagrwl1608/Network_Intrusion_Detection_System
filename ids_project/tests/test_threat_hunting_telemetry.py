"""
Unit and integration tests for multi-source Threat Hunting telemetry.
Validates search across alerts, network_flows, packet_events, and traffic_anomalies.
"""

import os
import sys
import time
import pytest
from unittest.mock import patch

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from dashboard.app import app
from storage.db import init_db, write_alert, get_connection
from storage.forensics_db import init_forensics_db
from engine.rule_metadata import RULE_METADATA
import config


@pytest.fixture(autouse=True)
def setup_isolated_db(tmp_path):
    orig_sqlite = config.SQLITE_PATH
    orig_backend = config.DB_BACKEND
    db_file = str(tmp_path / "test_hunting.db")
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
def populated_db():
    from storage.db import _sqlite_lock
    conn = get_connection()
    now = time.time()
    with _sqlite_lock:
        cur = conn.cursor()

        # Seed an alert
        cur.execute(
            """
            INSERT INTO alerts (timestamp, rule_name, severity, src_ip, dst_ip, src_port, dst_port, protocol, detail, flow_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (now - 100, "DNS_ANOMALY", "medium", "192.168.1.50", "8.8.8.8", 54321, 53, "UDP", "High entropy DNS query", "flow_hunt_1")
        )
        alert_id = cur.lastrowid

        # Seed a network flow
        cur.execute(
            """
            INSERT INTO network_flows (flow_id, start_time, last_seen, protocol, src_ip, src_port, dst_ip, dst_port, direction, packet_count, byte_count, alert_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("flow_hunt_1", now - 200, now - 100, "UDP", "192.168.1.50", 54321, "8.8.8.8", 53, "outbound", 15, 1200, 1)
        )

        # Seed packet events
        cur.execute(
            """
            INSERT INTO packet_events (event_id, flow_id, timestamp, packet_index, packet_len, protocol, src_ip, dst_ip, tcp_flags, payload_preview)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("ev_hunt_1", "flow_hunt_1", now - 150, 1, 120, "UDP", "192.168.1.50", "8.8.8.8", 0, "dns:exfil.c2corp.com")
        )

        # Seed a traffic anomaly
        cur.execute(
            """
            INSERT INTO traffic_anomalies (timestamp, metric_name, observed_value, expected_value, deviation_score, method, confidence, explanation, related_flow_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (now - 300, "dns_entropy", 4.8, 2.1, 6.75, "z_score", "high", "High entropy DNS anomaly detected", "flow_hunt_1")
        )

        conn.commit()
        cur.close()

    yield conn

    # Cleanup
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute("DELETE FROM alerts WHERE flow_id = 'flow_hunt_1'")
        cur.execute("DELETE FROM network_flows WHERE flow_id = 'flow_hunt_1'")
        cur.execute("DELETE FROM packet_events WHERE flow_id = 'flow_hunt_1'")
        cur.execute("DELETE FROM traffic_anomalies WHERE metric_name = 'dns_entropy'")
        conn.commit()
        cur.close()


def test_hunting_search_type_ip(client, populated_db):
    res = client.get("/api/hunting/search?type=ip&q=192.168.1.50&hours=24")
    assert res.status_code == 200
    data = res.get_json()
    assert "results" in data
    assert len(data["results"]) >= 1
    found = [r for r in data["results"] if r.get("indicator") == "192.168.1.50"]
    assert len(found) >= 1
    # Verify classification
    classes = [r.get("classification") for r in found]
    assert "Existing IDS alert" in classes or "Suspicious traffic indicator" in classes


def test_hunting_search_type_rule(client, populated_db):
    res = client.get("/api/hunting/search?type=rule&q=DNS_ANOMALY&hours=24")
    assert res.status_code == 200
    data = res.get_json()
    assert len(data["results"]) >= 1
    item = data["results"][0]
    assert item["context"] == "DNS_ANOMALY"
    assert item["classification"] == "Existing IDS alert"


def test_hunting_search_type_domain(client, populated_db):
    res = client.get("/api/hunting/search?type=domain&q=exfil.c2corp.com&hours=24")
    assert res.status_code == 200
    data = res.get_json()
    assert len(data["results"]) >= 1
    item = data["results"][0]
    assert "exfil.c2corp.com" in (item.get("detail") or "") or "exfil.c2corp.com" in (item.get("indicator") or "")


def test_hunting_search_type_anomaly(client, populated_db):
    res = client.get("/api/hunting/search?type=anomaly&q=dns_entropy&hours=24")
    assert res.status_code == 200
    data = res.get_json()
    assert len(data["results"]) >= 1
    item = data["results"][0]
    assert item["classification"] == "Statistical anomaly"
    assert "dns_entropy" in item["indicator"]


def test_hunting_search_type_port(client, populated_db):
    res = client.get("/api/hunting/search?type=port&q=53&hours=24")
    assert res.status_code == 200
    data = res.get_json()
    assert len(data["results"]) >= 1


def test_hunting_search_type_cidr(client, populated_db):
    res = client.get("/api/hunting/search?type=cidr&q=192.168.1.0/24&hours=24")
    assert res.status_code == 200
    data = res.get_json()
    assert len(data["results"]) >= 1


def test_hunting_preset_rule_alignment():
    # Verify all preset rule names match authentic NetGuard registered rules in RULE_METADATA
    preset_rules = [
        "DNS_ANOMALY",
        "TCP_STEALTH_SCAN",
        "ICMP_TUNNEL",
        "IP_FRAGMENT_ANOMALY",
        "CLEAR_HTTP_ON_TLS_PORT",
        "IRC_C2_BEACONING",
    ]
    for r in preset_rules:
        assert r in RULE_METADATA, f"Preset rule {r} not found in NetGuard RULE_METADATA!"


def test_hunting_empty_query(client):
    res = client.get("/api/hunting/search?type=rule&q=")
    assert res.status_code == 200
    data = res.get_json()
    assert data["results"] == []
