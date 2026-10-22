import json
import os
import sys
import tempfile
import time
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from storage.db import get_connection, init_db, write_alert
from dashboard.app import app


class TestDashboardApi(unittest.TestCase):
    def setUp(self):
        import dashboard.app as _d_app
        _d_app._db_conn = None
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_dashboard.db")
        config.DB_BACKEND = "sqlite"
        config.SQLITE_PATH = self.db_path
        conn = get_connection()
        init_db(conn)
        conn.close()
        self.client = app.test_client()

    def tearDown(self):
        import shutil
        import dashboard.app as _d_app
        if _d_app._db_conn is not None:
            try:
                _d_app._db_conn.close()
            except Exception:
                pass
            _d_app._db_conn = None
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_default_dashboard_host_is_localhost(self):
        """Dashboard should bind to 127.0.0.1 by default to prevent unintended LAN exposure."""
        self.assertEqual(config.DASHBOARD_HOST, "127.0.0.1")

    def test_alert_detail_renders_parsed_evidence(self):
        """Verify GET /api/alerts/<id> parses evidence_json into a structured evidence dict."""
        conn = get_connection()
        alert_data = {
            "rule_name": "PORT_SCAN",
            "rule_version": "1.2",
            "src_ip": "10.0.0.99",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 80,
            "protocol": "TCP",
            "severity": "medium",
            "confidence": "high",
            "detail": "Test vertical scan",
            "evidence": {
                "scan_type": "vertical",
                "probed_ports": [80, 443, 8080],
                "distinct_count": 3,
            },
            "evidence_json": json.dumps({
                "scan_type": "vertical",
                "probed_ports": [80, 443, 8080],
                "distinct_count": 3,
            }),
            "timestamp": time.time(),
        }
        write_alert(conn, alert_data)
        conn.close()

        resp = self.client.get("/api/alerts/1")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsNotNone(data.get("evidence"))
        self.assertEqual(data["evidence"]["scan_type"], "vertical")
        self.assertEqual(data["evidence"]["distinct_count"], 3)
        self.assertIn("vertical scan", data.get("explanation", "").lower())

    def test_status_endpoint_returns_active_rules_and_severity(self):
        """Verify GET /api/status returns active rule count and severity breakdown."""
        conn = get_connection()
        write_alert(conn, {
            "rule_name": "TCP_ZERO_WINDOW",
            "rule_version": "1.1",
            "src_ip": "10.0.0.99",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 80,
            "protocol": "TCP",
            "severity": "high",
            "confidence": "high",
            "detail": "Test zero window burst",
            "timestamp": time.time(),
        })
        conn.close()

        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("active_rules_count"), 19)
        self.assertEqual(data["severity_breakdown"]["high"], 1)
        self.assertEqual(data["rule_breakdown"]["TCP_ZERO_WINDOW"], 1)

    def test_alert_detail_explanations_for_new_rules(self):
        """Verify explanations are present for newly introduced rules like TCP_ZERO_WINDOW and TLS_ANOMALY."""
        conn = get_connection()
        write_alert(conn, {
            "rule_name": "TLS_ANOMALY",
            "rule_version": "1.0",
            "src_ip": "10.0.0.50",
            "dst_ip": "10.0.0.1",
            "src_port": 45678,
            "dst_port": 443,
            "protocol": "TCP",
            "severity": "high",
            "confidence": "high",
            "detail": "Literal IP in SNI",
            "timestamp": time.time(),
        })
        conn.close()

        resp = self.client.get("/api/alerts/1")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("rfc 6066", data.get("explanation", "").lower())

    def test_aggregator_plain_language_templates_for_new_rules(self):
        """Verify aggregator generates plain-language observations for newly registered rules."""
        from analysis.aggregator import _obs_per_alert_type
        alerts = [
            {
                "rule_name": "TCP_ZERO_WINDOW",
                "src_ip": "192.168.1.103",
                "dst_ip": "192.168.1.1",
                "dst_port": 80,
                "detail": "Zero-window burst",
            },
            {
                "rule_name": "TCP_FLAG_ANOMALY",
                "src_ip": "192.168.1.97",
                "dst_ip": "192.168.1.1",
                "dst_port": 80,
                "detail": "SYN+FIN flags",
            },
            {
                "rule_name": "DATA_EXFIL",
                "src_ip": "192.168.1.85",
                "dst_ip": "203.0.113.85",
                "dst_port": 9001,
                "detail": "High-volume transfer",
            },
        ]
        observations = _obs_per_alert_type(alerts)
        rules_observed = {o["rule_name"] for o in observations}
        self.assertIn("TCP_ZERO_WINDOW", rules_observed)
        self.assertIn("TCP_FLAG_ANOMALY", rules_observed)
        self.assertIn("DATA_EXFIL", rules_observed)


if __name__ == "__main__":
    unittest.main()
