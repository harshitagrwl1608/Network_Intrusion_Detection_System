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


if __name__ == "__main__":
    unittest.main()
