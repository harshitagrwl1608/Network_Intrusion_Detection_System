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
        from engine.rules import RuleEngine
        self.assertEqual(data.get("active_rules_count"), len(RuleEngine(None, set(), config).rules))
        self.assertEqual(data["severity_breakdown"]["high"], 1)
        self.assertEqual(data["rule_breakdown"]["TCP_ZERO_WINDOW"], 1)

    def test_alert_detail_explanations_for_new_rules(self):
        """Verify explanations are present for all 23 rules including recent additions."""
        conn = get_connection()
        test_alerts = [
            ("TLS_ANOMALY", "Literal IP in SNI", "rfc 6066"),
            ("NON_DNS_TRAFFIC_ON_DNS_PORT", "Shell on 53", "reverse shell"),
            ("ICMP_TUNNEL", "Covert ICMP", "ptunnel"),
            ("IP_FRAGMENT_ANOMALY", "Fragment overlap", "teardrop"),
            ("IRC_C2_BEACONING", "C2 beacon", "botnet"),
        ]
        for idx, (r_name, detail, expected_kw) in enumerate(test_alerts, start=1):
            write_alert(conn, {
                "rule_name": r_name,
                "rule_version": "1.0",
                "src_ip": f"10.0.0.{idx}",
                "dst_ip": "10.0.0.1",
                "src_port": 45678,
                "dst_port": 443,
                "protocol": "TCP",
                "severity": "high",
                "confidence": "high",
                "detail": detail,
                "timestamp": time.time(),
            })
            resp = self.client.get(f"/api/alerts/{idx}")
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            explanation = data.get("explanation", "").lower()
            self.assertNotEqual(explanation, "no explanation available.", f"Rule {r_name} missing explanation")
            self.assertIn(expected_kw, explanation, f"Rule {r_name} explanation missing keyword '{expected_kw}'")
        conn.close()

    def test_aggregator_plain_language_templates_for_new_rules(self):
        """Verify aggregator generates plain-language observations for newly registered rules."""
        from analysis.aggregator import _obs_per_alert_type, TEMPLATES
        from engine.rules import RuleEngine
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
            {
                "rule_name": "NON_DNS_TRAFFIC_ON_DNS_PORT",
                "src_ip": "192.168.1.106",
                "dst_ip": "203.0.113.106",
                "dst_port": 53,
                "detail": "Shell on 53",
            },
            {
                "rule_name": "ICMP_TUNNEL",
                "src_ip": "192.168.1.107",
                "dst_ip": "203.0.113.107",
                "dst_port": 0,
                "detail": "Covert ICMP",
            },
            {
                "rule_name": "IP_FRAGMENT_ANOMALY",
                "src_ip": "192.168.1.108",
                "dst_ip": "192.168.1.1",
                "dst_port": 80,
                "detail": "Fragment overlap",
            },
            {
                "rule_name": "IRC_C2_BEACONING",
                "src_ip": "192.168.1.109",
                "dst_ip": "185.244.25.235",
                "dst_port": 6667,
                "detail": "IRC beacon",
            },
        ]
        observations = _obs_per_alert_type(alerts)
        rules_observed = {o["rule_name"] for o in observations}
        self.assertIn("TCP_ZERO_WINDOW", rules_observed)
        self.assertIn("TCP_FLAG_ANOMALY", rules_observed)
        self.assertIn("DATA_EXFIL", rules_observed)
        self.assertIn("NON_DNS_TRAFFIC_ON_DNS_PORT", rules_observed)
        self.assertIn("ICMP_TUNNEL", rules_observed)
        self.assertIn("IP_FRAGMENT_ANOMALY", rules_observed)
        self.assertIn("IRC_C2_BEACONING", rules_observed)

        # Verify all 23 canonical detection rules have plain-language templates
        engine = RuleEngine(None, set(), config)
        for r in engine.rules:
            self.assertIn(r.name, TEMPLATES, f"Rule {r.name} missing from analysis/aggregator.py TEMPLATES")


if __name__ == "__main__":
    unittest.main()
