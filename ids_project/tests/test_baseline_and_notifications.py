"""
tests/test_baseline_and_notifications.py
-----------------------------------------
Verifies:
1. Baseline Telemetry Pipeline:
   - BaselineCollector samples metrics from FlowTracker / PacketProcessingMetrics.
   - Anti-poisoning safeguard: skips baseline learning during active high/critical alerts.
   - Quarantine mode: baseline updates frozen during investigation.
   - Anomaly detection: flags statistically significant MAD deviations after warmup.
2. Notification Outbox Pipeline:
   - Alert persistence hook automatically enqueues high/critical alerts to outbox.
   - Per-(rule, dst_ip) cooldown suppression.
   - Outbox processing with exponential backoff and retry limits.
   - Provider delivery (Email, Telegram, Webhook, SMS) with mocked endpoints.
   - Provider status reporting (configured, recipient_configured, worker_running, last_delivery, recent_errors).
"""

import os
import sys
import time
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from storage.db import init_db, get_connection, write_alert, register_alert_persistence_hook, unregister_alert_persistence_hook
from storage.forensics_db import init_forensics_db
from analytics.baselines import BaselineEngine, BaselineCollector
from notifications.outbox import NotificationOutboxManager, on_alert_persisted
from notifications.providers import EmailProvider, TelegramProvider, WebhookProvider, SmsProvider
from forensics.flow_tracker import FlowTracker


class TestBaselineAndNotifications(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_analytics.db")

        self.orig_sqlite = config.SQLITE_PATH
        self.orig_backend = config.DB_BACKEND
        config.DB_BACKEND = "sqlite"
        config.SQLITE_PATH = self.db_path

        self.conn = get_connection(self.db_path)
        init_db(self.conn)
        init_forensics_db(self.conn)

    def tearDown(self):
        self.conn.close()
        config.SQLITE_PATH = self.orig_sqlite
        config.DB_BACKEND = self.orig_backend
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_baseline_collector_telemetry_and_antipoisoning(self):
        """Verify BaselineCollector updates metrics and honors anti-poisoning safeguards."""
        engine = BaselineEngine(conn=self.conn, min_samples=3, mad_threshold=2.5)
        flow_tracker = FlowTracker(conn=self.conn, max_active_flows=50)

        collector = BaselineCollector(
            baseline_engine=engine,
            flow_tracker=flow_tracker,
            conn=self.conn,
            interval_s=1.0,
        )

        # 1. Warmup: inject 5 normal samples
        for i in range(5):
            t_now = 1000.0 + i * 5.0
            flow_tracker.process_packet({
                "type": "IP", "protocol": "TCP",
                "src_ip": f"192.168.1.{10 + i}", "dst_ip": "10.0.0.1",
                "src_port": 5000 + i, "dst_port": 80, "length": 500,
                "timestamp": t_now,
            })
            metrics = collector.sample_once(now=t_now)
            self.assertIn("packets_per_sec", metrics)
            self.assertIn("active_flows", metrics)

        baselines = engine.get_all_baselines()
        self.assertTrue(baselines["active_flows"]["is_ready"])
        self.assertGreater(baselines["active_flows"]["sample_count"], 0)

        # 2. Anti-Poisoning Safeguard: Write a high severity alert to simulate an active attack
        write_alert(self.conn, {
            "rule_name": "SYN_FLOOD",
            "src_ip": "198.51.100.99",
            "dst_ip": "10.0.0.1",
            "protocol": "TCP",
            "severity": "critical",
            "timestamp": 1030.0,
        })

        samples_before = engine.get_all_baselines()["active_flows"]["sample_count"]

        # Run sample_once during active incident
        collector.sample_once(now=1035.0)

        samples_after = engine.get_all_baselines()["active_flows"]["sample_count"]
        self.assertEqual(
            samples_before, samples_after,
            "Anti-poisoning safeguard MUST freeze baseline updates during active critical incidents!"
        )

        # 3. Quarantine mode test
        engine.set_quarantine(True, reason="SOC Manual Freeze")
        self.assertTrue(engine.is_quarantined)
        engine.update_metric("packets_per_sec", 9999.0)
        self.assertEqual(engine.get_all_baselines()["packets_per_sec"]["max_val"], 0.0)
        engine.set_quarantine(False)
        self.assertFalse(engine.is_quarantined)

        # 4. Anomaly detection after warmup
        anomaly = engine.evaluate_anomaly("packets_per_sec", 5000.0, timestamp=2000.0)
        # Note: packets_per_sec had 0 baseline, so evaluate anomaly with trained active_flows
        flow_anomaly = engine.evaluate_anomaly("active_flows", 500.0, timestamp=2000.0)
        self.assertTrue(flow_anomaly["is_anomaly"])
        self.assertIn("deviation_score", flow_anomaly)
        self.assertGreaterEqual(flow_anomaly["deviation_score"], 2.5)

    def test_notification_outbox_integration_and_delivery(self):
        """Verify alert persistence triggers outbox enqueueing and asynchronous delivery."""
        outbox = NotificationOutboxManager(conn=self.conn, min_severity="high", cooldown_s=10.0)

        # Mock outbox providers
        mock_webhook = MagicMock(return_value=(True, "Webhook accepted (HTTP 200)"))
        mock_email = MagicMock(return_value=(True, "Delivered via SMTP"))
        mock_telegram = MagicMock(return_value=(False, "Telegram API timeout"))

        outbox._providers["webhook"].send = mock_webhook
        outbox._providers["webhook"].url = "https://soc.example.com/webhook"
        outbox._providers["email"].send = mock_email
        outbox._providers["email"].host = "smtp.example.com"
        outbox._providers["email"].recipient = "analyst@example.com"
        # A sender must be configured explicitly. The SMTP provider no longer
        # falls back to "netguard-ids@localhost", which previously masked
        # missing configuration and produced 530 Authentication Required.
        outbox._providers["email"].from_addr = "netguard@example.com"
        outbox._providers["telegram"].send = mock_telegram
        outbox._providers["telegram"].bot_token = "fake-token"
        outbox._providers["telegram"].chat_id = "12345"

        # Register hook
        def _hook(conn, alert, alert_id):
            outbox.enqueue_alert(alert, alert_id=alert_id, enabled_providers=["webhook", "email", "telegram"])

        register_alert_persistence_hook(_hook)
        try:
            # 1. Medium severity alert should NOT trigger outbox (threshold is 'high')
            write_alert(self.conn, {
                "rule_name": "PORT_SCAN",
                "severity": "medium",
                "src_ip": "192.168.1.10",
                "dst_ip": "10.0.0.1",
                "timestamp": time.time(),
            })

            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM notification_outbox")
            count_medium = cur.fetchone()[0]
            self.assertEqual(count_medium, 0, "Medium severity should not trigger notification outbox")

            # 2. Critical severity alert should trigger outbox
            write_alert(self.conn, {
                "rule_name": "DATA_EXFIL",
                "severity": "critical",
                "src_ip": "192.168.1.50",
                "dst_ip": "198.51.100.99",
                "timestamp": time.time(),
            })

            cur.execute("SELECT COUNT(*) FROM notification_outbox WHERE rule_name = 'DATA_EXFIL'")
            count_critical = cur.fetchone()[0]
            self.assertEqual(count_critical, 3, "Expected 3 provider jobs for critical alert")

            # 3. Duplicate within cooldown window should be suppressed
            write_alert(self.conn, {
                "rule_name": "DATA_EXFIL",
                "severity": "critical",
                "src_ip": "192.168.1.50",
                "dst_ip": "198.51.100.99",
                "timestamp": time.time(),
            })
            cur.execute("SELECT COUNT(*) FROM notification_outbox WHERE rule_name = 'DATA_EXFIL'")
            count_cooldown = cur.fetchone()[0]
            self.assertEqual(count_cooldown, 3, "Cooldown must suppress duplicate alert notifications")

            # 4. Process outbox delivery
            delivered = outbox.process_pending_outbox(max_items=10)
            self.assertEqual(delivered, 2, "Expected webhook and email to succeed")

            # Verify status and retry accounting
            cur.execute("SELECT status, retry_count FROM notification_outbox WHERE provider = 'telegram'")
            row = cur.fetchone()
            self.assertEqual(row[0], "pending")
            self.assertEqual(row[1], 1, "Failed telegram delivery should increment retry count")

            # 5. Check get_providers_status()
            status = outbox.get_providers_status()
            self.assertTrue(status["webhook"]["configured"])
            self.assertTrue(status["email"]["configured"])
            self.assertTrue(status["email"]["recipient_configured"])
            self.assertIsNotNone(status["webhook"]["last_delivery"])
            self.assertGreater(len(status["telegram"]["recent_errors"]), 0)
            cur.close()

        finally:
            unregister_alert_persistence_hook(_hook)


if __name__ == "__main__":
    unittest.main()

