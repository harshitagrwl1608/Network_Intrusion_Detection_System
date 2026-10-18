import os
import sys
import tempfile
import time
import unittest

# Ensure ids_project is importable
PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from storage.db import init_db, get_connection
from engine.rules import RuleEngine


class TestAlertPersistence(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_alerts.db")
        config.DB_BACKEND = "sqlite"
        config.SQLITE_PATH = self.db_path
        conn = get_connection()
        init_db(conn)
        conn.close()

    def tearDown(self):
        if os.path.exists(self.tmp_dir):
            import shutil
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_bare_sqlite_path(self):
        """Verify that a bare filename without directory does not crash get_connection."""
        old_path = config.SQLITE_PATH
        bare_name = f"test_bare_{int(time.time()*1000)}.db"
        try:
            config.SQLITE_PATH = bare_name
            conn = get_connection()
            self.assertIsNotNone(conn)
            conn.close()
        finally:
            config.SQLITE_PATH = old_path
            if os.path.exists(bare_name):
                os.remove(bare_name)

    def test_alerts_not_dropped_under_device_saturation(self):
        """
        Verify that a burst of device updates (> queue size) does not crowd out alerts.
        In the old implementation, queue was maxsize=2000, shared between devices and alerts.
        Sending 3000 device packets caused queue saturation and dropped alerts.
        """
        conn = get_connection()
        engine = RuleEngine(conn, set(), config)
        try:
            # Send 2500 device updates with varying IPs to simulate traffic burst
            for i in range(2500):
                engine.check({
                    "src_mac": "00:11:22:33:44:55",
                    "src_ip": f"10.0.{i // 256}.{i % 256}",
                    "dst_ip": "10.0.0.1",
                    "protocol": "UDP",
                    "dst_port": 53,
                    "timestamp": time.time(),
                })

            # Send 50 alerts directly into engine write path or via an alert-triggering rule
            test_alert = {
                "rule_name": "PORT_SCAN",
                "rule_version": "1.0",
                "src_ip": "192.168.1.100",
                "dst_ip": "192.168.1.1",
                "detail": "Test alert under saturation",
                "evidence": {"ports": [80, 443]},
            }
            # Enqueue alerts
            for _ in range(50):
                if hasattr(engine, "_alert_queue"):
                    engine._alert_queue.put(("alert", dict(test_alert)))
                else:
                    engine._enqueue("alert", dict(test_alert))

            # Flush must drain completely
            engine.flush()

            # Query database
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM alerts WHERE rule_name='PORT_SCAN'")
            count = cur.fetchone()[0]
            conn.close()

            self.assertEqual(count, 50, f"Expected 50 alerts persisted, but found {count}")
            if hasattr(engine, "_stats"):
                self.assertEqual(engine._stats.get("alerts_dropped", 0), 0)
        finally:
            engine.flush()


if __name__ == "__main__":
    unittest.main()
