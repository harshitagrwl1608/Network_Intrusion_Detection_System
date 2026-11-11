"""
tests/test_offline_isolation.py
---------------------------------
Mandatory regression test verifying complete isolation of offline PCAP analysis:
- Live alert count remains unchanged.
- Live device inventory remains unchanged.
- Live ARP state remains unchanged.
- Operational spool state remains unchanged.
- Offline replay accurately triggers threat intelligence / blocklist alerts in its isolated database.
"""

import os
import sys
import json
import time
import copy
import shutil
import tempfile
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from storage.db import init_db, get_connection, write_alert, upsert_device, read_all_alerts, read_all_devices
from forensics.offline_analyzer import OfflinePcapAnalyzer
from engine.rules import AlertSpool


class TestOfflineAnalyzerIsolation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.live_db_path = os.path.join(self.tmp_dir, "live_operational.db")
        self.live_arp_path = os.path.join(self.tmp_dir, "live_arp.json")
        self.live_spool_path = os.path.join(self.tmp_dir, "live_spool.jsonl")

        self.orig_sqlite = config.SQLITE_PATH
        self.orig_arp = config.ARP_TABLE_PATH
        self.orig_backend = config.DB_BACKEND

        config.DB_BACKEND = "sqlite"
        config.SQLITE_PATH = self.live_db_path
        config.ARP_TABLE_PATH = self.live_arp_path

        # Seed initial operational state
        conn = get_connection(self.live_db_path)
        init_db(conn)

        write_alert(conn, {
            "rule_name": "PORT_SCAN",
            "rule_version": "1.0",
            "src_ip": "10.0.0.99",
            "dst_ip": "10.0.0.1",
            "protocol": "TCP",
            "src_port": 1234,
            "dst_port": 80,
            "detail": "Operational baseline alert",
            "severity": "medium",
            "idempotency_key": "live_seed_alert_1",
            "timestamp": time.time(),
        })
        upsert_device(conn, "00:aa:bb:cc:dd:ee", "10.0.0.99", vendor="OperationalHost")
        conn.close()

        with open(self.live_arp_path, "w", encoding="utf-8") as f:
            json.dump({"10.0.0.99": "00:aa:bb:cc:dd:ee"}, f)

        self.spool = AlertSpool(self.live_spool_path, max_size=50)

    def tearDown(self):
        config.SQLITE_PATH = self.orig_sqlite
        config.ARP_TABLE_PATH = self.orig_arp
        config.DB_BACKEND = self.orig_backend
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_offline_analysis_strictly_isolated_from_live_monitoring(self):
        """
        Record live monitoring state, execute offline PCAP analysis with blocklist hits,
        and confirm isolated detection with 0 change to operational state.
        """
        # 1. Record live baseline metrics
        live_conn = get_connection(self.live_db_path)
        live_alerts_before = read_all_alerts(live_conn)
        live_devices_before = read_all_devices(live_conn)
        live_conn.close()

        with open(self.live_arp_path, "rb") as f:
            live_arp_before = f.read()

        live_spool_before = self.spool.count()

        self.assertEqual(len(live_alerts_before), 1)
        self.assertEqual(len(live_devices_before), 1)
        self.assertEqual(live_spool_before, 0)

        # 2. Run offline analysis on test PCAP
        pcap_path = os.path.join(PROJECT_DIR, "data", "test_attacks.pcap")
        self.assertTrue(os.path.exists(pcap_path))

        jobs_dir = os.path.join(self.tmp_dir, "jobs")
        # Include blocklist IP to verify detection triggers in isolated replay
        threat_blocklist = {"198.51.100.42", "192.168.1.100"}

        analyzer = OfflinePcapAnalyzer(jobs_dir=jobs_dir, blocklist=threat_blocklist)
        try:
            job = analyzer.create_job("test_attacks.pcap", pcap_path)
            job_id = job["job_id"]

            res = analyzer.run_job_sync(job_id)
            self.assertEqual(res["status"], "completed")
            self.assertGreater(res["processed_packets"], 0)
            self.assertGreater(res["alert_count"], 0)

            # Confirm isolated alerts include threat blocklist detection
            job_detail = analyzer.get_job(job_id)
            alerts = job_detail.get("alerts", [])
            self.assertGreater(len(alerts), 0)
            rule_names = {a["rule_name"] for a in alerts}
            self.assertIn("BLOCKLIST", rule_names, "Offline replay MUST execute loaded threat intelligence!")

            # 3. Assert live monitoring state is completely untouched
            live_conn = get_connection(self.live_db_path)
            live_alerts_after = read_all_alerts(live_conn)
            live_devices_after = read_all_devices(live_conn)
            live_conn.close()

            with open(self.live_arp_path, "rb") as f:
                live_arp_after = f.read()

            live_spool_after = self.spool.count()

            self.assertEqual(len(live_alerts_after), 1, "Live alert table MUST NOT receive offline replay alerts!")
            self.assertEqual(live_alerts_after[0]["idempotency_key"], "live_seed_alert_1")
            self.assertEqual(len(live_devices_after), 1, "Live device inventory MUST NOT receive offline replay devices!")
            self.assertEqual(live_devices_after[0]["mac"], "00:aa:bb:cc:dd:ee")
            self.assertEqual(live_arp_before, live_arp_after, "Live ARP table must not be mutated!")
            self.assertEqual(live_spool_after, 0, "Live alert spool must remain empty!")

            # 4. Clean up job
            analyzer.cleanup_job(job_id)
            self.assertIsNone(analyzer.get_job(job_id))
        finally:
            analyzer.shutdown()


if __name__ == "__main__":
    unittest.main()

