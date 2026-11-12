"""
tests/test_forensics_and_dashboard_upgrade.py
---------------------------------------------
Comprehensive test suite verifying the SOC Dashboard, Forensics Data Foundation,
Traffic Explorer, Isolated PCAP Analysis, Statistical Baselines, Incident Cases,
Notification Outbox, Multi-format Reporting, and Parallel Pipeline.
"""

import os
import sys
import time
import json
import unittest
import tempfile
import shutil

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from storage.db import get_connection, init_db, write_alert, feedback_stats
from engine.rule_metadata import get_rule_metadata_inventory, RULE_METADATA
from forensics.flow_tracker import FlowTracker, compute_flow_id
from forensics.pcap_retention import PcapRetentionManager
from forensics.offline_analyzer import OfflinePcapAnalyzer
from analytics.baselines import BaselineEngine
from notifications.outbox import NotificationOutboxManager
from reports.generator import ReportGenerator, REPORT_TYPES
from parallel.profile import get_system_capabilities, resolve_performance_profile
from parallel.pipeline import ParallelCapturePipeline
from dashboard.app import app, _mac_to_vendor


class TestForensicsAndDashboardUpgrade(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_forensics.db")
        self.orig_sqlite = config.SQLITE_PATH
        self.orig_backend = config.DB_BACKEND
        config.DB_BACKEND = "sqlite"
        config.SQLITE_PATH = self.db_path

        import dashboard.app as d_app
        d_app._db_conn = None
        d_app._offline_analyzer = None

        self.conn = get_connection()
        init_db(self.conn)
        self.client = app.test_client()

    def tearDown(self):
        try:
            self.conn.close()
        except Exception:
            pass
        import dashboard.app as d_app
        if d_app._db_conn is not None:
            try:
                d_app._db_conn.close()
            except Exception:
                pass
            d_app._db_conn = None
        d_app._offline_analyzer = None
        config.SQLITE_PATH = self.orig_sqlite
        config.DB_BACKEND = self.orig_backend
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_rules_metadata_inventory(self):
        """Verify /api/rules returns all 23 rules with required metadata fields."""
        resp = self.client.get("/api/rules")
        self.assertEqual(resp.status_code, 200)
        rules = resp.get_json()
        self.assertEqual(len(rules), 23)
        rule_names = {r["rule_name"] for r in rules}
        self.assertIn("PORT_SCAN", rule_names)
        self.assertIn("NON_DNS_TRAFFIC_ON_DNS_PORT", rule_names)
        self.assertIn("ICMP_TUNNEL", rule_names)
        self.assertIn("IP_FRAGMENT_ANOMALY", rule_names)
        self.assertIn("IRC_C2_BEACONING", rule_names)

        for r in rules:
            self.assertIn("category", r)
            self.assertIn("default_severity", r)
            self.assertIn("default_confidence", r)
            self.assertIn("description", r)
            self.assertIn("color", r)
            self.assertIn("protocols", r)

    def test_02_randomized_mac_detection(self):
        """Verify _mac_to_vendor identifies IEEE 802 randomized/private MACs."""
        self.assertEqual(_mac_to_vendor("02:42:ac:11:00:02"), "Randomized / Private MAC")
        self.assertEqual(_mac_to_vendor("da:a1:19:22:33:44"), "Randomized / Private MAC")
        self.assertEqual(_mac_to_vendor("B8:27:EB:12:34:56"), "Raspberry Pi Foundation")
        self.assertEqual(_mac_to_vendor(""), "Unknown")

    def test_03_traffic_explorer_filtering_and_pagination(self):
        """Verify /api/traffic server-side search, filtering, and pagination over network flows."""
        cur = self.conn.cursor()
        now = time.time()
        flows_to_insert = [
            ("flow_1", now - 100, now - 10, "192.168.1.10", 12345, "10.0.0.1", 80, "TCP", 15, 1500, "inbound", 0),
            ("flow_2", now - 200, now - 20, "192.168.1.20", 54321, "10.0.0.2", 443, "TCP", 50, 10000, "outbound", 2),
            ("flow_3", now - 300, now - 50, "192.168.1.30", 9999, "8.8.8.8", 53, "UDP", 4, 300, "outbound", 0),
        ]
        for f in flows_to_insert:
            cur.execute("""
                INSERT INTO network_flows (
                    flow_id, start_time, last_seen, src_ip, src_port, dst_ip, dst_port,
                    protocol, packet_count, byte_count, direction, alert_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, f)
        self.conn.commit()
        cur.close()

        # Query all
        resp = self.client.get("/api/traffic")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["total"], 3)
        self.assertEqual(len(data["flows"]), 3)

        # Filter protocol UDP
        r_udp = self.client.get("/api/traffic?protocol=UDP")
        self.assertEqual(r_udp.status_code, 200)
        d_udp = r_udp.get_json()
        self.assertEqual(d_udp["total"], 1)
        self.assertEqual(d_udp["flows"][0]["flow_id"], "flow_3")

        # Filter has_alerts=true
        r_alert = self.client.get("/api/traffic?has_alerts=true")
        self.assertEqual(r_alert.status_code, 200)
        d_alert = r_alert.get_json()
        self.assertEqual(d_alert["total"], 1)
        self.assertEqual(d_alert["flows"][0]["flow_id"], "flow_2")

        # Search IP
        r_search = self.client.get("/api/traffic?search=8.8.8.8")
        self.assertEqual(r_search.status_code, 200)
        self.assertEqual(r_search.get_json()["total"], 1)

    def test_04_flow_detail_and_pcap_slice(self):
        """Verify /api/traffic/<flow_id> and /api/traffic/<flow_id>/pcap."""
        now = time.time()
        cur = self.conn.cursor()
        flow_id = "test_flow_session_123"
        cur.execute("""
            INSERT INTO network_flows (
                flow_id, start_time, last_seen, src_ip, src_port, dst_ip, dst_port,
                protocol, packet_count, byte_count, direction, alert_count
            ) VALUES (?, ?, ?, '192.168.1.100', 4444, '10.0.0.5', 80, 'TCP', 2, 120, 'outbound', 1)
        """, (flow_id, now - 5, now))

        write_alert(self.conn, {
            "rule_name": "PAYLOAD_HIT",
            "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5",
            "src_port": 4444, "dst_port": 80, "protocol": "TCP",
            "severity": "high", "confidence": "high", "detail": "SQL injection in URI",
            "timestamp": now, "flow_id": flow_id,
        })

        # Insert packet events
        pkt_hex = "4500003c1c4640004006b1e6c0a801640a000005115c00500000000000000000a00272106e230000020405b40402080a000000000000000001030307"
        cur.execute("""
            INSERT INTO packet_events (
                flow_id, packet_index, timestamp, protocol, src_ip, src_port, dst_ip, dst_port,
                packet_len, tcp_flags, raw_hex
            ) VALUES (?, 1, ?, 'TCP', '192.168.1.100', 4444, '10.0.0.5', 80, 60, 'SYN', ?)
        """, (flow_id, now, pkt_hex))
        self.conn.commit()
        cur.close()

        # Session detail endpoint
        resp = self.client.get(f"/api/traffic/{flow_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["flow"]["flow_id"], flow_id)
        self.assertEqual(len(data["alerts"]), 1)
        self.assertEqual(data["alerts"][0]["rule_name"], "PAYLOAD_HIT")
        self.assertEqual(len(data["packet_events"]), 1)

        # Download PCAP slice
        pcap_resp = self.client.get(f"/api/traffic/{flow_id}/pcap")
        self.assertEqual(pcap_resp.status_code, 200)
        self.assertEqual(pcap_resp.mimetype, "application/vnd.tcpdump.pcap")
        pcap_data = pcap_resp.data
        self.assertTrue(len(pcap_data) > 24)
        # Check libpcap magic header (0xd4c3b2a1 or 0xa1b2c3d4)
        self.assertIn(pcap_data[:4], (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"))

    def test_05_saved_searches_lifecycle(self):
        """Verify saved search creation, retrieval, and deletion."""
        create_resp = self.client.post("/api/saved-searches", json={
            "name": "Outbound Port 445 Probes",
            "query": {"dst_port": 445, "direction": "outbound"},
            "description": "SMB hunting filter",
        })
        self.assertEqual(create_resp.status_code, 200)
        search_id = create_resp.get_json()["id"]

        list_resp = self.client.get("/api/saved-searches")
        self.assertEqual(list_resp.status_code, 200)
        items = list_resp.get_json()
        self.assertTrue(any(s["id"] == search_id and s["name"] == "Outbound Port 445 Probes" for s in items))

        del_resp = self.client.delete(f"/api/saved-searches/{search_id}")
        self.assertEqual(del_resp.status_code, 200)

        list_after = self.client.get("/api/saved-searches").get_json()
        self.assertFalse(any(s["id"] == search_id for s in list_after))

    def test_06_statistical_baseline_and_quarantine(self):
        """Verify BaselineEngine computes Rolling Median, MAD, and honors quarantine."""
        engine = BaselineEngine(main_conn=self.conn, window_size=50, min_samples=10, mad_threshold=3.0)
        now = time.time()

        # Warm up with steady 100 packets/sec
        for i in range(20):
            engine.update_metric("packets_per_sec", 100.0, timestamp=now + i)

        b = engine.get_all_baselines()["metrics"]["packets_per_sec"]
        self.assertEqual(b["median"], 100.0)
        self.assertTrue(b["is_ready"])

        # Test mild variation (not an anomaly)
        res_normal = engine.evaluate_anomaly("packets_per_sec", 105.0, timestamp=now + 25)
        self.assertFalse(res_normal["is_anomaly"])

        # Test extreme spike (anomaly)
        res_spike = engine.evaluate_anomaly("packets_per_sec", 1000.0, timestamp=now + 26)
        self.assertTrue(res_spike["is_anomaly"])
        self.assertEqual(res_spike["severity"], "high")

        # Test Quarantine Mode
        engine.set_quarantine(True)
        self.assertTrue(engine.is_quarantined)

        # In quarantine, metric updates are rejected to prevent poisoning
        engine.update_metric("packets_per_sec", 5000.0, timestamp=now + 30)
        b_after = engine.get_all_baselines()["metrics"]["packets_per_sec"]
        self.assertEqual(b_after["median"], 100.0)  # Preserved!

        engine.set_quarantine(False)
        self.assertFalse(engine.is_quarantined)

    def test_07_isolated_offline_pcap_replay(self):
        """Verify OfflinePcapAnalyzer processes PCAP in isolation with zero live DB contamination."""
        analyzer = OfflinePcapAnalyzer(main_conn=self.conn, upload_dir=os.path.join(self.tmp_dir, "uploads"))
        pcap_path = os.path.abspath(os.path.join(PROJECT_DIR, "data", "test_benign.pcap"))
        self.assertTrue(os.path.exists(pcap_path), "data/test_benign.pcap must exist")

        job = analyzer.create_job("test_benign.pcap", pcap_path)
        job_id = job["job_id"]

        # Run synchronously for test verification
        analyzer._execute_job(job_id)

        job_info = analyzer.get_job(job_id)
        self.assertEqual(job_info["status"], "completed")
        self.assertTrue(job_info["total_packets"] > 0)
        self.assertEqual(job_info["alert_count"], 0)

        # Invariant: live database must remain strictly clean
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM alerts")
        live_alerts_count = cur.fetchone()[0]
        cur.close()
        self.assertEqual(live_alerts_count, 0, "Offline replay must NEVER write alerts into the live DB!")

    def test_08_incident_cases_lifecycle(self):
        """Verify case creation, status transition, alert linking, and analyst notes."""
        write_alert(self.conn, {
            "rule_name": "IRC_C2_BEACONING",
            "src_ip": "10.0.0.45", "dst_ip": "198.51.100.2",
            "src_port": 50000, "dst_port": 6667, "protocol": "TCP",
            "severity": "high", "confidence": "high", "detail": "Botnet IRC C2 beacon",
            "timestamp": time.time(),
        })
        cur = self.conn.cursor()
        cur.execute("SELECT MAX(id) FROM alerts")
        aid = cur.fetchone()[0]
        cur.close()

        # Create case
        create_resp = self.client.post("/api/cases", json={
            "title": "Botnet Infection Investigation",
            "severity": "high",
            "assigned_to": "Analyst Bob",
            "description": "Host 10.0.0.45 communicating with IRC botnet node",
            "alert_ids": [aid],
        })
        self.assertEqual(create_resp.status_code, 200)
        case_id = create_resp.get_json()["case_id"]

        # Retrieve case
        detail_resp = self.client.get(f"/api/cases/{case_id}")
        self.assertEqual(detail_resp.status_code, 200)
        cdata = detail_resp.get_json()
        self.assertEqual(cdata["case"]["case_id"], case_id)
        self.assertEqual(len(cdata["alerts"]), 1)
        self.assertEqual(cdata["alerts"][0]["rule_name"], "IRC_C2_BEACONING")

        # Add analyst note
        note_resp = self.client.post(f"/api/cases/{case_id}/notes", json={
            "author": "Analyst Bob",
            "note": "Host isolated from LAN via firewall rule.",
        })
        self.assertEqual(note_resp.status_code, 200)

        # Transition status via state machine: open -> investigating -> resolved
        step1 = self.client.patch(f"/api/cases/{case_id}", json={"status": "investigating"})
        self.assertEqual(step1.status_code, 200)
        patch_resp = self.client.patch(f"/api/cases/{case_id}", json={
            "status": "resolved",
        })
        self.assertEqual(patch_resp.status_code, 200)

        cdata_after = self.client.get(f"/api/cases/{case_id}").get_json()
        self.assertEqual(cdata_after["case"]["status"], "resolved")
        self.assertEqual(len(cdata_after["notes"]), 1)

    def test_09_notification_outbox_queue_and_cooldown(self):
        """Verify notification outbox enqueues alerts, enforces cooldown deduplication, and records test dispatches."""
        outbox = NotificationOutboxManager(main_conn=self.conn, cooldown_seconds=60)
        alert = {
            "id": 999,
            "rule_name": "SYN_FLOOD",
            "severity": "high",
            "src_ip": "10.0.0.99",
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "detail": "SYN flood attack",
            "timestamp": time.time(),
        }

        # First alert enqueued
        q1 = outbox.enqueue_alert(alert)
        self.assertTrue(q1)

        # Second alert within cooldown window deduplicated
        q2 = outbox.enqueue_alert(alert)
        self.assertFalse(q2, "Alert within cooldown window must be deduplicated!")

        # Low severity filtered out by default threshold (medium+)
        low_alert = dict(alert, id=1000, severity="low")
        q_low = outbox.enqueue_alert(low_alert)
        self.assertFalse(q_low, "Low severity alert should be suppressed by default notification filter.")

        # Test provider dispatch endpoint
        test_resp = self.client.post("/api/notifications/test", json={"provider": "webhook"})
        self.assertEqual(test_resp.status_code, 200)

    def test_10_multi_format_report_generation(self):
        """Verify ReportGenerator generates all 9 report types in HTML, JSON, and CSV."""
        gen = ReportGenerator(self.conn)
        for r_type in REPORT_TYPES.keys():
            # Test HTML
            mime_h, fn_h, c_h = gen.generate(report_type=r_type, hours=24, fmt="html")
            self.assertEqual(mime_h, "text/html")
            self.assertTrue(len(c_h) > 50)
            self.assertIn("NetGuard IDS", c_h)

            # Test JSON
            mime_j, fn_j, c_j = gen.generate(report_type=r_type, hours=24, fmt="json")
            self.assertEqual(mime_j, "application/json")
            data_j = json.loads(c_j)
            self.assertEqual(data_j["report_type"], r_type)

            # Test CSV
            mime_c, fn_c, c_c = gen.generate(report_type=r_type, hours=24, fmt="csv")
            self.assertEqual(mime_c, "text/csv")
            self.assertTrue(len(c_c) > 10)

    def test_11_feedback_reclassification_deduplication(self):
        """Verify reclassifying an alert updates feedback_stats without double-counting."""
        write_alert(self.conn, {
            "rule_name": "TCP_FLAG_ANOMALY",
            "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
            "src_port": 1000, "dst_port": 80, "protocol": "TCP",
            "severity": "high", "confidence": "high", "detail": "Illegal flags",
            "timestamp": time.time(),
        })
        cur = self.conn.cursor()
        cur.execute("SELECT MAX(id) FROM alerts")
        aid = cur.fetchone()[0]
        cur.close()

        # 1. Initial classification: true_positive
        self.client.post("/api/feedback", json={
            "alert_id": aid, "classification": "true_positive", "analyst_note": "Initial review"
        })
        stats1 = feedback_stats(self.conn)
        self.assertEqual(stats1["TCP_FLAG_ANOMALY"]["true_positive"], 1)
        self.assertEqual(stats1["TCP_FLAG_ANOMALY"]["false_positive"], 0)

        # 2. Reclassification: false_positive
        reclass_resp = self.client.post("/api/feedback/reclassify", json={
            "alert_id": aid, "new_classification": "false_positive", "analyst_note": "Corrected: legitimate test tool"
        })
        self.assertEqual(reclass_resp.status_code, 200)

        # Verify only latest classification counts
        stats2 = feedback_stats(self.conn)
        self.assertEqual(stats2["TCP_FLAG_ANOMALY"]["true_positive"], 0)
        self.assertEqual(stats2["TCP_FLAG_ANOMALY"]["false_positive"], 1)

    def test_12_parallel_pipeline_replay_reconciliation(self):
        """Verify ParallelCapturePipeline matches sequential replay alert-for-alert."""
        pcap_path = os.path.abspath(os.path.join(PROJECT_DIR, "data", "test_attacks.pcap"))
        self.assertTrue(os.path.exists(pcap_path))

        # Sequential reference
        from engine.blocklist import load_blocklist
        from engine.rules import RuleEngine
        from capture.sniffer import replay_pcap

        seq_alerts = []
        def _seq_sink(alert):
            seq_alerts.append((alert["rule_name"], alert.get("src_ip"), alert.get("dst_port")))

        seq_engine = RuleEngine(None, set(), config)
        seq_engine.set_alert_sink(_seq_sink)
        replay_pcap(pcap_path, seq_engine, use_fast_parser=True)

        # Parallel pipeline run
        par_alerts = []
        def _par_sink(alert):
            par_alerts.append((alert["rule_name"], alert.get("src_ip"), alert.get("dst_port")))

        par_engine = RuleEngine(None, set(), config)
        par_engine.set_alert_sink(_par_sink)

        pipeline = ParallelCapturePipeline(
            rule_engine=par_engine,
            worker_count=2,
            chunk_size=32,
            queue_max=500,
            reorder_max=200,
        )
        res = pipeline.process_pcap_file(pcap_path)

        self.assertEqual(len(par_alerts), len(seq_alerts))
        self.assertEqual(par_alerts, seq_alerts, "Parallel execution MUST reconcile 100% with sequential execution!")
        self.assertTrue(res["packets_per_sec"] > 500.0)

    def test_13_system_telemetry_and_audit_endpoints(self):
        """Verify /api/system/metrics and /api/audit-log."""
        m_resp = self.client.get("/api/system/metrics")
        self.assertEqual(m_resp.status_code, 200)
        m = m_resp.get_json()
        self.assertIn("capabilities", m)
        self.assertIn("performance_profile", m)
        self.assertIn("storage", m)

        a_resp = self.client.get("/api/audit-log")
        self.assertEqual(a_resp.status_code, 200)
        logs = a_resp.get_json()
        self.assertIsInstance(logs, list)


if __name__ == "__main__":
    unittest.main()
