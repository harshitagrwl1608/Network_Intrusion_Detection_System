import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import engine.rules as rules_mod
from engine.rules import DataExfiltrationRule


class TestDataExfiltrationRule(unittest.TestCase):
    def setUp(self):
        self.rule = DataExfiltrationRule(byte_threshold=50000, window=30)
        rules_mod.TRUSTED_HOSTS.clear()

    @staticmethod
    def _pkt(src_ip, dst_ip, payload=b"", ip_len=0, ts=100.0, dst_port=9001, proto="TCP"):
        return {
            "type": "IP",
            "protocol": proto,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": 50000,
            "dst_port": dst_port,
            "payload": payload,
            "ip_len": ip_len if ip_len else (len(payload) + 40 if payload else 60),
            "timestamp": ts,
            "event_timestamp": ts,
        }

    def test_volumetric_exfil_triggers_alert(self):
        # 192.168.1.50 -> 203.0.113.10 (internal -> external)
        chunk = b"A" * 10000
        alert = None
        for i in range(5):  # 5 * 10,000 = 50,000 bytes
            res = self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=chunk, ts=100.0 + i))
            if res:
                alert = res

        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "DATA_EXFIL")
        self.assertEqual(alert["evidence"]["sub_type"], "VOLUMETRIC_EXFIL")
        self.assertEqual(alert["evidence"]["bytes_transferred"], 50000)
        self.assertEqual(alert["severity"], "medium")

    def test_common_web_volume_uses_higher_threshold(self):
        chunk = b"A" * 10000
        for i in range(10):
            self.assertIsNone(self.rule.check(self._pkt(
                "192.168.1.50", "203.0.113.10", payload=chunk,
                dst_port=443, ts=100.0 + i * 0.1)))
        alert = None
        for i in range(90):
            alert = self.rule.check(self._pkt(
                "192.168.1.50", "203.0.113.10", payload=chunk,
                dst_port=443, ts=101.0 + i * 0.1))
            if alert:
                break
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["threshold"], 1_000_000)

    def test_archive_signature_still_alerts_on_web_port(self):
        payload = b"PK\x03\x04archive"
        alert = self.rule.check(self._pkt(
            "192.168.1.50", "203.0.113.10", payload=payload,
            dst_port=443, ts=100.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["sub_type"], "SIGNATURE_EXFIL")

    def test_bytes_on_separate_ports_do_not_combine(self):
        chunk = b"A" * 30000
        for port in (9001, 9002):
            self.assertIsNone(self.rule.check(self._pkt(
                "192.168.1.50", "203.0.113.10", payload=chunk,
                dst_port=port, ts=100.0)))

    def test_sub_threshold_traffic_does_not_alert(self):
        chunk = b"A" * 5000
        alert = None
        for i in range(4):  # 20,000 bytes (below 50,000)
            res = self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=chunk, ts=100.0 + i))
            if res:
                alert = res

        self.assertIsNone(alert)

    def test_internal_to_internal_lan_traffic_is_ignored(self):
        # 192.168.1.50 -> 192.168.1.1 (LAN transfer, e.g. local NAS or gateway)
        chunk = b"A" * 20000
        for i in range(5):  # 100,000 bytes
            alert = self.rule.check(self._pkt("192.168.1.50", "192.168.1.1", payload=chunk, ts=100.0 + i))
            self.assertIsNone(alert)

    def test_external_to_internal_inbound_traffic_is_ignored(self):
        # 203.0.113.10 -> 192.168.1.50 (inbound download from internet)
        chunk = b"A" * 20000
        for i in range(5):  # 100,000 bytes
            alert = self.rule.check(self._pkt("203.0.113.10", "192.168.1.50", payload=chunk, ts=100.0 + i))
            self.assertIsNone(alert)

    def test_database_dump_signature_exfil_triggers_alert(self):
        # Internal host uploads SQLite database to external server
        payload = b"SQLite format 3\x00" + b"\x04\x00\x01\x01" + b"\x00" * 100
        alert = self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=payload, ts=100.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "DATA_EXFIL")
        self.assertEqual(alert["evidence"]["sub_type"], "SIGNATURE_EXFIL")
        self.assertIn("SQLite", alert["detail"])

    def test_zip_archive_signature_exfil_triggers_alert(self):
        # Internal host sends PKZIP archive
        payload = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"sensitive_data.csv"
        alert = self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=payload, ts=100.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["sub_type"], "SIGNATURE_EXFIL")
        self.assertIn("ZIP", alert["detail"])

    def test_dns_traffic_port_53_is_exempt(self):
        chunk = b"A" * 30000
        # Port 53 traffic is ignored (monitored by DnsRule)
        for i in range(3):
            alert = self.rule.check(self._pkt("192.168.1.50", "8.8.8.8", payload=chunk, dst_port=53, ts=100.0 + i))
            self.assertIsNone(alert)

    def test_trusted_host_exemption(self):
        rules_mod.TRUSTED_HOSTS.add("192.168.1.50")
        chunk = b"A" * 30000
        for i in range(3):
            alert = self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=chunk, ts=100.0 + i))
            self.assertIsNone(alert)

    def test_cooldown_prevents_duplicate_alerts(self):
        chunk = b"A" * 30000
        # First two chunks hit threshold (60,000 >= 50,000)
        self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=chunk, ts=100.0))
        first_alert = self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=chunk, ts=101.0))
        self.assertIsNotNone(first_alert)

        # Subsequent packets within 60s cooldown do NOT produce new alerts
        dup_alert = self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=chunk, ts=105.0))
        self.assertIsNone(dup_alert)

    def test_prune_stale_cleans_flow_history(self):
        chunk = b"A" * 10000
        self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=chunk, ts=100.0))
        self.assertIn(("192.168.1.50", "203.0.113.10", 9001, "TCP"), self.rule._flows)

        # Prune at t=150 (30s window passed)
        self.rule.prune_stale(now=150.0)
        self.assertNotIn(("192.168.1.50", "203.0.113.10", 9001, "TCP"), self.rule._flows)


if __name__ == "__main__":
    unittest.main()
