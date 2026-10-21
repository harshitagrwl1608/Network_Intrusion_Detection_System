import os
import sys
import tempfile
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import DnsRule, ArpSpoofRule


class TestDnsAndArpDetection(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.arp_table_path = os.path.join(self.tmp_dir, "arp_table.json")

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_dns_freq_threshold_zero_disables_frequency_alerts(self):
        """
        DNS_FREQ_THRESHOLD=0 is documented to disable frequency detection.
        In the unfixed code, query_count >= 0 evaluated to True on the first query.
        """
        dns_rule = DnsRule(
            entropy_threshold=4.5,
            max_query_len=100,
            freq_threshold=0,  # 0 means disabled
            freq_window=60,
        )

        # Send a benign short low-entropy query
        record = {
            "type": "IP",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 53,
            "protocol": "UDP",
            "dns_query": "google.com",
            "timestamp": 1000.0,
        }
        alert = dns_rule.check(record)
        self.assertIsNone(alert, "freq_threshold=0 should disable frequency alerts, but an alert was returned")

    def test_dga_whitelist_does_not_suppress_dns_tunneling(self):
        """
        Domains on the CDN whitelist (e.g. cloudfront.net) should be exempt from entropy checks,
        but must NOT suppress excessive length checks (DNS tunneling).
        """
        dns_rule = DnsRule(
            entropy_threshold=3.5,
            max_query_len=60,
            freq_threshold=20,
            freq_window=60,
        )

        # 1. High-entropy CDN query under amazonaws.com (normal length < 60) -> should be exempt
        cdn_record = {
            "type": "IP",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 53,
            "protocol": "UDP",
            "dns_query": "d111111abcdef8.amazonaws.com",
            "timestamp": 1000.0,
        }
        self.assertIsNone(dns_rule.check(cdn_record), "Normal length CDN query should not alert")

        # 2. Tunneling payload disguised under amazonaws.com (> 60 chars) -> MUST fire DNS_TUNNEL
        tunnel_domain = "a" * 50 + "b" * 30 + ".amazonaws.com"  # 94 chars > 60
        tunnel_record = {
            "type": "IP",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 53,
            "protocol": "UDP",
            "dns_query": tunnel_domain,
            "timestamp": 1001.0,
        }
        alert = dns_rule.check(tunnel_record)
        self.assertIsNotNone(alert, "Excessive length under CDN suffix must not be suppressed")
        self.assertEqual(alert.get("evidence", {}).get("sub_type"), "DNS_TUNNEL")

    def test_arp_spoof_cooldown_prevents_alert_storm(self):
        """ARP spoofing alerts should have cooldown for the same IP to prevent alert storms."""
        arp_rule = ArpSpoofRule(table_path=self.arp_table_path)

        # Learn initial MAC
        arp_rule.check({
            "type": "ARP",
            "src_ip": "192.168.1.1",
            "src_mac": "00:11:22:33:44:01",
            "timestamp": 100.0,
        })

        # Conflicting MAC arrives -> first alert must fire
        alert1 = arp_rule.check({
            "type": "ARP",
            "src_ip": "192.168.1.1",
            "src_mac": "00:11:22:33:44:99",
            "timestamp": 101.0,
        })
        self.assertIsNotNone(alert1, "First ARP spoof event must fire")

        # Second conflicting MAC arrives 2 seconds later -> should be suppressed by cooldown
        alert2 = arp_rule.check({
            "type": "ARP",
            "src_ip": "192.168.1.1",
            "src_mac": "00:11:22:33:44:99",
            "timestamp": 103.0,
        })
        self.assertIsNone(alert2, "Rapid repeat ARP spoof for same IP should be suppressed by cooldown")


if __name__ == "__main__":
    unittest.main()
