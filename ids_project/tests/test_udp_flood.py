import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import engine.rules as rules_mod
from engine.rules import UdpFloodRule


class TestUdpFloodRule(unittest.TestCase):
    def setUp(self):
        self.rule = UdpFloodRule(threshold=50, window=5, cooldown=60.0)
        rules_mod.TRUSTED_HOSTS.clear()

    @staticmethod
    def _pkt(src_ip, dst_ip, src_port=50000, dst_port=5060, ts=100.0, proto="UDP"):
        return {
            "type": "IP",
            "protocol": proto,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "timestamp": ts,
            "event_timestamp": ts,
        }

    def test_udp_flood_triggers_alert(self):
        alert = None
        for i in range(50):
            res = self.rule.check(self._pkt("192.168.1.150", "192.168.1.1", dst_port=5060, ts=100.0 + i * 0.05))
            if res:
                alert = res

        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "UDP_FLOOD")
        self.assertEqual(alert["evidence"]["packet_count"], 50)
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["protocol"], "UDP")

    def test_sub_threshold_traffic_does_not_alert(self):
        alert = None
        for i in range(25):  # 25 packets in 5s (threshold is 50)
            res = self.rule.check(self._pkt("192.168.1.150", "192.168.1.1", dst_port=5060, ts=100.0 + i * 0.1))
            if res:
                alert = res

        self.assertIsNone(alert)

    def test_quic_port_uses_higher_web_burst_threshold(self):
        rule = UdpFloodRule(threshold=50, web_threshold=100, window=5)
        for i in range(99):
            self.assertIsNone(rule.check(self._pkt(
                "192.0.2.10", "198.51.100.20", src_port=52000,
                dst_port=443, ts=100.0 + i * 0.01)))
        alert = rule.check(self._pkt(
            "192.0.2.10", "198.51.100.20", src_port=52000,
            dst_port=443, ts=101.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["threshold"], 100)

    def test_dns_server_reply_is_exempt(self):
        # src_port == 53 is a DNS reply from a resolver, not a flood attack from the client
        for i in range(60):
            alert = self.rule.check(self._pkt("8.8.8.8", "192.168.1.50", src_port=53, dst_port=50000 + i, ts=100.0 + i * 0.02))
            self.assertIsNone(alert)

    def test_ntp_and_dhcp_replies_are_exempt(self):
        # src_port 123 (NTP) and 67 (DHCP server)
        for i in range(60):
            alert = self.rule.check(self._pkt("192.168.1.1", "192.168.1.50", src_port=123, dst_port=123, ts=100.0 + i * 0.02))
            self.assertIsNone(alert)
        for i in range(60):
            alert = self.rule.check(self._pkt("192.168.1.1", "192.168.1.50", src_port=67, dst_port=68, ts=110.0 + i * 0.02))
            self.assertIsNone(alert)

    def test_trusted_host_is_exempt(self):
        rules_mod.TRUSTED_HOSTS.add("192.168.1.150")
        for i in range(60):
            alert = self.rule.check(self._pkt("192.168.1.150", "192.168.1.1", ts=100.0 + i * 0.02))
            self.assertIsNone(alert)

    def test_alert_cooldown_prevents_duplicate_alerts(self):
        # First flood triggers
        first_alert = None
        for i in range(50):
            res = self.rule.check(self._pkt("192.168.1.150", "192.168.1.1", ts=100.0 + i * 0.05))
            if res:
                first_alert = res
        self.assertIsNotNone(first_alert)

        # Subsequent packets within 60s cooldown do NOT trigger
        second_alert = None
        for i in range(50):
            res = self.rule.check(self._pkt("192.168.1.150", "192.168.1.1", ts=105.0 + i * 0.05))
            if res:
                second_alert = res
        self.assertIsNone(second_alert)

    def test_prune_stale_cleans_expired_states(self):
        self.rule.check(self._pkt("192.168.1.150", "192.168.1.1", ts=100.0))
        self.assertIn(("192.168.1.150", "192.168.1.1"), self.rule._history)

        # Prune at t=120 (well past 5s window)
        self.rule.prune_stale(now=120.0)
        self.assertNotIn(("192.168.1.150", "192.168.1.1"), self.rule._history)


if __name__ == "__main__":
    unittest.main()
