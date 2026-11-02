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
        self.assertEqual(alert["rule_version"], "1.4")
        self.assertEqual(alert["evidence"]["packet_count"], 50)
        self.assertEqual(alert["severity"], "medium")
        self.assertEqual(alert["confidence"], "heuristic")
        self.assertEqual(alert["evidence"]["classification"], "UDP_PACKET_RATE_THRESHOLD")
        self.assertIn("review source context", alert["detail"])
        self.assertEqual(alert["protocol"], "UDP")

    def test_multicast_and_limited_broadcast_do_not_count_as_host_floods(self):
        rule = UdpFloodRule(threshold=3, window=5)
        destinations = ("224.0.0.251", "239.1.2.3", "ff02::fb", "255.255.255.255")
        for dst in destinations:
            with self.subTest(destination=dst):
                for i in range(3):
                    alert = rule.check(self._pkt(
                        "192.168.1.10", dst, src_port=53000, dst_port=5353,
                        ts=100.0 + i * 0.1))
                    self.assertIsNone(alert)
        self.assertEqual(rule._history, {})

    def test_sub_threshold_traffic_does_not_alert(self):
        alert = None
        for i in range(25):  # 25 packets in 5s (threshold is 50)
            res = self.rule.check(self._pkt("192.168.1.150", "192.168.1.1", dst_port=5060, ts=100.0 + i * 0.1))
            if res:
                alert = res

        self.assertIsNone(alert)

    def test_invalid_settings_fall_back_and_do_not_make_one_packet_a_flood(self):
        rule = UdpFloodRule(
            threshold=0, web_threshold="invalid", window=0,
            max_flows="invalid", cooldown=float("nan"),
        )
        self.assertEqual(rule.threshold, 50)
        self.assertEqual(rule.web_threshold, 500)
        self.assertEqual(rule.window, 5)
        self.assertEqual(rule.max_flows, 4096)
        self.assertEqual(rule.cooldown, 60.0)
        self.assertIsNone(rule.check(self._pkt("192.0.2.60", "198.51.100.60")))

    def test_valid_threshold_one_and_zero_cooldown_remain_supported(self):
        rule = UdpFloodRule(threshold=1, cooldown=0)
        self.assertEqual(rule.threshold, 1)
        self.assertEqual(rule.cooldown, 0.0)

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

    def test_cooldown_state_is_bounded_and_preserves_active_keys(self):
        rule = UdpFloodRule(threshold=1, max_flows=2, cooldown=10)
        self.assertIsNotNone(rule.check(self._pkt(
            "192.0.2.40", "198.51.100.80", ts=100)))
        self.assertIsNotNone(rule.check(self._pkt(
            "192.0.2.41", "198.51.100.81", ts=101)))
        self.assertIsNone(rule.check(self._pkt(
            "192.0.2.40", "198.51.100.80", ts=102)))
        self.assertIsNotNone(rule.check(self._pkt(
            "192.0.2.42", "198.51.100.82", ts=103)))

        key_a = ("192.0.2.40", "198.51.100.80")
        key_b = ("192.0.2.41", "198.51.100.81")
        self.assertLessEqual(len(rule._cooldown), rule.max_flows)
        self.assertIn(key_a, rule._cooldown)
        self.assertNotIn(key_b, rule._cooldown)
        self.assertIsNone(rule.check(self._pkt(
            "192.0.2.40", "198.51.100.80", ts=104)))

    def test_active_subthreshold_flow_survives_key_churn(self):
        rule = UdpFloodRule(threshold=3, window=5, max_flows=2)
        a = ("192.0.2.50", "198.51.100.90")
        b = ("192.0.2.51", "198.51.100.91")
        c = ("192.0.2.52", "198.51.100.92")
        self.assertIsNone(rule.check(self._pkt(*a, ts=100)))
        self.assertIsNone(rule.check(self._pkt(*b, ts=101)))
        self.assertIsNone(rule.check(self._pkt(*a, ts=102)))  # refresh A
        self.assertIsNone(rule.check(self._pkt(*c, ts=103)))  # evict B
        alert = rule.check(self._pkt(*a, ts=104))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["packet_count"], 3)

    def test_prune_stale_cleans_expired_states(self):
        self.rule.check(self._pkt("192.168.1.150", "192.168.1.1", ts=100.0))
        self.assertIn(("192.168.1.150", "192.168.1.1"), self.rule._history)

        # Prune at t=120 (well past 5s window)
        self.rule.prune_stale(now=120.0)
        self.assertNotIn(("192.168.1.150", "192.168.1.1"), self.rule._history)


if __name__ == "__main__":
    unittest.main()
