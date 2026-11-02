"""
tests/test_icmp_flood.py
-------------------------
Unit and regression tests for IcmpFloodRule:
  1. Detects high-rate ICMP Echo requests to a single host (IPv4 type 8)
  2. Detects high-rate ICMPv6 Echo requests (IPv6 type 128)
  3. Ignores ICMP Echo replies (type 0, 129) and non-echo types
  4. Respects threshold and window parameters
  5. Enforces alert cooldown per (source, destination)
  6. Prunes stale sliding window state cleanly
"""

import os
import sys
import time
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import IcmpFloodRule


def _icmp_pkt(src="10.0.0.1", dst="10.0.0.2", icmp_type=8,
              protocol="ICMP", icmp_code=0, timestamp=None):
    return {
        "type": "IP",
        "src_ip": src,
        "dst_ip": dst,
        "protocol": protocol,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "timestamp": timestamp or time.time(),
        "event_timestamp": timestamp or time.time(),
    }


class TestIcmpFloodRule(unittest.TestCase):

    def setUp(self):
        self.rule = IcmpFloodRule(threshold=10, window=5)

    def test_fires_when_threshold_reached(self):
        base = time.time()
        alert = None
        for i in range(10):
            alert = self.rule.check(_icmp_pkt(timestamp=base + i * 0.1))
            if alert:
                break
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "ICMP_FLOOD")
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["evidence"]["packet_count"], 10)
        self.assertEqual(alert["evidence"]["target_host"], "10.0.0.2")

    def test_does_not_fire_below_threshold(self):
        base = time.time()
        for i in range(9):
            alert = self.rule.check(_icmp_pkt(timestamp=base + i * 0.1))
            self.assertIsNone(alert)

    def test_invalid_settings_fall_back_and_do_not_make_one_packet_a_flood(self):
        rule = IcmpFloodRule(
            threshold=0, window="invalid", max_flows=0, cooldown=-1,
        )
        self.assertEqual(rule.threshold, 50)
        self.assertEqual(rule.window, 5)
        self.assertEqual(rule.max_flows, 4096)
        self.assertEqual(rule.cooldown, 60.0)
        self.assertIsNone(rule.check(_icmp_pkt(timestamp=100.0)))

    def test_valid_threshold_one_and_zero_cooldown_remain_supported(self):
        rule = IcmpFloodRule(threshold=1, cooldown=0)
        self.assertEqual(rule.threshold, 1)
        self.assertEqual(rule.cooldown, 0.0)

    def test_ignores_echo_replies(self):
        base = time.time()
        for i in range(20):
            alert = self.rule.check(_icmp_pkt(icmp_type=0, timestamp=base + i * 0.1))
            self.assertIsNone(alert)

    def test_ignores_nonzero_echo_codes_for_ipv4_and_ipv6(self):
        for protocol, icmp_type, src, dst in (
            ("ICMP", 8, "192.0.2.10", "192.0.2.20"),
            ("ICMPV6", 128, "2001:db8::10", "2001:db8::20"),
        ):
            with self.subTest(protocol=protocol):
                rule = IcmpFloodRule(threshold=2, window=5)
                base = 100.0
                for i in range(3):
                    self.assertIsNone(rule.check(_icmp_pkt(
                        src=src, dst=dst, protocol=protocol, icmp_type=icmp_type,
                        icmp_code=1, timestamp=base + i * 0.1)))
                self.assertEqual(rule._history, {})

                self.assertIsNone(rule.check(_icmp_pkt(
                    src=src, dst=dst, protocol=protocol, icmp_type=icmp_type,
                    icmp_code=0, timestamp=base + 1)))
                alert = rule.check(_icmp_pkt(
                    src=src, dst=dst, protocol=protocol, icmp_type=icmp_type,
                    icmp_code=0, timestamp=base + 1.1))
                self.assertIsNotNone(alert)

    def test_ipv6_echo_request_detected(self):
        base = time.time()
        alert = None
        for i in range(10):
            alert = self.rule.check(_icmp_pkt(
                src="2001:db8::1", dst="2001:db8::2",
                protocol="ICMPV6", icmp_type=128,
                timestamp=base + i * 0.1,
            ))
            if alert:
                break
        self.assertIsNotNone(alert)
        self.assertEqual(alert["protocol"], "ICMPV6")

    def test_ignores_ipv6_echo_replies(self):
        base = time.time()
        for i in range(20):
            alert = self.rule.check(_icmp_pkt(
                src="2001:db8::1", dst="2001:db8::2",
                protocol="ICMPV6", icmp_type=129,
                timestamp=base + i * 0.1,
            ))
            self.assertIsNone(alert)

    def test_cooldown_suppresses_repeat_alerts(self):
        base = time.time()
        first = None
        for i in range(10):
            a = self.rule.check(_icmp_pkt(timestamp=base + i * 0.05))
            if a:
                first = a
                break
        self.assertIsNotNone(first)

        # Immediate additional packets within cooldown should be suppressed
        for i in range(10):
            a = self.rule.check(_icmp_pkt(timestamp=base + 1.0 + i * 0.05))
            self.assertIsNone(a)

    def test_cooldown_state_is_bounded_and_preserves_active_keys(self):
        rule = IcmpFloodRule(threshold=1, window=5, max_flows=2, cooldown=10)
        self.assertIsNotNone(rule.check(_icmp_pkt(
            src="192.0.2.40", dst="192.0.2.80", timestamp=100)))
        self.assertIsNotNone(rule.check(_icmp_pkt(
            src="192.0.2.41", dst="192.0.2.81", timestamp=101)))
        self.assertIsNone(rule.check(_icmp_pkt(
            src="192.0.2.40", dst="192.0.2.80", timestamp=102)))
        self.assertIsNotNone(rule.check(_icmp_pkt(
            src="192.0.2.42", dst="192.0.2.82", timestamp=103)))

        key_a = ("192.0.2.40", "192.0.2.80")
        key_b = ("192.0.2.41", "192.0.2.81")
        self.assertLessEqual(len(rule._cooldown), rule.max_flows)
        self.assertIn(key_a, rule._cooldown)
        self.assertNotIn(key_b, rule._cooldown)
        self.assertIsNone(rule.check(_icmp_pkt(
            src="192.0.2.40", dst="192.0.2.80", timestamp=104)))

    def test_prune_stale(self):
        base = time.time()
        for i in range(5):
            self.rule.check(_icmp_pkt(timestamp=base + i * 0.1))
        self.assertEqual(len(self.rule._history), 1)
        self.rule.prune_stale(base + 100)
        self.assertEqual(len(self.rule._history), 0)


if __name__ == "__main__":
    unittest.main()
