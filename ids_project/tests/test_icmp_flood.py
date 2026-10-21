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
              protocol="ICMP", timestamp=None):
    return {
        "type": "IP",
        "src_ip": src,
        "dst_ip": dst,
        "protocol": protocol,
        "icmp_type": icmp_type,
        "icmp_code": 0,
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

    def test_ignores_echo_replies(self):
        base = time.time()
        for i in range(20):
            alert = self.rule.check(_icmp_pkt(icmp_type=0, timestamp=base + i * 0.1))
            self.assertIsNone(alert)

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

    def test_prune_stale(self):
        base = time.time()
        for i in range(5):
            self.rule.check(_icmp_pkt(timestamp=base + i * 0.1))
        self.assertEqual(len(self.rule._history), 1)
        self.rule.prune_stale(base + 100)
        self.assertEqual(len(self.rule._history), 0)


if __name__ == "__main__":
    unittest.main()
