import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import IcmpSweepRule


class TestIcmpSweepRule(unittest.TestCase):
    def setUp(self):
        self.rule = IcmpSweepRule(threshold=4, window=10)

    @staticmethod
    def record(dst, ts, **overrides):
        record = {
            "type": "IP", "protocol": "ICMP", "icmp_type": 8,
            "icmp_code": 0, "src_ip": "192.0.2.10", "dst_ip": dst,
            "event_timestamp": ts,
        }
        record.update(overrides)
        return record

    def test_unique_echo_targets_trigger_with_evidence(self):
        for i in range(3):
            self.assertIsNone(self.rule.check(self.record(f"198.51.100.{i+1}", 100 + i)))
        alert = self.rule.check(self.record("198.51.100.4", 103))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "ICMP_SWEEP")
        self.assertEqual(alert["evidence"]["distinct_targets"], 4)
        self.assertEqual(alert["window_start"], 100)

    def test_ipv6_echo_targets_trigger(self):
        alert = None
        for i in range(4):
            alert = self.rule.check(self.record(
                f"2001:db8::{i + 1}", 200 + i,
                protocol="ICMPV6", icmp_type=128,
            ))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["protocol"], "ICMPV6")
        self.assertEqual(alert["evidence"]["icmp_type"], 128)

    def test_duplicate_targets_do_not_inflate_scan_count(self):
        for i in range(20):
            alert = self.rule.check(self.record("198.51.100.1", 100 + i * 0.1))
        self.assertIsNone(alert)

    def test_duplicate_targets_and_source_cardinality_are_bounded(self):
        rule = IcmpSweepRule(threshold=4, window=10, max_sources=2)
        for i in range(5000):
            alert = rule.check(self.record("198.51.100.1", 100 + i / 1000))
        self.assertIsNone(alert)
        self.assertEqual(len(rule._history["192.0.2.10"]), 1)
        alert = None
        for i in range(3):
            alert = rule.check(self.record(f"198.51.100.{i+2}", 106 + i)) or alert
        self.assertIsNotNone(alert)

        capped = IcmpSweepRule(threshold=100, window=60, max_sources=2)
        for i in range(10):
            capped.check(self.record(
                "198.51.100.1", 200 + i, src_ip=f"192.0.2.{i+1}"
            ))
        self.assertLessEqual(len(capped._history), 2)

    def test_reply_and_non_echo_icmp_are_ignored(self):
        self.assertIsNone(self.rule.check(self.record("198.51.100.1", 100, icmp_type=0)))
        self.assertIsNone(self.rule.check(self.record("198.51.100.2", 101, icmp_type=3)))
        self.assertIsNone(self.rule.check(self.record("198.51.100.3", 102, icmp_code=1)))

    def test_window_expiration_and_out_of_order_event_are_safe(self):
        for i in range(3):
            self.rule.check(self.record(f"198.51.100.{i+1}", 100 + i))
        # The first three probes expired; this fresh burst has only one target.
        self.assertIsNone(self.rule.check(self.record("198.51.100.9", 111)))
        # A late packet cannot be counted into the current burst.
        self.assertIsNone(self.rule.check(self.record("198.51.100.8", 105)))

    def test_prune_stale_clears_history(self):
        self.rule.check(self.record("198.51.100.1", 100))
        self.rule.prune_stale(111)
        self.assertNotIn("192.0.2.10", self.rule._history)


if __name__ == "__main__":
    unittest.main()
