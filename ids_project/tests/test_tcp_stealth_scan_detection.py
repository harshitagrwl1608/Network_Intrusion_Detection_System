import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import TcpStealthScanRule


class TestTcpStealthScanRule(unittest.TestCase):
    def setUp(self):
        self.rule = TcpStealthScanRule(threshold=6, window=10)

    @staticmethod
    def packet(port, ts, flags, src="203.0.113.44", dst="203.0.113.80"):
        return {
            "type": "IP", "src_ip": src, "dst_ip": dst,
            "src_port": 50000, "dst_port": port, "protocol": "TCP",
            "tcp_flags": flags, "timestamp": ts,
        }

    def test_fin_null_and_xmas_probes_trigger_with_evidence(self):
        alert = None
        flags = (0x01, 0x00, 0x29)
        for i in range(6):
            alert = self.rule.check(self.packet(1000 + i, 100 + i * 0.1, flags[i % 3]))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "TCP_STEALTH_SCAN")
        self.assertEqual(alert["evidence"]["distinct_ports"], 6)
        self.assertEqual(alert["evidence"]["probe_types"], ["FIN", "NULL", "XMAS"])
        self.assertEqual(alert["evidence"]["scan_type"], "stealth_vertical")

    def test_normal_and_mixed_flags_do_not_accumulate(self):
        for i, flags in enumerate((0x02, 0x12, 0x10, 0x04, 0x05, 0x11, 0x09, 0x21)):
            self.assertIsNone(self.rule.check(self.packet(2000 + i, 100 + i, flags)))
        self.assertEqual(self.rule._probes, {})

    def test_duplicate_ports_are_not_extra_scan_evidence(self):
        for ts in range(20):
            self.assertIsNone(self.rule.check(self.packet(80, 100 + ts * 0.1, 0x01)))
        self.assertEqual(len(self.rule._probes[("203.0.113.44", "203.0.113.80")]), 1)
        for port in range(81, 86):
            alert = self.rule.check(self.packet(port, 103, 0x01))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["distinct_ports"], 6)

    def test_old_and_late_observations_do_not_corrupt_window(self):
        rule = TcpStealthScanRule(threshold=3, window=5)
        rule.check(self.packet(80, 100, 0x01))
        rule.check(self.packet(81, 101, 0x01))
        self.assertIsNone(rule.check(self.packet(82, 99, 0x01)))
        self.assertIsNone(rule.check(self.packet(82, 106, 0x01)))
        self.assertIsNone(rule.check(self.packet(83, 107, 0x01)))
        alert = rule.check(self.packet(84, 108, 0x01))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["window_start"], 106)

    def test_state_cardinality_is_bounded_and_prunable(self):
        rule = TcpStealthScanRule(threshold=50, window=5, max_states=2)
        for i in range(5):
            rule.check(self.packet(80, 100 + i, 0x01, src=f"198.51.100.{i + 1}"))
        self.assertLessEqual(len(rule._probes), 2)
        rule.prune_stale(200)
        self.assertEqual(rule._probes, {})


if __name__ == "__main__":
    unittest.main()
