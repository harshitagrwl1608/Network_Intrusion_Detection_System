import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import PortScanRule, UdpScanRule


class TestUdpScanRule(unittest.TestCase):
    def setUp(self):
        self.rule = UdpScanRule(threshold=4, window=10)

    @staticmethod
    def record(dst_port, ts, dst_ip="198.51.100.20", **overrides):
        record = {
            "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.20",
            "dst_ip": dst_ip, "src_port": 52000, "dst_port": dst_port,
            "timestamp": ts,
        }
        record.update(overrides)
        return record

    def test_distinct_udp_ports_trigger_vertical_scan(self):
        for port in (1000, 1001, 1002):
            self.assertIsNone(self.rule.check(self.record(port, 100)))
        alert = self.rule.check(self.record(1003, 101))
        self.assertEqual(alert["rule_name"], "UDP_SCAN")
        self.assertEqual(alert["evidence"]["distinct_ports"], 4)
        self.assertEqual(alert["evidence"]["transport"], "UDP")

    def test_tcp_scan_rule_still_ignores_udp(self):
        tcp_rule = PortScanRule(threshold=2, window=10)
        for port in (1000, 1001, 1002):
            self.assertIsNone(tcp_rule.check(self.record(port, 100)))

    def test_udp_rule_ignores_tcp_and_dns_server_replies(self):
        for port in (1000, 1001, 1002, 1003):
            self.assertIsNone(self.rule.check(
                self.record(port, 100, protocol="TCP", initial_syn=True)
            ))
            self.assertIsNone(self.rule.check(
                self.record(port, 100, src_port=53)
            ))

    def test_duplicates_do_not_trigger_and_horizon_scan_does(self):
        for i in range(20):
            self.assertIsNone(self.rule.check(
                self.record(5000, 100 + i * 0.1, dst_ip="198.51.100.20")
            ))
        result = None
        for i in range(4):
            result = self.rule.check(
                self.record(5001, 103 + i * 0.1, dst_ip=f"198.51.100.{i + 1}")
            )
        self.assertIsNotNone(result)
        self.assertEqual(result["evidence"]["scan_type"], "horizontal")


if __name__ == "__main__":
    unittest.main()
