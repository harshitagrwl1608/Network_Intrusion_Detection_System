"""
tests/test_tcp_flag_anomaly.py
--------------------------------
Unit and regression tests for TcpFlagAnomalyRule:
  1. Detects SYN+FIN anomaly (0x03)
  2. Detects SYN+RST anomaly (0x06)
  3. Detects Kamikaze / ALL_FLAGS anomaly (0x3F)
  4. Detects PSH without ACK or SYN
  5. Ignores legitimate TCP traffic (SYN, SYN-ACK, ACK, PSH-ACK, FIN-ACK, RST, RST-ACK)
  6. Enforces alert cooldown to prevent packet-storm flooding
  7. Bounded state cardinality and prune_stale
"""

import os
import sys
import time
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import TcpFlagAnomalyRule


def _tcp_pkt(src="10.0.0.1", dst="10.0.0.2", src_port=54321, dst_port=80,
             flags=0x02, timestamp=None):
    return {
        "type": "IP",
        "src_ip": src,
        "dst_ip": dst,
        "protocol": "TCP",
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_flags": flags,
        "timestamp": timestamp or time.time(),
        "event_timestamp": timestamp or time.time(),
    }


class TestTcpFlagAnomalyRule(unittest.TestCase):

    def setUp(self):
        self.rule = TcpFlagAnomalyRule(cooldown=60.0)

    def test_syn_fin_detected(self):
        alert = self.rule.check(_tcp_pkt(flags=0x03))  # SYN + FIN
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "TCP_FLAG_ANOMALY")
        self.assertEqual(alert["evidence"]["anomaly_type"], "SYN_FIN")
        self.assertEqual(alert["severity"], "high")

    def test_syn_rst_detected(self):
        alert = self.rule.check(_tcp_pkt(flags=0x06))  # SYN + RST
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "SYN_RST")
        self.assertEqual(alert["severity"], "high")

    def test_kamikaze_all_flags_detected(self):
        alert = self.rule.check(_tcp_pkt(flags=0x3F))  # SYN+FIN+RST+PSH+ACK+URG
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "ALL_FLAGS")
        self.assertEqual(alert["severity"], "high")

    def test_psh_without_ack_detected(self):
        alert = self.rule.check(_tcp_pkt(flags=0x08))  # PSH without ACK or SYN
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "PSH_WITHOUT_ACK")

    def test_legitimate_handshakes_not_flagged(self):
        legitimate = [
            0x02,  # SYN
            0x12,  # SYN-ACK
            0x10,  # ACK
            0x18,  # PSH-ACK
            0x11,  # FIN-ACK
            0x19,  # FIN-PSH-ACK
            0x04,  # RST
            0x14,  # RST-ACK
            0xC2,  # SYN-ECE-CWR (ECN setup)
            0x50,  # ACK-ECE
            0x29,  # FIN-PSH-URG (Xmas probe, handled by TcpStealthScanRule)
        ]
        for flag in legitimate:
            alert = self.rule.check(_tcp_pkt(flags=flag))
            self.assertIsNone(alert, f"Legitimate flag 0x{flag:02x} should not be flagged")

    def test_cooldown_suppresses_repeat_alerts(self):
        base = time.time()
        first = self.rule.check(_tcp_pkt(src="192.168.1.50", flags=0x03, timestamp=base))
        self.assertIsNotNone(first)

        # Repeated packets during cooldown should be suppressed
        second = self.rule.check(_tcp_pkt(src="192.168.1.50", flags=0x03, timestamp=base + 1.0))
        self.assertIsNone(second)

        # After cooldown, new alert fires
        third = self.rule.check(_tcp_pkt(src="192.168.1.50", flags=0x03, timestamp=base + 61.0))
        self.assertIsNotNone(third)

    def test_different_anomaly_types_cooldown_independently(self):
        base = time.time()
        a1 = self.rule.check(_tcp_pkt(src="192.168.1.60", flags=0x03, timestamp=base))
        a2 = self.rule.check(_tcp_pkt(src="192.168.1.60", flags=0x06, timestamp=base + 0.1))
        self.assertIsNotNone(a1)
        self.assertIsNotNone(a2)
        self.assertEqual(a1["evidence"]["anomaly_type"], "SYN_FIN")
        self.assertEqual(a2["evidence"]["anomaly_type"], "SYN_RST")

    def test_non_tcp_ignored(self):
        pkt = {
            "type": "IP",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "UDP",
            "src_port": 53,
            "dst_port": 53,
            "tcp_flags": 0x03,
        }
        self.assertIsNone(self.rule.check(pkt))

    def test_prune_stale(self):
        base = time.time()
        self.rule.check(_tcp_pkt(src="10.1.1.1", flags=0x03, timestamp=base))
        self.assertEqual(len(self.rule._cooldown), 1)
        self.rule.prune_stale(base + 1000)
        self.assertEqual(len(self.rule._cooldown), 0)


if __name__ == "__main__":
    unittest.main()
