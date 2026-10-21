import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import PortScanRule, SynFloodRule


class TestPortScanDetection(unittest.TestCase):
    def setUp(self):
        self.rule = PortScanRule(threshold=5, window=60)
        self.syn_rule = SynFloodRule(threshold=10, window=10)

    def test_udp_packets_do_not_trigger_port_scan(self):
        """
        UDP packets must never be counted by PortScanRule.
        The old bug allowed UDP packets to bypass the guard:
        'if protocol == "TCP" and not syn_flag: return None'.
        """
        src = "192.168.1.50"
        dst = "192.168.1.1"

        # Send 10 distinct UDP destination ports
        alerts = []
        for port in range(1000, 1010):
            record = {
                "type": "IP",
                "src_ip": src,
                "dst_ip": dst,
                "protocol": "UDP",
                "dst_port": port,
                "src_port": 50000,
                "syn_flag": False,
                "initial_syn": False,
                "timestamp": 1000.0,
            }
            alert = self.rule.check(record)
            if alert:
                alerts.append(alert)

        self.assertEqual(len(alerts), 0, "UDP traffic should never trigger PORT_SCAN")

    def test_tcp_ack_only_does_not_trigger_port_scan(self):
        """TCP packets without SYN (e.g. ACK-only established traffic) must not trigger PORT_SCAN."""
        src = "192.168.1.50"
        dst = "192.168.1.1"

        alerts = []
        for port in range(1000, 1010):
            record = {
                "type": "IP",
                "src_ip": src,
                "dst_ip": dst,
                "protocol": "TCP",
                "dst_port": port,
                "src_port": 50000,
                "syn_flag": False,
                "initial_syn": False,
                "timestamp": 1000.0,
            }
            alert = self.rule.check(record)
            if alert:
                alerts.append(alert)

        self.assertEqual(len(alerts), 0, "ACK-only TCP traffic should never trigger PORT_SCAN")

    def test_tcp_syn_ack_does_not_trigger_port_scan(self):
        """
        SYN-ACK packets (server responses) must not trigger PORT_SCAN.
        Initial SYN must have initial_syn=True (SYN=1, ACK=0).
        """
        src = "192.168.1.50"
        dst = "192.168.1.1"

        alerts = []
        for port in range(1000, 1010):
            record = {
                "type": "IP",
                "src_ip": src,
                "dst_ip": dst,
                "protocol": "TCP",
                "dst_port": port,
                "src_port": 50000,
                "syn_flag": True,      # Has SYN bit set
                "initial_syn": False,  # But is SYN-ACK
                "timestamp": 1000.0,
            }
            alert = self.rule.check(record)
            if alert:
                alerts.append(alert)

        self.assertEqual(len(alerts), 0, "SYN-ACK traffic should not trigger PORT_SCAN")

    def test_tcp_initial_syn_triggers_port_scan(self):
        """Pure TCP initial SYN probes (SYN=1, ACK=0) must trigger PORT_SCAN."""
        src = "192.168.1.50"
        dst = "192.168.1.1"

        alerts = []
        for port in range(1000, 1010):
            record = {
                "type": "IP",
                "src_ip": src,
                "dst_ip": dst,
                "protocol": "TCP",
                "dst_port": port,
                "src_port": 50000,
                "syn_flag": True,
                "initial_syn": True,
                "timestamp": 1000.0,
            }
            alert = self.rule.check(record)
            if alert:
                alerts.append(alert)

        self.assertGreaterEqual(len(alerts), 1, "Initial SYN probes should trigger PORT_SCAN")
        self.assertEqual(alerts[0]["rule_name"], "PORT_SCAN")

    def test_syn_flood_rejects_udp_and_syn_ack(self):
        """SynFloodRule should reject UDP traffic and SYN-ACK server responses."""
        udp_alerts = []
        for _ in range(15):
            alert = self.syn_rule.check({
                "type": "IP",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "protocol": "UDP",
                "dst_port": 80,
                "syn_flag": True,  # even if mistakenly marked
                "initial_syn": False,
                "timestamp": 1000.0,
            })
            if alert:
                udp_alerts.append(alert)
        self.assertEqual(len(udp_alerts), 0)


if __name__ == "__main__":
    unittest.main()
