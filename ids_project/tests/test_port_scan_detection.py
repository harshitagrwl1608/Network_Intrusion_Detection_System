import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import PortScanRule, SynFloodRule, DistributedSynFloodRule, UdpScanRule


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

    def test_late_packet_cannot_corrupt_scan_window(self):
        rule = PortScanRule(threshold=3, window=10)
        def packet(port, ts):
            return {
                "type": "IP", "src_ip": "203.0.113.20", "dst_ip": "203.0.113.30",
                "protocol": "TCP", "dst_port": port, "src_port": 50000,
                "initial_syn": True, "syn_flag": True, "timestamp": ts,
            }
        rule.check(packet(80, 20))
        rule.check(packet(81, 21))
        self.assertIsNone(rule.check(packet(82, 19)))
        alert = rule.check(packet(82, 22))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["window_start"], 20)
        self.assertEqual(alert["window_end"], 22)

    def test_duplicate_tcp_probes_refresh_one_entry_in_scan_state(self):
        rule = PortScanRule(threshold=5, window=60)
        def packet(port, ts, sport=50000):
            return {
                "type": "IP", "src_ip": "203.0.113.21", "dst_ip": "203.0.113.31",
                "protocol": "TCP", "dst_port": port, "src_port": sport,
                "initial_syn": True, "syn_flag": True, "timestamp": ts,
            }
        for i in range(5000):
            self.assertIsNone(rule.check(packet(80, 1000 + i / 1000, 50000 + i % 1000)))
        self.assertEqual(len(rule._vert[("203.0.113.21", "203.0.113.31")]), 1)
        self.assertEqual(len(rule._horiz[("203.0.113.21", 80)]), 1)
        alert = None
        for i, port in enumerate((81, 82, 83, 84), start=1):
            alert = rule.check(packet(port, 1006 + i)) or alert
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["distinct_ports"], 5)

    def test_duplicate_udp_probes_refresh_one_entry_in_scan_state(self):
        rule = UdpScanRule(threshold=5, window=60)
        def packet(port, ts):
            return {
                "type": "IP", "src_ip": "203.0.113.22", "dst_ip": "203.0.113.32",
                "protocol": "UDP", "dst_port": port, "src_port": 52000,
                "timestamp": ts,
            }
        for i in range(5000):
            self.assertIsNone(rule.check(packet(53, 1000 + i / 1000)))
        self.assertEqual(len(rule._vert[("203.0.113.22", "203.0.113.32")]), 1)
        self.assertEqual(len(rule._horiz[("203.0.113.22", 53)]), 1)

    def test_scan_and_syn_flow_key_cardinality_is_bounded(self):
        scan = PortScanRule(threshold=100, window=60, max_states=2)
        syn = SynFloodRule(threshold=100, window=60, max_flows=2)
        for i in range(10):
            src, dst = f"198.51.100.{i+1}", f"203.0.113.{i+1}"
            scan.check({
                "type": "IP", "src_ip": src, "dst_ip": dst, "protocol": "TCP",
                "src_port": 50000, "dst_port": 80 + i, "initial_syn": True,
                "timestamp": 100 + i,
            })
            syn.check({
                "type": "IP", "src_ip": src, "dst_ip": dst, "protocol": "TCP",
                "dst_port": 80 + i, "initial_syn": True, "timestamp": 100 + i,
            })
        self.assertLessEqual(len(scan._vert), 2)
        self.assertLessEqual(len(scan._horiz), 2)
        self.assertLessEqual(len(syn._history), 2)

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

    def test_late_syn_does_not_corrupt_flood_window(self):
        rule = SynFloodRule(threshold=3, window=10)
        def packet(ts):
            return {
                "type": "IP", "src_ip": "203.0.113.20", "dst_ip": "203.0.113.30",
                "protocol": "TCP", "dst_port": 80, "syn_flag": True,
                "initial_syn": True, "timestamp": ts,
            }
        rule.check(packet(20))
        rule.check(packet(21))
        self.assertIsNone(rule.check(packet(19)))
        alert = rule.check(packet(22))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["window_start"], 20)

    def test_distributed_syn_flood_requires_packet_and_source_thresholds(self):
        rule = DistributedSynFloodRule(threshold=6, min_sources=3, window=10)
        alert = None
        for i in range(6):
            alert = rule.check({
                "type": "IP", "src_ip": f"198.51.100.{i % 3 + 1}",
                "dst_ip": "203.0.113.80", "protocol": "TCP", "dst_port": 443,
                "src_port": 40000 + i, "initial_syn": True, "timestamp": 100 + i,
            })
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "DISTRIBUTED_SYN_FLOOD")
        self.assertEqual(alert["evidence"]["syn_count"], 6)
        self.assertEqual(alert["evidence"]["distinct_sources"], 3)

    def test_distributed_syn_flood_does_not_fire_for_one_source_or_syn_ack(self):
        rule = DistributedSynFloodRule(threshold=3, min_sources=2, window=10)
        for i in range(5):
            alert = rule.check({
                "type": "IP", "src_ip": "198.51.100.1", "dst_ip": "203.0.113.80",
                "protocol": "TCP", "dst_port": 443, "initial_syn": True,
                "timestamp": 100 + i,
            })
        self.assertIsNone(alert)
        self.assertIsNone(rule.check({
            "type": "IP", "src_ip": "198.51.100.2", "dst_ip": "203.0.113.80",
            "protocol": "TCP", "dst_port": 443, "initial_syn": False,
            "syn_flag": True, "timestamp": 106,
        }))

    def test_distributed_syn_flood_rejects_late_events_and_prunes(self):
        rule = DistributedSynFloodRule(threshold=3, min_sources=2, window=5)
        def packet(src, ts):
            return {
                "type": "IP", "src_ip": src, "dst_ip": "203.0.113.80",
                "protocol": "TCP", "dst_port": 443, "initial_syn": True,
                "timestamp": ts,
            }
        rule.check(packet("198.51.100.1", 100))
        rule.check(packet("198.51.100.2", 101))
        self.assertIsNone(rule.check(packet("198.51.100.3", 99)))
        rule.prune_stale(107)
        self.assertNotIn(("203.0.113.80", 443), rule._history)

    def test_distributed_syn_flood_memory_is_bounded_without_losing_source_signal(self):
        rule = DistributedSynFloodRule(threshold=3, min_sources=2, window=10)
        def packet(src, dst, ts):
            return {
                "type": "IP", "src_ip": src, "dst_ip": dst,
                "protocol": "TCP", "dst_port": 443, "initial_syn": True,
                "timestamp": ts,
            }

        # Sustained single-source traffic must not grow packet history forever.
        for i in range(1000):
            self.assertIsNone(rule.check(packet("198.51.100.1", "203.0.113.80", 100 + i / 1000)))
        packets, sources = rule._history[("203.0.113.80", 443)]
        self.assertEqual(len(packets), 3)
        self.assertEqual(len(sources), 1)

        # A new source still completes the two independent trigger conditions.
        alert = rule.check(packet("198.51.100.2", "203.0.113.80", 101.1))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["syn_count"], 3)
        self.assertEqual(alert["evidence"]["distinct_sources"], 2)
        self.assertTrue(alert["evidence"]["counts_are_lower_bounds"])

    def test_distributed_syn_flood_bounds_destination_state(self):
        rule = DistributedSynFloodRule(threshold=10, min_sources=2,
                                       window=10, max_targets=2)
        for i in range(10):
            self.assertIsNone(rule.check({
                "type": "IP", "src_ip": "198.51.100.1",
                "dst_ip": f"203.0.113.{i+1}", "protocol": "TCP",
                "dst_port": 443, "initial_syn": True, "timestamp": 100 + i,
            }))
        self.assertLessEqual(len(rule._history), 2)


if __name__ == "__main__":
    unittest.main()
