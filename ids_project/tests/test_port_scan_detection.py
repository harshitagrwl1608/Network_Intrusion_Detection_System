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

    def test_tcp_flags_reject_syn_ack_when_initial_syn_metadata_is_missing(self):
        rule = PortScanRule(threshold=2, window=10)
        for i, port in enumerate((22, 23, 25)):
            self.assertIsNone(rule.check({
                "type": "IP", "src_ip": "203.0.113.44",
                "dst_ip": "203.0.113.80", "protocol": "TCP",
                "src_port": 80, "dst_port": port, "syn_flag": True,
                "tcp_flags": 0x12, "timestamp": 100 + i * 0.1,
            }))
        self.assertEqual(rule._vert, {})
        self.assertEqual(rule._horiz, {})

        # Legacy telemetry with only syn_flag remains supported when raw flags
        # are unavailable.
        legacy = PortScanRule(threshold=2, window=10)
        alert = None
        for i, port in enumerate((22, 23)):
            alert = legacy.check({
                "type": "IP", "src_ip": "203.0.113.45",
                "dst_ip": "203.0.113.80", "protocol": "TCP",
                "src_port": 50000, "dst_port": port, "syn_flag": True,
                "timestamp": 101 + i * 0.1,
            }) or alert
        self.assertIsNotNone(alert)

    def test_tcp_scan_using_well_known_source_port_still_triggers(self):
        rule = PortScanRule(threshold=3, window=10)
        alert = None
        for i, port in enumerate((22, 23, 25)):
            alert = rule.check({
                "type": "IP", "src_ip": "203.0.113.44",
                "dst_ip": "203.0.113.80", "protocol": "TCP",
                "src_port": 80, "dst_port": port,
                "initial_syn": True, "timestamp": 100 + i * 0.1,
            }) or alert
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["distinct_ports"], 3)

    def test_udp_scan_keeps_common_service_source_port_exemptions(self):
        rule = UdpScanRule(threshold=3, window=10)
        for i in range(3):
            alert = rule.check({
                "type": "IP", "src_ip": "8.8.8.8",
                "dst_ip": f"203.0.113.{i + 1}", "protocol": "UDP",
                "src_port": 53, "dst_port": 53000, "timestamp": 100 + i,
            })
            self.assertIsNone(alert)
        self.assertEqual(rule._horiz, {})

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

    def test_invalid_port_scan_threshold_and_window_fall_back_to_defaults(self):
        for invalid in (0, -1, "invalid"):
            with self.subTest(value=invalid):
                rule = PortScanRule(threshold=invalid, window=invalid)
                self.assertEqual(rule.threshold, 15)
                self.assertEqual(rule.window, 10)
                self.assertIsNone(rule.check({
                    "type": "IP", "src_ip": "198.51.100.10",
                    "dst_ip": "203.0.113.10", "protocol": "TCP",
                    "src_port": 50000, "dst_port": 443,
                    "initial_syn": True, "timestamp": 100.0,
                }))

    def test_invalid_syn_flood_threshold_and_window_fall_back_to_defaults(self):
        for invalid in (0, -1, "invalid"):
            with self.subTest(value=invalid):
                rule = SynFloodRule(threshold=invalid, window=invalid)
                self.assertEqual(rule.threshold, 100)
                self.assertEqual(rule.window, 10)
                self.assertIsNone(rule.check({
                    "type": "IP", "src_ip": "198.51.100.11",
                    "dst_ip": "203.0.113.11", "protocol": "TCP",
                    "src_port": 50000, "dst_port": 443,
                    "initial_syn": True, "syn_flag": True,
                    "tcp_flags": 0x02, "timestamp": 100.0,
                }))

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

    def test_malformed_timestamps_are_ignored_without_corrupting_scan_window(self):
        for rule_cls, protocol, version in (
            (PortScanRule, "TCP", "1.13"),
            (UdpScanRule, "UDP", "1.4"),
        ):
            for invalid_time in ("bad-time", float("nan"), float("inf")):
                with self.subTest(rule=rule_cls.__name__, timestamp=invalid_time):
                    rule = rule_cls(threshold=3, window=10)
                    base = {
                        "type": "IP", "src_ip": "203.0.113.20",
                        "dst_ip": "203.0.113.30", "protocol": protocol,
                        "src_port": 50000, "initial_syn": True,
                    }
                    self.assertIsNone(rule.check(dict(base, dst_port=80, timestamp=100)))
                    self.assertIsNone(rule.check(dict(base, dst_port=81, timestamp=101)))
                    history_before = dict(rule._vert[(base["src_ip"], base["dst_ip"])])
                    self.assertIsNone(rule.check(dict(
                        base, dst_port=82, timestamp=invalid_time)))
                    self.assertEqual(
                        rule._vert[(base["src_ip"], base["dst_ip"])], history_before)
                    alert = rule.check(dict(base, dst_port=82, timestamp=102))
                    self.assertIsNotNone(alert)
                    self.assertEqual(alert["rule_version"], version)

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

    def test_horizontal_scan_evidence_is_bounded_after_threshold(self):
        rule = PortScanRule(threshold=3, window=60)
        rule._alert_cooldown = 0
        alert = None
        for i in range(500):
            record = {
                "type": "IP", "src_ip": "198.51.100.30",
                "dst_ip": f"203.0.{i // 256}.{i % 256 + 1}",
                "protocol": "TCP", "src_port": 50000, "dst_port": 443,
                "initial_syn": True, "timestamp": 100 + i / 10,
            }
            alert = rule.check(record) or alert
        key = ("198.51.100.30", 443)
        self.assertLessEqual(len(rule._horiz[key]), rule._max_evidence)
        self.assertTrue(rule._horiz_saturated.__contains__(key))
        self.assertLessEqual(alert["evidence"]["distinct_hosts"], rule._max_evidence)
        self.assertTrue(alert["evidence"]["distinct_hosts_saturated"])
        self.assertIn("at least", alert["detail"])

    def test_port_scan_cooldown_state_is_bounded_under_key_churn(self):
        rule = PortScanRule(threshold=2, window=60, max_states=5)
        for i in range(20):
            src, dst = f"198.51.{i}.1", f"203.0.{i}.1"
            for j in range(2):
                rule.check({
                    "type": "IP", "src_ip": src, "dst_ip": dst,
                    "protocol": "TCP", "src_port": 50000,
                    "dst_port": 80 + j, "initial_syn": True,
                    "timestamp": 100 + i + j / 10,
                })
        self.assertLessEqual(len(rule._vert), rule.max_states)
        self.assertLessEqual(len(rule._horiz), rule.max_states)
        self.assertLessEqual(len(rule._vert_fired), rule.max_states)
        self.assertLessEqual(len(rule._horiz_fired), rule.max_states)

    def test_active_vertical_scan_history_is_not_evicted_by_new_keys(self):
        rule = PortScanRule(threshold=3, window=60, max_states=2)

        def packet(src, dst, port, timestamp):
            return {
                "type": "IP", "src_ip": src, "dst_ip": dst,
                "protocol": "TCP", "src_port": 50000, "dst_port": port,
                "initial_syn": True, "timestamp": timestamp,
            }

        a = ("198.51.100.40", "203.0.113.40")
        b = ("198.51.100.41", "203.0.113.41")
        c = ("198.51.100.42", "203.0.113.42")
        self.assertIsNone(rule.check(packet(*a, 80, 100)))
        self.assertIsNone(rule.check(packet(*b, 80, 101)))
        self.assertIsNone(rule.check(packet(*a, 81, 102)))  # refresh A
        self.assertIsNone(rule.check(packet(*c, 80, 103)))  # evict B
        alert = rule.check(packet(*a, 82, 104))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["scan_type"], "vertical")
        self.assertEqual(alert["evidence"]["distinct_ports"], 3)

    def test_invalid_state_limit_uses_default_and_preserves_scan_history(self):
        rule = PortScanRule(threshold=2, window=60, max_states=0)
        self.assertEqual(rule.max_states, 10_000)

        def packet(src, dst, port, timestamp):
            return {
                "type": "IP", "src_ip": src, "dst_ip": dst,
                "protocol": "TCP", "src_port": 50000, "dst_port": port,
                "initial_syn": True, "timestamp": timestamp,
            }

        self.assertIsNone(rule.check(packet("198.51.100.60", "203.0.113.60", 22, 100)))
        self.assertIsNone(rule.check(packet("198.51.100.61", "203.0.113.61", 22, 101)))
        alert = rule.check(packet("198.51.100.60", "203.0.113.60", 23, 102))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["distinct_ports"], 2)

    def test_active_horizontal_scan_history_is_not_evicted_by_new_keys(self):
        rule = PortScanRule(threshold=3, window=60, max_states=2)

        def packet(src, dst, timestamp):
            return {
                "type": "IP", "src_ip": src, "dst_ip": dst,
                "protocol": "TCP", "src_port": 50000, "dst_port": 443,
                "initial_syn": True, "timestamp": timestamp,
            }

        a = "198.51.100.50"
        b = "198.51.100.51"
        c = "198.51.100.52"
        self.assertIsNone(rule.check(packet(a, "203.0.113.50", 100)))
        self.assertIsNone(rule.check(packet(b, "203.0.113.51", 101)))
        self.assertIsNone(rule.check(packet(a, "203.0.113.52", 102)))  # refresh A
        self.assertIsNone(rule.check(packet(c, "203.0.113.53", 103)))  # evict B
        alert = rule.check(packet(a, "203.0.113.54", 104))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["scan_type"], "horizontal")
        self.assertEqual(alert["evidence"]["distinct_hosts"], 3)

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

        # Older records may omit initial_syn but still carry raw flags. The
        # ACK bit must prevent SYN-ACK replies from entering the SYN history.
        syn_ack_alerts = []
        for i in range(15):
            alert = self.syn_rule.check({
                "type": "IP", "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
                "protocol": "TCP", "src_port": 80, "dst_port": 50000 + i,
                "syn_flag": True, "tcp_flags": 0x12, "timestamp": 1000.0 + i,
            })
            if alert:
                syn_ack_alerts.append(alert)
        self.assertEqual(syn_ack_alerts, [])
        self.assertEqual(self.syn_rule._history, {})

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

    def test_distributed_flood_uses_raw_flags_when_initial_syn_metadata_is_missing(self):
        rule = DistributedSynFloodRule(threshold=3, min_sources=2, window=10)
        for i in range(3):
            alert = rule.check({
                "type": "IP", "src_ip": f"198.51.100.{i + 1}",
                "dst_ip": "203.0.113.80", "protocol": "TCP", "dst_port": 443,
                "src_port": 40000 + i, "syn_flag": True, "tcp_flags": 0x12,
                "timestamp": 100 + i,
            })
            self.assertIsNone(alert)
        self.assertEqual(rule._history, {})

    def test_distributed_syn_flood_suppresses_alert_storm_but_recovers_for_later_burst(self):
        rule = DistributedSynFloodRule(threshold=3, min_sources=2,
                                       window=5, max_targets=8)
        rule.ALERT_COOLDOWN_S = 3.0

        def packet(src, ts):
            return {
                "type": "IP", "src_ip": src, "dst_ip": "203.0.113.81",
                "protocol": "TCP", "dst_port": 443, "initial_syn": True,
                "timestamp": ts,
            }

        sources = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
        alerts = [rule.check(packet(sources[i % 3], 100 + i * 0.1)) for i in range(3)]
        self.assertEqual(sum(alert is not None for alert in alerts), 1)

        # A sustained burst remains over threshold but must not emit an alert
        # for every subsequent SYN while the target cooldown is active.
        followups = [rule.check(packet(sources[i % 3], 100.4 + i * 0.05))
                     for i in range(30)]
        self.assertFalse(any(alert is not None for alert in followups))

        # Once both the event window and alert cooldown expire, a new burst fires.
        later = [rule.check(packet(sources[i % 2], 110 + i * 0.1))
                 for i in range(3)]
        self.assertEqual(sum(alert is not None for alert in later), 1)

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

    def test_distributed_syn_flood_bounds_cooldown_state_with_target_eviction(self):
        rule = DistributedSynFloodRule(threshold=1, min_sources=1,
                                       window=10, max_targets=2)
        for i in range(3):
            alert = rule.check({
                "type": "IP", "src_ip": f"198.51.100.{i + 1}",
                "dst_ip": f"203.0.113.{i + 1}", "protocol": "TCP",
                "dst_port": 443, "initial_syn": True, "timestamp": 100 + i,
            })
            self.assertIsNotNone(alert)
        self.assertLessEqual(len(rule._history), 2)
        self.assertLessEqual(len(rule._cooldown), 2)

    def test_distributed_syn_invalid_settings_use_defaults(self):
        rule = DistributedSynFloodRule(
            threshold=0, min_sources=0, window=0, max_targets="invalid")
        self.assertEqual(rule.threshold, 500)
        self.assertEqual(rule.min_sources, 20)
        self.assertEqual(rule.window, 10)
        self.assertEqual(rule.max_targets, 2048)
        alert = rule.check({
            "type": "IP", "src_ip": "198.51.100.10", "dst_ip": "203.0.113.80",
            "protocol": "TCP", "dst_port": 443, "initial_syn": True,
            "timestamp": 100,
        })
        self.assertIsNone(alert)
        self.assertEqual(len(rule._history[("203.0.113.80", 443)][0]), 1)

    def test_distributed_syn_flood_prune_stale_optional_now_and_source_lru(self):
        rule = DistributedSynFloodRule(threshold=10, min_sources=2, window=10)
        def packet(src, ts):
            return {
                "type": "IP", "src_ip": src, "dst_ip": "203.0.113.80",
                "protocol": "TCP", "dst_port": 443, "initial_syn": True,
                "timestamp": ts,
            }
        # Populate sources
        rule.check(packet("198.51.100.1", 100))
        rule.check(packet("198.51.100.2", 101))
        # Refresh 198.51.100.1 recency
        rule.check(packet("198.51.100.1", 102))
        # Add third source; since min_sources=2, oldest source (198.51.100.2) should be evicted
        rule.check(packet("198.51.100.3", 103))
        _, sources = rule._history[("203.0.113.80", 443)]
        self.assertIn("198.51.100.1", sources)
        self.assertNotIn("198.51.100.2", sources)
        self.assertIn("198.51.100.3", sources)

        # prune_stale with default now=None
        rule.prune_stale()
        self.assertNotIn(("203.0.113.80", 443), rule._history)

    def test_port_scan_prune_stale_clears_future_drifted_cooldown_and_orphaned_saturated(self):
        rule = PortScanRule(threshold=3, window=10)
        # Manually populate cooldown with future drift and stale past
        vkey_stale = ("192.0.2.1", "198.51.100.1")
        vkey_future = ("192.0.2.2", "198.51.100.2")
        rule._vert_fired[vkey_stale] = 50.0   # older than cutoff (now=100, window=10 -> cutoff=90)
        rule._vert_fired[vkey_future] = 200.0  # future drift relative to now=100
        rule._vert_saturated.add(vkey_stale)
        rule._vert_saturated.add(vkey_future)

        rule.prune_stale(now=100.0)

        # Both stale past and future drift should be pruned from _vert_fired
        self.assertNotIn(vkey_stale, rule._vert_fired)
        self.assertNotIn(vkey_future, rule._vert_fired)
        # Saturated sets should not retain orphaned keys
        self.assertNotIn(vkey_stale, rule._vert_saturated)
        self.assertNotIn(vkey_future, rule._vert_saturated)

    def test_clock_skew_future_poison_does_not_blind_port_scan(self):
        """Verifies that an injected future-timestamp packet does not blind PortScanRule (EV-02)."""
        rule = PortScanRule(threshold=5, window=10)
        # Attacker injects a single packet with a distant future timestamp
        pkt_future = {
            "type": "IP", "protocol": "TCP", "src_ip": "192.168.1.100", "dst_ip": "192.168.1.1",
            "src_port": 50000, "dst_port": 80, "initial_syn": True, "timestamp": 200.0,
        }
        rule.check(pkt_future)

        # Attacker then proceeds with real scan at current chronological time (105.0)
        alerts = []
        for port in range(81, 90):
            pkt = {
                "type": "IP", "protocol": "TCP", "src_ip": "192.168.1.100", "dst_ip": "192.168.1.1",
                "src_port": 50000 + port, "dst_port": port, "initial_syn": True, "timestamp": 105.0,
            }
            res = rule.check(pkt)
            if res:
                alerts.append(res)
        self.assertGreaterEqual(len(alerts), 1, "Future timestamp packet must not blind PortScanRule")
        self.assertEqual(alerts[0]["rule_name"], "PORT_SCAN")


if __name__ == "__main__":
    unittest.main()
