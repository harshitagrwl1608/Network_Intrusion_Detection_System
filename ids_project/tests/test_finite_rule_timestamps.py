import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import (
    BruteForceRule,
    CleartextHttpOnTlsPortRule,
    DistributedSynFloodRule,
    IcmpFloodRule,
    IcmpSweepRule,
    SlowPortScanRule,
    TcpFlagAnomalyRule,
    TcpStealthScanRule,
    TcpZeroWindowRule,
    UdpFloodRule,
)


class TestFiniteRuleTimestamps(unittest.TestCase):
    def test_invalid_event_timestamps_do_not_mutate_rate_rule_state(self):
        cases = (
            ("UDP_FLOOD", "1.10", lambda: UdpFloodRule(threshold=1), {
                "type": "IP", "protocol": "UDP", "src_ip": "198.51.100.10",
                "dst_ip": "203.0.113.10", "src_port": 50000, "dst_port": 5060,
            }, ("_history", "_cooldown")),
            ("TCP_STEALTH_SCAN", "1.8", lambda: TcpStealthScanRule(threshold=1), {
                "type": "IP", "protocol": "TCP", "src_ip": "198.51.100.11",
                "dst_ip": "203.0.113.11", "src_port": 50000, "dst_port": 22,
                "tcp_flags": 0x01,
            }, ("_probes", "_fired")),
            ("TCP_FLAG_ANOMALY", "1.9", TcpFlagAnomalyRule, {
                "type": "IP", "protocol": "TCP", "src_ip": "198.51.100.12",
                "dst_ip": "203.0.113.12", "src_port": 50000, "dst_port": 22,
                "tcp_flags": 0x03,
            }, ("_cooldown",)),
            ("DISTRIBUTED_SYN_FLOOD", "1.8", lambda: DistributedSynFloodRule(
                threshold=1, min_sources=1), {
                "type": "IP", "protocol": "TCP", "src_ip": "198.51.100.13",
                "dst_ip": "203.0.113.13", "src_port": 50000, "dst_port": 80,
                "initial_syn": True, "tcp_flags": 0x02,
            }, ("_history", "_cooldown")),
            ("ICMP_SWEEP", "1.8", lambda: IcmpSweepRule(threshold=1), {
                "type": "IP", "protocol": "ICMP", "src_ip": "198.51.100.14",
                "dst_ip": "203.0.113.14", "icmp_type": 8, "icmp_code": 0,
            }, ("_history", "_fired")),
            ("ICMP_FLOOD", "1.8", lambda: IcmpFloodRule(threshold=1), {
                "type": "IP", "protocol": "ICMP", "src_ip": "198.51.100.15",
                "dst_ip": "203.0.113.15", "icmp_type": 8, "icmp_code": 0,
            }, ("_history", "_cooldown")),
            ("BRUTE_FORCE", "1.12", lambda: BruteForceRule(threshold=1), {
                "type": "IP", "protocol": "TCP", "src_ip": "198.51.100.16",
                "dst_ip": "203.0.113.16", "src_port": 50000, "dst_port": 22,
                "initial_syn": True, "tcp_flags": 0x02,
            }, ("_history", "_cooldown", "_seen_syns")),
            ("SLOW_PORT_SCAN", "1.11", lambda: SlowPortScanRule(threshold=1), {
                "type": "IP", "protocol": "TCP", "src_ip": "198.51.100.17",
                "dst_ip": "203.0.113.17", "src_port": 50000, "dst_port": 22,
                "initial_syn": True, "tcp_flags": 0x02,
            }, ("_vert", "_horiz", "_alert_cooldown")),
            ("CLEAR_HTTP_ON_TLS_PORT", "1.11", lambda: CleartextHttpOnTlsPortRule(
                min_requests=2), {
                "type": "IP", "protocol": "TCP", "src_ip": "198.51.100.18",
                "dst_ip": "203.0.113.18", "src_port": 50000, "dst_port": 443,
                "payload": b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
            }, ("_history", "_seen", "_saturated", "_tcp_prefixes", "_seen_requests")),
            ("TCP_ZERO_WINDOW", "1.10", lambda: TcpZeroWindowRule(threshold=1), {
                "type": "IP", "protocol": "TCP", "src_ip": "198.51.100.19",
                "dst_ip": "203.0.113.19", "src_port": 50000, "dst_port": 443,
                "tcp_flags": 0x10, "tcp_window": 0,
            }, ("_history", "_fired", "_initiators")),
        )

        for invalid_time in ("bad-time", float("nan"), float("inf")):
            for name, version, make_rule, base_record, state_names in cases:
                with self.subTest(rule=name, timestamp=invalid_time):
                    rule = make_rule()
                    invalid = dict(base_record, timestamp=100.0,
                                   event_timestamp=invalid_time)
                    self.assertIsNone(rule.check(invalid))
                    for state_name in state_names:
                        state = getattr(rule, state_name)
                        self.assertEqual(state, type(state)())

                    valid = dict(base_record, timestamp=100.0,
                                 event_timestamp=100.0)
                    alert = rule.check(valid)
                    if alert is None:
                        next_record = dict(valid, timestamp=101.0,
                                           event_timestamp=101.0)
                        if name not in ("BRUTE_FORCE", "CLEAR_HTTP_ON_TLS_PORT"):
                            next_record["dst_port"] += 1
                        alert = rule.check(next_record)
                    self.assertIsNotNone(alert)
                    self.assertEqual(alert["rule_version"], version)

    def test_finite_record_timestamp_fallback_when_event_timestamp_is_none(self):
        from engine.rules import _finite_record_timestamp, _is_initial_syn
        record = {"event_timestamp": None, "timestamp": 1234567.89}
        self.assertEqual(_finite_record_timestamp(record), 1234567.89)

        record_only_event = {"event_timestamp": 987654.32}
        self.assertEqual(_finite_record_timestamp(record_only_event), 987654.32)

    def test_is_initial_syn_handles_explicit_none_gracefully(self):
        from engine.rules import _is_initial_syn
        record = {"initial_syn": None, "tcp_flags": 0x02}
        self.assertTrue(_is_initial_syn(record))
        record_syn_ack = {"initial_syn": None, "tcp_flags": 0x12}
        self.assertFalse(_is_initial_syn(record_syn_ack))

    def test_arp_spoof_finite_event_timestamp_handling(self):
        from engine.rules import ArpSpoofRule
        import tempfile
        with tempfile.NamedTemporaryFile("w+", suffix=".json") as f:
            f.write("{}")
            f.flush()
            rule = ArpSpoofRule(f.name)
            # Seed entry
            self.assertIsNone(rule.check({
                "type": "ARP", "src_ip": "192.168.1.50", "src_mac": "00:11:22:33:44:55",
                "timestamp": None, "event_timestamp": 100.0,
            }))
            # Spoof entry with timestamp=None but valid event_timestamp
            alert = rule.check({
                "type": "ARP", "src_ip": "192.168.1.50", "src_mac": "00:11:22:33:44:66",
                "timestamp": None, "event_timestamp": 101.0,
            })
            self.assertIsNotNone(alert)
            self.assertEqual(alert["rule_version"], "1.8")
            self.assertEqual(alert["evidence"]["new_mac"], "00:11:22:33:44:66")

    def test_blocklist_whitespace_and_string_ports(self):
        from engine.rules import BlocklistRule
        from engine.blocklist import BlocklistData
        rule = BlocklistRule(BlocklistData(exact={"198.51.100.55"}, networks=[]))
        # Address with surrounding whitespace
        alert = rule.check({
            "type": "IP", "src_ip": "192.168.1.10", "dst_ip": "  198.51.100.55  ",
            "src_port": "54321", "dst_port": "443", "protocol": "TCP",
        })
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_version"], "1.4")
        self.assertEqual(alert["src_port"], 54321)
        self.assertEqual(alert["dst_port"], 443)

    def test_tcp_flag_anomaly_string_ports(self):
        from engine.rules import TcpFlagAnomalyRule
        rule = TcpFlagAnomalyRule()
        alert = rule.check({
            "type": "IP", "protocol": "TCP", "src_ip": "198.51.100.22",
            "dst_ip": "203.0.113.22", "src_port": "50000", "dst_port": "80",
            "tcp_flags": 0x03, "timestamp": 100.0,
        })
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_version"], "1.9")
        self.assertEqual(alert["src_port"], 50000)
        self.assertEqual(alert["dst_port"], 80)

    def test_tcp_stealth_scan_string_ports(self):
        from engine.rules import TcpStealthScanRule
        rule = TcpStealthScanRule(threshold=2, window=10)
        self.assertIsNone(rule.check({
            "type": "IP", "protocol": "TCP", "src_ip": "198.51.100.23",
            "dst_ip": "203.0.113.23", "src_port": "50000", "dst_port": "22",
            "tcp_flags": 0x01, "timestamp": 100.0,
        }))
        alert = rule.check({
            "type": "IP", "protocol": "TCP", "src_ip": "198.51.100.23",
            "dst_ip": "203.0.113.23", "src_port": "50001", "dst_port": "23",
            "tcp_flags": 0x01, "timestamp": 101.0,
        })
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_version"], "1.8")
        self.assertEqual(alert["src_port"], 50001)
        self.assertEqual(alert["dst_port"], 23)


if __name__ == "__main__":
    unittest.main()
