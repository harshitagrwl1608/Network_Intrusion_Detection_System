import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import (
    BruteForceRule,
    DistributedSynFloodRule,
    IcmpFloodRule,
    IcmpSweepRule,
    SlowPortScanRule,
    TcpFlagAnomalyRule,
    TcpStealthScanRule,
    UdpFloodRule,
)


class TestFiniteRuleTimestamps(unittest.TestCase):
    def test_invalid_event_timestamps_do_not_mutate_rate_rule_state(self):
        cases = (
            ("UDP_FLOOD", "1.5", lambda: UdpFloodRule(threshold=1), {
                "type": "IP", "protocol": "UDP", "src_ip": "198.51.100.10",
                "dst_ip": "203.0.113.10", "src_port": 50000, "dst_port": 5060,
            }, ("_history", "_cooldown")),
            ("TCP_STEALTH_SCAN", "1.5", lambda: TcpStealthScanRule(threshold=1), {
                "type": "IP", "protocol": "TCP", "src_ip": "198.51.100.11",
                "dst_ip": "203.0.113.11", "src_port": 50000, "dst_port": 22,
                "tcp_flags": 0x01,
            }, ("_probes", "_fired")),
            ("TCP_FLAG_ANOMALY", "1.5", TcpFlagAnomalyRule, {
                "type": "IP", "protocol": "TCP", "src_ip": "198.51.100.12",
                "dst_ip": "203.0.113.12", "src_port": 50000, "dst_port": 22,
                "tcp_flags": 0x03,
            }, ("_cooldown",)),
            ("DISTRIBUTED_SYN_FLOOD", "1.6", lambda: DistributedSynFloodRule(
                threshold=1, min_sources=1), {
                "type": "IP", "protocol": "TCP", "src_ip": "198.51.100.13",
                "dst_ip": "203.0.113.13", "src_port": 50000, "dst_port": 80,
                "initial_syn": True, "tcp_flags": 0x02,
            }, ("_history", "_cooldown")),
            ("ICMP_SWEEP", "1.4", lambda: IcmpSweepRule(threshold=1), {
                "type": "IP", "protocol": "ICMP", "src_ip": "198.51.100.14",
                "dst_ip": "203.0.113.14", "icmp_type": 8, "icmp_code": 0,
            }, ("_history", "_fired")),
            ("ICMP_FLOOD", "1.5", lambda: IcmpFloodRule(threshold=1), {
                "type": "IP", "protocol": "ICMP", "src_ip": "198.51.100.15",
                "dst_ip": "203.0.113.15", "icmp_type": 8, "icmp_code": 0,
            }, ("_history", "_cooldown")),
            ("BRUTE_FORCE", "1.8", lambda: BruteForceRule(threshold=1), {
                "type": "IP", "protocol": "TCP", "src_ip": "198.51.100.16",
                "dst_ip": "203.0.113.16", "src_port": 50000, "dst_port": 22,
                "initial_syn": True, "tcp_flags": 0x02,
            }, ("_history", "_cooldown", "_seen_syns")),
            ("SLOW_PORT_SCAN", "1.6", lambda: SlowPortScanRule(threshold=1), {
                "type": "IP", "protocol": "TCP", "src_ip": "198.51.100.17",
                "dst_ip": "203.0.113.17", "src_port": 50000, "dst_port": 22,
                "initial_syn": True, "tcp_flags": 0x02,
            }, ("_vert", "_horiz", "_alert_cooldown")),
        )

        for invalid_time in ("bad-time", float("nan"), float("inf")):
            for name, version, make_rule, base_record, state_names in cases:
                with self.subTest(rule=name, timestamp=invalid_time):
                    rule = make_rule()
                    invalid = dict(base_record, timestamp=100.0,
                                   event_timestamp=invalid_time)
                    self.assertIsNone(rule.check(invalid))
                    for state_name in state_names:
                        self.assertEqual(getattr(rule, state_name), {})

                    valid = dict(base_record, timestamp=100.0,
                                 event_timestamp=100.0)
                    alert = rule.check(valid)
                    if alert is None:
                        next_record = dict(valid, timestamp=101.0,
                                           event_timestamp=101.0)
                        if name != "BRUTE_FORCE":
                            next_record["dst_port"] += 1
                        alert = rule.check(next_record)
                    self.assertIsNotNone(alert)
                    self.assertEqual(alert["rule_version"], version)


if __name__ == "__main__":
    unittest.main()
