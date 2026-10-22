import os
import sys
import unittest
import time

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import TcpZeroWindowRule
import engine.rules as rules_mod


class TestTcpZeroWindowRule(unittest.TestCase):
    def setUp(self):
        self.rule = TcpZeroWindowRule(threshold=20, window=10, cooldown=60.0, enabled=True)
        self.orig_trusted = set(rules_mod.TRUSTED_HOSTS)

    def tearDown(self):
        rules_mod.TRUSTED_HOSTS = self.orig_trusted

    def _pkt(self, src="192.168.1.50", dst="192.168.1.1", dport=80, win=0, proto="TCP", ts=100.0, tcp_flags=0x10):
        return {
            "type": "IP",
            "protocol": proto,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": 50000,
            "dst_port": dport,
            "tcp_window": win,
            "tcp_flags": tcp_flags,
            "event_timestamp": ts,
            "timestamp": ts,
        }

    def test_zero_window_burst_fires_alert(self):
        alert = None
        for i in range(20):
            alert = self.rule.check(self._pkt(win=0, ts=100.0 + i * 0.1))

        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "TCP_ZERO_WINDOW")
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["confidence"], "high")
        self.assertEqual(alert["src_ip"], "192.168.1.50")
        self.assertEqual(alert["dst_ip"], "192.168.1.1")
        self.assertEqual(alert["evidence"]["zero_window_count"], 20)

    def test_sub_threshold_traffic_does_not_fire(self):
        for i in range(19):
            alert = self.rule.check(self._pkt(win=0, ts=100.0 + i * 0.1))
            self.assertIsNone(alert)

    def test_positive_window_does_not_fire(self):
        for i in range(30):
            alert = self.rule.check(self._pkt(win=65535, ts=100.0 + i * 0.1))
            self.assertIsNone(alert)

    def test_rst_zero_window_is_ignored(self):
        for i in range(30):
            self.assertIsNone(self.rule.check(self._pkt(
                win=0, ts=100.0 + i * 0.1, tcp_flags=0x14)))

    def test_non_tcp_traffic_ignored(self):
        for i in range(30):
            alert = self.rule.check(self._pkt(proto="UDP", win=0, ts=100.0 + i * 0.1))
            self.assertIsNone(alert)

    def test_trusted_source_exempted(self):
        rules_mod.TRUSTED_HOSTS.add("192.168.1.50")
        for i in range(30):
            alert = self.rule.check(self._pkt(src="192.168.1.50", win=0, ts=100.0 + i * 0.1))
            self.assertIsNone(alert)

    def test_cooldown_suppresses_duplicate_alerts(self):
        # Fire initial alert
        for i in range(20):
            alert = self.rule.check(self._pkt(win=0, ts=100.0 + i * 0.1))
        self.assertIsNotNone(alert)

        # Packets within cooldown window (100.0 - 150.0) should not fire
        for i in range(20):
            alert = self.rule.check(self._pkt(win=0, ts=120.0 + i * 0.1))
            self.assertIsNone(alert)

        # After cooldown (ts=170.0), a new burst fires again
        for i in range(20):
            alert = self.rule.check(self._pkt(win=0, ts=170.0 + i * 0.1))
        self.assertIsNotNone(alert)

    def test_disabled_rule_does_not_fire(self):
        disabled_rule = TcpZeroWindowRule(threshold=5, window=10, enabled=False)
        for i in range(10):
            alert = disabled_rule.check(self._pkt(win=0, ts=100.0 + i * 0.1))
            self.assertIsNone(alert)

    def test_prune_stale_evicts_old_history(self):
        # Send 15 packets at ts=100
        for i in range(15):
            self.rule.check(self._pkt(win=0, ts=100.0 + i * 0.1))

        # Advance past window (ts=115) and prune
        self.rule.prune_stale(115.0)
        self.assertEqual(len(self.rule._history), 0)

    def test_out_of_order_event_cannot_corrupt_window_or_revive_stale_count(self):
        rule = TcpZeroWindowRule(threshold=3, window=2, cooldown=60.0)
        self.assertIsNone(rule.check(self._pkt(ts=100.0)))
        self.assertIsNone(rule.check(self._pkt(ts=102.5)))  # evicts the first event
        # A delayed packet must not be appended behind the newer event. If it
        # were, the following current packet could leave a stale count in deque.
        self.assertIsNone(rule.check(self._pkt(ts=100.5)))
        self.assertEqual(list(rule._history[("192.168.1.50", "192.168.1.1")]),
                         [(102.5, 80)])
        self.assertIsNone(rule.check(self._pkt(ts=103.0)))
        self.assertEqual(list(rule._history[("192.168.1.50", "192.168.1.1")]),
                         [(102.5, 80), (103.0, 80)])


if __name__ == "__main__":
    unittest.main()
