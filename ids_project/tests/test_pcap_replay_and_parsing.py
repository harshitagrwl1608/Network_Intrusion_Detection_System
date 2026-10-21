import os
import sys
import tempfile
import time
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from capture.sniffer import _replay_text_log
from engine.rules import RuleEngine, PortScanRule
import config


class DummyEngine:
    def __init__(self):
        self.records = []

    def check(self, record):
        self.records.append(record)


class TestPcapReplayAndParsing(unittest.TestCase):
    def test_tcpdump_full_date_format_parsing(self):
        """
        README documents: tcpdump -tttt -nn -r file.pcap > file.log.
        The -tttt flag outputs: 'YYYY-MM-DD HH:MM:SS.frac'.
        The parser must parse these lines instead of skipping them.
        """
        log_content = (
            "2026-10-18 14:30:15.123456 IP 192.168.1.50.45000 > 192.168.1.1.80: Flags [S], seq 1000\n"
            "2026-10-18 14:30:15.124000 IP 192.168.1.1.80 > 192.168.1.50.45000: Flags [S.], seq 2000, ack 1001\n"
            "2026-10-18 14:30:16.000000 IP 192.168.1.50.45001 > 192.168.1.1.443: Flags [S], seq 3000\n"
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False) as f:
            f.write(log_content)
            f.flush()
            tmp_path = f.name

        try:
            dummy = DummyEngine()
            _replay_text_log(tmp_path, dummy)

            self.assertEqual(len(dummy.records), 3, "Expected 3 records parsed from full-date tcpdump log")
            
            # Check first record: SYN
            r0 = dummy.records[0]
            self.assertEqual(r0["src_ip"], "192.168.1.50")
            self.assertEqual(r0["dst_ip"], "192.168.1.1")
            self.assertEqual(r0["dst_port"], 80)
            self.assertTrue(r0.get("syn_flag"))
            self.assertTrue(r0.get("initial_syn"), "Flags [S] must have initial_syn=True")

            # Check second record: SYN-ACK server reply
            r1 = dummy.records[1]
            self.assertTrue(r1.get("syn_flag"))
            self.assertFalse(r1.get("initial_syn"), "Flags [S.] must have initial_syn=False")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_gc_does_not_corrupt_historical_replay_state(self):
        """
        When replaying historical PCAP events (e.g. ts=1000.0), a GC loop using wall-clock
        time.time() would prune the historical history as 'stale' (now - 1000 > 60s).
        With an event_clock or safe GC clock, historical state must not be prematurely pruned.
        """
        rule = PortScanRule(threshold=5, window=60)
        # Add 3 historical probes at ts=1000.0
        for p in [80, 81, 82]:
            rule.check({
                "type": "IP",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "protocol": "TCP",
                "dst_port": p,
                "initial_syn": True,
                "timestamp": 1000.0,
            })

        # Simulate GC running with packet time (1005.0) -> history should NOT be pruned
        rule.prune_stale(now=1005.0)
        with rule._lock:
            history = rule._vert.get(("10.0.0.1", "10.0.0.2"), [])
            self.assertEqual(len(history), 3, "History should remain intact when GC uses packet clock")

        # Now send 2 more probes at ts=1010.0 -> must fire alert because total is 5
        alert = None
        for p in [83, 84]:
            res = rule.check({
                "type": "IP",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "protocol": "TCP",
                "dst_port": p,
                "initial_syn": True,
                "timestamp": 1010.0,
            })
            if res:
                alert = res

        self.assertIsNotNone(alert, "Port scan should fire across historical packet window")


if __name__ == "__main__":
    unittest.main()
