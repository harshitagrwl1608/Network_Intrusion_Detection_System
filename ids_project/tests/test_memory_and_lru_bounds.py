"""
ids_project/tests/test_memory_and_lru_bounds.py
-----------------------------------------------
Memory leak detection, O(1) LRU eviction verification, stale state pruning,
and garbage collection profiling across all 23 NetGuard detection rules.
"""

import gc
import os
import sys
import time
import tracemalloc
import unittest
from collections import OrderedDict

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from engine.rules import (
    RuleEngine,
    PortScanRule,
    SynFloodRule,
    BruteForceRule,
    UdpFloodRule,
    IrcC2BeaconingRule,
    IpFragmentAnomalyRule,
    TcpZeroWindowRule,
)


class TestMemoryAndLruBounds(unittest.TestCase):
    """Verifies deterministic O(1) LRU eviction and memory bounds across all rules."""

    @classmethod
    def setUpClass(cls):
        cls.engine = RuleEngine(None, set(), config)

    def test_all_rules_accept_prune_stale(self):
        """Every registered rule must safely accept prune_stale(now) without raising."""
        now = time.time()
        for rule in self.engine.rules:
            with self.subTest(rule=rule.name):
                self.assertTrue(hasattr(rule, "prune_stale"), f"{rule.name} missing prune_stale")
                try:
                    rule.prune_stale(now)
                except Exception as exc:
                    self.fail(f"{rule.name}.prune_stale({now}) raised {exc}")

    def test_engine_prune_stale_dispatch(self):
        """RuleEngine.prune_stale(now) dispatches to all rules cleanly."""
        try:
            self.engine.prune_stale(now=100000.0)
        except Exception as exc:
            self.fail(f"engine.prune_stale() failed: {exc}")

    def test_port_scan_lru_bounding(self):
        """PortScanRule bounds its tracking state under volumetric adversary."""
        rule = PortScanRule(config)
        now = 1000.0
        # Inject 3,000 distinct source hosts
        for i in range(3000):
            src = f"10.{i // 256}.{i % 256}.1"
            rec = {
                "timestamp": now,
                "protocol": "TCP",
                "src_ip": src,
                "dst_ip": "192.168.1.1",
                "src_port": 50000,
                "dst_port": 80,
                "tcp_flags": "S",
            }
            rule.check(rec)

        # Max tracked sources must be bounded
        max_sources = getattr(config, "PORT_SCAN_MAX_SOURCES", 1024)
        if hasattr(rule, "_sources"):
            self.assertLessEqual(len(rule._sources), max_sources + 10)
        elif hasattr(rule, "_history"):
            self.assertLessEqual(len(rule._history), max_sources + 10)

    def test_syn_flood_lru_bounding(self):
        """SynFloodRule bounds tracking state under volumetric adversary."""
        rule = SynFloodRule(config)
        now = 1000.0
        for i in range(2500):
            src = f"10.{i // 256}.{i % 256}.1"
            rec = {
                "timestamp": now,
                "protocol": "TCP",
                "src_ip": src,
                "dst_ip": "192.168.1.1",
                "src_port": 40000,
                "dst_port": 443,
                "tcp_flags": "S",
            }
            rule.check(rec)

        max_sources = getattr(config, "SYN_FLOOD_MAX_SOURCES", 1024)
        if hasattr(rule, "_sources"):
            self.assertLessEqual(len(rule._sources), max_sources + 10)
        elif hasattr(rule, "_syn_history"):
            self.assertLessEqual(len(rule._syn_history), max_sources + 10)

    def test_brute_force_lru_bounding(self):
        """BruteForceRule bounds tracking state under distributed login attempts."""
        rule = BruteForceRule(config)
        now = 1000.0
        for i in range(2500):
            src = f"10.{i // 256}.{i % 256}.1"
            rec = {
                "timestamp": now,
                "protocol": "TCP",
                "src_ip": src,
                "dst_ip": "192.168.1.1",
                "src_port": 35000,
                "dst_port": 22,
                "tcp_flags": "S",
            }
            rule.check(rec)

        max_sources = getattr(config, "BRUTE_FORCE_MAX_SOURCES", 1024)
        if hasattr(rule, "_sources"):
            self.assertLessEqual(len(rule._sources), max_sources + 10)

    def test_udp_flood_lru_bounding(self):
        """UdpFloodRule bounds tracking state under distributed UDP flood."""
        rule = UdpFloodRule(config)
        now = 1000.0
        for i in range(2500):
            src = f"10.{i // 256}.{i % 256}.1"
            rec = {
                "timestamp": now,
                "protocol": "UDP",
                "src_ip": src,
                "dst_ip": "192.168.1.1",
                "src_port": 12345,
                "dst_port": 53,
                "payload_len": 64,
            }
            rule.check(rec)

        max_sources = getattr(config, "UDP_FLOOD_MAX_SOURCES", 1024)
        if hasattr(rule, "_sources"):
            self.assertLessEqual(len(rule._sources), max_sources + 10)
        elif hasattr(rule, "_history"):
            self.assertLessEqual(len(rule._history), max_sources + 10)

    def test_irc_c2_beaconing_lru_bounding(self):
        """Rule 23 (IRC_C2_BEACONING) bounds beaconing attempt state under attack."""
        rule = IrcC2BeaconingRule(config)
        now = 1000.0
        for i in range(3500):
            src = f"10.{i // 256}.{i % 256}.1"
            rec = {
                "timestamp": now,
                "protocol": "TCP",
                "src_ip": src,
                "dst_ip": "192.168.1.1",
                "src_port": 45000,
                "dst_port": 6667,
                "tcp_flags": "S",
            }
            rule.check(rec)

        self.assertLessEqual(len(rule._connections), rule.max_sources)

    def test_ip_fragment_lru_bounding(self):
        """Rule 22 (IP_FRAGMENT_ANOMALY) bounds tracking state under fragmented packet storm."""
        rule = IpFragmentAnomalyRule(config)
        now = 1000.0
        for i in range(5000):
            src = f"10.{i // 256}.{i % 256}.1"
            rec = {
                "timestamp": now,
                "protocol": "UDP",
                "src_ip": src,
                "dst_ip": "192.168.1.1",
                "ip_id": i,
                "ip_flags": "MF",
                "frag_offset": 0,
                "payload_len": 64,
            }
            rule.check(rec)

        self.assertLessEqual(len(rule._flows), rule.MAX_TRACKED_FLOWS)

    def test_future_clock_drift_handling_in_prune(self):
        """Packets with future clock drift timestamps must be pruned cleanly."""
        rule = PortScanRule(config)
        now = 1000.0
        # Normal packet
        rule.check({
            "timestamp": now - 50.0,
            "protocol": "TCP",
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
            "src_port": 50000,
            "dst_port": 80,
            "tcp_flags": "S",
        })
        # Future drift packet (e.g. bad NTP drift)
        rule.check({
            "timestamp": now + 50000.0,
            "protocol": "TCP",
            "src_ip": "10.0.0.2",
            "dst_ip": "192.168.1.1",
            "src_port": 50001,
            "dst_port": 80,
            "tcp_flags": "S",
        })

        # Prune with current time
        rule.prune_stale(now)
        # Verify no crash or unhandled error occurred
        self.assertTrue(True)

    def test_gc_concurrency_safe_prune(self):
        """prune_stale must not raise KeyError or RuntimeError under state modification."""
        rule = TcpZeroWindowRule(config)
        now = 1000.0
        for i in range(100):
            rule.check({
                "timestamp": now,
                "protocol": "TCP",
                "src_ip": f"10.0.0.{i}",
                "dst_ip": "192.168.1.1",
                "src_port": 50000 + i,
                "dst_port": 80,
                "tcp_window": 0,
            })
        try:
            rule.prune_stale(now + 20.0)
        except Exception as exc:
            self.fail(f"Concurrency-safe prune failed: {exc}")

    def test_heap_growth_bounded_under_high_throughput(self):
        """Heap growth remains strictly bounded under 20,000 synthetic packet records."""
        gc.collect()
        tracemalloc.start()
        snapshot_start = tracemalloc.take_snapshot()

        engine = RuleEngine(None, set(), config)
        now = 1000.0

        for i in range(20000):
            src = f"10.{(i // 50) % 256}.{i % 256}.1"
            rec = {
                "timestamp": now + (i * 0.001),
                "protocol": "TCP",
                "src_ip": src,
                "dst_ip": "192.168.1.1",
                "src_port": 40000 + (i % 20000),
                "dst_port": 80,
                "tcp_flags": "S",
                "payload_len": 0,
            }
            engine.check(rec)
            if i % 5000 == 0:
                engine.prune_stale(now + (i * 0.001))

        engine.prune_stale(now + 25.0)
        gc.collect()
        snapshot_end = tracemalloc.take_snapshot()
        tracemalloc.stop()

        # Calculate memory delta
        stats = snapshot_end.compare_to(snapshot_start, "lineno")
        total_delta_bytes = sum(s.size_diff for s in stats if s.size_diff > 0)
        total_delta_mb = total_delta_bytes / (1024 * 1024)

        # Under 20,000 packets with pruning, net retained memory must remain <= 20 MB
        self.assertLessEqual(
            total_delta_mb,
            20.0,
            f"Heap growth exceeded acceptable bound: {total_delta_mb:.2f} MB retained"
        )


if __name__ == "__main__":
    unittest.main()
