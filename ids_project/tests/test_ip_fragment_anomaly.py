import os
import sys
import time
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import IpFragmentAnomalyRule


class TestIpFragmentAnomalyRule(unittest.TestCase):
    """
    Comprehensive verification of IpFragmentAnomalyRule:
    1. Positive detection of Teardrop overlapping fragments (CVE-1997-0047).
    2. Positive detection of Fragment Overflow / Ping of Death (RFC 791).
    3. Positive detection of Tiny Fragment Evasion (RFC 1858 / RFC 3128).
    4. Benign negative suppression for standard in-order fragmentation.
    5. Benign negative suppression for benign exact retransmissions.
    6. Benign negative suppression for out-of-order non-overlapping delivery.
    7. Alert cooldown, LRU state bounding, and prune_stale expiry.
    """

    def setUp(self):
        self.rule = IpFragmentAnomalyRule(cooldown=60.0, reassembly_timeout=30.0)

    # -------------------------------------------------------------------------
    # Positive Detection Tests
    # -------------------------------------------------------------------------

    def test_detects_teardrop_overlapping_fragment(self):
        """Detects overlapping IP fragments matching the canonical Teardrop attack (ws_teardrop)."""
        # Packet 1: offset 0, length 36 (covers 0..36)
        pkt1 = {
            "type": "IP",
            "protocol": "UDP",
            "src_ip": "10.1.1.1",
            "dst_ip": "129.111.30.27",
            "ip_fragment_id": 242,
            "ip_fragment_offset": 0,
            "ip_more_fragments": True,
            "ip_fragmented": True,
            "ip_fragment_data_len": 36,
            "timestamp": 1000.0,
        }
        alert1 = self.rule.check(pkt1)
        self.assertIsNone(alert1, "Initial fragment should be accepted into reassembly state")

        # Packet 2: offset 24, length 4 (covers 24..28, overlapping with 0..36)
        pkt2 = {
            "type": "IP",
            "protocol": "UDP",
            "src_ip": "10.1.1.1",
            "dst_ip": "129.111.30.27",
            "ip_fragment_id": 242,
            "ip_fragment_offset": 24,
            "ip_more_fragments": False,
            "ip_fragmented": True,
            "ip_fragment_data_len": 4,
            "timestamp": 1000.001,
        }
        alert2 = self.rule.check(pkt2)
        self.assertIsNotNone(alert2, "Overlapping fragment must trigger IP_FRAGMENT_ANOMALY")
        self.assertEqual(alert2["rule_name"], "IP_FRAGMENT_ANOMALY")
        self.assertEqual(alert2["evidence"]["anomaly_type"], "TEARDROP_OVERLAPPING_FRAGMENT")
        self.assertEqual(alert2["severity"], "critical")
        self.assertEqual(alert2["evidence"]["overlap_bytes"], 4)
        self.assertEqual(alert2["evidence"]["overlapping_range"], [24, 28])
        self.assertIn("overlapping", alert2["detail"].lower())

    def test_detects_fragment_overflow_ping_of_death(self):
        """Detects fragment whose offset + length exceeds RFC 791 maximum 65,535 bytes."""
        pkt = {
            "type": "IP",
            "protocol": "ICMP",
            "src_ip": "198.51.100.5",
            "dst_ip": "192.168.1.10",
            "ip_fragment_id": 999,
            "ip_fragment_offset": 65500,
            "ip_more_fragments": False,
            "ip_fragmented": True,
            "ip_fragment_data_len": 100,  # 65500 + 100 = 65600 > 65535
            "timestamp": 2000.0,
        }
        alert = self.rule.check(pkt)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "IP_FRAGMENT_ANOMALY")
        self.assertEqual(alert["evidence"]["anomaly_type"], "FRAGMENT_OVERFLOW")
        self.assertEqual(alert["severity"], "critical")
        self.assertIn("oversized", alert["detail"].lower())

    def test_detects_tiny_fragment_evasion_tcp(self):
        """Detects initial TCP fragment smaller than 20 bytes (RFC 1858 header split evasion)."""
        pkt = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "203.0.113.5",
            "dst_ip": "192.168.1.1",
            "ip_fragment_id": 777,
            "ip_fragment_offset": 0,
            "ip_more_fragments": True,
            "ip_fragmented": True,
            "ip_fragment_data_len": 12,  # < 20 bytes for TCP
            "timestamp": 3000.0,
        }
        alert = self.rule.check(pkt)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "TINY_FRAGMENT_EVASION")
        self.assertEqual(alert["severity"], "high")

    def test_detects_tiny_fragment_evasion_udp(self):
        """Detects initial UDP fragment smaller than 8 bytes."""
        pkt = {
            "type": "IP",
            "protocol": "UDP",
            "src_ip": "203.0.113.6",
            "dst_ip": "192.168.1.1",
            "ip_fragment_id": 778,
            "ip_fragment_offset": 0,
            "ip_more_fragments": True,
            "ip_fragmented": True,
            "ip_fragment_data_len": 4,  # < 8 bytes for UDP
            "timestamp": 3100.0,
        }
        alert = self.rule.check(pkt)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "TINY_FRAGMENT_EVASION")

    # -------------------------------------------------------------------------
    # Benign Negative Tests
    # -------------------------------------------------------------------------

    def test_benign_normal_fragmentation_does_not_fire(self):
        """Normal consecutive in-order fragments (e.g. 1480-byte MTU boundaries) do not fire."""
        # Frag 1: 0..1480
        pkt1 = {
            "type": "IP", "protocol": "UDP", "src_ip": "192.168.1.10", "dst_ip": "192.168.1.20",
            "ip_fragment_id": 1001, "ip_fragment_offset": 0, "ip_more_fragments": True,
            "ip_fragmented": True, "ip_fragment_data_len": 1480, "timestamp": 4000.0,
        }
        # Frag 2: 1480..2960
        pkt2 = {
            "type": "IP", "protocol": "UDP", "src_ip": "192.168.1.10", "dst_ip": "192.168.1.20",
            "ip_fragment_id": 1001, "ip_fragment_offset": 1480, "ip_more_fragments": True,
            "ip_fragmented": True, "ip_fragment_data_len": 1480, "timestamp": 4000.01,
        }
        # Frag 3: 2960..3000
        pkt3 = {
            "type": "IP", "protocol": "UDP", "src_ip": "192.168.1.10", "dst_ip": "192.168.1.20",
            "ip_fragment_id": 1001, "ip_fragment_offset": 2960, "ip_more_fragments": False,
            "ip_fragmented": True, "ip_fragment_data_len": 40, "timestamp": 4000.02,
        }
        self.assertIsNone(self.rule.check(pkt1))
        self.assertIsNone(self.rule.check(pkt2))
        self.assertIsNone(self.rule.check(pkt3))

    def test_benign_retransmission_does_not_fire(self):
        """Exact identical retransmission of a lost fragment does not trigger overlap anomaly."""
        pkt1 = {
            "type": "IP", "protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "ip_fragment_id": 2001, "ip_fragment_offset": 0, "ip_more_fragments": True,
            "ip_fragmented": True, "ip_fragment_data_len": 1480, "timestamp": 5000.0,
        }
        self.assertIsNone(self.rule.check(pkt1))

        # Retransmission with exact same offset and length
        pkt1_dup = {
            "type": "IP", "protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "ip_fragment_id": 2001, "ip_fragment_offset": 0, "ip_more_fragments": True,
            "ip_fragmented": True, "ip_fragment_data_len": 1480, "timestamp": 5000.5,
        }
        self.assertIsNone(self.rule.check(pkt1_dup))

    def test_benign_out_of_order_non_overlapping_does_not_fire(self):
        """Non-overlapping fragments arriving out-of-order do not trigger false positives."""
        # Frag 2 arrives first: 1480..2000
        pkt2 = {
            "type": "IP", "protocol": "UDP", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.6",
            "ip_fragment_id": 3001, "ip_fragment_offset": 1480, "ip_more_fragments": False,
            "ip_fragmented": True, "ip_fragment_data_len": 520, "timestamp": 6000.0,
        }
        # Frag 1 arrives second: 0..1480
        pkt1 = {
            "type": "IP", "protocol": "UDP", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.6",
            "ip_fragment_id": 3001, "ip_fragment_offset": 0, "ip_more_fragments": True,
            "ip_fragmented": True, "ip_fragment_data_len": 1480, "timestamp": 6000.01,
        }
        self.assertIsNone(self.rule.check(pkt2))
        self.assertIsNone(self.rule.check(pkt1))

    # -------------------------------------------------------------------------
    # State & Boundary Invariant Tests
    # -------------------------------------------------------------------------

    def test_cooldown_suppresses_duplicate_alerts(self):
        """Consecutive overlapping fragments between same hosts are cooled down."""
        pkt1 = {
            "type": "IP", "protocol": "UDP", "src_ip": "192.168.1.50", "dst_ip": "192.168.1.1",
            "ip_fragment_id": 4001, "ip_fragment_offset": 0, "ip_more_fragments": True,
            "ip_fragmented": True, "ip_fragment_data_len": 60, "timestamp": 7000.0,
        }
        pkt2 = {
            "type": "IP", "protocol": "UDP", "src_ip": "192.168.1.50", "dst_ip": "192.168.1.1",
            "ip_fragment_id": 4001, "ip_fragment_offset": 20, "ip_more_fragments": False,
            "ip_fragmented": True, "ip_fragment_data_len": 10, "timestamp": 7000.01,
        }
        self.assertIsNone(self.rule.check(pkt1))
        alert = self.rule.check(pkt2)
        self.assertIsNotNone(alert)

        # Another attack within cooldown window
        pkt3 = {
            "type": "IP", "protocol": "UDP", "src_ip": "192.168.1.50", "dst_ip": "192.168.1.1",
            "ip_fragment_id": 4002, "ip_fragment_offset": 0, "ip_more_fragments": True,
            "ip_fragmented": True, "ip_fragment_data_len": 60, "timestamp": 7010.0,
        }
        pkt4 = {
            "type": "IP", "protocol": "UDP", "src_ip": "192.168.1.50", "dst_ip": "192.168.1.1",
            "ip_fragment_id": 4002, "ip_fragment_offset": 20, "ip_more_fragments": False,
            "ip_fragmented": True, "ip_fragment_data_len": 10, "timestamp": 7010.01,
        }
        self.assertIsNone(self.rule.check(pkt3))
        self.assertIsNone(self.rule.check(pkt4), "Subsequent attack within cooldown must be suppressed")

    def test_prune_stale_evicts_expired_flows(self):
        """prune_stale evicts flows past the 30-second reassembly timeout."""
        pkt = {
            "type": "IP", "protocol": "UDP", "src_ip": "172.16.0.1", "dst_ip": "172.16.0.2",
            "ip_fragment_id": 5001, "ip_fragment_offset": 0, "ip_more_fragments": True,
            "ip_fragmented": True, "ip_fragment_data_len": 100, "timestamp": 8000.0,
        }
        self.rule.check(pkt)
        flow_key = ("172.16.0.1", "172.16.0.2", "UDP", 5001)
        self.assertIn(flow_key, self.rule._flows)

        # Prune with current time (not expired yet)
        self.rule.prune_stale(now=8010.0)
        self.assertIn(flow_key, self.rule._flows)

        # Prune past reassembly timeout (30s)
        self.rule.prune_stale(now=8035.0)
        self.assertNotIn(flow_key, self.rule._flows)

    def test_unfragmented_records_and_non_ip_skipped(self):
        """Unfragmented records and non-IP records are safely ignored."""
        unfrag = {
            "type": "IP", "protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "ip_fragmented": False, "ip_fragment_offset": 0, "ip_more_fragments": False,
            "timestamp": 9000.0,
        }
        self.assertIsNone(self.rule.check(unfrag))

        arp = {"type": "ARP", "timestamp": 9000.0}
        self.assertIsNone(self.rule.check(arp))


    def test_detects_conflicting_fragment_duplicate(self):
        """Detects conflicting duplicate fragments with identical byte range but differing payload content."""
        pkt1 = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "ip_fragment_id": 8888,
            "ip_fragment_offset": 0,
            "ip_more_fragments": True,
            "ip_fragmented": True,
            "ip_fragment_data_len": 100,
            "ip_fragment_data_digest": b"\x01" * 16,
            "timestamp": 1000.0,
        }
        self.assertIsNone(self.rule.check(pkt1))

        # Conflicting duplicate: identical offset 0 and len 100, but differing digest
        pkt2 = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "ip_fragment_id": 8888,
            "ip_fragment_offset": 0,
            "ip_more_fragments": True,
            "ip_fragmented": True,
            "ip_fragment_data_len": 100,
            "ip_fragment_data_digest": b"\x02" * 16,
            "timestamp": 1000.1,
        }
        alert = self.rule.check(pkt2)
        self.assertIsNotNone(alert, "Conflicting fragment duplicate must trigger IP_FRAGMENT_ANOMALY")
        self.assertEqual(alert["evidence"]["anomaly_type"], "CONFLICTING_FRAGMENT_DUPLICATE")
        self.assertEqual(alert["confidence"], "confirmed")
        self.assertEqual(alert["severity"], "high")

    def test_ipv6_fragment_handling(self):
        """IPv6 fragments with overlapping ranges trigger TEARDROP_OVERLAPPING_FRAGMENT."""
        pkt1 = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "2001:db8::1",
            "dst_ip": "2001:db8::2",
            "ip_fragment_id": 123456,
            "ip_fragment_offset": 0,
            "ip_more_fragments": True,
            "ip_fragmented": True,
            "ip_fragment_data_len": 64,
            "timestamp": 2000.0,
        }
        self.assertIsNone(self.rule.check(pkt1))

        pkt2 = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "2001:db8::1",
            "dst_ip": "2001:db8::2",
            "ip_fragment_id": 123456,
            "ip_fragment_offset": 32,
            "ip_more_fragments": False,
            "ip_fragmented": True,
            "ip_fragment_data_len": 64,
            "timestamp": 2000.01,
        }
        alert = self.rule.check(pkt2)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "TEARDROP_OVERLAPPING_FRAGMENT")
        self.assertEqual(alert["evidence"]["overlap_bytes"], 32)

    def test_per_datagram_fragment_count_bounded(self):
        """A single datagram cannot exceed MAX_FRAGMENTS_PER_DATAGRAM tracked ranges."""
        flow_key = ("10.1.1.1", "10.1.1.2", "UDP", 77777)
        for i in range(120):
            pkt = {
                "type": "IP",
                "protocol": "UDP",
                "src_ip": "10.1.1.1",
                "dst_ip": "10.1.1.2",
                "ip_fragment_id": 77777,
                "ip_fragment_offset": i * 100,
                "ip_more_fragments": True,
                "ip_fragmented": True,
                "ip_fragment_data_len": 100,
                "timestamp": 3000.0 + (i * 0.01),
            }
            self.rule.check(pkt)
        self.assertIn(flow_key, self.rule._flows)
        self.assertLessEqual(len(self.rule._flows[flow_key]["fragments"]), self.rule.MAX_FRAGMENTS_PER_DATAGRAM)

    def test_total_fragment_ranges_globally_bounded(self):
        """Global total fragment ranges across all flows cannot exceed MAX_TOTAL_FRAGMENT_RANGES."""
        for flow_idx in range(500):
            for frag_idx in range(40):
                pkt = {
                    "type": "IP",
                    "protocol": "UDP",
                    "src_ip": f"10.{flow_idx // 256}.{flow_idx % 256}.1",
                    "dst_ip": "10.2.2.2",
                    "ip_fragment_id": 1000 + flow_idx,
                    "ip_fragment_offset": frag_idx * 50,
                    "ip_more_fragments": True,
                    "ip_fragmented": True,
                    "ip_fragment_data_len": 50,
                    "timestamp": 4000.0,
                }
                self.rule.check(pkt)
        self.assertLessEqual(self.rule._total_ranges, self.rule.MAX_TOTAL_FRAGMENT_RANGES)
        self.assertLessEqual(len(self.rule._flows), self.rule.MAX_TRACKED_FLOWS)


if __name__ == "__main__":
    unittest.main()

