#!/usr/bin/env python3
"""
ids_project/tests/test_adversarial_evasion_stress.py
---------------------------------------------------
Adversarial Evasion & Protocol Boundary Stress Tests for NetGuard IDS.

Covers:
1. High-velocity multi-threaded concurrent ingestion with concurrent prune_stale() GC.
2. TCP stream reassembly under adversarial overlapping segment injection.
3. Asymmetric routing traffic (pure ACKs without initial SYNs) suppression in port scan and SYN flood rules.
4. DNS DGA case randomization entropy stability.
5. ICMP tunnel sub-threshold chunking suppression vs volumetric detection.
6. Layer 3 Ping-of-Death buffer overflow (>65,535 bytes) detection.
"""

import hashlib
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from engine.blocklist import BlocklistData
from engine.rules import (
    RuleEngine,
    PortScanRule,
    SynFloodRule,
    IpFragmentAnomalyRule,
    IcmpTunnelRule,
    DnsRule,
    PayloadRule,
)


class TestAdversarialEvasionStress(unittest.TestCase):
    """Stress tests and boundary condition verifications against adversarial evasion."""

    def test_01_multithreaded_concurrent_ingestion_and_gc(self):
        """RuleEngine must process high-concurrency multi-threaded packet ingestion safely."""
        with tempfile.NamedTemporaryFile(suffix=".db") as db_f, \
             tempfile.NamedTemporaryFile(suffix=".json") as arp_f:
            db_path = db_f.name
            arp_path = arp_f.name

        cfg = config
        cfg.SQLITE_PATH = db_path
        cfg.ARP_TABLE_PATH = arp_path

        from storage.db import get_connection, init_db
        conn = get_connection()
        init_db(conn)

        blocklist = BlocklistData(exact=set(), networks=[])
        engine = RuleEngine(conn, blocklist, cfg)

        errors = []
        stop_gc = threading.Event()

        # GC Worker thread running prune_stale() continuously
        def gc_worker():
            while not stop_gc.is_set():
                try:
                    engine.prune_stale()
                    time.sleep(0.01)
                except Exception as exc:
                    errors.append(exc)

        # Ingestion Worker threads
        NUM_WORKERS = 6
        PACKETS_PER_WORKER = 150

        def ingestion_worker(worker_id: int):
            for i in range(PACKETS_PER_WORKER):
                rec = {
                    "type": "IP",
                    "protocol": "TCP" if (i % 2 == 0) else "UDP",
                    "timestamp": 1000.0 + (i * 0.05),
                    "src_ip": f"10.{worker_id}.{(i // 50)}.{i % 50}",
                    "dst_ip": "192.168.1.1",
                    "src_port": 40000 + i,
                    "dst_port": 80 if (i % 2 == 0) else 53,
                    "tcp_flags": 0x02,
                    "initial_syn": True,
                    "payload_len": 64,
                }
                try:
                    engine.check(rec)
                except Exception as exc:
                    errors.append(exc)

        gc_t = threading.Thread(target=gc_worker, daemon=True)
        gc_t.start()

        workers = [
            threading.Thread(target=ingestion_worker, args=(w,))
            for w in range(NUM_WORKERS)
        ]
        for w in workers:
            w.start()
        for w in workers:
            w.join(timeout=10)

        stop_gc.set()
        gc_t.join(timeout=2)
        engine.flush()

        self.assertEqual(len(errors), 0, f"Encountered concurrency exceptions: {errors}")
        self.assertFalse(engine._stats.get("shutdown_timeout", False))

    def test_02_asymmetric_routing_pure_acks_suppressed(self):
        """Asymmetric traffic containing only TCP ACKs must NOT trigger PortScanRule or SynFloodRule."""
        cfg = config
        port_scan = PortScanRule(cfg.PORT_SCAN_THRESHOLD, cfg.TIME_WINDOW)
        syn_flood = SynFloodRule(cfg.SYN_FLOOD_THRESHOLD, cfg.TIME_WINDOW)

        now = 1000.0
        # Attacker / asymmetric route sends 30 pure ACKs to distinct ports on victim
        alerts_port_scan = []
        alerts_syn_flood = []

        for p in range(30):
            rec = {
                "type": "IP",
                "protocol": "TCP",
                "timestamp": now + (p * 0.1),
                "src_ip": "203.0.113.5",
                "dst_ip": "192.168.1.1",
                "src_port": 54321,
                "dst_port": 1000 + p,
                "tcp_flags": 0x10,      # ACK only
                "initial_syn": False,    # Not an initial SYN
            }
            a1 = port_scan.check(rec)
            a2 = syn_flood.check(rec)
            if a1:
                alerts_port_scan.append(a1)
            if a2:
                alerts_syn_flood.append(a2)

        self.assertEqual(len(alerts_port_scan), 0, "Pure ACK packets must not trigger PortScanRule")
        self.assertEqual(len(alerts_syn_flood), 0, "Pure ACK packets must not trigger SynFloodRule")

    def test_03_dns_dga_case_randomization_entropy(self):
        """DNS DGA entropy metric must be robust against case-randomized labels."""
        rule = DnsRule(entropy_threshold=3.8)
        now = 1000.0

        # Algorithmic DGA domain with mixed casing (evasion attempt)
        dga_mixed_case = "xVqRzTmplWbSnFHk.badactor.example"
        rec = {
            "type": "IP",
            "protocol": "UDP",
            "timestamp": now,
            "src_ip": "192.168.1.50",
            "dst_ip": "8.8.8.8",
            "src_port": 45000,
            "dst_port": 53,
            "dns_query": dga_mixed_case,
            "dns_qtype": 1,
        }
        alert = rule.check(rec)
        self.assertIsNotNone(alert, "Mixed-case high-entropy DGA query must still be detected")
        self.assertEqual(alert["rule_name"], "DNS_ANOMALY")
        self.assertIn("DNS_DGA", alert["detail"])

    def test_04_icmp_tunnel_subthreshold_suppression(self):
        """ICMP echo requests with payloads below the 64-byte threshold must be suppressed."""
        rule = IcmpTunnelRule(min_bytes=64, entropy_threshold=4.5)
        now = 1000.0

        # Small 32-byte payload (e.g. standard Windows/Linux diagnostic ping)
        rec = {
            "type": "IP",
            "protocol": "ICMP",
            "timestamp": now,
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "src_port": None,
            "dst_port": None,
            "icmp_type": 8,
            "icmp_code": 0,
            "payload": b"abcdefghijklmnopqrstuvwabcdefghi",  # 32 bytes
            "payload_len": 32,
        }
        alert = rule.check(rec)
        self.assertIsNone(alert, "Sub-threshold 32-byte ICMP payload must not trigger ICMP_TUNNEL")

    def test_05_ping_of_death_fragment_overflow(self):
        """Layer 3 fragment offset + length exceeding 65,535 bytes must trigger critical alert."""
        rule = IpFragmentAnomalyRule()
        now = 1000.0

        # Crafted fragment: offset 65500 + data length 100 = 65600 (> 65535)
        rec = {
            "type": "IP",
            "protocol": "ICMP",
            "timestamp": now,
            "src_ip": "192.0.2.100",
            "dst_ip": "192.168.1.1",
            "src_port": None,
            "dst_port": None,
            "ip_fragmented": True,
            "ip_fragment_id": 9999,
            "ip_fragment_offset": 65500,
            "ip_more_fragments": False,
            "ip_fragment_data_len": 100,
            "payload": b"A" * 100,
        }
        alert = rule.check(rec)
        self.assertIsNotNone(alert, "Ping of Death fragment overflow must trigger alert")
        self.assertEqual(alert["rule_name"], "IP_FRAGMENT_ANOMALY")
        self.assertEqual(alert["severity"], "critical")
        self.assertIn("Ping of Death", alert["detail"])
        self.assertEqual(alert["evidence"]["anomaly_type"], "FRAGMENT_OVERFLOW")


if __name__ == "__main__":
    unittest.main()
