import os
import sys
import tempfile
import time
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from capture.sniffer import _replay_text_log, replay_pcap
from capture.sniffer import _extract
from engine.rules import RuleEngine, PortScanRule, TcpStealthScanRule
import config
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMPv6EchoRequest, DNS, DNSQR
from unittest.mock import patch


class DummyEngine:
    def __init__(self):
        self.records = []

    def check(self, record):
        self.records.append(record)


class TestPcapReplayAndParsing(unittest.TestCase):
    def test_binary_pcap_replay_streams_packets_and_closes_reader(self):
        packets = [
            Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=40000, dport=80, flags="S"),
            Ether() / IP(src="192.0.2.2", dst="192.0.2.1") / TCP(sport=80, dport=40000, flags="SA"),
        ]
        packets[0].time = 100.0
        packets[1].time = 100.1

        class OnePassReader:
            def __init__(self):
                self._packets = iter(packets)
                self.closed = False

            def __iter__(self):
                return self

            def __next__(self):
                return next(self._packets)

            def close(self):
                self.closed = True

        reader = OnePassReader()
        with tempfile.NamedTemporaryFile("wb", suffix=".pcap", delete=False) as f:
            # The magic number is enough for replay_pcap to select binary mode;
            # PcapReader itself is replaced with the one-pass fixture below.
            f.write(b"\xd4\xc3\xb2\xa1")
            f.flush()
            path = f.name

        try:
            dummy = DummyEngine()
            with patch("scapy.utils.PcapReader", return_value=reader) as factory:
                replay_pcap(path, dummy)

            factory.assert_called_once_with(path)
            self.assertTrue(reader.closed)
            self.assertEqual(len(dummy.records), 2)
            self.assertEqual([record["event_timestamp"] for record in dummy.records], [100.0, 100.1])
            self.assertEqual([record["initial_syn"] for record in dummy.records], [True, False])
        finally:
            os.unlink(path)

    def test_tcpdump_text_replay_preserves_tcp_probe_flags(self):
        lines = (
            "14:30:15.100000 IP 203.0.113.44.50000 > 203.0.113.80.1000: Flags [F], seq 1\n"
            "14:30:15.200000 IP 203.0.113.44.50001 > 203.0.113.80.1001: Flags [none], win 0\n"
            "14:30:15.300000 IP 203.0.113.44.50002 > 203.0.113.80.1002: Flags [FPU], seq 2\n"
            "14:30:15.400000 IP 203.0.113.44.50003 > 203.0.113.80.1003: Flags [F.], seq 3, ack 4\n"
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False) as f:
            f.write(lines)
            f.flush()
            tmp_path = f.name
        try:
            dummy = DummyEngine()
            _replay_text_log(tmp_path, dummy)
            self.assertEqual([record["tcp_flags"] for record in dummy.records],
                             [0x01, 0x00, 0x29, 0x11])
            self.assertEqual([record["initial_syn"] for record in dummy.records],
                             [False, False, False, False])
        finally:
            os.unlink(tmp_path)

    def test_text_replay_detects_a_tcp_stealth_scan_end_to_end(self):
        flags = ("F", "none", "FPU")
        lines = "".join(
            f"14:30:15.100000 IP 203.0.113.44.{50000 + i} > "
            f"203.0.113.80.{8000 + i}: Flags [{flags[i % 3]}], seq {i}\n"
            for i in range(15)
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False) as f:
            f.write(lines)
            f.flush()
            tmp_path = f.name
        try:
            rule = TcpStealthScanRule(threshold=15, window=10)
            alerts = []

            class RuleAdapter:
                def check(self, record):
                    alert = rule.check(record)
                    if alert:
                        alerts.append(alert)

            _replay_text_log(tmp_path, RuleAdapter())
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["evidence"]["distinct_ports"], 15)
            self.assertEqual(alerts[0]["evidence"]["probe_types"],
                             ["FIN", "NULL", "XMAS"])
        finally:
            os.unlink(tmp_path)

    def test_extract_dns_over_tcp_query(self):
        pkt = (Ether() / IP(src="192.0.2.4", dst="192.0.2.53") /
               TCP(sport=42000, dport=53, flags="PA") /
               DNS(id=12, qr=0, rd=1, qd=DNSQR(qname="xvqrztmplwbsnfhk.badactor.example")))
        record = _extract(pkt, capture_ts=1000.0)
        self.assertEqual(record["protocol"], "TCP")
        self.assertEqual(record["dns_query"], "xvqrztmplwbsnfhk.badactor.example.")
        self.assertEqual(record["dns_qtype"], 1)
        self.assertIsNone(record["src_mac"], "Missing Ethernet source must not be inferred from the host interface")

    def test_extract_ipv6_transport_headers(self):
        tcp = _extract(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") /
                       TCP(sport=44000, dport=443, flags="S"), capture_ts=1001)
        udp = _extract(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::53") /
                       UDP(sport=44000, dport=53), capture_ts=1002)
        self.assertEqual((tcp["src_ip"], tcp["dst_ip"], tcp["protocol"]),
                         ("2001:db8::1", "2001:db8::2", "TCP"))
        self.assertTrue(tcp["initial_syn"])
        self.assertEqual(tcp["tcp_seq"], 0)
        self.assertEqual(tcp["tcp_payload_seq"], 1)
        self.assertEqual(tcp["tcp_flags"] & 0x02, 0x02)
        self.assertEqual((udp["protocol"], udp["src_port"], udp["dst_port"]),
                         ("UDP", 44000, 53))

    def test_extract_ipv6_echo_request(self):
        record = _extract(
            Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest(),
            capture_ts=1003,
        )
        self.assertEqual(record["protocol"], "ICMPV6")
        self.assertEqual(record["icmp_type"], 128)
        self.assertEqual(record["icmp_code"], 0)

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

    def test_time_only_tcpdump_log_advances_date_at_midnight(self):
        content = (
            "23:59:59.900000 IP 192.0.2.1.40000 > 192.0.2.2.80: Flags [S], seq 1\n"
            "00:00:00.100000 IP 192.0.2.1.40001 > 192.0.2.2.80: Flags [S], seq 2\n"
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False) as f:
            f.write(content)
            f.flush()
            tmp_path = f.name
        try:
            dummy = DummyEngine()
            _replay_text_log(tmp_path, dummy)
            self.assertEqual(len(dummy.records), 2)
            elapsed = (
                dummy.records[1]["event_timestamp"]
                - dummy.records[0]["event_timestamp"]
            )
            self.assertAlmostEqual(elapsed, 0.2, places=4)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_tcpdump_text_log_parses_ipv6_endpoints(self):
        content = (
            "2026-10-21 12:00:00.000000 IP6 2001:db8::1.40000 > "
            "2001:db8::2.80: Flags [S], seq 1\n"
            "2026-10-21 12:00:00.100000 IP6 2001:db8::1.53000 > "
            "2001:db8::53.53: UDP, length 20\n"
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False) as f:
            f.write(content)
            f.flush()
            tmp_path = f.name
        try:
            dummy = DummyEngine()
            _replay_text_log(tmp_path, dummy)
            self.assertEqual(len(dummy.records), 2)
            tcp, udp = dummy.records
            self.assertEqual(
                (tcp["src_ip"], tcp["dst_ip"], tcp["src_port"], tcp["dst_port"]),
                ("2001:db8::1", "2001:db8::2", 40000, 80),
            )
            self.assertTrue(tcp["initial_syn"])
            self.assertEqual(
                (udp["src_ip"], udp["dst_ip"], udp["src_port"], udp["dst_port"], udp["protocol"]),
                ("2001:db8::1", "2001:db8::53", 53000, 53, "UDP"),
            )
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_tcpdump_text_log_parses_arp_requests_without_inventing_mac(self):
        content = (
            "12:00:00.000000 ARP, Request who-has 192.0.2.20 "
            "(28:56:5a:45:5d:63 (oui Unknown)) "
            "tell 192.0.2.10, length 28\n"
            "12:00:00.100000 ARP, Request who-has 192.0.2.30 (Broadcast) "
            "tell 192.0.2.10, length 28\n"
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False) as f:
            f.write(content)
            f.flush()
            tmp_path = f.name
        try:
            dummy = DummyEngine()
            _replay_text_log(tmp_path, dummy)
            self.assertEqual(len(dummy.records), 2)
            record = dummy.records[0]
            self.assertEqual(record["type"], "ARP")
            self.assertEqual(record["arp_operation"], "request")
            self.assertEqual(record["src_ip"], "192.0.2.10")
            self.assertEqual(record["dst_ip"], "192.0.2.20")
            self.assertIsNone(record["src_mac"])
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
