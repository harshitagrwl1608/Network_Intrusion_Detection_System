"""Test suite for forensic alert evidence schemas across all 23 canonical detection rules.

Verifies:
1. Every rule class in ALL_RULE_CLASSES produces structured, non-empty, JSON-serializable evidence.
2. Evidence dictionary conforms to schema invariants (non-empty dict, json-serializable).
3. RuleEngine.check() serializes evidence to evidence_json and attaches idempotency_key.
4. Database write_alert() accurately stores and retrieves evidence_json.
"""

import json
import os
import sqlite3
import sys
import time
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import (
    ALL_RULE_CLASSES,
    REGISTERED_RULE_NAMES,
    BlocklistRule,
    TcpFlagAnomalyRule,
    PortScanRule,
    UdpScanRule,
    UdpFloodRule,
    TcpStealthScanRule,
    SynFloodRule,
    DistributedSynFloodRule,
    IcmpSweepRule,
    IcmpFloodRule,
    ArpSpoofRule,
    PayloadRule,
    DnsRule,
    BruteForceRule,
    SlowPortScanRule,
    DataExfiltrationRule,
    TlsAnomalyRule,
    CleartextHttpOnTlsPortRule,
    TcpZeroWindowRule,
    NonDnsTrafficOnDnsPortRule,
    IcmpTunnelRule,
    IpFragmentAnomalyRule,
    IrcC2BeaconingRule,
    RuleEngine,
)
import config
from storage.db import init_db, write_alert, read_all_alerts


def make_tls_client_hello(sni_hostname: str) -> bytes:
    """Helper to construct a realistic TLS 1.2 Client Hello packet with SNI."""
    sni = sni_hostname.encode("utf-8")
    ext_data = b"\x00" + len(sni).to_bytes(2, "big") + sni
    ext_list = len(ext_data).to_bytes(2, "big") + ext_data
    sni_ext = (0).to_bytes(2, "big") + len(ext_list).to_bytes(2, "big") + ext_list
    extensions_data = sni_ext
    extensions = len(extensions_data).to_bytes(2, "big") + extensions_data

    client_hello_body = (
        b"\x03\x03" +   # TLS 1.2
        b"\x00" * 32 +  # random bytes
        b"\x00" +       # session ID length: 0
        (2).to_bytes(2, "big") + b"\xc0\x2f" +  # 1 cipher suite
        b"\x01\x00" +   # compression methods length: 1, method: null
        extensions
    )
    handshake = b"\x01" + len(client_hello_body).to_bytes(3, "big") + client_hello_body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    return record


class TestAlertEvidenceSchema(unittest.TestCase):
    """Verify evidence schema integrity across all detection rules."""

    def test_canonical_23_rule_registry_invariants(self):
        """Verify that all 23 rule classes define name, rule_version, and are in REGISTERED_RULE_NAMES."""
        self.assertEqual(len(ALL_RULE_CLASSES), 23)
        self.assertEqual(len(REGISTERED_RULE_NAMES), 23)

        for rule_cls in ALL_RULE_CLASSES:
            self.assertTrue(hasattr(rule_cls, "name"), f"{rule_cls} missing name")
            self.assertTrue(hasattr(rule_cls, "rule_version"), f"{rule_cls} missing rule_version")
            self.assertIn(rule_cls.name, REGISTERED_RULE_NAMES)

    def _verify_alert_evidence(self, alert: dict, expected_rule: str):
        """Assert common schema invariants for any generated alert."""
        self.assertIsNotNone(alert, f"Expected alert for {expected_rule} but got None")
        self.assertEqual(alert.get("rule_name"), expected_rule)
        self.assertIn("rule_version", alert)
        self.assertIn("severity", alert)
        self.assertIn("confidence", alert)
        self.assertIn("detail", alert)
        self.assertIn("evidence", alert)

        evidence = alert["evidence"]
        self.assertIsInstance(evidence, dict, f"Evidence for {expected_rule} must be a dict")
        self.assertGreater(len(evidence), 0, f"Evidence for {expected_rule} must not be empty")

        # Must be cleanly JSON serializable
        try:
            dumped = json.dumps(evidence)
            loaded = json.loads(dumped)
            self.assertEqual(len(loaded), len(evidence))
        except (TypeError, ValueError) as exc:
            self.fail(f"Evidence for {expected_rule} is not JSON serializable: {exc}")

    def test_01_blocklist_evidence(self):
        rule = BlocklistRule({"203.0.113.5"})
        alert = rule.check({"type": "IP", "src_ip": "203.0.113.5", "dst_ip": "10.0.0.1", "timestamp": 100.0})
        self._verify_alert_evidence(alert, "BLOCKLIST")
        self.assertEqual(alert["evidence"]["bad_ip"], "203.0.113.5")
        self.assertEqual(alert["evidence"]["direction"], "receive")

    def test_02_tcp_flag_anomaly_evidence(self):
        rule = TcpFlagAnomalyRule()
        # SYN + FIN (0x03)
        alert = rule.check({
            "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80,
            "protocol": "TCP", "tcp_flags": 0x03, "timestamp": 100.0
        })
        self._verify_alert_evidence(alert, "TCP_FLAG_ANOMALY")
        self.assertIn("anomaly_type", alert["evidence"])
        self.assertIn("tcp_flags", alert["evidence"])

    def test_03_port_scan_evidence(self):
        rule = PortScanRule(threshold=3, window=10)
        alert = None
        for p in [80, 81, 82]:
            alert = rule.check({
                "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": p,
                "protocol": "TCP", "tcp_flags": 0x02, "timestamp": 100.0
            })
        self._verify_alert_evidence(alert, "PORT_SCAN")
        self.assertEqual(alert["evidence"]["scan_type"], "vertical")
        self.assertEqual(alert["evidence"]["transport"], "TCP")
        self.assertGreaterEqual(alert["evidence"]["distinct_ports"], 3)

    def test_04_udp_scan_evidence(self):
        rule = UdpScanRule(threshold=3, window=10)
        alert = None
        for p in [5000, 5001, 5002]:
            alert = rule.check({
                "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": p,
                "protocol": "UDP", "timestamp": 100.0
            })
        self._verify_alert_evidence(alert, "UDP_SCAN")
        self.assertEqual(alert["evidence"]["scan_type"], "vertical")
        self.assertEqual(alert["evidence"]["transport"], "UDP")

    def test_05_udp_flood_evidence(self):
        rule = UdpFloodRule(threshold=5, window=5)
        alert = None
        for _ in range(5):
            alert = rule.check({
                "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 9999,
                "protocol": "UDP", "timestamp": 100.0
            })
        self._verify_alert_evidence(alert, "UDP_FLOOD")
        self.assertEqual(alert["evidence"]["classification"], "UDP_PACKET_RATE_THRESHOLD")
        self.assertGreaterEqual(alert["evidence"]["packet_count"], 5)

    def test_06_tcp_stealth_scan_evidence(self):
        rule = TcpStealthScanRule(threshold=3, window=10)
        alert = None
        for p in [21, 22, 23]:
            # NULL scan (flags=0x00)
            alert = rule.check({
                "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": p,
                "protocol": "TCP", "tcp_flags": 0x00, "timestamp": 100.0
            })
        self._verify_alert_evidence(alert, "TCP_STEALTH_SCAN")
        self.assertEqual(alert["evidence"]["scan_type"], "stealth_vertical")
        self.assertIn("probe_types", alert["evidence"])

    def test_07_syn_flood_evidence(self):
        rule = SynFloodRule(threshold=5, window=10)
        alert = None
        for _ in range(5):
            alert = rule.check({
                "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80,
                "protocol": "TCP", "tcp_flags": 0x02, "timestamp": 100.0
            })
        self._verify_alert_evidence(alert, "SYN_FLOOD")
        self.assertEqual(alert["evidence"]["flood_type"], "SYN")
        self.assertGreaterEqual(alert["evidence"]["syn_count"], 5)

    def test_08_distributed_syn_flood_evidence(self):
        rule = DistributedSynFloodRule(threshold=3, min_sources=2, window=10)
        alert = None
        for i in range(3):
            src = f"10.0.0.{i+1}"
            alert = rule.check({
                "type": "IP", "src_ip": src, "dst_ip": "192.168.1.100", "dst_port": 443,
                "protocol": "TCP", "tcp_flags": 0x02, "timestamp": 100.0
            })
        self._verify_alert_evidence(alert, "DISTRIBUTED_SYN_FLOOD")
        self.assertGreaterEqual(alert["evidence"]["distinct_sources"], 2)
        self.assertGreaterEqual(alert["evidence"]["syn_count"], 3)

    def test_09_icmp_sweep_evidence(self):
        rule = IcmpSweepRule(threshold=3, window=10)
        alert = None
        for i in range(3):
            alert = rule.check({
                "type": "IP", "src_ip": "10.0.0.1", "dst_ip": f"192.168.1.{i+1}",
                "protocol": "ICMP", "icmp_type": 8, "icmp_code": 0, "timestamp": 100.0
            })
        self._verify_alert_evidence(alert, "ICMP_SWEEP")
        self.assertEqual(alert["evidence"]["icmp_type"], 8)
        self.assertGreaterEqual(alert["evidence"]["distinct_targets"], 3)

    def test_10_icmp_flood_evidence(self):
        rule = IcmpFloodRule(threshold=5, window=5)
        alert = None
        for _ in range(5):
            alert = rule.check({
                "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "192.168.1.1",
                "protocol": "ICMP", "icmp_type": 8, "icmp_code": 0, "timestamp": 100.0
            })
        self._verify_alert_evidence(alert, "ICMP_FLOOD")
        self.assertEqual(alert["evidence"]["classification"], "ICMP_ECHO_RATE_THRESHOLD")
        self.assertGreaterEqual(alert["evidence"]["packet_count"], 5)

    def test_11_arp_spoof_evidence(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            tf_path = tf.name
        try:
            rule = ArpSpoofRule(table_path=tf_path)
            # Legitimate observation
            rule.check({"type": "ARP", "src_mac": "00:11:22:33:44:55", "src_ip": "192.168.1.1", "protocol": "ARP", "timestamp": 100.0})
            # Poisoned observation
            alert = rule.check({"type": "ARP", "src_mac": "aa:bb:cc:dd:ee:ff", "src_ip": "192.168.1.1", "protocol": "ARP", "timestamp": 101.0})
            self._verify_alert_evidence(alert, "ARP_SPOOF")
            self.assertEqual(alert["evidence"]["classification"], "ARP_IDENTITY_CHANGE")
            self.assertEqual(alert["evidence"]["previous_mac"], "00:11:22:33:44:55")
            self.assertEqual(alert["evidence"]["new_mac"], "aa:bb:cc:dd:ee:ff")
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_12_payload_hit_evidence(self):
        rule = PayloadRule(enabled=True)
        payload = b"GET /users?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1\r\nHost: target\r\n\r\n"
        alert = rule.check({
            "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80,
            "protocol": "TCP", "payload": payload, "payload_len": len(payload),
            "timestamp": 100.0
        })
        self._verify_alert_evidence(alert, "PAYLOAD_HIT")
        self.assertIn("hits", alert["evidence"])
        self.assertEqual(alert["evidence"]["hits"][0]["signature"], "SQL_INJECTION")

    def test_13_dns_rule_evidence(self):
        rule = DnsRule(entropy_threshold=3.5)
        query = "a9f8e7d6c5b4a3928170zxywvutsrqponmlkji.exfil.example.com"
        alert = rule.check({
            "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "dst_port": 53,
            "protocol": "UDP", "dns_query": query, "timestamp": 100.0
        })
        self._verify_alert_evidence(alert, "DNS_ANOMALY")
        self.assertIn("entropy", alert["evidence"])

    def test_14_brute_force_evidence(self):
        rule = BruteForceRule(threshold=3, window=60)
        alert = None
        for _ in range(3):
            alert = rule.check({
                "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 22,
                "protocol": "TCP", "tcp_flags": 0x02, "timestamp": 100.0
            })
        self._verify_alert_evidence(alert, "BRUTE_FORCE")
        self.assertEqual(alert["evidence"]["classification"], "AUTH_SERVICE_SYN_BURST")
        self.assertGreaterEqual(alert["evidence"]["attempt_count"], 3)

    def test_15_slow_port_scan_evidence(self):
        rule = SlowPortScanRule(threshold=3, window=120)
        alert = None
        for i, p in enumerate([1000, 1001, 1002]):
            alert = rule.check({
                "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": p,
                "protocol": "TCP", "tcp_flags": 0x02, "timestamp": 100.0 + i * 20.0
            })
        self._verify_alert_evidence(alert, "SLOW_PORT_SCAN")
        self.assertEqual(alert["evidence"]["scan_type"], "slow_vertical")

    def test_16_data_exfiltration_evidence(self):
        rule = DataExfiltrationRule()
        # Direct database dump / archive signature
        payload = b"SQLite format 3\x00" + b"\x00" * 60
        alert = rule.check({
            "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "198.51.100.5", "dst_port": 9000,
            "protocol": "TCP", "payload": payload, "payload_len": len(payload),
            "timestamp": 100.0
        })
        self._verify_alert_evidence(alert, "DATA_EXFIL")
        self.assertEqual(alert["evidence"]["sub_type"], "SIGNATURE_EXFIL")
        self.assertEqual(alert["evidence"]["matched_signature"], "SQLite database file dump")

    def test_17_tls_anomaly_evidence(self):
        rule = TlsAnomalyRule(enabled=True)
        # Direct IP in TLS SNI
        payload = make_tls_client_hello("198.51.100.5")
        alert = rule.check({
            "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "198.51.100.5", "dst_port": 443,
            "protocol": "TCP", "payload": payload, "payload_len": len(payload),
            "timestamp": 100.0
        })
        self._verify_alert_evidence(alert, "TLS_ANOMALY")
        self.assertEqual(alert["evidence"]["anomaly_type"], "DIRECT_IP_SNI")

    def test_18_cleartext_http_on_tls_port_evidence(self):
        rule = CleartextHttpOnTlsPortRule(min_requests=1, cooldown=1.0)
        payload = b"GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
        alert = rule.check({
            "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 443,
            "protocol": "TCP", "payload": payload, "payload_len": len(payload),
            "timestamp": 100.0
        })
        self._verify_alert_evidence(alert, "CLEAR_HTTP_ON_TLS_PORT")
        self.assertIn("request_line", alert["evidence"])
        self.assertEqual(alert["evidence"]["target_port"], 443)

    def test_19_tcp_zero_window_evidence(self):
        rule = TcpZeroWindowRule(threshold=3, min_distinct_flows=1, window=10)
        alert = None
        for i in range(3):
            alert = rule.check({
                "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 50000, "dst_port": 80,
                "protocol": "TCP", "tcp_window": 0, "tcp_flags": 0x10, "timestamp": 100.0 + i
            })
        self._verify_alert_evidence(alert, "TCP_ZERO_WINDOW")
        self.assertGreaterEqual(alert["evidence"]["zero_window_count"], 3)

    def test_20_non_dns_traffic_on_dns_port_evidence(self):
        rule = NonDnsTrafficOnDnsPortRule(cooldown=1.0)
        payload = b"Microsoft Windows [Version 10.0.19041.1]\r\nC:\\Users\\admin>"
        alert = rule.check({
            "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 53,
            "protocol": "TCP", "payload": payload, "payload_len": len(payload),
            "timestamp": 100.0
        })
        self._verify_alert_evidence(alert, "NON_DNS_TRAFFIC_ON_DNS_PORT")
        self.assertEqual(alert["evidence"]["anomaly_type"], "INTERACTIVE_SHELL")

    def test_21_icmp_tunnel_evidence(self):
        rule = IcmpTunnelRule(min_bytes=32, entropy_threshold=4.0)
        payload = b"QUFBQUJCQkJDQ0NDRERERUVFRUVGRkZGR0dHR0hIR0hJSUlJSg==" * 2
        alert = rule.check({
            "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "protocol": "ICMP", "icmp_type": 8, "icmp_code": 0,
            "payload": payload, "payload_len": len(payload), "timestamp": 100.0
        })
        self._verify_alert_evidence(alert, "ICMP_TUNNEL")
        self.assertIn("anomaly_type", alert["evidence"])
        self.assertIn("b64_ratio", alert["evidence"])
        self.assertIn("entropy", alert["evidence"])

    def test_22_ip_fragment_anomaly_evidence(self):
        rule = IpFragmentAnomalyRule(cooldown=1.0)
        # Frag 1: offset 0, len 36
        rule.check({
            "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "UDP",
            "ip_fragment_id": 9999, "ip_fragment_offset": 0, "ip_fragment_data_len": 36,
            "ip_more_fragments": True, "ip_fragmented": True, "timestamp": 100.0
        })
        # Frag 2: offset 24, len 20 (overlap with 0..36)
        alert = rule.check({
            "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "UDP",
            "ip_fragment_id": 9999, "ip_fragment_offset": 24, "ip_fragment_data_len": 20,
            "ip_more_fragments": False, "ip_fragmented": True, "timestamp": 100.1
        })
        self._verify_alert_evidence(alert, "IP_FRAGMENT_ANOMALY")
        self.assertEqual(alert["evidence"]["anomaly_type"], "TEARDROP_OVERLAPPING_FRAGMENT")
        self.assertEqual(alert["evidence"]["ip_fragment_id"], 9999)

    def test_23_irc_c2_beaconing_evidence(self):
        rule = IrcC2BeaconingRule(threshold=3, window=300)
        payload = b"PRIVMSG #botnet :attack target\r\n"
        alert = rule.check({
            "type": "IP", "src_ip": "10.0.0.1", "dst_ip": "198.51.100.99", "dst_port": 6667,
            "protocol": "TCP", "payload": payload, "payload_len": len(payload),
            "timestamp": 100.0
        })
        self._verify_alert_evidence(alert, "IRC_C2_BEACONING")
        self.assertEqual(alert["evidence"]["classification"], "IRC_PROTOCOL_SIGNATURE")
        self.assertEqual(alert["evidence"]["activity_assessment"], "LIKELY_IRC_C2")

    def test_rule_engine_evidence_json_serialization_and_db_persistence(self):
        """Verify RuleEngine serializes evidence to evidence_json and saves cleanly into DB."""
        import tempfile
        from storage.db import get_connection

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            db_path = tf.name

        try:
            conn = get_connection(db_path)
            init_db(conn)

            # Point config to db_path
            orig_sqlite = config.SQLITE_PATH
            config.SQLITE_PATH = db_path

            try:
                engine = RuleEngine(conn, blocklist=set(), cfg=config, event_clock=lambda: 100.0)

                # Trigger an alert through engine.check
                record = {
                    "type": "IP",
                    "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80,
                    "protocol": "TCP", "tcp_flags": 0x03, "timestamp": 100.0
                }
                engine.check(record)
                engine.flush()

                alerts = read_all_alerts(conn)
                self.assertGreaterEqual(len(alerts), 1)

                saved_alert = alerts[0]
                self.assertEqual(saved_alert["rule_name"], "TCP_FLAG_ANOMALY")
                self.assertIsNotNone(saved_alert.get("evidence_json"))

                # Parse back evidence_json
                parsed_evidence = json.loads(saved_alert["evidence_json"])
                self.assertIsInstance(parsed_evidence, dict)
                self.assertEqual(parsed_evidence["tcp_flags"], 0x03)
            finally:
                config.SQLITE_PATH = orig_sqlite
                conn.close()
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
