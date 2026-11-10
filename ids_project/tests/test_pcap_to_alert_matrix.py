#!/usr/bin/env python3
"""
ids_project/tests/test_pcap_to_alert_matrix.py
----------------------------------------------
End-to-End PCAP-to-Alert Integration Test Matrix for NetGuard IDS.

Verifies the complete execution pipeline:
PCAP -> Scapy extraction -> normalized packet records -> RuleEngine -> alert queue -> persisted DB alerts -> evaluation result

At minimum exercises:
1. IRC SYN beaconing traffic (detection)
2. Legitimate IRC traffic (benign suppression)
3. IPv4 fragment overlap Teardrop (detection)
4. IPv6 fragmentation handling (clean extraction & flow tracking)
5. ICMP tunnel demonstration capture (detection)
6. DNS-port shell capture (detection)
7. Benign DNS traffic (benign suppression)
8. Benign fragmented traffic (benign suppression)
9. Normal TLS traffic (benign suppression)
10. Benign web browsing (benign suppression)

Preserves strict provenance tagging:
- real_world: independent live field telemetry
- curated_research_fixture: targeted security research capture
- synthetic_fixture: deterministically generated Scapy packet suite
- mock_demonstration: demonstration fixture for covert tunneling
"""

import json
import os
import sqlite3
import sys
import tempfile
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from capture.sniffer import _extract, replay_pcap
from engine.blocklist import BlocklistData
from evaluation.replay import run_standalone_replay
from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, fragment, raw
from scapy.layers.inet6 import IPv6ExtHdrFragment, fragment6


VERIFIED_DATASETS_DIR = "/run/media/harshitgarg/Data1/NetGuard-datasets/verified"
ATTACK_PCAP_PATH = os.path.join(PROJECT_DIR, "data", "test_attacks.pcap")
BENIGN_PCAP_PATH = os.path.join(PROJECT_DIR, "data", "test_benign.pcap")
BLOCKLIST_PATH = os.path.join(PROJECT_DIR, "data", "test_blocklist.txt")


class TestPcapToAlertIntegrationMatrix(unittest.TestCase):
    """Rigorous end-to-end integration tests verifying PCAP -> RuleEngine -> SQLite alerts."""

    def _run_pcap_and_get_alerts(self, pcap_path: str) -> list[dict]:
        """Replay a PCAP through an isolated database and return all persisted alerts."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as db_f, \
             tempfile.NamedTemporaryFile(suffix=".json", delete=False) as arp_f:
            db_path = db_f.name
            arp_path = arp_f.name

        try:
            # Write a valid empty JSON dictionary for ARP table isolation
            with open(arp_path, "w") as f:
                json.dump({}, f)

            run_standalone_replay(
                pcap_path=pcap_path,
                blocklist_path=BLOCKLIST_PATH if os.path.isfile(BLOCKLIST_PATH) else None,
                db_path=db_path,
                arp_table_path=arp_path
            )

            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("""
                SELECT rule_name, src_ip, dst_ip, src_port, dst_port,
                       protocol, severity, confidence, detail, evidence_json
                FROM alerts
                ORDER BY id ASC
            """)
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return rows
        finally:
            for p in (db_path, arp_path):
                if os.path.exists(p):
                    try:
                        os.unlink(p)
                    except OSError:
                        pass

    def test_01_irc_syn_beaconing_detection(self):
        """Matrix Item 1: IRC SYN traffic detected end-to-end (synthetic fixture)."""
        provenance = "synthetic_fixture"
        self.assertTrue(os.path.isfile(ATTACK_PCAP_PATH))
        alerts = self._run_pcap_and_get_alerts(ATTACK_PCAP_PATH)
        irc_alerts = [a for a in alerts if a["rule_name"] == "IRC_C2_BEACONING"]
        self.assertGreaterEqual(len(irc_alerts), 1, f"Expected IRC_C2_BEACONING alert from {provenance}")
        alert = irc_alerts[0]
        self.assertEqual(alert["src_ip"], "192.168.1.109")
        self.assertEqual(alert["dst_ip"], "185.244.25.235")
        self.assertEqual(alert["dst_port"], 6667)
        self.assertEqual(alert["severity"], "high")
        self.assertIn("beaconing", alert["detail"].lower())

    def test_02_legitimate_irc_traffic_suppression(self):
        """Matrix Item 2: Legitimate IRC traffic must NOT trigger botnet C2 alerts."""
        # 1. Benign synthetic fixture (B29: single SYN attempt to 6667)
        self.assertTrue(os.path.isfile(BENIGN_PCAP_PATH))
        benign_alerts = self._run_pcap_and_get_alerts(BENIGN_PCAP_PATH)
        irc_benign = [a for a in benign_alerts if a["rule_name"] == "IRC_C2_BEACONING"]
        self.assertEqual(len(irc_benign), 0, "Benign IRC probe must not trigger IRC_C2_BEACONING")

        # 2. Curated research fixture: real Wireshark IRC chat sessions
        ws_irc_pcap = os.path.join(VERIFIED_DATASETS_DIR, "ws_skype_irc.pcap")
        if os.path.isfile(ws_irc_pcap):
            provenance = "curated_research_fixture"
            real_alerts = self._run_pcap_and_get_alerts(ws_irc_pcap)
            c2_alerts = [a for a in real_alerts if a["rule_name"] == "IRC_C2_BEACONING"]
            self.assertEqual(len(c2_alerts), 0, f"Legitimate IRC traffic in {provenance} must have 0 C2 alerts")

    def test_03_ipv4_fragment_overlap_teardrop_detection(self):
        """Matrix Item 3: IPv4 fragment overlap Teardrop attack detected end-to-end."""
        # 1. Synthetic fixture (S41)
        alerts = self._run_pcap_and_get_alerts(ATTACK_PCAP_PATH)
        frag_alerts = [a for a in alerts if a["rule_name"] == "IP_FRAGMENT_ANOMALY"]
        self.assertGreaterEqual(len(frag_alerts), 1, "Expected IP_FRAGMENT_ANOMALY alert from attack fixture")
        self.assertEqual(frag_alerts[0]["src_ip"], "192.168.1.108")
        self.assertEqual(frag_alerts[0]["dst_ip"], "192.168.1.1")
        self.assertEqual(frag_alerts[0]["severity"], "critical")

        # 2. Curated research fixture: authentic Teardrop attack capture
        ws_teardrop_pcap = os.path.join(VERIFIED_DATASETS_DIR, "ws_teardrop.pcap")
        if os.path.isfile(ws_teardrop_pcap):
            provenance = "curated_research_fixture"
            teardrop_alerts = self._run_pcap_and_get_alerts(ws_teardrop_pcap)
            self.assertEqual(len(teardrop_alerts), 1, f"Expected 1 Teardrop alert from {provenance}")
            self.assertEqual(teardrop_alerts[0]["rule_name"], "IP_FRAGMENT_ANOMALY")
            self.assertEqual(teardrop_alerts[0]["src_ip"], "10.1.1.1")
            self.assertEqual(teardrop_alerts[0]["dst_ip"], "129.111.30.27")
            self.assertEqual(teardrop_alerts[0]["severity"], "critical")

    def test_04_ipv6_fragmentation_handling(self):
        """Matrix Item 4: IPv6 fragmented packets extracted and processed through engine without false alerts,
        and overlapping IPv6 fragments correctly detected as an attack."""
        provenance = "synthetic_fixture"
        # Non-overlapping IPv6 fragments (first fragment 40 bytes total: 20B TCP + 20B payload; second starts at 40B, offset 5*8)
        packet = (
            IPv6(src="2001:db8::1", dst="2001:db8::2") /
            IPv6ExtHdrFragment(nh=6, id=777, offset=0, m=1) /
            TCP(sport=50000, dport=443, flags="PA") / Raw(load=b"SecurePayloadChunk12")
        )
        packet_frag2 = (
            IPv6(src="2001:db8::1", dst="2001:db8::2") /
            IPv6ExtHdrFragment(nh=6, id=777, offset=5, m=0) /
            Raw(load=b"SecurePayloadChunk3")
        )
        r1 = _extract(Ether(raw(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / packet)), capture_ts=100.0)
        r2 = _extract(Ether(raw(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / packet_frag2)), capture_ts=100.1)

        self.assertTrue(r1["ip_fragmented"])
        self.assertTrue(r2["ip_fragmented"])
        self.assertEqual(r1["ip_fragment_id"], 777)
        self.assertEqual(r2["ip_fragment_id"], 777)
        self.assertEqual(r1["protocol"], "TCP")
        self.assertEqual(r2["protocol"], "TCP")

        # 1. Non-overlapping IPv6 fragments must NOT fire IP_FRAGMENT_ANOMALY
        from engine.rules import IpFragmentAnomalyRule
        rule = IpFragmentAnomalyRule()
        a1 = rule.check(r1)
        a2 = rule.check(r2)
        self.assertIsNone(a1, f"First IPv6 fragment in {provenance} must not trigger alert")
        self.assertIsNone(a2, f"In-order second IPv6 fragment in {provenance} must not trigger alert")

        # 2. Overlapping IPv6 fragment (offset 4*8 = 32 bytes, overlapping [0-40] by 8 bytes) MUST trigger alert
        packet_overlap = (
            IPv6(src="2001:db8::1", dst="2001:db8::2") /
            IPv6ExtHdrFragment(nh=6, id=777, offset=4, m=0) /
            Raw(load=b"MaliciousOverlapPkt")
        )
        r_overlap = _extract(Ether(raw(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / packet_overlap)), capture_ts=100.2)
        a_overlap = rule.check(r_overlap)
        self.assertIsNotNone(a_overlap, "Overlapping IPv6 fragment must trigger IP_FRAGMENT_ANOMALY")
        self.assertEqual(a_overlap["evidence"]["anomaly_type"], "TEARDROP_OVERLAPPING_FRAGMENT")

    def test_05_icmp_tunnel_demonstration_capture(self):
        """Matrix Item 5: ICMP tunnel covert channel detected end-to-end."""
        # 1. Synthetic fixture (S40)
        alerts = self._run_pcap_and_get_alerts(ATTACK_PCAP_PATH)
        icmp_tunnel_alerts = [a for a in alerts if a["rule_name"] == "ICMP_TUNNEL"]
        self.assertGreaterEqual(len(icmp_tunnel_alerts), 1, "Expected ICMP_TUNNEL alert from synthetic fixture")
        self.assertEqual(icmp_tunnel_alerts[0]["src_ip"], "192.168.1.107")
        self.assertEqual(icmp_tunnel_alerts[0]["dst_ip"], "203.0.113.107")

        # 2. Mock demonstration capture (curated mock fixture by m-rau5)
        m_rau5_pcap = os.path.join(VERIFIED_DATASETS_DIR, "m_rau5_icmp_tunnel.pcap")
        if os.path.isfile(m_rau5_pcap):
            provenance = "mock_demonstration"
            m_alerts = self._run_pcap_and_get_alerts(m_rau5_pcap)
            m_icmp = [a for a in m_alerts if a["rule_name"] == "ICMP_TUNNEL"]
            self.assertGreaterEqual(len(m_icmp), 1, f"Expected ICMP_TUNNEL alert from {provenance}")
            self.assertEqual(m_icmp[0]["src_ip"], "192.168.0.35")
            self.assertEqual(m_icmp[0]["dst_ip"], "192.168.1.1")
            self.assertIn("Base64-encoded exfiltration", m_icmp[0]["detail"])

    def test_06_dns_port_shell_capture(self):
        """Matrix Item 6: Interactive shell / non-DNS traffic over DNS port 53 detected end-to-end."""
        # 1. Synthetic fixture (S39)
        alerts = self._run_pcap_and_get_alerts(ATTACK_PCAP_PATH)
        dns_shell = [a for a in alerts if a["rule_name"] == "NON_DNS_TRAFFIC_ON_DNS_PORT"]
        self.assertGreaterEqual(len(dns_shell), 1, "Expected NON_DNS_TRAFFIC_ON_DNS_PORT from attack fixture")
        self.assertEqual(dns_shell[0]["src_ip"], "192.168.1.106")
        self.assertEqual(dns_shell[0]["dst_port"], 53)
        self.assertEqual(dns_shell[0]["severity"], "high")

        # 2. Curated research fixture (Wireshark DNS remote shell)
        ws_dns_pcap = os.path.join(VERIFIED_DATASETS_DIR, "ws_dns_remoteshell.pcap")
        if os.path.isfile(ws_dns_pcap):
            provenance = "curated_research_fixture"
            ws_alerts = self._run_pcap_and_get_alerts(ws_dns_pcap)
            shell_alerts = [a for a in ws_alerts if a["rule_name"] == "NON_DNS_TRAFFIC_ON_DNS_PORT"]
            self.assertGreaterEqual(len(shell_alerts), 1, f"Expected alert from {provenance}")
            self.assertEqual(shell_alerts[0]["src_ip"], "192.168.1.2")
            self.assertEqual(shell_alerts[0]["dst_ip"], "192.168.1.3")

    def test_07_benign_dns_traffic_suppression(self):
        """Matrix Item 7: Valid DNS queries and TCP DNS traffic must NOT trigger false alerts."""
        provenance = "synthetic_fixture"
        benign_alerts = self._run_pcap_and_get_alerts(BENIGN_PCAP_PATH)
        dns_non_dns_alerts = [a for a in benign_alerts if a["rule_name"] == "NON_DNS_TRAFFIC_ON_DNS_PORT"]
        self.assertEqual(len(dns_non_dns_alerts), 0, f"Valid DNS in {provenance} must not trigger NON_DNS_TRAFFIC_ON_DNS_PORT")

    def test_08_benign_fragmented_traffic_suppression(self):
        """Matrix Item 8: In-order, non-overlapping fragmented packets must NOT trigger anomaly alerts."""
        provenance = "synthetic_fixture"
        benign_alerts = self._run_pcap_and_get_alerts(BENIGN_PCAP_PATH)
        frag_alerts = [a for a in benign_alerts if a["rule_name"] == "IP_FRAGMENT_ANOMALY"]
        self.assertEqual(len(frag_alerts), 0, f"Benign fragmentation in {provenance} must have 0 IP_FRAGMENT_ANOMALY alerts")

    def test_09_normal_tls_traffic_suppression(self):
        """Matrix Item 9: Normal HTTPS / TLS traffic must NOT trigger false alerts."""
        # 1. Synthetic benign fixture (B15, B16)
        benign_alerts = self._run_pcap_and_get_alerts(BENIGN_PCAP_PATH)
        tls_alerts = [a for a in benign_alerts if a["rule_name"] in ("TLS_ANOMALY", "CLEAR_HTTP_ON_TLS_PORT")]
        self.assertEqual(len(tls_alerts), 0, "Normal TLS traffic must not trigger TLS anomaly alerts")

        # 2. Curated research fixture
        oisf_tls_pcap = os.path.join(VERIFIED_DATASETS_DIR, "oisf_tls_sni_anomaly.pcap")
        if os.path.isfile(oisf_tls_pcap):
            provenance = "curated_research_fixture"
            oisf_alerts = self._run_pcap_and_get_alerts(oisf_tls_pcap)
            self.assertEqual(len(oisf_alerts), 0, f"Standard TLS handshake in {provenance} must not fire false alerts")

    def test_10_benign_web_browsing_suppression(self):
        """Matrix Item 10: Standard HTTP web browsing traffic must NOT trigger false alerts."""
        ws_http_pcap = os.path.join(VERIFIED_DATASETS_DIR, "ws_http_browsing.pcap")
        if os.path.isfile(ws_http_pcap):
            provenance = "curated_research_fixture"
            http_alerts = self._run_pcap_and_get_alerts(ws_http_pcap)
            self.assertEqual(len(http_alerts), 0, f"Benign HTTP browsing in {provenance} must have 0 alerts")


if __name__ == "__main__":
    unittest.main()
