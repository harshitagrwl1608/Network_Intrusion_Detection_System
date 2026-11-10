"""
Unit tests for IcmpTunnelRule (Rule 21).

Verifies detection of covert ICMP tunnels, reverse shells (icmpsh), data exfiltration,
and embedded executables in ICMP Echo packets, while ensuring zero false positives
on standard diagnostic pings and MTU sweeps.
"""

import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import IcmpTunnelRule


class TestIcmpTunnelRule(unittest.TestCase):

    def setUp(self):
        self.rule = IcmpTunnelRule(
            entropy_threshold=4.5,
            min_bytes=128,
            cooldown=60.0
        )

    # -------------------------------------------------------------------------
    # Positive Detection Tests
    # -------------------------------------------------------------------------

    def test_detects_ptunnel_magic_signature(self):
        """Detects Ptunnel traffic containing magic signature 0xD5200804."""
        payload = b"\xd5\x20\x08\x04" + b"\x00" * 40
        record = {
            "type": "IP",
            "protocol": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
            "src_ip": "192.168.1.100",
            "dst_ip": "198.51.100.5",
            "payload": payload,
            "timestamp": 1000.0,
        }
        alert = self.rule.check(record)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "ICMP_TUNNEL")
        self.assertEqual(alert["evidence"]["anomaly_type"], "PTUNNEL_TRAFFIC")
        self.assertEqual(alert["severity"], "critical")
        self.assertEqual(alert["confidence"], "high")

    def test_detects_embedded_elf_executable(self):
        """Detects Linux ELF executable header in ICMP Echo payload."""
        payload = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 60
        record = {
            "type": "IP",
            "protocol": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
            "src_ip": "10.0.0.5",
            "dst_ip": "198.51.100.10",
            "payload": payload,
            "timestamp": 2000.0,
        }
        alert = self.rule.check(record)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "EMBEDDED_EXECUTABLE")
        self.assertEqual(alert["severity"], "high")

    def test_detects_embedded_windows_pe_executable(self):
        """Detects Windows PE (MZ header) executable in ICMP Echo payload."""
        payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 80
        record = {
            "type": "IP",
            "protocol": "ICMP",
            "icmp_type": 0,  # Echo Reply
            "icmp_code": 0,
            "src_ip": "198.51.100.10",
            "dst_ip": "10.0.0.5",
            "payload": payload,
            "timestamp": 2100.0,
        }
        alert = self.rule.check(record)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "EMBEDDED_EXECUTABLE")

    def test_detects_icmpsh_interactive_shell_payload(self):
        """Detects Windows cmd.exe or /bin/sh reverse shell data in ICMP Echo."""
        payload = b"cmd.exe /c whoami\r\n"
        record = {
            "type": "IP",
            "protocol": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
            "src_ip": "192.168.1.50",
            "dst_ip": "203.0.113.1",
            "payload": payload,
            "timestamp": 3000.0,
        }
        alert = self.rule.check(record)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "ICMP_SHELL_PAYLOAD")
        self.assertEqual(alert["evidence"]["matched_indicator"], "cmd.exe")

    def test_detects_high_entropy_encrypted_tunnel(self):
        """Detects oversized high-entropy ciphertext payload (>128 bytes, entropy > 4.5)."""
        import os
        random_ciphertext = os.urandom(256)
        record = {
            "type": "IP",
            "protocol": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
            "src_ip": "172.16.0.4",
            "dst_ip": "198.51.100.20",
            "payload": random_ciphertext,
            "timestamp": 4000.0,
        }
        alert = self.rule.check(record)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "HIGH_ENTROPY_TUNNEL")
        self.assertGreaterEqual(alert["evidence"]["entropy"], 4.5)

    def test_detects_covert_base64_icmp_tunnel_chunk(self):
        """Detects 100-byte high-entropy Base64 data exfiltration chunk in ICMP Echo (m_rau5)."""
        rule = IcmpTunnelRule()  # uses default min_bytes=64
        payload = b"PMpjoOZnR8KJ5txLR60yUY0q8G1WoN8HroObMEttyHPM6DT7HvLTZQw9UyxC3QE5RMMq2vyhinGtrDumiGpVGmC57QKxV1iOe234"
        record = {
            "type": "IP",
            "protocol": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
            "src_ip": "192.168.0.35",
            "dst_ip": "192.168.1.1",
            "payload": payload,
            "timestamp": 4100.0,
        }
        alert = rule.check(record)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "ICMP_TUNNEL")
        self.assertEqual(alert["evidence"]["anomaly_type"], "BASE64_EXFILTRATION")
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["confidence"], "high")
        self.assertGreaterEqual(alert["evidence"]["entropy"], 4.5)
        self.assertGreaterEqual(alert["evidence"]["b64_ratio"], 0.95)

    def test_detects_ipv6_icmpv6_tunnel(self):
        """Detects covert tunnel transported over ICMPv6 Echo Request (type 128)."""
        payload = b"root@victim:/# cat /etc/shadow\n"
        record = {
            "type": "IP",
            "protocol": "ICMPV6",
            "icmp_type": 128,
            "icmp_code": 0,
            "src_ip": "2001:db8::1",
            "dst_ip": "2001:db8::2",
            "payload": payload,
            "timestamp": 4500.0,
        }
        alert = self.rule.check(record)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "ICMP_SHELL_PAYLOAD")

    def test_detects_ipv6_icmpv6_echo_reply_tunnel(self):
        """Detects covert tunnel transported over ICMPv6 Echo Reply (type 129)."""
        payload = b"cmd.exe /c dir\r\n"
        record = {
            "type": "IP",
            "protocol": "ICMPV6",
            "icmp_type": 129,
            "icmp_code": 0,
            "src_ip": "2001:db8::2",
            "dst_ip": "2001:db8::1",
            "payload": payload,
            "timestamp": 4510.0,
        }
        alert = self.rule.check(record)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "ICMP_SHELL_PAYLOAD")

    def test_sniffer_extracts_icmpv6_echo_reply(self):
        """Verifies that sniffer._extract properly parses Scapy ICMPv6EchoReply packets."""
        from capture.sniffer import _extract
        from scapy.all import IPv6, ICMPv6EchoReply
        pkt = IPv6(src="2001:db8::2", dst="2001:db8::1") / ICMPv6EchoReply(data=b"cmd.exe shell reply")
        rec = _extract(pkt, capture_ts=4520.0)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["protocol"], "ICMPV6")
        self.assertEqual(rec["icmp_type"], 129)
        self.assertEqual(rec["payload"], b"cmd.exe shell reply")
        alert = self.rule.check(rec)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["anomaly_type"], "ICMP_SHELL_PAYLOAD")

    # -------------------------------------------------------------------------
    # Negative Tests (Standard Diagnostic Pings & Benign Controls)
    # -------------------------------------------------------------------------

    def test_ignores_standard_windows_ping(self):
        """Standard Windows ping (32 bytes: abcdefghijklmnopqrstuvwabcdefghi) is ignored."""
        windows_ping = b"abcdefghijklmnopqrstuvwabcdefghi"
        record = {
            "type": "IP",
            "protocol": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "payload": windows_ping,
            "timestamp": 5000.0,
        }
        self.assertIsNone(self.rule.check(record))

    def test_ignores_standard_linux_ping(self):
        """Standard Linux ping (56 bytes payload) is ignored."""
        linux_ping = b"\x00" * 16 + b"!" * 40
        record = {
            "type": "IP",
            "protocol": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "payload": linux_ping,
            "timestamp": 5010.0,
        }
        self.assertIsNone(self.rule.check(record))

    def test_ignores_diagnostic_mtu_ping_zeros(self):
        """Diagnostic jumbo ping with zero padding (e.g. ping -s 1472) is ignored."""
        zero_payload = b"\x00" * 1472
        record = {
            "type": "IP",
            "protocol": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "payload": zero_payload,
            "timestamp": 5020.0,
        }
        self.assertIsNone(self.rule.check(record))

    def test_ignores_diagnostic_mtu_ping_sequential_pattern(self):
        """Diagnostic Linux ping sweep with sequential bytes (e.g. ping -s 500) is ignored."""
        # 16 bytes timestamp + 484 sequential incrementing bytes
        seq_payload = b"\x00" * 16 + bytes((i % 256) for i in range(484))
        record = {
            "type": "IP",
            "protocol": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "payload": seq_payload,
            "timestamp": 5030.0,
        }
        self.assertIsNone(self.rule.check(record))

    def test_ignores_non_echo_icmp_control_messages(self):
        """Destination unreachable (type 3), TTL exceeded (type 11) are ignored."""
        record = {
            "type": "IP",
            "protocol": "ICMP",
            "icmp_type": 3,  # Destination Unreachable
            "icmp_code": 3,  # Port Unreachable
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.10",
            "payload": b"\x7fELF" + b"\x00" * 50,  # Embedded packet in ICMP error
            "timestamp": 5040.0,
        }
        self.assertIsNone(self.rule.check(record))

    def test_ignores_non_icmp_protocols(self):
        """TCP or UDP packets are ignored by IcmpTunnelRule."""
        record = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 1234,
            "dst_port": 80,
            "payload": b"\x7fELF" + b"\x00" * 50,
            "timestamp": 5050.0,
        }
        self.assertIsNone(self.rule.check(record))

    # -------------------------------------------------------------------------
    # Cooldown & State Management
    # -------------------------------------------------------------------------

    def test_cooldown_suppresses_duplicate_alerts(self):
        """Repeated tunnel packets between same pair within cooldown generate only 1 alert."""
        payload = b"\xd5\x20\x08\x04" + b"\x00" * 40
        record1 = {
            "type": "IP",
            "protocol": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
            "src_ip": "192.168.1.100",
            "dst_ip": "198.51.100.5",
            "payload": payload,
            "timestamp": 6000.0,
        }
        record2 = {
            "type": "IP",
            "protocol": "ICMP",
            "icmp_type": 0,
            "icmp_code": 0,
            "src_ip": "198.51.100.5",
            "dst_ip": "192.168.1.100",
            "payload": payload,
            "timestamp": 6015.0,  # 15s later
        }
        record3 = {
            "type": "IP",
            "protocol": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
            "src_ip": "192.168.1.100",
            "dst_ip": "198.51.100.5",
            "payload": payload,
            "timestamp": 6070.0,  # 70s later, cooldown expired
        }
        self.assertIsNotNone(self.rule.check(record1))
        self.assertIsNone(self.rule.check(record2))
        self.assertIsNotNone(self.rule.check(record3))

    def test_prune_stale_evicts_expired_entries(self):
        """prune_stale() cleans up seen entries past cooldown."""
        payload = b"cmd.exe /c dir\r\n"
        record = {
            "type": "IP",
            "protocol": "ICMP",
            "icmp_type": 8,
            "icmp_code": 0,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "payload": payload,
            "timestamp": 7000.0,
        }
        self.assertIsNotNone(self.rule.check(record))
        self.assertEqual(len(self.rule._seen), 1)

        self.rule.prune_stale(now=7030.0)
        self.assertEqual(len(self.rule._seen), 1)

        self.rule.prune_stale(now=7065.0)
        self.assertEqual(len(self.rule._seen), 0)


if __name__ == "__main__":
    unittest.main()

