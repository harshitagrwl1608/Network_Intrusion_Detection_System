import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import TlsAnomalyRule
import engine.rules as rules_mod


def make_tls_client_hello(sni_hostname: str) -> bytes:
    """Helper to construct a realistic TLS 1.2 Client Hello packet with SNI."""
    sni = sni_hostname.encode("utf-8")
    ext_data = b"\x00" + len(sni).to_bytes(2, "big") + sni
    ext_list = len(ext_data).to_bytes(2, "big") + ext_data
    sni_ext = (0).to_bytes(2, "big") + len(ext_list).to_bytes(2, "big") + ext_list
    extensions = len(sni_ext).to_bytes(2, "big") + sni_ext

    client_hello_body = (
        b"\x03\x03" +   # TLS 1.2
        b"\x00" * 32 +  # random bytes
        b"\x00" +       # session ID length: 0
        (2).to_bytes(2, "big") + b"\xc0\x2f" +  # 1 cipher suite (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        b"\x01\x00" +   # compression methods length: 1, method: null
        extensions
    )
    handshake = b"\x01" + len(client_hello_body).to_bytes(3, "big") + client_hello_body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    return record


class TestTlsAnomalyRule(unittest.TestCase):
    def setUp(self):
        self.rule = TlsAnomalyRule(cooldown=60.0, enabled=True)
        self.orig_trusted = set(rules_mod.TRUSTED_HOSTS)

    def tearDown(self):
        rules_mod.TRUSTED_HOSTS = self.orig_trusted

    def _pkt(self, src="192.168.1.50", dst="198.51.100.42", dport=443, payload=b"", ts=100.0):
        return {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": src,
            "dst_ip": dst,
            "src_port": 54000,
            "dst_port": dport,
            "payload": payload,
            "event_timestamp": ts,
            "timestamp": ts,
        }

    def test_literal_ipv4_sni_triggers_direct_ip_alert(self):
        payload = make_tls_client_hello("198.51.100.42")
        alert = self.rule.check(self._pkt(payload=payload, ts=100.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "TLS_ANOMALY")
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["confidence"], "high")
        self.assertEqual(alert["evidence"]["anomaly_type"], "DIRECT_IP_SNI")
        self.assertEqual(alert["evidence"]["sni"], "198.51.100.42")
        self.assertIn("violates RFC 6066", alert["detail"])

    def test_suspicious_tunnel_sni_triggers_alert(self):
        for i, domain in enumerate(("c2-node.ngrok-free.app", "beacon.duckdns.org", "tunnel.localtunnel.me", "drop.serveo.net")):
            payload = make_tls_client_hello(domain)
            alert = self.rule.check(self._pkt(dst=f"203.0.113.{100 + i}", payload=payload, ts=100.0))
            self.assertIsNotNone(alert, f"Expected alert for suspicious SNI {domain}")
            self.assertEqual(alert["rule_name"], "TLS_ANOMALY")
            self.assertEqual(alert["evidence"]["anomaly_type"], "SUSPICIOUS_TUNNEL_SNI")
            self.assertEqual(alert["evidence"]["sni"], domain)

    def test_legitimate_domain_sni_does_not_fire(self):
        for domain in ("www.google.com", "api.github.com", "example.com", "login.microsoftonline.com"):
            payload = make_tls_client_hello(domain)
            alert = self.rule.check(self._pkt(payload=payload, ts=100.0))
            self.assertIsNone(alert, f"Unexpected alert on legitimate domain {domain}")

    def test_non_tls_port_is_skipped(self):
        payload = make_tls_client_hello("198.51.100.42")
        alert = self.rule.check(self._pkt(dport=80, payload=payload, ts=100.0))
        self.assertIsNone(alert, "Port 80 must be skipped by TlsAnomalyRule")

    def test_empty_or_truncated_payload_does_not_crash(self):
        for p in (b"", b"\x16\x03\x01", b"\x16\x03\x01\x00\x10\x01\x00\x00\x0c", b"A" * 100):
            alert = self.rule.check(self._pkt(payload=p, ts=100.0))
            self.assertIsNone(alert)

    def test_cooldown_suppresses_repeat_alerts(self):
        payload = make_tls_client_hello("198.51.100.42")
        first = self.rule.check(self._pkt(payload=payload, ts=100.0))
        self.assertIsNotNone(first)

        # Same flow within 60s cooldown -> suppressed
        second = self.rule.check(self._pkt(payload=payload, ts=130.0))
        self.assertIsNone(second)

        # After cooldown (ts=165 > 100 + 60) -> fires again
        third = self.rule.check(self._pkt(payload=payload, ts=165.0))
        self.assertIsNotNone(third)

    def test_trusted_host_exemption(self):
        rules_mod.TRUSTED_HOSTS.add("192.168.1.50")
        payload = make_tls_client_hello("198.51.100.42")
        alert = self.rule.check(self._pkt(src="192.168.1.50", payload=payload, ts=100.0))
        self.assertIsNone(alert, "Trusted hosts must be exempt from TlsAnomalyRule")

    def test_prune_stale_cleans_expired_cooldowns(self):
        payload = make_tls_client_hello("198.51.100.42")
        self.rule.check(self._pkt(payload=payload, ts=100.0))
        self.assertEqual(len(self.rule._seen), 1)

        self.rule.prune_stale(now=200.0)
        self.assertEqual(len(self.rule._seen), 0)


if __name__ == "__main__":
    unittest.main()
