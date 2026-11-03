import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import TlsAnomalyRule
import engine.rules as rules_mod


def make_tls_client_hello(sni_hostname: str, padding_bytes: int = 0) -> bytes:
    """Helper to construct a realistic TLS 1.2 Client Hello packet with SNI."""
    sni = sni_hostname.encode("utf-8")
    ext_data = b"\x00" + len(sni).to_bytes(2, "big") + sni
    ext_list = len(ext_data).to_bytes(2, "big") + ext_data
    sni_ext = (0).to_bytes(2, "big") + len(ext_list).to_bytes(2, "big") + ext_list
    padding_ext = b""
    if padding_bytes:
        padding_ext = (21).to_bytes(2, "big") + padding_bytes.to_bytes(2, "big") + b"P" * padding_bytes
    extensions_data = padding_ext + sni_ext
    extensions = len(extensions_data).to_bytes(2, "big") + extensions_data

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

    def _pkt(self, src="192.168.1.50", dst="198.51.100.42", dport=443, payload=b"", ts=100.0, **extra):
        record = {
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
        record.update(extra)
        return record

    def test_sni_after_generic_payload_cap_is_detected_from_tls_sample(self):
        hello = make_tls_client_hello("c2-node.ngrok-free.app", padding_bytes=600)
        self.assertGreater(len(hello), 512)
        self.assertIsNone(rules_mod._extract_tls_sni(hello[:512]))
        alert = self.rule.check(self._pkt(payload=hello[:512], tls_payload=hello, ts=100.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["sni"], "c2-node.ngrok-free.app")

    def test_malformed_record_length_cannot_supply_sni_from_trailing_bytes(self):
        valid = make_tls_client_hello("c2-node.ngrok-free.app")
        malformed_records = (
            b"\x16\x03\x01\x00\x04" + valid[5:],
            valid[:6] + (len(valid).to_bytes(3, "big")) + valid[9:],
            valid[:-1],
        )
        for malformed in malformed_records:
            with self.subTest(payload_length=len(malformed)):
                self.assertIsNone(rules_mod._extract_tls_sni(malformed))
                self.assertIsNone(self.rule.check(self._pkt(payload=malformed, ts=100.0)))

    def test_segmented_client_hello_detects_sni_when_gap_arrives(self):
        hello = make_tls_client_hello("c2-node.ngrok-free.app", padding_bytes=600)
        seq = 4000
        first, middle, last = hello[:220], hello[220:470], hello[470:]
        self.assertIsNone(self.rule.check(self._pkt(payload=first, tcp_payload_seq=seq, ts=100.0)))
        # Hold the later bytes until the missing middle segment arrives.
        self.assertIsNone(self.rule.check(self._pkt(
            payload=last, tcp_payload_seq=seq + len(first) + len(middle), ts=100.2)))
        alert = self.rule.check(self._pkt(
            payload=middle, tcp_payload_seq=seq + len(first), ts=100.3))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["sni"], "c2-node.ngrok-free.app")

    def test_literal_ipv4_sni_triggers_direct_ip_alert(self):
        payload = make_tls_client_hello("198.51.100.42")
        alert = self.rule.check(self._pkt(payload=payload, ts=100.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "TLS_ANOMALY")
        self.assertEqual(alert["rule_version"], "1.10")
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["confidence"], "high")
        self.assertEqual(alert["evidence"]["anomaly_type"], "DIRECT_IP_SNI")
        self.assertEqual(alert["evidence"]["sni"], "198.51.100.42")
        self.assertIn("violates RFC 6066", alert["detail"])

    def test_invalid_event_timestamps_do_not_mutate_tls_state(self):
        payload = make_tls_client_hello("198.51.100.42")
        for invalid_time in ("bad-time", float("nan"), float("inf")):
            with self.subTest(timestamp=invalid_time):
                rule = TlsAnomalyRule(cooldown=60.0, enabled=True)
                self.assertIsNone(rule.check(self._pkt(
                    payload=payload, ts=100.0, event_timestamp=invalid_time)))
                self.assertEqual(rule._seen, {})
                self.assertEqual(rule._hello_prefixes, {})
                alert = rule.check(self._pkt(payload=payload, ts=100.0))
                self.assertIsNotNone(alert)
                self.assertEqual(alert["rule_version"], "1.10")

    def test_suspicious_tunnel_sni_triggers_alert(self):
        for i, domain in enumerate(("c2-node.ngrok-free.app", "beacon.duckdns.org", "tunnel.localtunnel.me", "drop.serveo.net")):
            payload = make_tls_client_hello(domain)
            alert = self.rule.check(self._pkt(dst=f"203.0.113.{100 + i}", payload=payload, ts=100.0))
            self.assertIsNotNone(alert, f"Expected alert for suspicious SNI {domain}")
            self.assertEqual(alert["rule_name"], "TLS_ANOMALY")
            self.assertEqual(alert["rule_version"], "1.10")
            self.assertEqual(alert["severity"], "medium")
            self.assertEqual(alert["confidence"], "heuristic")
            self.assertEqual(alert["evidence"]["anomaly_type"], "SUSPICIOUS_TUNNEL_SNI")
            self.assertEqual(alert["evidence"]["sni"], domain)

    def test_apex_and_modern_tunnel_services_detected(self):
        # Apex domain and newer reverse proxy tunnels (Pinggy, Packetriot, Telebit)
        for i, domain in enumerate(("trycloudflare.com", "ngrok.io", "tunnel.pinggy.link", "c2.packetriot.net")):
            with self.subTest(domain=domain):
                payload = make_tls_client_hello(domain)
                alert = self.rule.check(self._pkt(dst=f"203.0.113.{150 + i}", payload=payload, ts=100.0))
                self.assertIsNotNone(alert, f"Expected alert for {domain}")
                self.assertEqual(alert["evidence"]["anomaly_type"], "SUSPICIOUS_TUNNEL_SNI")

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

    def test_invalid_cooldowns_fall_back_while_zero_remains_supported(self):
        for invalid in (float("nan"), float("inf"), -1, "invalid"):
            with self.subTest(cooldown=invalid):
                rule = TlsAnomalyRule(cooldown=invalid)
                self.assertEqual(rule.cooldown, 60.0)
                payload = make_tls_client_hello("198.51.100.42")
                self.assertIsNotNone(rule.check(self._pkt(payload=payload, ts=100.0)))
                self.assertIsNone(rule.check(self._pkt(payload=payload, ts=101.0)))

        no_cooldown = TlsAnomalyRule(cooldown=0)
        payload = make_tls_client_hello("198.51.100.42")
        self.assertIsNotNone(no_cooldown.check(self._pkt(payload=payload, ts=100.0)))
        self.assertIsNotNone(no_cooldown.check(self._pkt(payload=payload, ts=101.0)))

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

    def test_active_cooldown_survives_flow_key_churn(self):
        self.rule.MAX_TRACKED_FLOWS = 2
        payload = make_tls_client_hello("198.51.100.42")
        self.assertIsNotNone(self.rule.check(self._pkt(src="192.0.2.1", payload=payload, ts=100.0)))
        self.assertIsNotNone(self.rule.check(self._pkt(src="192.0.2.2", payload=payload, ts=100.0)))
        self.assertIsNone(self.rule.check(self._pkt(src="192.0.2.1", payload=payload, ts=101.0)))
        self.assertIsNotNone(self.rule.check(self._pkt(src="192.0.2.3", payload=payload, ts=102.0)))
        self.assertIn(("192.0.2.1", "198.51.100.42", "DIRECT_IP_SNI"), self.rule._seen)
        self.assertNotIn(("192.0.2.2", "198.51.100.42", "DIRECT_IP_SNI"), self.rule._seen)
        self.assertLessEqual(len(self.rule._seen), self.rule.MAX_TRACKED_FLOWS)

    def test_tls_anomaly_string_src_port_normalized_in_alert(self):
        payload = make_tls_client_hello("198.51.100.42")
        pkt = self._pkt(payload=payload, ts=100.0)
        pkt["src_port"] = "54321"
        alert = self.rule.check(pkt)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["src_port"], 54321)
        self.assertIsInstance(alert["src_port"], int)


if __name__ == "__main__":
    unittest.main()
