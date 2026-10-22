import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import CleartextHttpOnTlsPortRule


class TestCleartextHttpOnTlsPortRule(unittest.TestCase):
    def setUp(self):
        self.rule = CleartextHttpOnTlsPortRule(cooldown=10, window=10, min_requests=2)

    @staticmethod
    def packet(payload, **overrides):
        record = {
            "type": "IP", "protocol": "TCP", "src_ip": "192.0.2.10",
            "dst_ip": "198.51.100.20", "src_port": 50000, "dst_port": 443,
            "payload": payload, "event_timestamp": 100.0,
        }
        record.update(overrides)
        return record

    def test_repeated_plain_http_requests_to_tls_port_alert_once_per_service(self):
        payload = b"POST /fakeurl.htm HTTP/1.1\r\nHost: c2.example\r\n\r\n"
        first_request = self.rule.check(self.packet(payload))
        first_alert = self.rule.check(self.packet(
            payload, src_port=50001, event_timestamp=101.0))
        repeated = self.rule.check(self.packet(payload, src_port=50002,
                                               event_timestamp=102.0))
        after_cooldown = self.rule.check(self.packet(payload, src_port=50003,
                                                     event_timestamp=112.0))
        self.assertEqual(first_alert["rule_name"], "CLEAR_HTTP_ON_TLS_PORT")
        self.assertEqual(first_alert["evidence"]["request_line"],
                         "POST /fakeurl.htm HTTP/1.1")
        self.assertEqual(first_alert["evidence"]["request_count"], 2)
        self.assertEqual(first_alert["severity"], "medium")
        self.assertIsNone(repeated)
        self.assertIsNotNone(after_cooldown)
        self.assertIsNone(first_request)
        self.assertIsNotNone(first_alert)

    def test_encrypted_tls_bytes_and_http_on_port_80_are_ignored(self):
        self.assertIsNone(self.rule.check(self.packet(b"\x16\x03\x01\x00\x20")))
        self.assertIsNone(self.rule.check(self.packet(
            b"GET / HTTP/1.1\r\n", dst_port=80)))

    def test_server_response_is_not_mistaken_for_client_request(self):
        self.assertIsNone(self.rule.check(self.packet(b"HTTP/1.1 200 OK\r\n")))


if __name__ == "__main__":
    unittest.main()
