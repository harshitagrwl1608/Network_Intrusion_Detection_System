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

    def test_invalid_settings_preserve_repeated_request_requirement(self):
        rule = CleartextHttpOnTlsPortRule(
            cooldown=float("nan"), window=0, min_requests=0,
            max_states="invalid",
        )
        self.assertEqual(rule.cooldown, 600.0)
        self.assertEqual(rule.window, 600.0)
        self.assertEqual(rule.min_requests, 2)
        self.assertEqual(rule.max_states, 4096)
        payload = b"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n"
        self.assertIsNone(rule.check(self.packet(payload, event_timestamp=100)))
        service_key = ("192.0.2.10", "198.51.100.20", 443)
        self.assertEqual(len(rule._history[service_key]), 1)

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
        self.assertFalse(first_alert["evidence"]["request_count_saturated"])
        self.assertEqual(first_alert["severity"], "medium")
        self.assertIsNone(repeated)
        self.assertIsNotNone(after_cooldown)
        self.assertIsNone(first_request)
        self.assertIsNotNone(first_alert)

    def test_request_history_is_threshold_bounded_during_cooldown(self):
        rule = CleartextHttpOnTlsPortRule(cooldown=5, window=60,
                                          min_requests=2)
        payload = b"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n"
        key = ("192.0.2.10", "198.51.100.20", 443)
        self.assertIsNone(rule.check(self.packet(payload, event_timestamp=100)))
        first_alert = rule.check(self.packet(payload, event_timestamp=101))
        self.assertIsNotNone(first_alert)
        for i in range(1000):
            self.assertIsNone(rule.check(self.packet(
                payload, event_timestamp=102 + i * 0.001)))
        self.assertEqual(len(rule._history[key]), rule.min_requests)
        later_alert = rule.check(self.packet(payload, event_timestamp=107))
        self.assertIsNotNone(later_alert)
        self.assertEqual(later_alert["evidence"]["request_count"], 2)
        self.assertTrue(later_alert["evidence"]["request_count_saturated"])

    def test_active_service_history_uses_lru_eviction(self):
        rule = CleartextHttpOnTlsPortRule(cooldown=5, window=60,
                                          min_requests=3, max_states=2)
        payload = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"

        def request(dst_ip, timestamp):
            return rule.check(self.packet(payload, dst_ip=dst_ip,
                                          event_timestamp=timestamp))

        self.assertIsNone(request("198.51.100.20", 100))  # active A
        self.assertIsNone(request("198.51.100.21", 101))  # active B
        self.assertIsNone(request("198.51.100.20", 102))  # refresh A
        self.assertIsNone(request("198.51.100.22", 103))  # should evict B
        self.assertEqual(list(rule._history), [
            ("192.0.2.10", "198.51.100.20", 443),
            ("192.0.2.10", "198.51.100.22", 443),
        ])
        alert = request("198.51.100.20", 104)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["request_count"], 3)

    def test_active_cooldown_is_retained_under_alert_key_churn(self):
        rule = CleartextHttpOnTlsPortRule(cooldown=10, window=60,
                                          min_requests=1, max_states=2)
        payload = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"

        def request(dst_ip, timestamp):
            return rule.check(self.packet(payload, dst_ip=dst_ip,
                                          event_timestamp=timestamp))

        self.assertIsNotNone(request("198.51.100.30", 100))  # alert A
        self.assertIsNotNone(request("198.51.100.31", 101))  # alert B
        self.assertIsNone(request("198.51.100.30", 102))  # touch A's cooldown
        self.assertIsNotNone(request("198.51.100.32", 103))  # evict B, not A
        self.assertIsNone(request("198.51.100.30", 104))  # A still cooled down

    def test_encrypted_tls_bytes_and_http_on_port_80_are_ignored(self):
        self.assertIsNone(self.rule.check(self.packet(b"\x16\x03\x01\x00\x20")))
        self.assertIsNone(self.rule.check(self.packet(
            b"GET / HTTP/1.1\r\n", dst_port=80)))

    def test_server_response_is_not_mistaken_for_client_request(self):
        self.assertIsNone(self.rule.check(self.packet(b"HTTP/1.1 200 OK\r\n")))

    def test_split_request_line_is_reassembled_before_counting(self):
        rule = CleartextHttpOnTlsPortRule(cooldown=10, window=10, min_requests=2)
        request = b"GET /split HTTP/1.1\r\nHost: example.test\r\n\r\n"
        split_at = 9
        self.assertIsNone(rule.check(self.packet(
            request[:split_at], src_port=51000, tcp_payload_seq=1000,
            event_timestamp=100.0)))
        self.assertIsNone(rule.check(self.packet(
            request[split_at:], src_port=51000,
            tcp_payload_seq=1000 + split_at, event_timestamp=100.1)))
        service_key = ("192.0.2.10", "198.51.100.20", 443)
        self.assertEqual(len(rule._history[service_key]), 1)

        alert = rule.check(self.packet(
            b"POST /status HTTP/1.1\r\nHost: example.test\r\n\r\n",
            src_port=51001, tcp_payload_seq=3000, event_timestamp=100.2))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["request_line"],
                         "POST /status HTTP/1.1")
        self.assertEqual(alert["evidence"]["request_count"], 2)

    def test_retransmitted_partial_segment_does_not_count_as_another_request(self):
        rule = CleartextHttpOnTlsPortRule(cooldown=10, window=10, min_requests=2)
        first = b"GET /split "
        remainder = b"HTTP/1.1\r\nHost: example.test\r\n\r\n"
        self.assertIsNone(rule.check(self.packet(
            first, src_port=52000, tcp_payload_seq=2000,
            event_timestamp=100.0)))
        self.assertIsNone(rule.check(self.packet(
            first, src_port=52000, tcp_payload_seq=2000,
            event_timestamp=100.05)))
        self.assertIsNone(rule.check(self.packet(
            remainder, src_port=52000,
            tcp_payload_seq=2000 + len(first), event_timestamp=100.1)))
        alert = rule.check(self.packet(
            b"GET /other HTTP/1.1\r\nHost: example.test\r\n\r\n",
            src_port=52001, tcp_payload_seq=4000, event_timestamp=100.2))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["request_count"], 2)

    def test_retransmitted_complete_request_does_not_satisfy_repeat_threshold(self):
        rule = CleartextHttpOnTlsPortRule(cooldown=10, window=10, min_requests=2)
        request = b"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n"
        first = self.packet(request, src_port=52500, tcp_payload_seq=9000,
                            event_timestamp=100.0)
        self.assertIsNone(rule.check(first))
        self.assertIsNone(rule.check(dict(first, event_timestamp=100.1)))
        service_key = ("192.0.2.10", "198.51.100.20", 443)
        self.assertEqual(len(rule._history[service_key]), 1)

        # A new request with the same line but advanced TCP sequence is real.
        alert = rule.check(self.packet(
            request, src_port=52500, tcp_payload_seq=9000 + len(request),
            event_timestamp=100.2))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["request_count"], 2)

    def test_late_complete_request_does_not_poison_retransmission_cache(self):
        rule = CleartextHttpOnTlsPortRule(cooldown=10, window=10, min_requests=2)
        request = b"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n"
        first_seq = 9000
        self.assertIsNone(rule.check(self.packet(
            request, src_port=52600, tcp_payload_seq=first_seq,
            event_timestamp=100.0)))
        next_seq = first_seq + len(request)
        self.assertIsNone(rule.check(self.packet(
            request, src_port=52600, tcp_payload_seq=next_seq,
            event_timestamp=99.0)))
        alert = rule.check(self.packet(
            request, src_port=52600, tcp_payload_seq=next_seq,
            event_timestamp=100.1))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["request_count"], 2)

    def test_out_of_order_continuation_is_joined_when_gap_fills(self):
        rule = CleartextHttpOnTlsPortRule(cooldown=10, window=10, min_requests=2)
        request = b"GET /reordered HTTP/1.1\r\nHost: example.test\r\n\r\n"
        first_end, second_end = 9, 17
        self.assertIsNone(rule.check(self.packet(
            request[:first_end], src_port=51500,
            tcp_payload_seq=1000, event_timestamp=100.0)))
        self.assertIsNone(rule.check(self.packet(
            request[second_end:], src_port=51500,
            tcp_payload_seq=1000 + second_end, event_timestamp=100.1)))
        self.assertIsNone(rule.check(self.packet(
            request[first_end:second_end], src_port=51500,
            tcp_payload_seq=1000 + first_end, event_timestamp=100.2)))
        service_key = ("192.0.2.10", "198.51.100.20", 443)
        self.assertEqual(len(rule._history[service_key]), 1)

        alert = rule.check(self.packet(
            b"POST /next HTTP/1.1\r\nHost: example.test\r\n\r\n",
            src_port=51501, tcp_payload_seq=4000, event_timestamp=100.3))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["request_count"], 2)

    def test_partial_stream_state_is_bounded_and_expires(self):
        rule = CleartextHttpOnTlsPortRule(max_states=2, min_requests=2)
        for i in range(3):
            self.assertIsNone(rule.check(self.packet(
                b"GET /partial", src_port=53000 + i,
                tcp_payload_seq=5000, event_timestamp=100.0 + i)))
        self.assertEqual(len(rule._tcp_prefixes), 2)
        rule.prune_stale(100.0 + rule.STREAM_TIMEOUT_S + 5)
        self.assertEqual(rule._tcp_prefixes, {})

    def test_late_segment_does_not_replace_a_current_partial_request(self):
        rule = CleartextHttpOnTlsPortRule(cooldown=10, window=10, min_requests=2)
        prefix = b"GET /split "
        remainder = b"HTTP/1.1\r\nHost: example.test\r\n\r\n"
        self.assertIsNone(rule.check(self.packet(
            prefix, src_port=54000, tcp_payload_seq=6000,
            event_timestamp=100.0)))
        self.assertIsNone(rule.check(self.packet(
            b"POST /late ", src_port=54000, tcp_payload_seq=7000,
            event_timestamp=99.0)))
        self.assertEqual(len(rule._tcp_prefixes), 1)
        self.assertIsNone(rule.check(self.packet(
            remainder, src_port=54000,
            tcp_payload_seq=6000 + len(prefix), event_timestamp=101.0)))
        alert = rule.check(self.packet(
            b"GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n",
            src_port=54001, tcp_payload_seq=8000, event_timestamp=102.0))
        self.assertIsNotNone(alert)

    def test_clear_http_tls_string_src_port_normalized_in_alert(self):
        payload = b"GET /admin HTTP/1.1\r\nHost: c2.example\r\n\r\n"
        self.assertIsNone(self.rule.check(self.packet(payload, src_port="50000", event_timestamp=100.0)))
        alert = self.rule.check(self.packet(payload, src_port="50001", event_timestamp=101.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["src_port"], 50001)
        self.assertIsInstance(alert["src_port"], int)
        self.assertEqual(alert["rule_version"], "1.10")

    def test_connect_and_trace_methods_detected(self):
        for method in (b"CONNECT proxy.internal:8080 HTTP/1.1\r\nHost: proxy.internal:8080\r\n\r\n",
                       b"TRACE /diagnostics HTTP/1.1\r\nHost: c2.example\r\n\r\n"):
            with self.subTest(method=method[:7]):
                rule = CleartextHttpOnTlsPortRule(min_requests=2)
                self.assertIsNone(rule.check(self.packet(method, src_port=51000, event_timestamp=200.0)))
                alert = rule.check(self.packet(method, src_port=51001, event_timestamp=201.0))
                self.assertIsNotNone(alert)
                self.assertEqual(alert["rule_name"], "CLEAR_HTTP_ON_TLS_PORT")
                self.assertEqual(alert["rule_version"], "1.10")


if __name__ == "__main__":
    unittest.main()
