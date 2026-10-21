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


if __name__ == "__main__":
    unittest.main()
