import os
import sys
import unittest
import hashlib

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import engine.rules as rules_mod
from engine.rules import DataExfiltrationRule


class TestDataExfiltrationRule(unittest.TestCase):
    def setUp(self):
        self.rule = DataExfiltrationRule(byte_threshold=50000, window=30)
        rules_mod.TRUSTED_HOSTS.clear()

    @staticmethod
    def _pkt(src_ip, dst_ip, payload=b"", ip_len=0, ts=100.0, dst_port=9001, proto="TCP"):
        return {
            "type": "IP",
            "protocol": proto,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": 50000,
            "dst_port": dst_port,
            "payload": payload,
            "payload_len": len(payload),
            "ip_len": ip_len if ip_len else (len(payload) + 40 if payload else 60),
            "timestamp": ts,
            "event_timestamp": ts,
        }

    @staticmethod
    def _tcp_payload_pkt(payload, seq, ts, src_port=50000):
        record = TestDataExfiltrationRule._pkt(
            "192.168.1.50", "203.0.113.10", payload=payload,
            ts=ts, dst_port=9001, proto="TCP")
        record["src_port"] = src_port
        record["tcp_payload_seq"] = seq
        record["tcp_payload_digest"] = hashlib.blake2s(payload, digest_size=16).digest()
        return record

    def test_invalid_thresholds_and_window_use_defaults(self):
        rule = DataExfiltrationRule(
            byte_threshold=0, web_byte_threshold="invalid", window=0)
        self.assertEqual(rule.byte_threshold, 50_000)
        self.assertEqual(rule.web_byte_threshold, 1_000_000)
        self.assertEqual(rule.window, 30)
        alert = rule.check(self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"A" * 1000, ts=100.0))
        self.assertIsNone(alert)

    def test_volumetric_exfil_triggers_alert(self):
        # 192.168.1.50 -> 203.0.113.10 (internal -> external)
        chunk = b"A" * 10000
        alert = None
        for i in range(5):  # 5 * 10,000 = 50,000 bytes
            res = self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=chunk, ts=100.0 + i))
            if res:
                alert = res

        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "DATA_EXFIL")
        self.assertEqual(alert["evidence"]["sub_type"], "VOLUMETRIC_EXFIL")
        self.assertEqual(alert["evidence"]["bytes_transferred"], 50000)
        self.assertEqual(
            alert["evidence"]["byte_count_basis"],
            "captured_payload_bytes_after_exact_duplicate_suppression")
        self.assertTrue(alert["evidence"]["partial_tcp_overlaps_counted"])
        self.assertEqual(alert["severity"], "medium")

    def test_rolling_byte_total_expires_old_packets_without_false_alert(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        first = self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"A" * 600, ts=100.0)
        second = self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"B" * 500, ts=131.0)
        self.assertIsNone(rule.check(first))
        self.assertIsNone(rule.check(second))
        flow_key = ("192.168.1.50", "203.0.113.10", 9001, "TCP")
        self.assertEqual(rule._flow_totals[flow_key], 500)
        third = self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"C" * 500, ts=131.1)
        alert = rule.check(third)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["bytes_transferred"], 1000)
        self.assertEqual(rule._flow_totals[flow_key], 1000)

    def test_out_of_order_packet_cannot_distort_rolling_total(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        flow_key = ("192.168.1.50", "203.0.113.10", 9001, "TCP")
        self.assertIsNone(rule.check(self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"A" * 600, ts=100.0)))
        self.assertIsNone(rule.check(self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"B" * 200, ts=120.0)))
        # This delayed observation predates the newest flow event. It must not
        # be appended behind newer timestamps or inflate the current volume.
        self.assertIsNone(rule.check(self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"C" * 500, ts=105.0)))
        self.assertEqual(rule._flow_totals[flow_key], 800)
        alert = rule.check(self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"D" * 500, ts=131.0))
        self.assertIsNone(alert)
        self.assertEqual(rule._flow_totals[flow_key], 700)

    def test_out_of_order_archive_signature_is_still_detected(self):
        rule = DataExfiltrationRule(byte_threshold=5000, window=30)
        self.assertIsNone(rule.check(self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"A" * 100, ts=120.0)))
        alert = rule.check(self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"PK\x03\x04" + b"Z" * 96,
            ts=105.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["sub_type"], "SIGNATURE_EXFIL")

    def test_rolling_byte_total_is_removed_with_pruned_or_evicted_flow(self):
        rule = DataExfiltrationRule(byte_threshold=5000, window=30)
        rule.MAX_TRACKED_FLOWS = 1
        first_key = ("192.168.1.50", "203.0.113.10", 9001, "TCP")
        self.assertIsNone(rule.check(self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"A" * 100, ts=100.0)))
        self.assertIn(first_key, rule._flow_totals)
        self.assertIsNone(rule.check(self._pkt(
            "192.168.1.50", "203.0.113.11", payload=b"B" * 100, ts=101.0)))
        self.assertNotIn(first_key, rule._flow_totals)
        rule.prune_stale(200.0)
        self.assertEqual(rule._flow_totals, {})
        self.assertEqual(rule._flow_event_count, 0)

    def test_packet_history_is_bounded_by_threshold_bytes(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        flow_key = ("192.168.1.50", "203.0.113.10", 9001, "TCP")
        first_alert = None
        for i in range(2000):
            alert = rule.check(self._pkt(
                "192.168.1.50", "203.0.113.10", payload=b"x",
                ts=100.0 + i * 0.001))
            if alert is not None and first_alert is None:
                first_alert = alert
        self.assertIsNotNone(first_alert)
        self.assertEqual(first_alert["evidence"]["bytes_transferred"], 1000)
        self.assertFalse(first_alert["evidence"]["byte_count_is_lower_bound"])
        self.assertLessEqual(len(rule._flows[flow_key]), 1000)
        self.assertEqual(rule._flow_totals[flow_key], 1000)
        self.assertIn(flow_key, rule._flow_saturated)

    def test_saturation_clears_after_old_suffix_expires(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        rule.ALERT_COOLDOWN_S = 0
        first = rule.check(self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"A" * 1100, ts=100.0))
        self.assertIsNotNone(first)
        flow_key = ("192.168.1.50", "203.0.113.10", 9001, "TCP")
        self.assertIn(flow_key, rule._flow_saturated)
        self.assertIsNone(rule.check(self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"B" * 100, ts=131.0)))
        self.assertNotIn(flow_key, rule._flow_saturated)
        alert = rule.check(self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"C" * 900, ts=131.1))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["bytes_transferred"], 1000)
        self.assertFalse(alert["evidence"]["byte_count_is_lower_bound"])

    def test_global_flow_event_budget_evicts_oldest_flow_state(self):
        rule = DataExfiltrationRule(
            byte_threshold=1000, window=30, web_byte_threshold=1000)
        rule.MAX_TRACKED_FLOW_EVENTS = 1000
        first_key = ("192.168.1.50", "203.0.113.10", 9001, "TCP")
        second_key = ("192.168.1.50", "203.0.113.11", 9001, "TCP")
        for i in range(600):
            self.assertIsNone(rule.check(self._pkt(
                "192.168.1.50", "203.0.113.10", payload=b"x",
                ts=100.0 + i * 0.001)))
        for i in range(600):
            self.assertIsNone(rule.check(self._pkt(
                "192.168.1.50", "203.0.113.11", payload=b"x",
                ts=101.0 + i * 0.001)))
        self.assertNotIn(first_key, rule._flows)
        self.assertIn(second_key, rule._flows)
        self.assertLessEqual(rule._flow_event_count, rule._flow_event_limit)
        alert = None
        for i in range(400):
            alert = rule.check(self._pkt(
                "192.168.1.50", "203.0.113.11", payload=b"x",
                ts=102.0 + i * 0.001))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["bytes_transferred"], 1000)

    def test_cooldown_keys_remain_bounded_after_history_pruning(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=1)
        rule.MAX_TRACKED_FLOWS = 5
        for i in range(20):
            alert = rule.check(self._pkt(
                "192.168.1.50", f"203.0.113.{i + 1}",
                payload=b"x" * 1000, ts=100.0 + i * 2.0))
            self.assertIsNotNone(alert)
            rule.prune_stale(101.5 + i * 2.0)
        self.assertLessEqual(len(rule._cooldown), rule.MAX_TRACKED_FLOWS)

    def test_capped_payload_uses_full_captured_payload_length(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        record = self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"A" * 512,
            ip_len=1240, ts=100.0, dst_port=9001)
        record["payload_len"] = 1200
        alert = rule.check(record)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["bytes_transferred"], 1200)

    def test_exact_tcp_retransmission_counts_payload_once(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        payload = b"A" * 600
        self.assertIsNone(rule.check(self._tcp_payload_pkt(payload, 1000, 100.0)))
        self.assertIsNone(rule.check(self._tcp_payload_pkt(payload, 1000, 101.0)))
        alert = rule.check(self._tcp_payload_pkt(b"B" * 500, 1600, 102.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["bytes_transferred"], 1100)

    def test_same_sequence_with_different_payload_is_not_suppressed(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        self.assertIsNone(rule.check(self._tcp_payload_pkt(b"A" * 600, 1000, 100.0)))
        alert = rule.check(self._tcp_payload_pkt(b"B" * 600, 1000, 101.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["bytes_transferred"], 1200)

    def test_reused_tcp_tuple_with_new_syn_is_counted_as_a_new_connection(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        syn = self._pkt(
            "192.168.1.50", "203.0.113.10", ts=99.0, dst_port=9001)
        syn["tcp_flags"] = 0x02
        syn["tcp_seq"] = 100
        self.assertIsNone(rule.check(syn))

        payload = b"R" * 600
        self.assertIsNone(rule.check(self._tcp_payload_pkt(payload, 1001, 100.0)))
        self.assertIsNone(rule.check(self._tcp_payload_pkt(payload, 1001, 101.0)))

        # Retransmitting the same initial SYN must not create a new generation.
        retransmitted_syn = dict(syn, timestamp=101.5, event_timestamp=101.5)
        self.assertIsNone(rule.check(retransmitted_syn))
        self.assertIsNone(rule.check(self._tcp_payload_pkt(payload, 1001, 102.0)))

        # A different initial sequence number on the same 4-tuple marks a new
        # connection even when its payload bytes and sequence range repeat.
        reused_syn = dict(syn, timestamp=102.5, event_timestamp=102.5, tcp_seq=200)
        self.assertIsNone(rule.check(reused_syn))
        late_old_syn = dict(syn, timestamp=99.5, event_timestamp=99.5)
        self.assertIsNone(rule.check(late_old_syn))
        alert = rule.check(self._tcp_payload_pkt(payload, 1001, 103.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_version"], "1.12")
        self.assertEqual(alert["evidence"]["bytes_transferred"], 1200)

    def test_tcp_connection_generation_state_is_bounded(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        rule.MAX_TRACKED_TCP_CONNECTIONS = 2
        for i in range(3):
            syn = self._pkt(
                "192.168.1.50", "203.0.113.10", ts=100.0 + i,
                dst_port=9001)
            syn.update(src_port=50000 + i, tcp_flags=0x02, tcp_seq=100 + i)
            self.assertIsNone(rule.check(syn))
        self.assertEqual(len(rule._tcp_connection_generations), 2)

    def test_malformed_tcp_flags_do_not_break_payload_accounting(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        record = self._tcp_payload_pkt(b"M" * 600, 1000, 100.0)
        record["tcp_flags"] = "invalid"
        self.assertIsNone(rule.check(record))
        alert = rule.check(self._tcp_payload_pkt(b"N" * 500, 1600, 101.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["bytes_transferred"], 1100)

    def test_fragment_payload_is_attributed_to_first_fragment_service_port(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        alert = None
        ts = 100.0
        for fragment_id in range(4):
            # One 250-byte original transport payload split into first and
            # non-initial fragments (76 + 100 + 74 application bytes).
            first = self._pkt(
                "192.168.1.50", "203.0.113.10", payload=b"A" * 76,
                ts=ts, dst_port=9001)
            first.update(ip_fragmented=True, ip_fragment_id=fragment_id,
                         ip_fragment_offset=0, ip_more_fragments=True)
            alert = rule.check(first)
            ts += 0.01
            for offset, size, more in ((96, 100, True), (196, 74, False)):
                continuation = self._pkt(
                    "192.168.1.50", "203.0.113.10", payload=b"A" * size,
                    ts=ts, dst_port=None)
                continuation["src_port"] = None
                continuation["payload_len"] = size
                continuation["ip_fragment_data_len"] = size
                continuation["ip_fragment_data_digest"] = hashlib.blake2s(
                    b"A" * size, digest_size=16).digest()
                continuation.update(ip_fragmented=True, ip_fragment_id=fragment_id,
                                    ip_fragment_offset=offset, ip_more_fragments=more)
                alert = rule.check(continuation)
                ts += 0.01
        self.assertIsNotNone(alert)
        self.assertEqual(alert["dst_port"], 9001)
        self.assertEqual(alert["evidence"]["bytes_transferred"], 1000)

    def test_exact_noninitial_fragment_retransmission_counts_once(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        alert = None
        ts = 100.0
        for fragment_id in range(4):
            first = self._pkt(
                "192.168.1.50", "203.0.113.10", payload=b"A" * 76,
                ts=ts, dst_port=9001)
            first.update(ip_fragmented=True, ip_fragment_id=fragment_id,
                         ip_fragment_offset=0, ip_more_fragments=True,
                         ip_fragment_data_len=96,
                         ip_fragment_data_digest=hashlib.blake2s(
                             b"H" * 20 + b"A" * 76, digest_size=16).digest())
            alert = rule.check(first)
            ts += 0.01
            continuation = self._pkt(
                "192.168.1.50", "203.0.113.10", payload=b"A" * 100,
                ts=ts, dst_port=None)
            continuation["src_port"] = None
            continuation["payload_len"] = 100
            continuation.update(
                ip_fragmented=True, ip_fragment_id=fragment_id,
                ip_fragment_offset=96, ip_more_fragments=True,
                ip_fragment_data_len=100,
                ip_fragment_data_digest=hashlib.blake2s(b"A" * 100, digest_size=16).digest())
            alert = rule.check(continuation)
            ts += 0.01
            if fragment_id == 0:
                retransmission = dict(continuation)
                retransmission["event_timestamp"] = ts
                retransmission["timestamp"] = ts
                self.assertIsNone(rule.check(retransmission))
                ts += 0.01
            last = self._pkt(
                "192.168.1.50", "203.0.113.10", payload=b"A" * 74,
                ts=ts, dst_port=None)
            last["src_port"] = None
            last["payload_len"] = 74
            last.update(
                ip_fragmented=True, ip_fragment_id=fragment_id,
                ip_fragment_offset=196, ip_more_fragments=False,
                ip_fragment_data_len=74,
                ip_fragment_data_digest=hashlib.blake2s(b"A" * 74, digest_size=16).digest())
            alert = rule.check(last)
            ts += 0.01
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["bytes_transferred"], 1000)

    def test_out_of_order_fragment_bytes_join_after_first_fragment_identifies_port(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        alert = None
        ts = 100.0
        for fragment_id in range(4):
            # Captures may start mid-datagram or deliver fragments out of order.
            for offset, size, more in ((96, 100, True), (196, 74, False)):
                continuation = self._pkt(
                    "192.168.1.50", "203.0.113.10", payload=b"B" * size,
                    ts=ts, dst_port=None)
                continuation["src_port"] = None
                continuation["payload_len"] = size
                continuation.update(ip_fragmented=True, ip_fragment_id=fragment_id,
                                    ip_fragment_offset=offset, ip_more_fragments=more)
                self.assertIsNone(rule.check(continuation))
                ts += 0.01
            first = self._pkt(
                "192.168.1.50", "203.0.113.10", payload=b"B" * 76,
                ts=ts, dst_port=9001)
            first.update(ip_fragmented=True, ip_fragment_id=fragment_id,
                         ip_fragment_offset=0, ip_more_fragments=True)
            alert = rule.check(first)
            ts += 0.01
        self.assertIsNotNone(alert)
        self.assertEqual(alert["dst_port"], 9001)
        self.assertEqual(alert["evidence"]["bytes_transferred"], 1000)

    def test_fragment_orphan_and_port_state_is_pruned(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        orphan = self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"D" * 100,
            ts=100.0, dst_port=None)
        orphan["src_port"] = None
        orphan.update(ip_fragmented=True, ip_fragment_id=50,
                      ip_fragment_offset=96, ip_more_fragments=True)
        self.assertIsNone(rule.check(orphan))
        self.assertEqual(rule._fragment_orphan_count, 1)

        first = self._pkt(
            "192.168.1.50", "203.0.113.10", payload=b"D" * 76,
            ts=101.0, dst_port=9001)
        first.update(ip_fragmented=True, ip_fragment_id=51,
                     ip_fragment_offset=0, ip_more_fragments=True)
        self.assertIsNone(rule.check(first))
        self.assertIn(("192.168.1.50", "203.0.113.10", "TCP", 51), rule._fragment_ports)

        rule.prune_stale(now=132.0)
        self.assertEqual(rule._fragment_orphan_count, 0)
        self.assertEqual(rule._fragment_orphans, {})
        self.assertEqual(rule._fragment_ports, {})

    def test_fragment_orphan_buffer_has_a_global_event_bound(self):
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        rule.MAX_FRAGMENT_ORPHAN_EVENTS = 2
        for i in range(3):
            fragment = self._pkt(
                "192.168.1.50", "203.0.113.10", payload=b"E" * 100,
                ts=100.0 + i, dst_port=None)
            fragment["src_port"] = None
            fragment.update(ip_fragmented=True, ip_fragment_id=60+i,
                            ip_fragment_offset=96, ip_more_fragments=True)
            self.assertIsNone(rule.check(fragment))
        self.assertEqual(rule._fragment_orphan_count, 2)
        self.assertEqual(len(rule._fragment_orphans), 2)

    def test_common_web_volume_uses_higher_threshold(self):
        chunk = b"A" * 10000
        for i in range(10):
            self.assertIsNone(self.rule.check(self._pkt(
                "192.168.1.50", "203.0.113.10", payload=chunk,
                dst_port=443, ts=100.0 + i * 0.1)))
        alert = None
        for i in range(90):
            alert = self.rule.check(self._pkt(
                "192.168.1.50", "203.0.113.10", payload=chunk,
                dst_port=443, ts=101.0 + i * 0.1))
            if alert:
                break
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["threshold"], 1_000_000)

    def test_archive_signature_still_alerts_on_web_port(self):
        payload = b"PK\x03\x04archive"
        alert = self.rule.check(self._pkt(
            "192.168.1.50", "203.0.113.10", payload=payload,
            dst_port=443, ts=100.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["sub_type"], "SIGNATURE_EXFIL")

    def test_bytes_on_separate_ports_do_not_combine(self):
        chunk = b"A" * 30000
        for port in (9001, 9002):
            self.assertIsNone(self.rule.check(self._pkt(
                "192.168.1.50", "203.0.113.10", payload=chunk,
                dst_port=port, ts=100.0)))

    def test_sub_threshold_traffic_does_not_alert(self):
        chunk = b"A" * 5000
        alert = None
        for i in range(4):  # 20,000 bytes (below 50,000)
            res = self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=chunk, ts=100.0 + i))
            if res:
                alert = res

        self.assertIsNone(alert)

    def test_header_only_ipv4_tcp_option_bytes_do_not_count_as_exfil(self):
        # A 52-byte IPv4/TCP ACK with TCP options has no app data. A fixed
        # 40-byte header subtraction incorrectly treated the options as 12 B.
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        for i in range(100):
            alert = rule.check(self._pkt(
                "192.168.1.50", "203.0.113.10", payload=b"", ip_len=52,
                ts=100.0 + i * 0.01))
            self.assertIsNone(alert)
        self.assertEqual(rule._flows, {})

    def test_header_only_ipv6_tcp_packets_do_not_count_as_exfil(self):
        # IPv6 (40 B) + bare TCP (20 B): the old IPv4-oriented subtraction
        # incorrectly counted 20 B of every control packet as data.
        rule = DataExfiltrationRule(byte_threshold=1000, window=30)
        for i in range(100):
            alert = rule.check(self._pkt(
                "fd00::50", "2001:4860:4860::8888", payload=b"", ip_len=60,
                ts=100.0 + i * 0.01))
            self.assertIsNone(alert)
        self.assertEqual(rule._flows, {})

    def test_internal_to_internal_lan_traffic_is_ignored(self):
        # 192.168.1.50 -> 192.168.1.1 (LAN transfer, e.g. local NAS or gateway)
        chunk = b"A" * 20000
        for i in range(5):  # 100,000 bytes
            alert = self.rule.check(self._pkt("192.168.1.50", "192.168.1.1", payload=chunk, ts=100.0 + i))
            self.assertIsNone(alert)

    def test_external_to_internal_inbound_traffic_is_ignored(self):
        # 203.0.113.10 -> 192.168.1.50 (inbound download from internet)
        chunk = b"A" * 20000
        for i in range(5):  # 100,000 bytes
            alert = self.rule.check(self._pkt("203.0.113.10", "192.168.1.50", payload=chunk, ts=100.0 + i))
            self.assertIsNone(alert)

    def test_database_dump_signature_exfil_triggers_alert(self):
        # Internal host uploads SQLite database to external server
        payload = b"SQLite format 3\x00" + b"\x04\x00\x01\x01" + b"\x00" * 100
        alert = self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=payload, ts=100.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "DATA_EXFIL")
        self.assertEqual(alert["evidence"]["sub_type"], "SIGNATURE_EXFIL")
        self.assertIn("SQLite", alert["detail"])

    def test_zip_archive_signature_exfil_triggers_alert(self):
        # Internal host sends PKZIP archive
        payload = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"sensitive_data.csv"
        alert = self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=payload, ts=100.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["sub_type"], "SIGNATURE_EXFIL")
        self.assertIn("ZIP", alert["detail"])

    def test_dns_traffic_port_53_is_exempt(self):
        chunk = b"A" * 30000
        # Port 53 traffic is ignored (monitored by DnsRule)
        for i in range(3):
            alert = self.rule.check(self._pkt("192.168.1.50", "8.8.8.8", payload=chunk, dst_port=53, ts=100.0 + i))
            self.assertIsNone(alert)

    def test_trusted_host_exemption(self):
        rules_mod.TRUSTED_HOSTS.add("192.168.1.50")
        chunk = b"A" * 30000
        for i in range(3):
            alert = self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=chunk, ts=100.0 + i))
            self.assertIsNone(alert)

    def test_cooldown_prevents_duplicate_alerts(self):
        chunk = b"A" * 30000
        # First two chunks hit threshold (60,000 >= 50,000)
        self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=chunk, ts=100.0))
        first_alert = self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=chunk, ts=101.0))
        self.assertIsNotNone(first_alert)

        # Subsequent packets within 60s cooldown do NOT produce new alerts
        dup_alert = self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=chunk, ts=105.0))
        self.assertIsNone(dup_alert)

    def test_prune_stale_cleans_flow_history(self):
        chunk = b"A" * 10000
        self.rule.check(self._pkt("192.168.1.50", "203.0.113.10", payload=chunk, ts=100.0))
        self.assertIn(("192.168.1.50", "203.0.113.10", 9001, "TCP"), self.rule._flows)

        # Prune at t=150 (30s window passed)
        self.rule.prune_stale(now=150.0)
        self.assertNotIn(("192.168.1.50", "203.0.113.10", 9001, "TCP"), self.rule._flows)


if __name__ == "__main__":
    unittest.main()
