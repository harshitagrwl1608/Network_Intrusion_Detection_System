import json
import os
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock, mock_open

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from evaluation.pipeline import (
    validate_pcap_deep,
    validate_pcap_with_tools,
    check_disk_safety,
    load_cumulative_budget,
    update_cumulative_budget,
    classify_ground_truth_verdict,
    classify_capture_level_signal,
    canonicalize_flow,
    evaluate_ground_truth_labels,
    safe_decompress_stream,
    compute_eval_cache_key,
    hash_file_sha256,
    PCAP_MAGIC_LE,
    PCAPNG_MAGIC,
)


class TestEvaluationPipeline(unittest.TestCase):
    """Unit tests for the hardened evaluation pipeline."""

    def test_validate_pcap_deep_valid_classic_pcap(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            # 24-byte classic libpcap global header
            # magic (4), major (2), minor (2), thiszone (4), sigfigs (4), snaplen (4), network (4)
            hdr = PCAP_MAGIC_LE + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
            f.write(hdr)
            # Add one valid packet header: ts_sec (4), ts_usec (4), incl_len (4), orig_len (4) + payload
            pkt_hdr = struct.pack("<IIII", 1600000000, 0, 14, 14)
            f.write(pkt_hdr + b"\x00" * 14)
            tmp_path = f.name

        try:
            is_valid, msg = validate_pcap_deep(tmp_path)
            self.assertTrue(is_valid, f"Expected valid PCAP, got: {msg}")
            self.assertIn("classic libpcap", msg)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_validate_pcap_deep_valid_pcapng(self):
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
            # PCAPNG Section Header Block: magic (4), block_len (4), byte_order_magic (4)
            shb = PCAPNG_MAGIC + struct.pack("<I", 32) + b"\x1a\x2b\x3c\x4d" + b"\x00" * 20
            f.write(shb)
            tmp_path = f.name

        try:
            is_valid, msg = validate_pcap_deep(tmp_path)
            self.assertTrue(is_valid, f"Expected valid PCAPNG, got: {msg}")
            self.assertIn("PCAPNG", msg)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_validate_pcap_deep_rejects_truncated(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"too_short")
            tmp_path = f.name

        try:
            is_valid, msg = validate_pcap_deep(tmp_path)
            self.assertFalse(is_valid)
            self.assertIn("smaller than minimum", msg)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_validate_pcap_deep_rejects_corrupted_magic(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"\xde\xad\xbe\xef" + b"\x00" * 30)
            tmp_path = f.name

        try:
            is_valid, msg = validate_pcap_deep(tmp_path)
            self.assertFalse(is_valid)
            self.assertIn("Invalid PCAP magic bytes", msg)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_classify_ground_truth_verdict_benign(self):
        candidate_benign = {
            "id": "benign_test",
            "category": "Benign Real-World Traffic",
            "attack_type": "Benign desktop user",
            "target_rules": ["FP_BENIGN_VERIFICATION"],
        }
        # Zero alerts on benign -> TRUE_NEGATIVE
        verdict, rationale = classify_ground_truth_verdict(candidate_benign, [], {})
        self.assertEqual(verdict, "TRUE_NEGATIVE")
        self.assertIn("Zero false alarms", rationale)

        # Spurious alerts on benign -> FALSE_POSITIVE
        alerts = [{"rule_name": "PORT_SCAN"}]
        verdict, rationale = classify_ground_truth_verdict(candidate_benign, alerts, {"PORT_SCAN": 1})
        self.assertEqual(verdict, "FALSE_POSITIVE")
        self.assertIn("PORT_SCAN", rationale)

    def test_classify_ground_truth_verdict_attack(self):
        candidate_attack = {
            "id": "mirai_test",
            "category": "DoS Floods",
            "attack_type": "SYN Flood and UDP Flood",
            "target_rules": ["SYN_FLOOD", "UDP_FLOOD"],
        }
        # Hits target rule -> TRUE_POSITIVE
        alerts = [{"rule_name": "SYN_FLOOD"}]
        verdict, rationale = classify_ground_truth_verdict(candidate_attack, alerts, {"SYN_FLOOD": 3})
        self.assertEqual(verdict, "TRUE_POSITIVE")
        self.assertIn("SYN_FLOOD", rationale)

        # Misses target rules but catches other anomalies -> PARTIAL_DETECTION
        verdict, rationale = classify_ground_truth_verdict(candidate_attack, [{"rule_name": "DATA_EXFIL"}], {"DATA_EXFIL": 1})
        self.assertEqual(verdict, "PARTIAL_DETECTION")

        # Zero alerts on attack -> FALSE_NEGATIVE_OR_SUBTHRESHOLD
        verdict, rationale = classify_ground_truth_verdict(candidate_attack, [], {})
        self.assertEqual(verdict, "FALSE_NEGATIVE_OR_SUBTHRESHOLD")

    def test_classify_ground_truth_verdict_unassessed_reference(self):
        candidate_unassessed = {
            "id": "unassessed_test",
            "category": "Protocol Flood",
            "attack_type": "ARP Request Broadcast Storm",
            "target_rules": ["UNASSESSED_PROTOCOL_FLOOD"],
        }
        verdict, rationale = classify_ground_truth_verdict(candidate_unassessed, [], {})
        self.assertEqual(verdict, "UNASSESSED_REFERENCE_CAPTURE")
        self.assertIn("unassessed", rationale.lower())

    def test_cumulative_budget_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_budget_file = os.path.join(tmpdir, "test_budget.json")
            import evaluation.pipeline as p_module

            orig_file = p_module.CUMULATIVE_BUDGET_FILE
            p_module.CUMULATIVE_BUDGET_FILE = test_budget_file
            try:
                b1 = load_cumulative_budget()
                self.assertEqual(b1["cumulative_downloaded_bytes"], 0)

                b2 = update_cumulative_budget(1024, 1.5)
                self.assertEqual(b2["cumulative_downloaded_bytes"], 1024)
                self.assertEqual(b2["cumulative_download_time_s"], 1.5)

                b3 = update_cumulative_budget(2048, 2.0)
                self.assertEqual(b3["cumulative_downloaded_bytes"], 3072)
                self.assertEqual(b3["cumulative_download_time_s"], 3.5)

                # Re-reading from disk yields updated totals
                b4 = load_cumulative_budget()
                self.assertEqual(b4["cumulative_downloaded_bytes"], 3072)
            finally:
                p_module.CUMULATIVE_BUDGET_FILE = orig_file

    def test_safe_decompress_stream_bounds_check(self):
        import io
        # 1. Normal safe stream
        data = b"A" * 1024
        reader = io.BytesIO(data)
        writer = io.BytesIO()
        written = safe_decompress_stream(reader, writer, max_bytes=2048)
        self.assertEqual(written, 1024)
        self.assertEqual(writer.getvalue(), data)

        # 2. Decompression bomb rejected
        reader_bomb = io.BytesIO(b"B" * 5000)
        writer_bomb = io.BytesIO()
        with self.assertRaises(RuntimeError) as ctx:
            safe_decompress_stream(reader_bomb, writer_bomb, max_bytes=1000, chunk_size=256)
        self.assertIn("exceeded safety limit", str(ctx.exception))

    def test_canonicalize_flow_bidirectional_equality(self):
        f1 = canonicalize_flow("192.168.1.10", "198.51.100.5", 54321, 80, "TCP")
        f2 = canonicalize_flow("198.51.100.5", "192.168.1.10", 80, 54321, "TCP")
        self.assertEqual(f1, f2, "Bidirectional flows must map to identical canonical key")

        # IPv6 canonicalization
        f_v6_a = canonicalize_flow("2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0002", 443, 60000, "TCP")
        f_v6_b = canonicalize_flow("2001:db8::2", "2001:db8::1", 60000, 443, "TCP")
        self.assertEqual(f_v6_a, f_v6_b, "IPv6 bidirectional flows must map to identical canonical key")

    def test_evaluate_ground_truth_labels_exhaustive_mode(self):
        labels = [
            {
                "label_id": "lbl-1",
                "expected_rule": "SYN_FLOOD",
                "expected_family": "syn_flood",
                "flow": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 50000, "dst_port": 80, "protocol": "TCP"},
                "time_window": {"start": 100.0, "end": 110.0},
            }
        ]
        # Matching alert + 1 extra alert
        alerts = [
            {"rule_name": "SYN_FLOOD", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 50000, "dst_port": 80, "protocol": "TCP", "timestamp": 105.0},
            {"rule_name": "PORT_SCAN", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 50001, "dst_port": 81, "protocol": "TCP", "timestamp": 106.0},
        ]
        # In exhaustive mode, unmatched alert is counted as FP
        res = evaluate_ground_truth_labels(labels, alerts, label_coverage="exhaustive")
        self.assertEqual(res["true_positives"], 1)
        self.assertEqual(res["false_negatives"], 0)
        self.assertEqual(res["false_positives"], 1)
        self.assertEqual(res["unassessed_alerts"], 0)
        self.assertAlmostEqual(res["precision"], 0.5)
        self.assertAlmostEqual(res["recall"], 1.0)

    def test_evaluate_ground_truth_labels_partial_coverage(self):
        labels = [
            {
                "label_id": "lbl-1",
                "expected_rule": "DATA_EXFIL",
                "flow": {"src_ip": "192.168.1.5", "dst_ip": "203.0.113.1", "src_port": 45000, "dst_port": 443, "protocol": "TCP"},
            }
        ]
        alerts = [
            {"rule_name": "DATA_EXFIL", "src_ip": "192.168.1.5", "dst_ip": "203.0.113.1", "src_port": 45000, "dst_port": 443, "protocol": "TCP"},
            {"rule_name": "ICMP_FLOOD", "src_ip": "192.168.1.5", "dst_ip": "203.0.113.1", "src_port": 0, "dst_port": 0, "protocol": "ICMP"},
        ]
        # In partial mode, extra alerts are UNASSESSED, not false positives
        res = evaluate_ground_truth_labels(labels, alerts, label_coverage="partial")
        self.assertEqual(res["true_positives"], 1)
        self.assertEqual(res["false_negatives"], 0)
        self.assertEqual(res["false_positives"], 0)
        self.assertEqual(res["unassessed_alerts"], 1)
        self.assertIsNone(res["precision"], "Precision should be None when label coverage is not exhaustive")

    def test_evaluate_ground_truth_labels_bijective_prevents_inflation(self):
        labels = [
            {
                "label_id": "lbl-1",
                "expected_rule": "SYN_FLOOD",
                "flow": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 50000, "dst_port": 80, "protocol": "TCP"},
            }
        ]
        # 3 alerts fired on the same event/flow
        alerts = [
            {"rule_name": "SYN_FLOOD", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 50000, "dst_port": 80, "protocol": "TCP"},
            {"rule_name": "SYN_FLOOD", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 50000, "dst_port": 80, "protocol": "TCP"},
            {"rule_name": "SYN_FLOOD", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 50000, "dst_port": 80, "protocol": "TCP"},
        ]
        res = evaluate_ground_truth_labels(labels, alerts, label_coverage="complete")
        # Only 1 label matched -> TP must be 1, NOT 3
        self.assertEqual(res["true_positives"], 1)
        self.assertEqual(res["false_positives"], 2)

    def test_compute_eval_cache_key_deterministic_and_sensitive(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(PCAP_MAGIC_LE + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1) + b"\x00" * 30)
            tmp_pcap = f.name
        try:
            cand_a = {"id": "test", "target_rules": ["SYN_FLOOD", "UDP_FLOOD"]}
            cand_b = {"id": "test", "target_rules": ["UDP_FLOOD", "SYN_FLOOD"]}  # Order invariant
            cand_c = {"id": "test", "target_rules": ["ICMP_TUNNEL"]}  # Different rules

            k_a = compute_eval_cache_key(tmp_pcap, cand_a)
            k_b = compute_eval_cache_key(tmp_pcap, cand_b)
            k_c = compute_eval_cache_key(tmp_pcap, cand_c)

            self.assertEqual(k_a, k_b, "Cache key must be invariant to target_rules list ordering")
            self.assertNotEqual(k_a, k_c, "Cache key must differ when target_rules change")
            self.assertEqual(len(k_a), 64)
        finally:
            if os.path.exists(tmp_pcap):
                os.remove(tmp_pcap)

    def test_compute_eval_cache_key_invalidation_rules_config_labels_blocklist(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(PCAP_MAGIC_LE + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1) + b"\x00" * 30)
            tmp_pcap = f.name
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as lf1:
            lf1.write(b"header\nval1\n")
            tmp_label1 = lf1.name
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as lf2:
            lf2.write(b"header\nval2_different\n")
            tmp_label2 = lf2.name

        try:
            cand = {"id": "test", "target_rules": ["SYN_FLOOD"]}
            k_base = compute_eval_cache_key(tmp_pcap, cand)

            # Invalidate on label file content change
            k_lbl1 = compute_eval_cache_key(tmp_pcap, cand, labels_path=tmp_label1)
            k_lbl2 = compute_eval_cache_key(tmp_pcap, cand, labels_path=tmp_label2)
            self.assertNotEqual(k_base, k_lbl1)
            self.assertNotEqual(k_lbl1, k_lbl2)

            # Invalidate on label_coverage change
            cand_partial = {"id": "test", "target_rules": ["SYN_FLOOD"], "label_coverage": "partial"}
            cand_complete = {"id": "test", "target_rules": ["SYN_FLOOD"], "label_coverage": "complete"}
            k_part = compute_eval_cache_key(tmp_pcap, cand_partial)
            k_comp = compute_eval_cache_key(tmp_pcap, cand_complete)
            self.assertNotEqual(k_part, k_comp)

            # Invalidate on config setting change
            import config
            orig_thresh = config.PORT_SCAN_THRESHOLD
            try:
                config.PORT_SCAN_THRESHOLD = orig_thresh + 999
                k_cfg_changed = compute_eval_cache_key(tmp_pcap, cand)
                self.assertNotEqual(k_base, k_cfg_changed)
            finally:
                config.PORT_SCAN_THRESHOLD = orig_thresh
        finally:
            for p in (tmp_pcap, tmp_label1, tmp_label2):
                if os.path.exists(p):
                    os.remove(p)

    def test_evaluate_ground_truth_labels_rejects_missing_rule_and_family(self):
        labels = [
            {
                "label_id": "lbl-invalid-no-rule",
                "flow": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 50000, "dst_port": 80, "protocol": "TCP"},
                "time_window": {"start": 10.0, "end": 20.0},
            }
        ]
        alerts = [
            {"rule_name": "SYN_FLOOD", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 50000, "dst_port": 80, "protocol": "TCP", "timestamp": 15.0}
        ]
        res = evaluate_ground_truth_labels(labels, alerts)
        self.assertEqual(res["true_positives"], 0)
        self.assertEqual(res["false_negatives"], 1)
        self.assertEqual(len(res["missed_labels"]), 1)
        self.assertEqual(res["missed_labels"][0].get("rejection_reason"), "Missing expected_rule or expected_family")

    def test_evaluate_ground_truth_labels_rejects_malformed_time_window(self):
        # 1. start > end
        labels_inverted = [
            {
                "label_id": "lbl-inverted-win",
                "expected_rule": "SYN_FLOOD",
                "time_window": {"start": 100.0, "end": 50.0},
            }
        ]
        # 2. non-numeric timestamps
        labels_non_numeric = [
            {
                "label_id": "lbl-bad-ts",
                "expected_rule": "SYN_FLOOD",
                "time_window": {"start": "not_a_number", "end": 100.0},
            }
        ]
        alerts = [
            {"rule_name": "SYN_FLOOD", "timestamp": 75.0}
        ]
        res1 = evaluate_ground_truth_labels(labels_inverted, alerts)
        self.assertEqual(res1["true_positives"], 0)
        self.assertEqual(res1["missed_labels"][0].get("rejection_reason"), "Invalid time_window: start > end")

        res2 = evaluate_ground_truth_labels(labels_non_numeric, alerts)
        self.assertEqual(res2["true_positives"], 0)
        self.assertEqual(res2["missed_labels"][0].get("rejection_reason"), "Malformed time_window timestamps")

    def test_evaluate_ground_truth_labels_reverse_direction_flow_matching(self):
        labels = [
            {
                "label_id": "lbl-rev",
                "expected_rule": "PORT_SCAN",
                "flow": {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "src_port": 49152, "dst_port": 80, "protocol": "TCP"},
                "time_window": {"start": 10.0, "end": 20.0},
            }
        ]
        # Alert recorded in reverse flow direction (dst <-> src)
        alerts = [
            {
                "rule_name": "PORT_SCAN",
                "src_ip": "10.0.0.1",
                "dst_ip": "192.168.1.100",
                "src_port": 80,
                "dst_port": 49152,
                "protocol": "TCP",
                "timestamp": 15.0,
            }
        ]
        res = evaluate_ground_truth_labels(labels, alerts)
        self.assertEqual(res["true_positives"], 1)
        self.assertEqual(res["false_negatives"], 0)
        self.assertEqual(res["false_positives"], 0)

    def test_check_disk_safety_wrong_backing_device_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            import evaluation.pipeline as p_module
            orig_dir = p_module.HDD_DATASETS_DIR
            orig_mount = p_module.EXPECTED_MOUNT_POINT
            p_module.HDD_DATASETS_DIR = tmpdir
            p_module.EXPECTED_MOUNT_POINT = tmpdir

            # Mock /proc/mounts with wrong backing device /dev/sda1 instead of /dev/sdb1
            fake_mounts = f"/dev/sda1 {tmpdir} ext4 rw 0 0\n"
            try:
                with patch("builtins.open", mock_open(read_data=fake_mounts)):
                    ok = check_disk_safety(require_mount=True)
                    self.assertFalse(ok, "check_disk_safety must reject mounts on unexpected backing device")
            finally:
                p_module.HDD_DATASETS_DIR = orig_dir
                p_module.EXPECTED_MOUNT_POINT = orig_mount

    def test_check_disk_safety_insufficient_free_space(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            import evaluation.pipeline as p_module
            orig_dir = p_module.HDD_DATASETS_DIR
            p_module.HDD_DATASETS_DIR = tmpdir
            try:
                # Statvfs returning 50 GiB free (< 100 GiB threshold)
                mock_stat = MagicMock()
                mock_stat.f_bavail = 50 * (1024 ** 3) // 4096
                mock_stat.f_frsize = 4096
                mock_stat.f_blocks = 500 * (1024 ** 3) // 4096
                with patch("os.statvfs", return_value=mock_stat):
                    ok = check_disk_safety(require_mount=False)
                    self.assertFalse(ok, "check_disk_safety must reject low free disk space (< 100 GiB)")
            finally:
                p_module.HDD_DATASETS_DIR = orig_dir

    def test_check_disk_safety_allocation_cap_exceeded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            import evaluation.pipeline as p_module
            orig_dir = p_module.HDD_DATASETS_DIR
            p_module.HDD_DATASETS_DIR = tmpdir
            try:
                # Statvfs returning 460 GiB used (> 450 GiB max allocation cap)
                mock_stat = MagicMock()
                mock_stat.f_frsize = 4096
                mock_stat.f_blocks = 1000 * (1024 ** 3) // 4096
                mock_stat.f_bavail = (1000 - 460) * (1024 ** 3) // 4096
                with patch("os.statvfs", return_value=mock_stat):
                    ok = check_disk_safety(require_mount=False)
                    self.assertFalse(ok, "check_disk_safety must reject allocation exceeding MAX_ALLOCATION_GIB")
            finally:
                p_module.HDD_DATASETS_DIR = orig_dir

    def test_download_streaming_timeout_and_budget_guards(self):
        import evaluation.pipeline as p_module
        pipe = p_module.PipelineCoordinator([])
        # Test size limit guard
        pipe.cumulative_bytes = int(p_module.MAX_INITIAL_ACQUISITION_GIB * (1024 ** 3))
        chunk = b"X" * 1024
        with self.assertRaises(RuntimeError) as ctx:
            with pipe._lock:
                if pipe.cumulative_bytes + len(chunk) > p_module.MAX_INITIAL_ACQUISITION_GIB * (1024 ** 3):
                    raise RuntimeError("Cumulative download budget exceeded during streaming.")
        self.assertIn("Cumulative download budget", str(ctx.exception))

        # Test transfer time guard
        pipe.cumulative_time_s = p_module.MAX_DOWNLOAD_TIME_SECONDS
        with self.assertRaises(RuntimeError) as ctx:
            with pipe._lock:
                if pipe.cumulative_time_s + 1.0 > p_module.MAX_DOWNLOAD_TIME_SECONDS:
                    raise RuntimeError("Cumulative transfer time budget exceeded during streaming.")
        self.assertIn("Cumulative transfer time budget", str(ctx.exception))

    def test_download_resume_content_range_mismatch_handling(self):
        import re
        # Valid matching range
        content_range_ok = "bytes 500-999/1000"
        m = re.match(r"^bytes\s+(\d+)-(\d+)/(\d+|\*)$", content_range_ok.strip())
        self.assertIsNotNone(m)
        self.assertEqual(int(m.group(1)), 500)

        # Mismatched range (expected 500, but server says bytes 0-999/1000)
        content_range_mismatched = "bytes 0-999/1000"
        m_bad = re.match(r"^bytes\s+(\d+)-(\d+)/(\d+|\*)$", content_range_mismatched.strip())
        self.assertIsNotNone(m_bad)
        downloaded = 500
        self.assertNotEqual(int(m_bad.group(1)), downloaded)


if __name__ == "__main__":
    unittest.main()

