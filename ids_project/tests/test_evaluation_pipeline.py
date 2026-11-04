import json
import os
import struct
import sys
import tempfile
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from evaluation.pipeline import (
    validate_pcap_deep,
    check_disk_safety,
    load_cumulative_budget,
    update_cumulative_budget,
    classify_ground_truth_verdict,
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


if __name__ == "__main__":
    unittest.main()

