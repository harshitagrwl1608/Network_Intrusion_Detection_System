import csv
import os
import sys
import tempfile
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EVAL_DIR = os.path.join(PROJECT_DIR, "evaluation")
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)
if EVAL_DIR not in sys.path:
    sys.path.insert(0, EVAL_DIR)

from run_eval import _load_labels, _run_metadata, _scenario_results, _write_csv


class TestEvaluationArtifacts(unittest.TestCase):
    def test_label_validation_rejects_unknown_rule_and_duplicate_ids(self):
        cases = (
            "scenario_id,expected_rule\nS1,NOT_A_RULE\n",
            "scenario_id,expected_rule\nS1,PORT_SCAN\nS1,PORT_SCAN\n",
        )
        with tempfile.TemporaryDirectory() as tmp:
            for index, content in enumerate(cases):
                path = os.path.join(tmp, f"labels-{index}.csv")
                with open(path, "w", encoding="utf-8") as labels:
                    labels.write(content)
                with self.assertRaises(SystemExit) as exc:
                    _load_labels(path)
                self.assertEqual(exc.exception.code, 2)

    def test_run_metadata_captures_versions_and_non_secret_thresholds(self):
        metadata = _run_metadata()
        self.assertIn("DISTRIBUTED_SYN_FLOOD", metadata["rule_versions"])
        self.assertIn("TCP_STEALTH_SCAN", metadata["rule_versions"])
        self.assertIn("PAYLOAD_HIT", metadata["rule_versions"])
        self.assertIn("DNS_FREQ_THRESHOLD", metadata["settings"])
        self.assertIn("TCP_STEALTH_SCAN_THRESHOLD", metadata["settings"])
        self.assertEqual(metadata["bounded_rule_state"]["tcp_stealth_scan_keys"], 10_000)
        self.assertEqual(metadata["bounded_rule_state"]["device_dedup_keys"], 65_536)
        self.assertEqual(metadata["bounded_rule_state"]["arp_identity_mappings"], 65_536)
        self.assertEqual(metadata["bounded_rule_state"]["scan_keys_per_dimension"], 10_000)
        self.assertEqual(metadata["bounded_rule_state"]["distributed_syn_targets"], 2048)
        self.assertNotIn("POSTGRES_URL", metadata["settings"])
        self.assertEqual(metadata["schema_version"], 1)

    def test_csv_contains_scenario_and_false_positive_rows(self):
        scenarios = [
            {"scenario_id": "S1", "expected_rule": "PORT_SCAN", "src_ip": "192.0.2.1"},
            {"scenario_id": "S2", "expected_rule": "UDP_SCAN", "src_ip": "192.0.2.2"},
        ]
        alert = {
            "rule_name": "PORT_SCAN", "src_ip": "192.0.2.1",
            "dst_ip": "192.0.2.5", "dst_port": 80, "protocol": "TCP",
        }
        results = _scenario_results(scenarios, [(scenarios[0], alert)], [scenarios[1]])
        artifact = {
            "scenario_results": results,
            "unmatched_attack_alerts": [{"rule_name": "PAYLOAD_HIT", "detail": "extra"}],
            "benign_alerts": [{"rule_name": "UDP_SCAN", "detail": "benign alert"}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "evaluation.csv")
            _write_csv(path, artifact)
            with open(path, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        self.assertEqual([row["result"] for row in rows], ["TP", "FN", "FP_attack", "FP_benign"])
        self.assertEqual(rows[0]["alert_rule"], "PORT_SCAN")
        self.assertEqual(rows[1]["scenario_id"], "S2")


if __name__ == "__main__":
    unittest.main()
