import os
import json
import csv
import subprocess
import sys
import tempfile
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)


class TestRunEvalHarness(unittest.TestCase):
    def test_run_eval_cli_execution(self):
        """Verify that evaluation/run_eval.py runs cleanly with exit code 0."""
        eval_script = os.path.join(PROJECT_DIR, "evaluation", "run_eval.py")
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "results.json")
            csv_path = os.path.join(tmp, "results.csv")
            cmd = [sys.executable, eval_script, "--out-json", json_path,
                   "--out-csv", csv_path]
            proc = subprocess.run(
                cmd, cwd=PROJECT_DIR, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(
                proc.returncode,
                0,
                f"run_eval.py failed with code {proc.returncode}.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
            )
            self.assertIn("NETGUARD IDS — COMBINED EVALUATION REPORT", proc.stdout)
            self.assertIn("True Positives (TP)", proc.stdout)
            self.assertIn("Zero false positives", proc.stdout)
            with open(json_path, encoding="utf-8") as f:
                result = json.load(f)
            self.assertEqual(result["metadata"]["schema_version"], 1)
            self.assertIn("DNS_ANOMALY", result["metadata"]["rule_versions"])
            self.assertEqual(result["scenarios"], len(result["scenario_results"]))
            self.assertEqual(result["replay_stats"]["attack"]["alerts_dropped"], 0)
            with open(csv_path, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            scenario_rows = [row for row in rows if row["record_type"] == "scenario"]
            self.assertEqual(len(scenario_rows), result["scenarios"])
            self.assertTrue(all(row["result"] == "TP" for row in scenario_rows))

    def test_read_alerts_extracts_evidence_and_rule_version(self):
        from evaluation.run_eval import _read_alerts
        import sqlite3
        with tempfile.NamedTemporaryFile("w+", suffix=".db") as tf:
            conn = sqlite3.connect(tf.name)
            conn.execute("""
                CREATE TABLE alerts (
                    id INTEGER PRIMARY KEY,
                    timestamp REAL,
                    rule_name TEXT,
                    rule_version TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    detail TEXT,
                    severity TEXT,
                    confidence TEXT,
                    evidence_json TEXT
                )
            """)
            conn.execute("""
                INSERT INTO alerts (
                    timestamp, rule_name, rule_version, src_ip, dst_ip, src_port, dst_port,
                    protocol, detail, severity, confidence, evidence_json
                ) VALUES (
                    100.0, 'SYN_FLOOD', '1.13', '192.168.1.100', '192.168.1.1', 50000, 80,
                    'TCP', 'SYN flood detected', 'high', 'heuristic', '{"packet_count": 100, "target_port": 80}'
                )
            """)
            conn.commit()
            conn.close()

            alerts = _read_alerts(tf.name)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["rule_name"], "SYN_FLOOD")
            self.assertEqual(alerts[0]["rule_version"], "1.13")
            self.assertIsInstance(alerts[0]["evidence"], dict)
            self.assertEqual(alerts[0]["evidence"]["packet_count"], 100)
            self.assertEqual(alerts[0]["evidence"]["target_port"], 80)


    def test_all_23_rules_in_eval_metadata_and_labels(self):
        """All 23 registered engine rules must be discoverable in evaluation metadata and labels CSV."""
        from engine.rules import ALL_RULE_CLASSES, REGISTERED_RULE_NAMES
        from evaluation.run_eval import _run_metadata

        self.assertEqual(len(ALL_RULE_CLASSES), 23)
        self.assertEqual(len(REGISTERED_RULE_NAMES), 23)

        meta = _run_metadata()
        meta_rules = set(meta["rule_versions"].keys())
        self.assertEqual(meta_rules, set(REGISTERED_RULE_NAMES), "Evaluation metadata must cover all 23 rules")

        labels_path = os.path.join(PROJECT_DIR, "evaluation", "scenarios", "test_labels.csv")
        with open(labels_path, newline="", encoding="utf-8") as f:
            labels_rules = {row["expected_rule"] for row in csv.DictReader(f)}
        self.assertEqual(labels_rules, set(REGISTERED_RULE_NAMES), "Labels CSV must cover scenarios for all 23 rules")


if __name__ == "__main__":
    unittest.main()
