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


if __name__ == "__main__":
    unittest.main()
