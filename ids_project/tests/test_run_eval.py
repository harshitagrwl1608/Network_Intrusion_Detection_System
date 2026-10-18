import os
import subprocess
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)


class TestRunEvalHarness(unittest.TestCase):
    def test_run_eval_cli_execution(self):
        """Verify that evaluation/run_eval.py runs cleanly with exit code 0."""
        eval_script = os.path.join(PROJECT_DIR, "evaluation", "run_eval.py")
        cmd = [sys.executable, eval_script]
        proc = subprocess.run(cmd, cwd=PROJECT_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(
            proc.returncode,
            0,
            f"run_eval.py failed with code {proc.returncode}.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
        self.assertIn("NETGUARD IDS — COMBINED EVALUATION REPORT", proc.stdout)
        self.assertIn("True Positives (TP)", proc.stdout)
        self.assertIn("Zero false positives", proc.stdout)


if __name__ == "__main__":
    unittest.main()
