import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from engine.rules import RuleEngine


class TestRuleGovernanceInvariants(unittest.TestCase):
    """Dynamic invariant tests replacing rigid numerical rule-count assertions.

    Enforces that every registered detection rule provides distinct, justified,
    tested, and maintainable value without arbitrary numerical limits.
    """

    @classmethod
    def setUpClass(cls):
        cls.engine = RuleEngine(None, set(), config)

    def test_rule_identities_are_unique(self):
        """Every registered rule must have a globally unique rule name."""
        names = [r.name for r in self.engine.rules]
        duplicates = [name for name in set(names) if names.count(name) > 1]
        self.assertEqual(duplicates, [], f"Duplicate rule names detected in registry: {duplicates}")

    def test_no_duplicate_rule_classes(self):
        """No duplicate class instances may be registered."""
        classes = [r.__class__.__name__ for r in self.engine.rules]
        duplicates = [c for c in set(classes) if classes.count(c) > 1]
        self.assertEqual(duplicates, [], f"Duplicate rule class instances registered: {duplicates}")

    def test_rule_instances_are_valid(self):
        """Every registered rule instance must adhere to the Rule interface contract."""
        for rule in self.engine.rules:
            with self.subTest(rule=rule.__class__.__name__):
                self.assertTrue(hasattr(rule, "name"), f"{rule} missing 'name'")
                self.assertIsInstance(rule.name, str)
                self.assertTrue(len(rule.name) > 0, f"{rule} has empty name")

                self.assertTrue(hasattr(rule, "rule_version"), f"{rule} missing 'rule_version'")
                self.assertIsInstance(rule.rule_version, str)
                self.assertTrue(len(rule.rule_version) > 0, f"{rule} has empty rule_version")

                self.assertTrue(callable(getattr(rule, "check", None)), f"{rule} check() is not callable")
                self.assertTrue(callable(getattr(rule, "prune_stale", None)), f"{rule} prune_stale() is not callable")

    def test_core_baseline_rules_preserved(self):
        """All core baseline detection capabilities must be preserved without accidental omission."""
        BASELINE_RULES = {
            "BLOCKLIST", "PORT_SCAN", "UDP_SCAN", "UDP_FLOOD", "TCP_STEALTH_SCAN",
            "TCP_FLAG_ANOMALY", "SYN_FLOOD", "DISTRIBUTED_SYN_FLOOD", "ICMP_SWEEP",
            "ICMP_FLOOD", "ARP_SPOOF", "PAYLOAD_HIT", "DNS_ANOMALY", "BRUTE_FORCE",
            "SLOW_PORT_SCAN", "DATA_EXFIL", "CLEAR_HTTP_ON_TLS_PORT", "TLS_ANOMALY",
            "TCP_ZERO_WINDOW",
        }
        registered_names = {r.name for r in self.engine.rules}
        missing = BASELINE_RULES - registered_names
        self.assertEqual(missing, set(), f"Core baseline rule(s) accidentally omitted from registry: {missing}")

    def test_registered_rules_have_associated_test_coverage(self):
        """Every registered rule name must have associated automated test coverage in ids_project/tests/."""
        tests_dir = os.path.dirname(__file__)
        all_test_code = []
        for root, _, files in os.walk(tests_dir):
            for file in files:
                if file.startswith("test_") and file.endswith(".py"):
                    with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                        all_test_code.append(f.read())
        corpus = "\n".join(all_test_code)

        for rule in self.engine.rules:
            with self.subTest(rule_name=rule.name):
                # Assert either the rule name (e.g. 'PORT_SCAN') or class name is referenced in the test suite
                is_referenced = (rule.name in corpus) or (rule.__class__.__name__ in corpus)
                self.assertTrue(is_referenced, f"Rule {rule.name} ({rule.__class__.__name__}) has no test references")

    def test_dynamic_registry_integrity_and_count_intentionality(self):
        """Registry count must be non-zero and match the sum of valid, registered rule instances."""
        count = len(self.engine.rules)
        self.assertGreaterEqual(count, 19, "Registry count must be at least the baseline count (>=19)")
        self.assertEqual(count, len(set(self.engine.rules)), "All registered rules must be distinct objects")


if __name__ == "__main__":
    unittest.main()
