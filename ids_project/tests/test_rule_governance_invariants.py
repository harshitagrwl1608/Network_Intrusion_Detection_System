import os
import sys
import time
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

    def test_semantic_rule_lifecycle_governance(self):
        """Rules must adhere to semantic lifecycle governance: valid versioning and state pruning."""
        import re
        for rule in self.engine.rules:
            with self.subTest(rule=rule.name):
                # Version must follow semantic number formatting (e.g. 1.0, 1.12)
                self.assertRegex(
                    rule.rule_version,
                    r"^\d+\.\d+(\.\d+)?$",
                    f"Rule {rule.name} has non-standard version '{rule.rule_version}'"
                )
                # prune_stale must accept a timestamp argument without raising
                try:
                    rule.prune_stale(now=time.time())
                except Exception as exc:
                    self.fail(f"Rule {rule.name}.prune_stale() failed: {exc}")

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

    def test_dynamic_registry_integrity_and_distinctness(self):
        """Registry must contain active, distinct rule instances without arbitrary numerical caps or floors."""
        rules = self.engine.rules
        self.assertGreater(len(rules), 0, "Registry must contain active rules")
        self.assertEqual(len(rules), len(set(rules)), "All registered rules must be distinct objects")
        # Ensure all registered rules have non-empty uppercase standard identifiers
        for r in rules:
            self.assertTrue(r.name.isupper(), f"Rule name '{r.name}' should follow UPPER_SNAKE_CASE standard")


if __name__ == "__main__":
    unittest.main()

