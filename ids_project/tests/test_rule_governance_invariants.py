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

    def test_port_boundaries_enforced_across_transport_rules(self):
        """Transport rules must strictly enforce 1 <= port <= 65535 and reject invalid port boundaries."""
        invalid_records = [
            {"type": "IP", "protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 0, "dst_port": 80, "tcp_flags": 0x02, "timestamp": 100.0},
            {"type": "IP", "protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 50000, "dst_port": 0, "tcp_flags": 0x02, "timestamp": 100.0},
            {"type": "IP", "protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": -1, "dst_port": 80, "tcp_flags": 0x02, "timestamp": 100.0},
            {"type": "IP", "protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 50000, "dst_port": 65536, "tcp_flags": 0x02, "timestamp": 100.0},
            {"type": "IP", "protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 50000, "dst_port": "bad_port", "tcp_flags": 0x02, "timestamp": 100.0},
        ]
        for rule in self.engine.rules:
            for rec in invalid_records:
                with self.subTest(rule=rule.name, rec=rec):
                    try:
                        alert = rule.check(rec)
                        # Invalid port bounds must never produce a port-based scan or beacon alert
                        if alert:
                            src_p = alert.get("src_port")
                            dst_p = alert.get("dst_port")
                            if src_p is not None:
                                self.assertTrue(1 <= src_p <= 65535, f"Rule {rule.name} emitted invalid src_port: {src_p}")
                            if dst_p is not None:
                                self.assertTrue(1 <= dst_p <= 65535, f"Rule {rule.name} emitted invalid dst_port: {dst_p}")
                    except Exception as exc:
                        self.fail(f"Rule {rule.name}.check() crashed on invalid port boundary {rec}: {exc}")

    def test_finite_timestamp_drift_protection(self):
        """Rules must reject non-finite (NaN, inf) or negative timestamps without state corruption."""
        import math
        bad_timestamps = [float("nan"), float("inf"), float("-inf"), -1.0, -999999.0]
        base_rec = {
            "type": "IP", "protocol": "TCP",
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 49152, "dst_port": 80, "tcp_flags": 0x02,
        }
        for rule in self.engine.rules:
            for ts in bad_timestamps:
                with self.subTest(rule=rule.name, ts=ts):
                    rec = dict(base_rec, timestamp=ts)
                    try:
                        alert = rule.check(rec)
                        # Invalid timestamps must never produce valid alerts
                        self.assertIsNone(alert, f"Rule {rule.name} alerted on non-finite timestamp {ts}")
                    except Exception as exc:
                        self.fail(f"Rule {rule.name}.check() crashed on bad timestamp {ts}: {exc}")


    def test_malformed_record_type_fuzz_resilience(self):
        """All registered detection rules must handle malformed data types gracefully without crashing."""
        fuzz_records = [
            {"type": "IP", "protocol": "TCP", "src_ip": 12345, "dst_ip": "10.0.0.2", "payload": 99999, "timestamp": 100.0},
            {"type": "IP", "protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": None, "payload": [1, 2, 3], "timestamp": 100.0},
            {"type": "IP", "protocol": "UDP", "src_port": "bad_port", "dst_port": 53, "dns_query": 999, "timestamp": 100.0},
            {"type": "IP", "protocol": "UDP", "src_port": 53000, "dst_port": 53, "dns_query": ["evil.com"], "timestamp": 100.0},
            {"type": "IP", "protocol": "ICMP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "icmp_type": "not_int", "payload": 1234, "timestamp": 100.0},
            {"type": "IP", "protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "tcp_flags": "invalid_flags", "timestamp": 100.0},
            {"type": "IP", "protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "tcp_payload_seq": "not_a_seq", "timestamp": 100.0},
        ]
        for rule in self.engine.rules:
            for rec in fuzz_records:
                with self.subTest(rule=rule.name, rec=rec):
                    try:
                        rule.check(rec)
                    except Exception as exc:
                        self.fail(f"Rule {rule.name}.check() crashed on malformed record {rec}: {exc}")


if __name__ == "__main__":
    unittest.main()

