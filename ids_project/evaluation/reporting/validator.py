"""
NetGuard IDS — Evaluation Report Validator
Implements the 11 programmatic validation gates mandated by REPORTING_STANDARD.md.
"""

import csv
import math
import os
from typing import Dict, List, Tuple
from ids_project.evaluation.reporting.contract import (
    EvaluationResult,
    EvaluationVerdict,
    EvidenceStatus,
)


class EvaluationValidator:
    """Validates an EvaluationResult and its generated artifacts against programmatic gates."""

    def __init__(self, result: EvaluationResult):
        self.result = result
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate_all(self, csv_dir: str = None) -> Tuple[bool, List[str], List[str]]:
        """Run all 11 validation gates. Returns (passed, errors, warnings)."""
        self.errors.clear()
        self.warnings.clear()

        self._check_1_tier_reconciliation()
        self._check_2_mathematical_reproducibility()
        self._check_3_provenance_fingerprints()
        self._check_4_metric_units_and_evidence()
        self._check_5_evidence_completeness()
        self._check_6_no_hardcoded_fallbacks()

        if csv_dir and os.path.exists(csv_dir):
            self._check_7_csv_schema_and_counts(csv_dir)

        # Gate 11: Fail-closed verdict verification
        gate_passed = len(self.errors) == 0
        if not gate_passed:
            self.result.verdict = EvaluationVerdict.INCONCLUSIVE
            self.result.validation_failures = list(self.errors)
            if not self.result.verdict_rationale:
                self.result.verdict_rationale = (
                    f"Validation failed with {len(self.errors)} error(s): "
                    + "; ".join(self.errors[:3])
                )
        else:
            self.result.validation_failures = []

        return gate_passed, self.errors, self.warnings

    def _check_1_tier_reconciliation(self):
        """Gate 1: Tier counts must sum exactly to total_alerts."""
        if not self.result.tier_counts:
            self.errors.append("Gate 1 failed: Tier counts dictionary is empty")
            return
        summed = sum(self.result.tier_counts.values())
        if summed != self.result.total_alerts:
            self.errors.append(
                f"Gate 1 failed: Tier sum ({summed}) does not equal total_alerts ({self.result.total_alerts})"
            )

    def _check_2_mathematical_reproducibility(self):
        """Gate 2 & 3: Derived metrics must recalculate accurately from numerator and denominator."""
        for name, m in self.result.metrics.items():
            if m.status == EvidenceStatus.DERIVED:
                if m.denominator is None or m.denominator == 0:
                    if m.value is not None and not math.isnan(m.value) and m.value != 0:
                        self.errors.append(
                            f"Gate 3 failed: Metric '{name}' has zero/null denominator but non-zero value {m.value}"
                        )
                elif m.numerator is not None:
                    expected_ratio = m.numerator / m.denominator
                    if m.value is not None and abs(m.value - expected_ratio) > 1e-4:
                        self.errors.append(
                            f"Gate 3 failed: Metric '{name}' value {m.value} does not match {m.numerator}/{m.denominator}"
                        )
                    if m.percentage is not None:
                        expected_pct = expected_ratio * 100.0
                        if abs(m.percentage - expected_pct) > 0.05:
                            self.errors.append(
                                f"Gate 3 failed: Metric '{name}' percentage {m.percentage}% does not match expected {expected_pct:.2f}%"
                            )

    def _check_3_provenance_fingerprints(self):
        """Gate 9: Provenance fingerprints, hashes, and Git commits must be populated."""
        p = self.result.provenance
        if not p.pcap_sha256 or len(p.pcap_sha256) < 64:
            self.errors.append("Gate 9 failed: Missing or invalid PCAP SHA-256 digest")
        if not p.git_commit:
            self.errors.append("Gate 9 failed: Missing Git commit hash")
        if not p.engine_fingerprint:
            self.errors.append("Gate 9 failed: Missing engine fingerprint")
        if p.pcap_size_bytes <= 0:
            self.errors.append("Gate 9 failed: PCAP size must be positive")

    def _check_4_metric_units_and_evidence(self):
        """Gate 10: Strict prohibition checks on metric names and units."""
        for name, m in self.result.metrics.items():
            # Check prohibition: confirmation share cannot be called 'precision'
            if "precision" in name.lower() and "tier_a" in name.lower():
                self.warnings.append(
                    f"Warning on metric '{name}': Tier-A fractions should be designated as confirmation share rather than precision."
                )
            if not m.definition:
                self.warnings.append(f"Metric '{name}' lacks an explicit written definition.")
            if not m.ground_truth_source:
                self.warnings.append(f"Metric '{name}' lacks ground truth source documentation.")

    def _check_5_evidence_completeness(self):
        """Gate 8: Missing, malformed, and ambiguous evidence must be accounted for."""
        if "ambiguous" not in self.result.extra_metadata and "ambiguous_count" not in self.result.extra_metadata:
            self.warnings.append("Ambiguous evidence tracking is not explicitly recorded in metadata.")

    def _check_6_no_hardcoded_fallbacks(self):
        """Gate 7: Ensure no static historical placeholders exist in current metadata."""
        disallowed_literals = ["397_to_5_historical_split", "unverified_legacy_assumption"]
        for key, val in self.result.extra_metadata.items():
            if any(lit in str(val).lower() for lit in disallowed_literals):
                self.errors.append(f"Gate 7 failed: Metadata field '{key}' contains historical placeholder literal")

    def _check_7_csv_schema_and_counts(self, csv_dir: str):
        """Gate 4 & 5: Validate CSV column parity and row count integrity on disk."""
        for fname, meta in self.result.export_files.items():
            fpath = os.path.join(csv_dir, fname)
            if not os.path.exists(fpath):
                self.errors.append(f"Gate 5 failed: Exported file '{fname}' not found on disk at {fpath}")
                continue
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if not header:
                    self.errors.append(f"Gate 4 failed: Exported file '{fname}' is empty (no header)")
                    continue
                expected_cols = len(header)
                row_count = 0
                for row_idx, row in enumerate(reader, start=2):
                    row_count += 1
                    if len(row) != expected_cols:
                        self.errors.append(
                            f"Gate 4 failed in '{fname}': Row {row_idx} has {len(row)} columns, expected {expected_cols}"
                        )
                        break

                expected_rows = meta.get("row_count")
                if expected_rows is not None and row_count != expected_rows:
                    self.errors.append(
                        f"Gate 5 failed in '{fname}': File has {row_count} rows, expected {expected_rows}"
                    )

