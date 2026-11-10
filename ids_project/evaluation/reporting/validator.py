"""
NetGuard IDS — Evaluation Report Validator
Implements the 11 programmatic validation gates mandated by REPORTING_STANDARD.md.
"""

import csv
import json
import math
import os
from typing import Dict, List, Tuple
from ids_project.evaluation.reporting.contract import (
    EvaluationResult,
    EvaluationVerdict,
    EvidenceStatus,
)
from ids_project.evaluation.reporting.builder import get_file_sha256


class EvaluationValidator:
    """Validates an EvaluationResult and its generated artifacts against programmatic gates."""

    def __init__(self, result: EvaluationResult):
        self.result = result
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate_all(
        self,
        csv_dir: str = None,
        json_path: str = None,
        markdown_path: str = None,
    ) -> Tuple[bool, List[str], List[str]]:
        """Run all programmatic validation gates. Returns (passed, errors, warnings)."""
        self.errors.clear()
        self.warnings.clear()

        self._check_1_tier_reconciliation()
        self._check_2_mathematical_reproducibility()
        self._check_3_provenance_fingerprints()
        self._check_4_metric_units_and_evidence()
        self._check_5_evidence_completeness()
        self._check_6_no_hardcoded_fallbacks()

        # Gate 4 & 5: Required CSV artifact validation (fail closed)
        if self.result.export_files:
            if not csv_dir or not os.path.exists(csv_dir) or not os.path.isdir(csv_dir):
                self.errors.append(
                    f"Gate 5 failed: Required export directory is missing or invalid: '{csv_dir}'"
                )
            else:
                self._check_7_csv_schema_and_counts(csv_dir)
        elif csv_dir and os.path.exists(csv_dir):
            self._check_7_csv_schema_and_counts(csv_dir)

        # Gate 6: Canonical JSON and Markdown output consistency
        if json_path or markdown_path:
            self._check_8_json_markdown_consistency(json_path, markdown_path)

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
        """Gate 4 & 5: Validate CSV schema, column parity, row count, file size, and SHA-256 on disk."""
        for fname, meta in self.result.export_files.items():
            fpath = os.path.join(csv_dir, fname)
            if not os.path.exists(fpath):
                self.errors.append(f"Gate 5 failed: Exported file '{fname}' not found on disk at {fpath}")
                continue

            # Recorded file size check
            expected_size = meta.get("size_bytes")
            actual_size = os.path.getsize(fpath)
            if expected_size is not None and actual_size != expected_size:
                self.errors.append(
                    f"Gate 5 failed in '{fname}': Recorded size ({expected_size}) != actual file size ({actual_size})"
                )

            # Recorded SHA-256 check
            expected_sha = meta.get("sha256")
            if expected_sha and len(expected_sha) == 64:
                actual_sha = get_file_sha256(fpath)
                if actual_sha.lower() != expected_sha.lower():
                    self.errors.append(
                        f"Gate 5 failed in '{fname}': Recorded SHA-256 ({expected_sha[:16]}...) != actual SHA-256 ({actual_sha[:16]}...)"
                    )

            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if not header:
                    self.errors.append(f"Gate 4 failed: Exported file '{fname}' is empty (no header)")
                    continue
                expected_cols = len(header)

                # Explicit schema check if column count or expected columns are defined in metadata
                meta_cols = meta.get("column_count")
                if meta_cols is not None and expected_cols != meta_cols:
                    self.errors.append(
                        f"Gate 4 failed in '{fname}': Header has {expected_cols} columns, expected {meta_cols}"
                    )

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

    def _check_8_json_markdown_consistency(self, json_path: str = None, markdown_path: str = None):
        """Validate exact numerical and status consistency between canonical JSON and Markdown outputs."""
        if not json_path or not os.path.exists(json_path):
            self.errors.append(f"Gate 6 failed: Canonical JSON summary missing at: '{json_path}'")
            return
        if not markdown_path or not os.path.exists(markdown_path):
            self.errors.append(f"Gate 6 failed: Markdown report missing at: '{markdown_path}'")
            return

        try:
            with open(json_path, "r", encoding="utf-8") as jf:
                jdata = json.load(jf)
            with open(markdown_path, "r", encoding="utf-8") as mf:
                mtext = mf.read()
        except Exception as e:
            self.errors.append(f"Gate 6 failed: Could not read JSON/Markdown outputs: {e}")
            return

        # Verdict consistency
        j_verdict = jdata.get("verdict", "")
        if j_verdict and j_verdict not in mtext:
            self.errors.append(f"Gate 6 consistency failure: JSON verdict '{j_verdict}' not found in Markdown")

        # Total alerts consistency
        j_tot = jdata.get("total_alerts")
        if j_tot is not None and str(j_tot) not in mtext:
            self.errors.append(f"Gate 6 consistency failure: Total alerts '{j_tot}' not found in Markdown")

        # Tier counts consistency
        for t_key, cnt in jdata.get("tier_counts", {}).items():
            if t_key not in mtext or str(cnt) not in mtext:
                self.errors.append(
                    f"Gate 6 consistency failure: Tier '{t_key}' count '{cnt}' not represented in Markdown"
                )

        # Git commit consistency
        g_commit = jdata.get("provenance", {}).get("git_commit", "")
        if g_commit and g_commit not in mtext:
            self.errors.append(f"Gate 6 consistency failure: Git commit '{g_commit}' not found in Markdown")

        # Export files and digests consistency
        for ef, meta in jdata.get("export_files", {}).items():
            if ef not in mtext:
                self.errors.append(f"Gate 6 consistency failure: Export file '{ef}' not found in Markdown")
            sha = meta.get("sha256")
            if sha and len(sha) == 64 and sha not in mtext:
                self.errors.append(f"Gate 6 consistency failure: Export SHA-256 for '{ef}' not found in Markdown")
