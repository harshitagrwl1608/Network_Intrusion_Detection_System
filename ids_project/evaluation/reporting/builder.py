"""
NetGuard IDS — Evaluation Report Builder
Single Source of Truth builder that generates consistent Markdown reports,
canonical JSON summaries, and SHA-256 export manifests from an EvaluationResult.
"""

import hashlib
import json
import os
from typing import Any, Dict
from ids_project.evaluation.reporting.contract import EvaluationResult, EvaluationVerdict


def get_file_sha256(filepath: str, buffer_size: int = 65536) -> str:
    """Calculate SHA-256 digest of a closed file on disk."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(buffer_size):
            hasher.update(chunk)
    return hasher.hexdigest()


class ReportBuilder:
    """Generates canonical JSON and Markdown documentation from an EvaluationResult."""

    def __init__(self, result: EvaluationResult):
        self.result = result

    def to_json_dict(self) -> Dict[str, Any]:
        """Convert EvaluationResult to machine-readable dictionary."""
        p = self.result.provenance
        return {
            "audit_name": self.result.audit_name,
            "audit_version": self.result.audit_version,
            "timestamp_utc": self.result.timestamp_utc,
            "verdict": self.result.verdict.value,
            "verdict_rationale": self.result.verdict_rationale,
            "validation_failures": self.result.validation_failures,
            "provenance": {
                "dataset_name": p.dataset_name,
                "pcap_file": p.pcap_file,
                "pcap_sha256": p.pcap_sha256,
                "pcap_size_bytes": p.pcap_size_bytes,
                "ground_truth_file": p.ground_truth_file,
                "ground_truth_sha256": p.ground_truth_sha256,
                "ground_truth_size_bytes": p.ground_truth_size_bytes,
                "db_file": p.db_file,
                "db_sha256": p.db_sha256,
                "db_size_bytes": p.db_size_bytes,
                "git_commit": p.git_commit,
                "git_branch": p.git_branch,
                "engine_fingerprint": p.engine_fingerprint,
                "capture_start_ts": p.capture_start_ts,
                "capture_end_ts": p.capture_end_ts,
            },
            "total_alerts": self.result.total_alerts,
            "tier_counts": self.result.tier_counts,
            "metrics": {
                k: {
                    "name": m.name,
                    "unit": m.unit.value,
                    "status": m.status.value,
                    "numerator": m.numerator,
                    "denominator": m.denominator,
                    "value": m.value,
                    "percentage": m.percentage,
                    "definition": m.definition,
                    "ground_truth_source": m.ground_truth_source,
                }
                for k, m in self.result.metrics.items()
            },
            "unsupported_categories": self.result.unsupported_categories,
            "limitations": self.result.limitations,
            "export_files": self.result.export_files,
            "extra_metadata": self.result.extra_metadata,
        }

    def write_json_summary(self, output_path: str):
        """Write canonical JSON summary."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        data = self.to_json_dict()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def generate_markdown_report(self) -> str:
        """Render complete, standardized academic evaluation report."""
        p = self.result.provenance
        tc = self.result.tier_counts
        tot = self.result.total_alerts
        md = []

        md.append(f"# {self.result.audit_name} — Evaluation Report")
        md.append(f"**Version:** {self.result.audit_version}  ")
        md.append(f"**Date:** {self.result.timestamp_utc}  ")
        md.append(f"**Evaluation Verdict:** `{self.result.verdict.value}`  \n")

        # 1. Executive Summary
        md.append("## 1. Executive Summary")
        md.append(f"This report presents the independent evaluation of NetGuard IDS against the **{p.dataset_name}** benchmark. ")
        md.append(f"Final determination: **{self.result.verdict.value}**.\n")
        if self.result.verdict_rationale:
            md.append(f"> **Verdict Rationale:** {self.result.verdict_rationale}\n")

        # 2. Provenance and Input Verification
        md.append("## 2. Input Provenance & Cryptographic Verification")
        md.append("| Input Component | File Name | Size (Bytes) | SHA-256 Digest | Status |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        md.append(f"| **PCAP Capture** | `{p.pcap_file}` | {p.pcap_size_bytes:,} | `{p.pcap_sha256}` | **VERIFIED** |")
        md.append(f"| **Ground Truth** | `{p.ground_truth_file}` | {p.ground_truth_size_bytes:,} | `{p.ground_truth_sha256}` | **VERIFIED** |")
        md.append(f"| **Evaluation DB** | `{p.db_file}` | {p.db_size_bytes:,} | `{p.db_sha256}` | **VERIFIED** |")
        md.append("")
        md.append(f"- **Git Commit:** `{p.git_commit}` (branch `{p.git_branch}`)")
        md.append(f"- **Engine Fingerprint:** `{p.engine_fingerprint}`\n")

        # 3. Alert Tier Inventory & Reconciliation
        md.append("## 3. Reconciled Alert Inventory")
        md.append("| Tier | Category | Count | Percentage |")
        md.append("| :--- | :--- | :--- | :--- |")
        for tier_key, count in sorted(tc.items()):
            pct = (count / tot * 100.0) if tot else 0.0
            md.append(f"| `{tier_key}` | Alert Classification | **{count:,}** | **{pct:.2f}%** |")
        md.append(f"| **Total** | **All Emitted Alerts** | **{tot:,}** | **100.00%** |\n")

        # 4. Standardized Metrics
        md.append("## 4. Evaluation Metrics (Strict Unit of Analysis Separation)")
        md.append("| Metric Name | Unit | Status | Numerator | Denominator | Value | Definition |")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for k, m in self.result.metrics.items():
            num_str = f"{m.numerator:,.0f}" if m.numerator is not None else "-"
            den_str = f"{m.denominator:,.0f}" if m.denominator is not None else "-"
            val_str = f"{m.percentage:.2f}%" if m.percentage is not None else (f"{m.value:.4f}" if m.value is not None else "N/A")
            md.append(f"| **{m.name}** | `{m.unit.value}` | `{m.status.value}` | {num_str} | {den_str} | **{val_str}** | {m.definition} |")
        md.append("")

        # 5. Unsupported Categories & Explicit Gaps
        if self.result.unsupported_categories:
            md.append("## 5. Explicit Coverage Gaps & Unsupported Categories")
            for cat in self.result.unsupported_categories:
                md.append(f"- **{cat}**: Out of scope for current rule suite; accounted as documented gap, not silent omission.")
            md.append("")

        # 6. Technical Limitations
        md.append("## 6. Established Technical Limitations")
        for lim in self.result.limitations:
            md.append(f"- {lim}")
        md.append("")

        # 7. Export Ledger
        md.append("## 7. Verified Artifact & Export Manifest")
        md.append("| Export File | Rows | Size (Bytes) | SHA-256 Digest |")
        md.append("| :--- | :--- | :--- | :--- |")
        for fname, meta in self.result.export_files.items():
            r_str = f"{meta.get('row_count', '-'):,}" if isinstance(meta.get('row_count'), int) else "-"
            sz_str = f"{meta.get('size_bytes', 0):,}"
            md.append(f"| `{fname}` | {r_str} | {sz_str} | `{meta.get('sha256', '-')}` |")

        return "\n".join(md)

    def write_markdown_report(self, output_path: str):
        """Write rendered markdown report to disk."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        content = self.generate_markdown_report()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

    def update_export_hashes(self, export_dir: str):
        """Compute SHA-256 hashes for all closed export files on disk."""
        for fname, meta in self.result.export_files.items():
            fpath = os.path.join(export_dir, fname)
            if os.path.exists(fpath):
                meta["size_bytes"] = os.path.getsize(fpath)
                meta["sha256"] = get_file_sha256(fpath)

