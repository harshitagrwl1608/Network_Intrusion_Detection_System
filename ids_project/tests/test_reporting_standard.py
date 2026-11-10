"""
NetGuard IDS — Test Suite for Self-Validating Reporting Standard
Exercises the real ReportBuilder and EvaluationValidator against synthetic fixtures.
"""

import csv
import json
import os
import sys
import tempfile
import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ids_project.evaluation.reporting import (
    UnitOfAnalysis,
    EvidenceStatus,
    EvaluationVerdict,
    MetricDefinition,
    ProvenanceRecord,
    EvaluationResult,
    EvaluationValidator,
    ReportBuilder,
    get_file_sha256,
)


def _make_dummy_provenance():
    return ProvenanceRecord(
        dataset_name="Synthetic Benchmark",
        pcap_file="synthetic.pcap",
        pcap_sha256="a" * 64,
        pcap_size_bytes=1024,
        ground_truth_file="synthetic_gt.csv",
        ground_truth_sha256="b" * 64,
        ground_truth_size_bytes=512,
        db_file="synthetic_eval.db",
        db_sha256="c" * 64,
        db_size_bytes=256,
        git_commit="abcdef1234567890abcdef1234567890abcdef12",
        git_branch="antigravity/overnight-work",
        engine_fingerprint="f" * 64,
        capture_start_ts=1000.0,
        capture_end_ts=2000.0,
    )


def test_01_tier_count_reconciliation_failure():
    """Gate 1: Inconsistent tier counts must fail validation and force INCONCLUSIVE."""
    res = EvaluationResult(
        audit_name="Test Audit",
        audit_version="1.0",
        timestamp_utc="2026-11-10T00:00:00Z",
        provenance=_make_dummy_provenance(),
        total_alerts=100,
        tier_counts={"TIER_A": 50, "TIER_B": 40},  # Sum = 90 != 100!
        verdict=EvaluationVerdict.SUPPORTED,
    )
    validator = EvaluationValidator(res)
    passed, errors, _ = validator.validate_all()

    assert not passed
    assert any("Gate 1 failed" in e for e in errors)
    assert res.verdict == EvaluationVerdict.INCONCLUSIVE
    assert len(res.validation_failures) > 0


def test_02_mathematical_reproducibility_check():
    """Gate 3: Mismatched derived metric values must trigger validation error."""
    res = EvaluationResult(
        audit_name="Test Audit",
        audit_version="1.0",
        timestamp_utc="2026-11-10T00:00:00Z",
        provenance=_make_dummy_provenance(),
        total_alerts=100,
        tier_counts={"TIER_A": 100},
        metrics={
            "tier_a_share": MetricDefinition(
                name="Tier-A Confirmation Share",
                unit=UnitOfAnalysis.ALERT,
                status=EvidenceStatus.DERIVED,
                numerator=50.0,
                denominator=100.0,
                value=0.80,  # Should be 0.50! Mismatch!
                percentage=80.0,
                definition="Tier A fraction",
                ground_truth_source="Synthetic",
            )
        },
    )
    validator = EvaluationValidator(res)
    passed, errors, _ = validator.validate_all()

    assert not passed
    assert any("Gate 3 failed" in e for e in errors)
    assert res.verdict == EvaluationVerdict.INCONCLUSIVE


def test_03_csv_column_count_mismatch(tmp_path):
    """Gate 4: CSV with mismatched column count must fail validation."""
    csv_file = tmp_path / "test_alerts.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["col1", "col2", "col3"])  # Header has 3 columns
        writer.writerow(["v1", "v2"])              # Row has 2 columns!

    res = EvaluationResult(
        audit_name="Test Audit",
        audit_version="1.0",
        timestamp_utc="2026-11-10T00:00:00Z",
        provenance=_make_dummy_provenance(),
        total_alerts=1,
        tier_counts={"TIER_A": 1},
        export_files={"test_alerts.csv": {"row_count": 1}},
    )
    validator = EvaluationValidator(res)
    passed, errors, _ = validator.validate_all(csv_dir=str(tmp_path))

    assert not passed
    assert any("Gate 4 failed" in e for e in errors)


def test_04_csv_row_count_integrity(tmp_path):
    """Gate 5: CSV with missing data rows must fail row-count integrity."""
    csv_file = tmp_path / "test_alerts.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["col1", "col2"])
        writer.writerow(["v1", "v2"])  # Only 1 data row

    res = EvaluationResult(
        audit_name="Test Audit",
        audit_version="1.0",
        timestamp_utc="2026-11-10T00:00:00Z",
        provenance=_make_dummy_provenance(),
        total_alerts=10,
        tier_counts={"TIER_A": 10},
        export_files={"test_alerts.csv": {"row_count": 10}},  # Expected 10!
    )
    validator = EvaluationValidator(res)
    passed, errors, _ = validator.validate_all(csv_dir=str(tmp_path))

    assert not passed
    assert any("Gate 5 failed" in e for e in errors)


def test_05_missing_provenance_sha256():
    """Gate 9: Empty or truncated SHA-256 digest must fail."""
    prov = _make_dummy_provenance()
    prov.pcap_sha256 = ""  # Missing!

    res = EvaluationResult(
        audit_name="Test Audit",
        audit_version="1.0",
        timestamp_utc="2026-11-10T00:00:00Z",
        provenance=prov,
        total_alerts=10,
        tier_counts={"TIER_A": 10},
    )
    validator = EvaluationValidator(res)
    passed, errors, _ = validator.validate_all()

    assert not passed
    assert any("Gate 9 failed" in e for e in errors)


def test_06_builder_generates_matching_json_and_markdown(tmp_path):
    """Verifies that ReportBuilder renders matching figures across JSON and Markdown."""
    prov = _make_dummy_provenance()
    res = EvaluationResult(
        audit_name="Canonical Test Evaluation",
        audit_version="2.0",
        timestamp_utc="2026-11-10T12:00:00Z",
        provenance=prov,
        total_alerts=50,
        tier_counts={"TIER_A": 45, "TIER_B": 5},
        verdict=EvaluationVerdict.SUPPORTED_WITH_LIMITATIONS,
        verdict_rationale="Evaluated against verified synthetic baseline.",
        metrics={
            "confirmation_share": MetricDefinition(
                name="Tier-A Confirmation Share",
                unit=UnitOfAnalysis.ALERT,
                status=EvidenceStatus.DERIVED,
                numerator=45.0,
                denominator=50.0,
                value=0.90,
                percentage=90.0,
                definition="Tier-A fraction of alerts",
                ground_truth_source="Synthetic GT",
            )
        },
        limitations=["Evaluated on synthetic capture."],
        export_files={"alerts.csv": {"row_count": 50, "size_bytes": 1000, "sha256": "d" * 64}},
    )

    builder = ReportBuilder(res)
    json_path = tmp_path / "summary.json"
    md_path = tmp_path / "report.md"

    builder.write_json_summary(str(json_path))
    builder.write_markdown_report(str(md_path))

    # Read back JSON
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["total_alerts"] == 50
    assert data["tier_counts"]["TIER_A"] == 45
    assert data["metrics"]["confirmation_share"]["percentage"] == 90.0

    # Read back Markdown
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()
    assert "90.00%" in md_text
    assert "45" in md_text
    assert "SUPPORTED WITH LIMITATIONS" in md_text


def test_07_export_hashes_updated_after_close(tmp_path):
    """Verifies that export file SHA-256 hashes are accurately computed from closed files."""
    test_csv = tmp_path / "export.csv"
    content = "col1,col2\nval1,val2\n"
    test_csv.write_text(content, encoding="utf-8")

    res = EvaluationResult(
        audit_name="Test",
        audit_version="1.0",
        timestamp_utc="2026-11-10T00:00:00Z",
        provenance=_make_dummy_provenance(),
        export_files={"export.csv": {"row_count": 1}},
    )

    builder = ReportBuilder(res)
    builder.update_export_hashes(str(tmp_path))

    expected_hash = get_file_sha256(str(test_csv))
    assert res.export_files["export.csv"]["sha256"] == expected_hash
    assert res.export_files["export.csv"]["size_bytes"] == len(content.encode("utf-8"))


def test_08_missing_csv_directory_fails_closed():
    """Gate 5: Missing CSV directory when exports are declared must fail closed."""
    res = EvaluationResult(
        audit_name="Test Audit",
        audit_version="1.0",
        timestamp_utc="2026-11-10T00:00:00Z",
        provenance=_make_dummy_provenance(),
        total_alerts=10,
        tier_counts={"TIER_A": 10},
        export_files={"missing.csv": {"row_count": 10}},
    )
    validator = EvaluationValidator(res)
    # csv_dir is None
    passed, errors, _ = validator.validate_all(csv_dir=None)
    assert not passed
    assert any("Required export directory is missing" in e for e in errors)

    # csv_dir does not exist
    passed2, errors2, _ = validator.validate_all(csv_dir="/nonexistent/directory/path")
    assert not passed2
    assert any("Required export directory is missing" in e for e in errors2)


def test_09_csv_size_and_sha_mismatch_fails(tmp_path):
    """Gate 5: Mismatched size or SHA-256 hash on disk must fail closed."""
    csv_file = tmp_path / "alerts.csv"
    content = "col1,col2\nv1,v2\n"
    csv_file.write_text(content, encoding="utf-8")

    # Mismatched size
    res_bad_size = EvaluationResult(
        audit_name="Test",
        audit_version="1.0",
        timestamp_utc="2026-11-10T00:00:00Z",
        provenance=_make_dummy_provenance(),
        total_alerts=1,
        tier_counts={"TIER_A": 1},
        export_files={"alerts.csv": {"row_count": 1, "size_bytes": 99999}},
    )
    v_size = EvaluationValidator(res_bad_size)
    passed_sz, errors_sz, _ = v_size.validate_all(csv_dir=str(tmp_path))
    assert not passed_sz
    assert any("Recorded size (99999) != actual file size" in e for e in errors_sz)

    # Mismatched SHA-256
    res_bad_sha = EvaluationResult(
        audit_name="Test",
        audit_version="1.0",
        timestamp_utc="2026-11-10T00:00:00Z",
        provenance=_make_dummy_provenance(),
        total_alerts=1,
        tier_counts={"TIER_A": 1},
        export_files={"alerts.csv": {"row_count": 1, "size_bytes": len(content.encode("utf-8")), "sha256": "0" * 64}},
    )
    v_sha = EvaluationValidator(res_bad_sha)
    passed_sha, errors_sha, _ = v_sha.validate_all(csv_dir=str(tmp_path))
    assert not passed_sha
    assert any("Recorded SHA-256" in e for e in errors_sha)


def test_10_json_markdown_consistency_validation(tmp_path):
    """Gate 6: Consistency between canonical JSON and Markdown outputs is validated."""
    prov = _make_dummy_provenance()
    res = EvaluationResult(
        audit_name="Canonical Consistency Test",
        audit_version="1.0",
        timestamp_utc="2026-11-10T12:00:00Z",
        provenance=prov,
        total_alerts=20,
        tier_counts={"TIER_A": 15, "TIER_B": 5},
        verdict=EvaluationVerdict.SUPPORTED_WITH_LIMITATIONS,
    )
    builder = ReportBuilder(res)
    json_path = tmp_path / "summary.json"
    md_path = tmp_path / "report.md"

    builder.write_json_summary(str(json_path))
    builder.write_markdown_report(str(md_path))

    validator = EvaluationValidator(res)
    passed, errors, _ = validator.validate_all(json_path=str(json_path), markdown_path=str(md_path))
    assert passed
    assert len(errors) == 0

    # Introduce discrepancy in Markdown (e.g. tamper with verdict)
    md_tampered = tmp_path / "report_tampered.md"
    md_tampered.write_text("# Report\nVerdict: INCONCLUSIVE\nTotal: 20\n", encoding="utf-8")
    passed_t, errors_t, _ = validator.validate_all(json_path=str(json_path), markdown_path=str(md_tampered))
    assert not passed_t
    assert any("consistency failure" in e for e in errors_t)


def test_11_provenance_distinguishes_hashing_and_no_hardcoded_verified():
    """Gate 9: Markdown report explicitly distinguishes hashing from provenance without bare VERIFIED."""
    res = EvaluationResult(
        audit_name="Provenance Audit",
        audit_version="1.0",
        timestamp_utc="2026-11-10T00:00:00Z",
        provenance=_make_dummy_provenance(),
        total_alerts=10,
        tier_counts={"TIER_A": 10},
    )
    builder = ReportBuilder(res)
    md = builder.generate_markdown_report()

    # Must contain provenance distinction note
    assert "Cryptographic Integrity & Provenance Distinctions" in md
    assert "SHA-256 digests confirm bit-level file integrity" in md

    # Must not contain bare hardcoded '| **VERIFIED** |' in provenance table
    assert "| **VERIFIED** |" not in md
