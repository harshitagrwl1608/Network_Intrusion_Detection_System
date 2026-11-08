"""
ids_project/tests/test_holdout_pipeline.py
-----------------------------------------
Unit and integration tests for the Independent Holdout Validation Pipeline.

Tests:
  - Aggregate engine fingerprint computation and sensitivity
  - Git engine freeze verification and dirty tree enforcement
  - Quarantine integrity, magic byte verification, and read-only permissions
  - Candidate registration and quarantine promotion
  - Single-pass blind evaluation on benign and attack fixtures
  - Strict freeze enforcement blocking evaluation on uncommitted state
  - Immutable audit report structure and read-only file sealing
"""

import json
import os
import stat
import sys
import tempfile
import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_IDS_ROOT = os.path.dirname(_HERE)
if _IDS_ROOT not in sys.path:
    sys.path.insert(0, _IDS_ROOT)

from evaluation.holdout_pipeline import (
    compute_engine_fingerprint,
    verify_engine_freeze,
    enforce_quarantine_permissions,
    verify_holdout_quarantine,
    register_holdout_candidate,
    run_blind_holdout_evaluation,
)

_HERE = os.path.dirname(os.path.abspath(__file__))
_IDS_ROOT = os.path.dirname(_HERE)
BENIGN_PCAP = os.path.join(_IDS_ROOT, "data", "test_benign.pcap")
ATTACK_PCAP = os.path.join(_IDS_ROOT, "data", "test_attacks.pcap")


def test_compute_engine_fingerprint():
    """Verify engine fingerprint returns valid 64-char SHA-256 and detects modifications."""
    agg_hash, per_file = compute_engine_fingerprint()
    assert isinstance(agg_hash, str)
    assert len(agg_hash) == 64
    assert int(agg_hash, 16) > 0
    assert "rules.py" in per_file
    assert len(per_file["rules.py"]) == 64

    # Test modification sensitivity with dummy files
    with tempfile.NamedTemporaryFile("w", delete=False) as f1, tempfile.NamedTemporaryFile("w", delete=False) as f2:
        f1.write("print('hello')\n")
        f2.write("print('world')\n")
        f1_path = f1.name
        f2_path = f2.name

    try:
        h1, _ = compute_engine_fingerprint([f1_path, f2_path])
        # Modify f1
        with open(f1_path, "a") as f1_mod:
            f1_mod.write("# modified\n")
        h2, _ = compute_engine_fingerprint([f1_path, f2_path])
        assert h1 != h2, "Modifying engine file must change the aggregate fingerprint"
    finally:
        if os.path.exists(f1_path):
            os.remove(f1_path)
        if os.path.exists(f2_path):
            os.remove(f2_path)


def test_verify_engine_freeze():
    """Verify engine freeze check reports commit and branch."""
    res = verify_engine_freeze(allow_dirty=True)
    assert res["git_commit"] is not None
    assert len(res["git_commit"]) == 40
    assert res["engine_fingerprint"] is not None
    assert len(res["engine_fingerprint"]) == 64


def test_verify_holdout_quarantine_valid():
    """Verify quarantine integrity on valid PCAP fixture."""
    res = verify_holdout_quarantine(BENIGN_PCAP)
    assert res["valid"] is True
    assert res["size_bytes"] > 0
    assert res["magic_hex"] is not None
    assert len(res["sha256"]) == 64


def test_verify_holdout_quarantine_failures():
    """Verify quarantine validation fails on missing, empty, or corrupt files."""
    # Missing file
    res = verify_holdout_quarantine("/tmp/nonexistent_holdout_12345.pcap")
    assert res["valid"] is False
    assert "does not exist" in res["error"]

    with tempfile.NamedTemporaryFile("wb", delete=False) as empty_f:
        empty_path = empty_f.name

    try:
        # Empty file
        res = verify_holdout_quarantine(empty_path)
        assert res["valid"] is False
        assert "empty" in res["error"]

        # Corrupt magic
        with open(empty_path, "wb") as f:
            f.write(b"CORRUPT_NOT_PCAP_MAGIC_1234567890")
        res = verify_holdout_quarantine(empty_path)
        assert res["valid"] is False
        assert "Invalid PCAP header magic bytes" in res["error"]

        # Expected SHA-256 mismatch
        res_mismatch = verify_holdout_quarantine(BENIGN_PCAP, expected_sha256="0" * 64)
        assert res_mismatch["valid"] is False
        assert "SHA-256 mismatch" in res_mismatch["error"]
    finally:
        if os.path.exists(empty_path):
            os.remove(empty_path)


def test_enforce_quarantine_permissions():
    """Verify enforce_quarantine_permissions sets 0o444 read-only mode."""
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)  # Minimal pcap header
        path = f.name

    try:
        # Initially writeable
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        assert bool(os.stat(path).st_mode & stat.S_IWUSR) is True

        enforce_quarantine_permissions(path)
        # Should now be read-only
        mode = os.stat(path).st_mode
        assert not bool(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        assert bool(mode & stat.S_IRUSR)

        q_info = verify_holdout_quarantine(path)
        assert q_info["valid"] is True
        assert q_info["is_read_only"] is True
    finally:
        # Restore write permission to allow cleanup
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            os.remove(path)
        except OSError:
            pass


def test_register_holdout_candidate():
    """Verify holdout candidate registration and metadata persistence in quarantine."""
    with tempfile.TemporaryDirectory() as q_dir:
        meta_in = {
            "name": "Test Holdout Capture",
            "publisher": "Evaluation Lab",
            "attack_family": "Port Reconnaissance",
            "ground_truth_source": "Synthetic Benchmark",
            "target_rules": ["PORT_SCAN"],
        }
        reg_info = register_holdout_candidate(
            source_pcap_path=BENIGN_PCAP,
            candidate_id="test_candidate_01",
            candidate_meta=meta_in,
            quarantine_dir=q_dir,
        )

        assert reg_info["candidate_id"] == "test_candidate_01"
        assert reg_info["quarantined_pcap_path"].endswith("test_candidate_01.pcap")
        assert os.path.isfile(reg_info["quarantined_pcap_path"])

        # Check permissions
        mode = os.stat(reg_info["quarantined_pcap_path"]).st_mode
        assert not bool(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))

        # Check .meta.json
        meta_file = os.path.join(q_dir, "test_candidate_01.meta.json")
        assert os.path.isfile(meta_file)
        with open(meta_file, "r") as mf:
            saved_meta = json.load(mf)
        assert saved_meta["sha256"] == reg_info["sha256"]


def test_run_blind_holdout_evaluation_benign():
    """Verify single-pass blind holdout evaluation on benign traffic produces TRUE_NEGATIVE."""
    with tempfile.TemporaryDirectory() as out_dir:
        candidate_meta = {
            "candidate_id": "holdout_benign_eval",
            "is_benign": True,
            "target_rules": ["FP_BENIGN"],
            "ground_truth_source": "Clean network traffic baseline",
        }
        report = run_blind_holdout_evaluation(
            pcap_path=BENIGN_PCAP,
            candidate_meta=candidate_meta,
            output_dir=out_dir,
            strict_freeze=False,
            allow_dirty=True,
        )

        assert report["evaluation_type"] == "INDEPENDENT_BLIND_HOLDOUT"
        assert report["verdict_analysis"]["verdict"] == "TRUE_NEGATIVE"
        assert report["execution_metrics"]["total_alerts"] == 0
        assert report["execution_metrics"]["packets_processed"] > 0
        assert report["engine_freeze"]["engine_fingerprint"] is not None
        assert len(report["raw_alerts"]) == 0

        # Verify audit report file on disk is read-only
        report_files = [f for f in os.listdir(out_dir) if f.startswith("holdout_holdout_benign_eval_")]
        assert len(report_files) == 1
        report_path = os.path.join(out_dir, report_files[0])
        mode = os.stat(report_path).st_mode
        assert not bool(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def test_run_blind_holdout_evaluation_attack():
    """Verify single-pass blind holdout evaluation on attack traffic produces TRUE_POSITIVE."""
    with tempfile.TemporaryDirectory() as out_dir:
        candidate_meta = {
            "candidate_id": "holdout_attack_eval",
            "is_benign": False,
            "target_rules": ["PORT_SCAN", "SYN_FLOOD"],
            "ground_truth_source": "Synthetic attack harness",
        }
        report = run_blind_holdout_evaluation(
            pcap_path=ATTACK_PCAP,
            candidate_meta=candidate_meta,
            output_dir=out_dir,
            strict_freeze=False,
            allow_dirty=True,
        )

        assert report["verdict_analysis"]["verdict"] == "TRUE_POSITIVE"
        assert report["execution_metrics"]["total_alerts"] > 0
        assert "PORT_SCAN" in report["execution_metrics"]["alerts_by_rule"] or "SYN_FLOOD" in report["execution_metrics"]["alerts_by_rule"]

        # Verify raw alert structure contains evidence dict
        for alert in report["raw_alerts"]:
            assert "evidence" in alert
            assert isinstance(alert["evidence"], dict)


def test_strict_freeze_blocks_on_dirty(monkeypatch):
    """Verify that strict_freeze=True blocks evaluation if engine has uncommitted modifications."""
    from evaluation import holdout_pipeline

    def mock_verify_freeze(repo_dir=None, allow_dirty=False):
        return {
            "frozen": False,
            "git_commit": "abcdef1234567890abcdef1234567890abcdef12",
            "dirty": True,
            "error": "Engine has uncommitted modifications: ['M ids_project/engine/rules.py']",
        }

    monkeypatch.setattr(holdout_pipeline, "verify_engine_freeze", mock_verify_freeze)

    with tempfile.TemporaryDirectory() as out_dir:
        candidate_meta = {"candidate_id": "test_freeze_block", "is_benign": True}
        with pytest.raises(RuntimeError) as exc_info:
            run_blind_holdout_evaluation(
                pcap_path=BENIGN_PCAP,
                candidate_meta=candidate_meta,
                output_dir=out_dir,
                strict_freeze=True,
                allow_dirty=False,
            )
        assert "Holdout evaluation blocked by engine freeze check" in str(exc_info.value)


def test_holdout_pipeline_cli():
    """Verify holdout pipeline CLI runs --verify-freeze and outputs valid JSON."""
    import subprocess
    proc = subprocess.run(
        [sys.executable, os.path.join(_IDS_ROOT, "evaluation", "holdout_pipeline.py"), "--verify-freeze", "--allow-dirty"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert proc.returncode == 0
    res = json.loads(proc.stdout)
    assert "frozen" in res
    assert "engine_fingerprint" in res
    assert len(res["engine_fingerprint"]) == 64


