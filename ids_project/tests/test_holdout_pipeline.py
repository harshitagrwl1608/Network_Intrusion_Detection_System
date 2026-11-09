"""
ids_project/tests/test_holdout_pipeline.py
-----------------------------------------
Unit and integration tests for the Independent Holdout Validation Pipeline.

Tests:
  - Aggregate engine fingerprint computation and sensitivity
  - Git engine freeze verification and dirty tree enforcement
  - Candidate ID allowlist validation (path traversal, illegal chars, length bounds)
  - Quarantine path containment and boundary enforcement
  - Quarantine integrity, magic byte verification, and read-only permissions (0o444)
  - Candidate registration, exclusive creation, and overwrite prevention
  - Development corpus hash collision rejection
  - Complete structural validation of PCAP format (capinfos / tshark)
  - Single-pass blind evaluation on benign and attack fixtures
  - Separation of capture-level rule firing from ground-truth verification
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
    validate_candidate_id,
    check_quarantine_path_containment,
    validate_pcap_structure,
)

BENIGN_PCAP = os.path.join(_IDS_ROOT, "data", "test_benign.pcap")
ATTACK_PCAP = os.path.join(_IDS_ROOT, "data", "test_attacks.pcap")

# Valid 24-byte PCAP global header: magic(4), v_maj=2, v_min=4, zone=0, sig=0, snap=65535, net=1
VALID_MINIMAL_PCAP_HEADER = (
    b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
)


def _make_quarantined_pcap(source_path: str, target_dir: str, filename: str = "quarantined.pcap") -> str:
    """Helper to copy a test PCAP into quarantine and seal read-only permissions (0o444)."""
    os.makedirs(target_dir, exist_ok=True)
    dst = os.path.join(target_dir, filename)
    with open(source_path, "rb") as sf, open(dst, "wb") as df:
        df.write(sf.read())
    enforce_quarantine_permissions(dst)
    return dst


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


def test_candidate_id_allowlist_validation():
    """Candidate IDs must strictly match [A-Za-z0-9][A-Za-z0-9._-]{0,63}."""
    valid_ids = ["holdout_01", "candidate-A", "test.pcap", "RUN_2026", "a", "A" * 64]
    for cid in valid_ids:
        assert validate_candidate_id(cid) == cid

    invalid_ids = [
        "../bad",
        "foo/bar",
        "../../etc/passwd",
        "test$id",
        "has space",
        "bad\\backslash",
        "null\x00byte",
        "",
        "A" * 65,
        "-starts-with-dash",
        ".starts-with-dot",
    ]
    for cid in invalid_ids:
        with pytest.raises(ValueError):
            validate_candidate_id(cid)


def test_quarantine_path_containment():
    """Verify quarantine path containment rejects traversal outside quarantine directory."""
    with tempfile.TemporaryDirectory() as q_dir:
        inside = os.path.join(q_dir, "valid.pcap")
        with open(inside, "wb") as f:
            f.write(b"data")
        assert check_quarantine_path_containment(inside, q_dir) == os.path.realpath(inside)

        # Attempt to reference outside directory via ..
        outside = os.path.join(q_dir, "..", "outside.pcap")
        with pytest.raises(ValueError) as exc:
            check_quarantine_path_containment(outside, q_dir)
        assert "escapes quarantine root" in str(exc.value)


def test_verify_holdout_quarantine_valid():
    """Verify quarantine integrity on valid quarantined PCAP fixture."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        q_pcap = _make_quarantined_pcap(BENIGN_PCAP, tmp_dir)
        res = verify_holdout_quarantine(q_pcap, quarantine_dir=tmp_dir)
        assert res["valid"] is True
        assert res["size_bytes"] > 0
        assert res["is_read_only"] is True
        assert res["magic_hex"] is not None
        assert len(res["sha256"]) == 64


def test_verify_holdout_quarantine_failures():
    """Verify quarantine validation fails on missing, empty, writeable, or corrupt files."""
    # Missing file
    res = verify_holdout_quarantine("/tmp/nonexistent_holdout_12345.pcap")
    assert res["valid"] is False
    assert "does not exist" in res["error"]

    with tempfile.NamedTemporaryFile("wb", delete=False) as empty_f:
        empty_path = empty_f.name

    try:
        enforce_quarantine_permissions(empty_path)
        # Empty file
        res = verify_holdout_quarantine(empty_path)
        assert res["valid"] is False
        assert "empty" in res["error"]

        # Corrupt magic
        os.chmod(empty_path, stat.S_IRUSR | stat.S_IWUSR)
        with open(empty_path, "wb") as f:
            f.write(b"CORRUPT_NOT_PCAP_MAGIC_1234567890")
        enforce_quarantine_permissions(empty_path)
        res = verify_holdout_quarantine(empty_path)
        assert res["valid"] is False
        assert "Invalid PCAP header magic bytes" in res["error"]

        # Expected SHA-256 mismatch
        with tempfile.TemporaryDirectory() as tmp_dir:
            q_pcap = _make_quarantined_pcap(BENIGN_PCAP, tmp_dir)
            res_mismatch = verify_holdout_quarantine(q_pcap, expected_sha256="0" * 64)
            assert res_mismatch["valid"] is False
            assert "SHA-256 mismatch" in res_mismatch["error"]
    finally:
        try:
            os.chmod(empty_path, stat.S_IRUSR | stat.S_IWUSR)
            os.remove(empty_path)
        except OSError:
            pass


def test_enforce_quarantine_permissions():
    """Verify enforce_quarantine_permissions sets 0o444 read-only mode and structural check passes."""
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(VALID_MINIMAL_PCAP_HEADER)
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
            check_dev_overlap=False,  # Allow test fixture re-use for unit testing
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


def test_register_holdout_candidate_dev_corpus_collision():
    """register_holdout_candidate must reject development corpus captures when check_dev_overlap=True."""
    with tempfile.TemporaryDirectory() as q_dir:
        meta_in = {
            "name": "Dev Collision Test",
            "publisher": "Evaluation Lab",
            "attack_family": "Test",
        }
        with pytest.raises(ValueError) as exc:
            register_holdout_candidate(
                source_pcap_path=BENIGN_PCAP,
                candidate_id="dev_collision_candidate",
                candidate_meta=meta_in,
                quarantine_dir=q_dir,
                check_dev_overlap=True,
            )
        assert "matches known development capture" in str(exc.value)


def test_register_holdout_candidate_overwrite_rejected():
    """Exclusive creation prevents overwriting existing quarantine PCAP or metadata."""
    with tempfile.TemporaryDirectory() as q_dir:
        meta_in = {"name": "Overwrite Test"}
        register_holdout_candidate(
            source_pcap_path=BENIGN_PCAP,
            candidate_id="test_unique_id",
            candidate_meta=meta_in,
            quarantine_dir=q_dir,
            check_dev_overlap=False,
        )

        # Attempt to register again under the same ID
        with pytest.raises(FileExistsError) as exc:
            register_holdout_candidate(
                source_pcap_path=BENIGN_PCAP,
                candidate_id="test_unique_id",
                candidate_meta=meta_in,
                quarantine_dir=q_dir,
                check_dev_overlap=False,
            )
        assert "already exists" in str(exc.value) and "Overwriting is prohibited" in str(exc.value)


def test_run_blind_holdout_evaluation_benign():
    """Verify single-pass blind holdout evaluation on benign traffic produces BENIGN_BASELINE_ZERO_ALERTS."""
    with tempfile.TemporaryDirectory() as q_dir, tempfile.TemporaryDirectory() as out_dir:
        q_pcap = _make_quarantined_pcap(BENIGN_PCAP, q_dir, "benign_holdout.pcap")
        candidate_meta = {
            "candidate_id": "holdout_benign_eval",
            "is_benign": True,
            "target_rules": ["FP_BENIGN"],
            "ground_truth_source": "Clean network traffic baseline",
        }
        report = run_blind_holdout_evaluation(
            pcap_path=q_pcap,
            candidate_meta=candidate_meta,
            output_dir=out_dir,
            strict_freeze=False,
            allow_dirty=True,
        )

        assert report["evaluation_type"] == "INDEPENDENT_BLIND_HOLDOUT"
        assert report["verdict_analysis"]["verdict"] == "BENIGN_BASELINE_ZERO_ALERTS"
        assert report["execution_metrics"]["total_alerts"] == 0
        assert report["execution_metrics"]["packets_processed"] > 0
        assert report["engine_freeze"]["engine_fingerprint"] is not None
        assert len(report["raw_alerts"]) == 0
        assert report["tamper_evident"] is True

        # Verify audit report file on disk is read-only
        report_files = [f for f in os.listdir(out_dir) if f.startswith("holdout_holdout_benign_eval_")]
        assert len(report_files) == 1
        report_path = os.path.join(out_dir, report_files[0])
        mode = os.stat(report_path).st_mode
        assert not bool(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def test_run_blind_holdout_evaluation_attack():
    """Verify single-pass blind holdout evaluation on attack traffic produces OBSERVATIONAL_UNASSESSED without granular GT."""
    with tempfile.TemporaryDirectory() as q_dir, tempfile.TemporaryDirectory() as out_dir:
        q_pcap = _make_quarantined_pcap(ATTACK_PCAP, q_dir, "attack_holdout.pcap")
        candidate_meta = {
            "candidate_id": "holdout_attack_eval",
            "is_benign": False,
            "target_rules": ["PORT_SCAN", "SYN_FLOOD"],
            "ground_truth_source": "Synthetic attack harness",
        }
        report = run_blind_holdout_evaluation(
            pcap_path=q_pcap,
            candidate_meta=candidate_meta,
            output_dir=out_dir,
            strict_freeze=False,
            allow_dirty=True,
        )

        assert report["verdict_analysis"]["verdict"] == "OBSERVATIONAL_UNASSESSED"
        assert report["verdict_analysis"]["capture_level_observation"]["observation_status"] == "TARGET_RULES_OBSERVED"
        assert report["verdict_analysis"]["capture_level_observation"]["target_rules_fired"] is True
        assert report["verdict_analysis"]["ground_truth_evaluation"]["has_granular_ground_truth"] is False
        assert report["execution_metrics"]["total_alerts"] > 0
        assert "PORT_SCAN" in report["execution_metrics"]["alerts_by_rule"] or "SYN_FLOOD" in report["execution_metrics"]["alerts_by_rule"]
        assert "capture_level_observation" in report["verdict_analysis"]

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

    with tempfile.TemporaryDirectory() as q_dir, tempfile.TemporaryDirectory() as out_dir:
        q_pcap = _make_quarantined_pcap(BENIGN_PCAP, q_dir)
        candidate_meta = {"candidate_id": "test_freeze_block", "is_benign": True}
        with pytest.raises(RuntimeError) as exc_info:
            run_blind_holdout_evaluation(
                pcap_path=q_pcap,
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
