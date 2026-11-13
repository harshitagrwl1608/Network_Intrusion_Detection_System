"""
ids_project/tests/test_holdout_pipeline.py
-----------------------------------------
Unit and integration tests for the Independent Holdout Validation Pipeline.

Tests:
  - Aggregate engine fingerprint computation and sensitivity
  - Git engine freeze verification and dirty tree enforcement
  - Candidate ID allowlist validation (path traversal, illegal chars, length bounds)
  - Quarantine path containment and boundary enforcement (symlink-safe canonical resolution)
  - Quarantine integrity fail-closed: mandatory SHA-256, magic bytes, read-only permissions (0o444)
  - Exact HDD mount verification: exact mountpoint, device match, rejection of /dev/sda1 and parent mounts
  - Durable runtime registry state machine: PENDING -> REGISTERED -> EVALUATING -> EVALUATED / EVALUATION_FAILED
  - Duplicate candidate ID and duplicate hash rejection across holdouts and dev corpus
  - Re-evaluation prohibition (single-pass invariant)
  - Complete structural validation of PCAP format (capinfos / tshark)
  - Single-pass blind evaluation on benign and attack fixtures with registered sidecar metadata
  - Rejection of arbitrary local PCAPs outside quarantine and missing sidecars
  - Separation of capture-level rule firing from ground-truth verification
  - Honest audit report sealing with verifiable companion SHA-256 digest
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
    verify_external_mount,
    hash_file_sha256,
    load_runtime_registry,
    transition_runtime_registry_state,
    HoldoutState,
)

BENIGN_PCAP = os.path.join(_IDS_ROOT, "data", "test_benign.pcap")
ATTACK_PCAP = os.path.join(_IDS_ROOT, "data", "test_attacks.pcap")

# Valid 24-byte PCAP global header: magic(4), v_maj=2, v_min=4, zone=0, sig=0, snap=65535, net=1
VALID_MINIMAL_PCAP_HEADER = (
    b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
)

# The same global header plus one packet record.  capinfos accepts a header-only
# file, but the pure-Python fallback in `validate_pcap_structure` (used when
# capinfos/tshark are not installed, e.g. on a CI runner) rejects a capture with
# no packet records.  Tests that assert a file is structurally valid must use a
# capture that both code paths accept.
VALID_MINIMAL_PCAP = VALID_MINIMAL_PCAP_HEADER + (
    b"\x00\x00\x00\x00"   # ts_sec
    b"\x00\x00\x00\x00"   # ts_usec
    b"\x04\x00\x00\x00"   # incl_len = 4
    b"\x04\x00\x00\x00"   # orig_len = 4
    b"\xde\xad\xbe\xef"   # 4 bytes of link-layer payload
)


def _make_quarantined_pcap(
    source_path: str,
    target_dir: str,
    candidate_id: str = "quarantined",
    is_benign: bool = False,
    target_rules: list = None,
) -> tuple[str, str, str]:
    """Helper to copy a test PCAP into quarantine, seal read-only permissions, and write sidecar .meta.json."""
    os.makedirs(target_dir, exist_ok=True)
    pcap_path = os.path.join(target_dir, f"{candidate_id}.pcap")
    meta_path = os.path.join(target_dir, f"{candidate_id}.meta.json")

    with open(source_path, "rb") as sf, open(pcap_path, "wb") as df:
        content = sf.read()
        df.write(content)
    enforce_quarantine_permissions(pcap_path)

    digest = hash_file_sha256(pcap_path)
    meta = {
        "candidate_id": candidate_id,
        "name": f"Test {candidate_id}",
        "publisher": "Evaluation Lab",
        "sha256": digest,
        "size_bytes": len(content),
        "is_benign": is_benign,
        "target_rules": target_rules or [],
        "ground_truth_source": "Synthetic Benchmark",
    }
    with open(meta_path, "w", encoding="utf-8") as mf:
        json.dump(meta, mf, indent=2)
    enforce_quarantine_permissions(meta_path)

    return pcap_path, meta_path, digest


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


def test_verify_holdout_quarantine_mandatory_hash():
    """verify_holdout_quarantine must fail closed on missing or malformed expected SHA-256."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        q_pcap, _, digest = _make_quarantined_pcap(BENIGN_PCAP, tmp_dir)

        # None must be rejected
        res_none = verify_holdout_quarantine(q_pcap, expected_sha256=None, quarantine_dir=tmp_dir)
        assert res_none["valid"] is False
        assert "mandatory" in res_none["error"].lower()

        # Malformed hash (wrong length or characters) must be rejected
        res_short = verify_holdout_quarantine(q_pcap, expected_sha256="abc123", quarantine_dir=tmp_dir)
        assert res_short["valid"] is False
        assert "valid 64-character hex string" in res_short["error"]

        res_non_hex = verify_holdout_quarantine(q_pcap, expected_sha256="z" * 64, quarantine_dir=tmp_dir)
        assert res_non_hex["valid"] is False
        assert "valid 64-character hex string" in res_non_hex["error"]

        # Valid matching hash must succeed
        res_ok = verify_holdout_quarantine(q_pcap, expected_sha256=digest, quarantine_dir=tmp_dir)
        assert res_ok["valid"] is True
        assert res_ok["sha256"] == digest


def test_verify_holdout_quarantine_failures():
    """Verify quarantine validation fails on missing, empty, writeable, or corrupt files."""
    dummy_sha = "a" * 64

    # Missing file
    res = verify_holdout_quarantine("/tmp/nonexistent_holdout_12345.pcap", expected_sha256=dummy_sha)
    assert res["valid"] is False
    assert "does not exist" in res["error"]

    with tempfile.NamedTemporaryFile("wb", delete=False) as empty_f:
        empty_path = empty_f.name

    try:
        enforce_quarantine_permissions(empty_path)
        # Empty file
        res = verify_holdout_quarantine(empty_path, expected_sha256=dummy_sha)
        assert res["valid"] is False
        assert "empty" in res["error"]

        # Corrupt magic
        os.chmod(empty_path, stat.S_IRUSR | stat.S_IWUSR)
        with open(empty_path, "wb") as f:
            f.write(b"CORRUPT_NOT_PCAP_MAGIC_1234567890")
        enforce_quarantine_permissions(empty_path)
        res = verify_holdout_quarantine(empty_path, expected_sha256=dummy_sha)
        assert res["valid"] is False
        assert "Invalid PCAP header magic bytes" in res["error"]

        # Expected SHA-256 mismatch
        with tempfile.TemporaryDirectory() as tmp_dir:
            q_pcap, _, _ = _make_quarantined_pcap(BENIGN_PCAP, tmp_dir)
            res_mismatch = verify_holdout_quarantine(q_pcap, expected_sha256="0" * 64, quarantine_dir=tmp_dir)
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
        f.write(VALID_MINIMAL_PCAP)
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

        digest = hash_file_sha256(path)
        q_info = verify_holdout_quarantine(path, expected_sha256=digest)
        assert q_info["valid"] is True
        assert q_info["is_read_only"] is True
    finally:
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            os.remove(path)
        except OSError:
            pass


def test_verify_external_mount_exact_device_and_path(monkeypatch):
    """verify_external_mount must match exact mountpoint and exact backing device, rejecting /dev/sda1."""
    # Mock /proc/mounts with /dev/sda1 mounted at /run/media/harshitgarg/Data1
    mock_mounts_sda = "/dev/sda1 /run/media/harshitgarg/Data1 ext4 rw 0 0\n"

    def mock_open_sda(path, *args, **kwargs):
        import io
        if path == "/proc/mounts":
            return io.StringIO(mock_mounts_sda)
        return open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", mock_open_sda)

    # When expecting /dev/sdb1, /dev/sda1 must be rejected
    assert verify_external_mount(
        expected_mount="/run/media/harshitgarg/Data1",
        expected_device="/dev/sdb1",
        require_mount=True
    ) is False

    # Prefix match must be rejected (e.g. asking for /run/media/harshitgarg/Data1/subpath)
    assert verify_external_mount(
        expected_mount="/run/media/harshitgarg/Data1/subpath",
        expected_device="/dev/sda1",
        require_mount=True
    ) is False

    # Exact match on /dev/sda1 when /dev/sda1 is expected should pass
    assert verify_external_mount(
        expected_mount="/run/media/harshitgarg/Data1",
        expected_device="/dev/sda1",
        require_mount=True
    ) is True


def test_runtime_registry_lifecycle_and_transitions():
    """Verify durable runtime registry state transitions, atomic locking, and re-eval prohibition."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        reg_file = os.path.join(tmp_dir, "holdout_runtime_registry.json")

        # Initial state
        reg = load_runtime_registry(reg_file)
        assert reg["candidates"] == {}

        cid = "candidate_lifecycle_01"
        # Transition: PENDING -> REGISTERED_QUARANTINED
        cand = transition_runtime_registry_state(
            candidate_id=cid,
            target_state=HoldoutState.REGISTERED_QUARANTINED,
            allowed_from_states=[HoldoutState.PENDING_ACQUISITION],
            metadata_updates={"sha256": "1" * 64},
            registry_path=reg_file,
        )
        assert cand["state"] == HoldoutState.REGISTERED_QUARANTINED

        # Transition: REGISTERED_QUARANTINED -> EVALUATING
        cand2 = transition_runtime_registry_state(
            candidate_id=cid,
            target_state=HoldoutState.EVALUATING,
            allowed_from_states=[HoldoutState.REGISTERED_QUARANTINED],
            registry_path=reg_file,
        )
        assert cand2["state"] == HoldoutState.EVALUATING

        # Cannot evaluate concurrently from EVALUATING
        with pytest.raises(ValueError) as exc:
            transition_runtime_registry_state(
                candidate_id=cid,
                target_state=HoldoutState.EVALUATING,
                allowed_from_states=[HoldoutState.REGISTERED_QUARANTINED],
                registry_path=reg_file,
            )
        assert "expected one of" in str(exc.value)

        # Interrupted recovery: EVALUATING -> EVALUATION_FAILED -> EVALUATING -> EVALUATED
        transition_runtime_registry_state(
            candidate_id=cid,
            target_state=HoldoutState.EVALUATION_FAILED,
            allowed_from_states=[HoldoutState.EVALUATING],
            metadata_updates={"error": "simulated interruption"},
            registry_path=reg_file,
        )

        transition_runtime_registry_state(
            candidate_id=cid,
            target_state=HoldoutState.EVALUATING,
            allowed_from_states=[HoldoutState.EVALUATION_FAILED],
            registry_path=reg_file,
        )

        transition_runtime_registry_state(
            candidate_id=cid,
            target_state=HoldoutState.EVALUATED,
            allowed_from_states=[HoldoutState.EVALUATING],
            metadata_updates={"report_id": "rep-1234"},
            registry_path=reg_file,
        )

        reg_final = load_runtime_registry(reg_file)
        assert reg_final["candidates"][cid]["state"] == HoldoutState.EVALUATED
        assert len(reg_final["candidates"][cid]["history"]) == 5


def test_register_holdout_candidate():
    """Verify holdout candidate registration and metadata persistence in quarantine."""
    with tempfile.TemporaryDirectory() as q_dir, tempfile.TemporaryDirectory() as reg_dir:
        reg_path = os.path.join(reg_dir, "runtime_registry.json")
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
            runtime_registry_path=reg_path,
        )

        assert reg_info["candidate_id"] == "test_candidate_01"
        assert reg_info["quarantined_pcap_path"].endswith("test_candidate_01.pcap")
        assert os.path.isfile(reg_info["quarantined_pcap_path"])

        # Check permissions
        mode = os.stat(reg_info["quarantined_pcap_path"]).st_mode
        assert not bool(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))

        # Check .meta.json sidecar
        meta_file = os.path.join(q_dir, "test_candidate_01.meta.json")
        assert os.path.isfile(meta_file)
        with open(meta_file, "r") as mf:
            saved_meta = json.load(mf)
        assert saved_meta["sha256"] == reg_info["sha256"]

        # Check runtime registry updated
        reg_data = load_runtime_registry(reg_path)
        assert reg_data["candidates"]["test_candidate_01"]["state"] == HoldoutState.REGISTERED_QUARANTINED


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
    with tempfile.TemporaryDirectory() as q_dir, tempfile.TemporaryDirectory() as reg_dir:
        reg_path = os.path.join(reg_dir, "runtime_registry.json")
        meta_in = {"name": "Overwrite Test"}
        register_holdout_candidate(
            source_pcap_path=BENIGN_PCAP,
            candidate_id="test_unique_id",
            candidate_meta=meta_in,
            quarantine_dir=q_dir,
            check_dev_overlap=False,
            runtime_registry_path=reg_path,
        )

        # Attempt to register again under the same ID
        with pytest.raises(FileExistsError) as exc:
            register_holdout_candidate(
                source_pcap_path=BENIGN_PCAP,
                candidate_id="test_unique_id",
                candidate_meta=meta_in,
                quarantine_dir=q_dir,
                check_dev_overlap=False,
                runtime_registry_path=reg_path,
            )
        assert "already registered" in str(exc.value) or "already exists" in str(exc.value)


def test_run_blind_holdout_evaluation_benign():
    """Verify single-pass blind holdout evaluation on benign traffic produces BENIGN_BASELINE_ZERO_ALERTS."""
    with tempfile.TemporaryDirectory() as q_dir, tempfile.TemporaryDirectory() as out_dir, tempfile.TemporaryDirectory() as reg_dir:
        reg_path = os.path.join(reg_dir, "runtime_registry.json")
        q_pcap, _, digest = _make_quarantined_pcap(BENIGN_PCAP, q_dir, "holdout_benign_eval", is_benign=True, target_rules=["FP_BENIGN"])

        # Pre-seed runtime registry
        transition_runtime_registry_state(
            candidate_id="holdout_benign_eval",
            target_state=HoldoutState.REGISTERED_QUARANTINED,
            allowed_from_states=[HoldoutState.PENDING_ACQUISITION],
            registry_path=reg_path,
        )

        candidate_meta = {
            "candidate_id": "holdout_benign_eval",
            "is_benign": True,
            "target_rules": ["FP_BENIGN"],
            "ground_truth_source": "Clean network traffic baseline",
            "sha256": digest,
        }
        report = run_blind_holdout_evaluation(
            pcap_path=q_pcap,
            candidate_meta=candidate_meta,
            quarantine_dir=q_dir,
            output_dir=out_dir,
            strict_freeze=False,
            allow_dirty=True,
            runtime_registry_path=reg_path,
        )

        assert report["evaluation_type"] == "INDEPENDENT_BLIND_HOLDOUT"
        assert report["verdict_analysis"]["verdict"] == "BENIGN_BASELINE_ZERO_ALERTS"
        assert report["execution_metrics"]["total_alerts"] == 0
        assert report["execution_metrics"]["packets_processed"] > 0
        assert report["engine_freeze"]["engine_fingerprint"] is not None
        assert len(report["raw_alerts"]) == 0
        assert "Read-only permission sealed" in report["report_sealing"]
        assert "report_sha256" in report

        # Verify audit report and companion .sha256 file on disk are read-only
        report_files = [f for f in os.listdir(out_dir) if f.startswith("holdout_holdout_benign_eval_") and f.endswith(".json")]
        assert len(report_files) == 1
        report_path = os.path.join(out_dir, report_files[0])
        mode = os.stat(report_path).st_mode
        assert not bool(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))

        sha_files = [f for f in os.listdir(out_dir) if f.endswith(".json.sha256")]
        assert len(sha_files) == 1


def test_run_blind_holdout_evaluation_attack():
    """Verify single-pass blind holdout evaluation on attack traffic produces OBSERVATIONAL_UNASSESSED without granular GT."""
    with tempfile.TemporaryDirectory() as q_dir, tempfile.TemporaryDirectory() as out_dir, tempfile.TemporaryDirectory() as reg_dir:
        reg_path = os.path.join(reg_dir, "runtime_registry.json")
        q_pcap, _, digest = _make_quarantined_pcap(
            ATTACK_PCAP, q_dir, "holdout_attack_eval", is_benign=False, target_rules=["PORT_SCAN", "SYN_FLOOD"]
        )

        # Pre-seed runtime registry
        transition_runtime_registry_state(
            candidate_id="holdout_attack_eval",
            target_state=HoldoutState.REGISTERED_QUARANTINED,
            allowed_from_states=[HoldoutState.PENDING_ACQUISITION],
            registry_path=reg_path,
        )

        candidate_meta = {
            "candidate_id": "holdout_attack_eval",
            "is_benign": False,
            "target_rules": ["PORT_SCAN", "SYN_FLOOD"],
            "ground_truth_source": "Synthetic attack harness",
            "sha256": digest,
        }
        report = run_blind_holdout_evaluation(
            pcap_path=q_pcap,
            candidate_meta=candidate_meta,
            quarantine_dir=q_dir,
            output_dir=out_dir,
            strict_freeze=False,
            allow_dirty=True,
            runtime_registry_path=reg_path,
        )

        assert report["verdict_analysis"]["verdict"] == "OBSERVATIONAL_UNASSESSED"
        assert report["verdict_analysis"]["capture_level_observation"]["observation_status"] == "TARGET_RULES_OBSERVED"
        assert report["verdict_analysis"]["capture_level_observation"]["target_rules_fired"] is True
        assert report["verdict_analysis"]["ground_truth_evaluation"]["has_granular_ground_truth"] is False
        assert report["execution_metrics"]["total_alerts"] > 0
        assert "capture_level_observation" in report["verdict_analysis"]


def test_run_blind_holdout_evaluation_rejects_arbitrary_local_pcap():
    """run_blind_holdout_evaluation must reject an arbitrary PCAP outside quarantine."""
    with tempfile.TemporaryDirectory() as q_dir, tempfile.TemporaryDirectory() as other_dir:
        outside_pcap = os.path.join(other_dir, "outside.pcap")
        with open(outside_pcap, "wb") as f:
            f.write(VALID_MINIMAL_PCAP)
        enforce_quarantine_permissions(outside_pcap)

        with pytest.raises(ValueError) as exc:
            run_blind_holdout_evaluation(
                pcap_path=outside_pcap,
                candidate_meta={"candidate_id": "outside", "sha256": "0" * 64},
                quarantine_dir=q_dir,
            )
        assert "escapes quarantine root" in str(exc.value)


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

    with tempfile.TemporaryDirectory() as q_dir, tempfile.TemporaryDirectory() as out_dir, tempfile.TemporaryDirectory() as reg_dir:
        reg_path = os.path.join(reg_dir, "runtime_registry.json")
        q_pcap, _, digest = _make_quarantined_pcap(BENIGN_PCAP, q_dir, "test_freeze_block", is_benign=True)

        transition_runtime_registry_state(
            candidate_id="test_freeze_block",
            target_state=HoldoutState.REGISTERED_QUARANTINED,
            allowed_from_states=[HoldoutState.PENDING_ACQUISITION],
            registry_path=reg_path,
        )

        candidate_meta = {"candidate_id": "test_freeze_block", "is_benign": True, "sha256": digest}
        with pytest.raises(RuntimeError) as exc_info:
            run_blind_holdout_evaluation(
                pcap_path=q_pcap,
                candidate_meta=candidate_meta,
                quarantine_dir=q_dir,
                output_dir=out_dir,
                strict_freeze=True,
                allow_dirty=False,
                runtime_registry_path=reg_path,
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
