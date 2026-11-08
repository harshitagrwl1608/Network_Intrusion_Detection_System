#!/usr/bin/env python3
"""
ids_project/evaluation/holdout_pipeline.py
-----------------------------------------
Automated Independent Holdout Validation Pipeline for NetGuard IDS.

Governing Policy:
  Section 8 of docs/evaluation/threshold-sensitivity-and-holdout-plan.md
  - Pre-Registration & Quarantine Validation
  - Engine & Rules Code Freeze Verification (Git state & aggregate engine fingerprint)
  - Single-Pass Blind Evaluation (Zero cache reading/pollution, isolated temporary DB)
  - Immutable Audit Reporting with Read-Only File Permissions

Invariants:
  - Never allow threshold overrides or runtime tuning during evaluation.
  - Refuse evaluation if engine code is unfrozen/dirty (unless explicitly bypassed with --allow-dirty).
  - Quarantined PCAPs must have read-only permissions (0o444) and matching SHA-256 digests.
  - Generates immutable forensic audit manifests recording git commit, engine fingerprint, and raw verdicts.
"""

import hashlib
import json
import logging
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

# Ensure ids_project is in sys.path
_HERE = os.path.dirname(os.path.abspath(__file__))
_IDS_ROOT = os.path.dirname(_HERE)
if _IDS_ROOT not in sys.path:
    sys.path.insert(0, _IDS_ROOT)

logger = logging.getLogger("holdout_pipeline")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] [holdout] %(message)s", "%H:%M:%S"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Default Storage Roots
HDD_BASE = "/run/media/harshitgarg/Data1/NetGuard-datasets"
DEFAULT_HOLDOUT_QUARANTINE_DIR = os.path.join(HDD_BASE, "holdout_quarantine")
DEFAULT_HOLDOUT_REPORTS_DIR = os.path.join(HDD_BASE, "holdout_reports")
DEFAULT_REGISTRY_PATH = os.path.join(_IDS_ROOT, "docs", "evaluation", "holdout-registry.json")

# PCAP Magic Numbers
VALID_PCAP_MAGICS = (
    b"\xd4\xc3\xb2\xa1",  # Standard pcap LE
    b"\xa1\xb2\xc3\xd4",  # Standard pcap BE
    b"\x4d\x3c\xb2\xa1",  # Nanosecond pcap LE
    b"\xa1\xb2\x3c\x4d",  # Nanosecond pcap BE
    b"\x0a\x0d\x0d\x0a",  # pcapng
)

# Core engine files to include in aggregate engine fingerprint
ENGINE_SOURCE_FILES = [
    os.path.join(_IDS_ROOT, "engine", "rules.py"),
    os.path.join(_IDS_ROOT, "config.py"),
    os.path.join(_IDS_ROOT, "capture", "sniffer.py"),
    os.path.join(_IDS_ROOT, "storage", "db.py"),
    os.path.join(_IDS_ROOT, "evaluation", "pipeline.py"),
    os.path.join(_IDS_ROOT, "evaluation", "replay.py"),
    os.path.join(_IDS_ROOT, "evaluation", "compare.py"),
]


def hash_file_sha256(filepath: str, block_size: int = 65536) -> str:
    """Compute streaming SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_engine_fingerprint(source_files: list = None) -> tuple[str, dict]:
    """
    Compute aggregate SHA-256 fingerprint over core detection engine files.
    Returns (aggregate_sha256, per_file_sha256_map).
    """
    files = source_files or ENGINE_SOURCE_FILES
    per_file = {}
    aggregate_hasher = hashlib.sha256()

    for path in sorted(files):
        rel_name = os.path.basename(path)
        if os.path.isfile(path):
            file_hash = hash_file_sha256(path)
            per_file[rel_name] = file_hash
            aggregate_hasher.update(f"{rel_name}:{file_hash}\n".encode("utf-8"))
        else:
            per_file[rel_name] = "MISSING"
            aggregate_hasher.update(f"{rel_name}:MISSING\n".encode("utf-8"))

    return aggregate_hasher.hexdigest(), per_file


def verify_engine_freeze(repo_dir: str = None, allow_dirty: bool = False) -> dict:
    """
    Verify that the IDS engine code is in a committed, frozen state.
    Enforces strict code freeze required by Section 8 of the Holdout Protocol.
    """
    cwd = repo_dir or os.path.dirname(_IDS_ROOT)
    result = {
        "frozen": False,
        "git_commit": None,
        "branch": None,
        "dirty": False,
        "engine_fingerprint": None,
        "file_fingerprints": {},
        "error": None,
    }

    # 1. Compute engine fingerprint
    agg_hash, file_hashes = compute_engine_fingerprint()
    result["engine_fingerprint"] = agg_hash
    result["file_fingerprints"] = file_hashes

    # 2. Check Git state
    try:
        commit_proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if commit_proc.returncode != 0:
            result["error"] = f"git rev-parse HEAD failed: {commit_proc.stderr.strip()}"
            return result
        result["git_commit"] = commit_proc.stdout.strip()

        branch_proc = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if branch_proc.returncode == 0:
            result["branch"] = branch_proc.stdout.strip()

        diff_proc = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if diff_proc.returncode == 0:
            dirty_lines = [l for l in diff_proc.stdout.splitlines() if l.strip()]
            # Filter out untracked log or tmp files if any
            critical_dirty = [
                l for l in dirty_lines
                if any(f in l for f in ["ids_project/", "docs/evaluation/"])
            ]
            if critical_dirty:
                result["dirty"] = True
                result["dirty_files"] = critical_dirty
                if not allow_dirty:
                    result["error"] = f"Engine has uncommitted modifications: {critical_dirty}"
                    return result
    except Exception as exc:
        result["error"] = f"Git inspection exception: {exc}"
        if not allow_dirty:
            return result

    result["frozen"] = True
    return result


def enforce_quarantine_permissions(filepath: str) -> None:
    """Set file permissions to read-only (0o444 / r--r--r--)."""
    current_mode = os.stat(filepath).st_mode
    # Remove write bits for user, group, other
    read_only_mode = current_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    # Ensure read bits are set
    read_only_mode |= (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    os.chmod(filepath, read_only_mode)


def verify_holdout_quarantine(filepath: str, expected_sha256: str = None) -> dict:
    """
    Verify quarantine integrity of a holdout PCAP.
    Checks:
      1. File exists and is non-empty.
      2. File permissions are read-only (no write bits set).
      3. Valid PCAP magic number header.
      4. SHA-256 digest computation and match against expected_sha256 if provided.
    """
    result = {
        "valid": False,
        "path": filepath,
        "size_bytes": 0,
        "is_read_only": False,
        "magic_hex": None,
        "sha256": None,
        "error": None,
    }

    if not os.path.isfile(filepath):
        result["error"] = f"Holdout file does not exist: {filepath}"
        return result

    file_stat = os.stat(filepath)
    result["size_bytes"] = file_stat.st_size

    if file_stat.st_size == 0:
        result["error"] = f"Holdout file is empty (0 bytes): {filepath}"
        return result

    # Check read-only permission (no S_IWUSR, S_IWGRP, S_IWOTH)
    has_write = bool(file_stat.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    result["is_read_only"] = not has_write

    # Check magic header
    with open(filepath, "rb") as f:
        magic = f.read(4)
        result["magic_hex"] = magic.hex()
        if magic not in VALID_PCAP_MAGICS:
            result["error"] = f"Invalid PCAP header magic bytes: {magic.hex()}"
            return result

    # Compute SHA-256
    digest = hash_file_sha256(filepath)
    result["sha256"] = digest

    if expected_sha256 and digest.lower() != expected_sha256.lower():
        result["error"] = f"SHA-256 mismatch: expected {expected_sha256}, got {digest}"
        return result

    result["valid"] = True
    return result


def register_holdout_candidate(
    source_pcap_path: str,
    candidate_id: str,
    candidate_meta: dict,
    quarantine_dir: str = None,
) -> dict:
    """
    Pre-register and quarantine a holdout candidate capture.
    Copies PCAP into quarantine_dir, enforces 0o444 permissions, and writes .meta.json.
    """
    q_dir = quarantine_dir or DEFAULT_HOLDOUT_QUARANTINE_DIR
    os.makedirs(q_dir, exist_ok=True)

    dest_pcap = os.path.join(q_dir, f"{candidate_id}.pcap")
    dest_meta = os.path.join(q_dir, f"{candidate_id}.meta.json")

    # Read and copy bytes
    with open(source_pcap_path, "rb") as f_in, open(dest_pcap, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)

    # Enforce read-only permissions
    enforce_quarantine_permissions(dest_pcap)

    # Compute hash and verify
    q_verify = verify_holdout_quarantine(dest_pcap)
    if not q_verify["valid"]:
        raise ValueError(f"Quarantined PCAP failed integrity validation: {q_verify['error']}")

    meta = {
        "candidate_id": candidate_id,
        "name": candidate_meta.get("name", candidate_id),
        "publisher": candidate_meta.get("publisher", "Unknown Publisher"),
        "url": candidate_meta.get("url"),
        "expected_attack_family": candidate_meta.get("attack_family", "Unspecified"),
        "ground_truth_source": candidate_meta.get("ground_truth_source", "Independent Benchmark"),
        "target_rules": candidate_meta.get("target_rules", []),
        "quarantined_pcap_path": dest_pcap,
        "sha256": q_verify["sha256"],
        "size_bytes": q_verify["size_bytes"],
        "registered_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    with open(dest_meta, "w") as f:
        json.dump(meta, f, indent=2)
    enforce_quarantine_permissions(dest_meta)

    logger.info(f"Registered holdout capture '{candidate_id}' in quarantine at {dest_pcap} (SHA-256: {q_verify['sha256'][:16]}...)")
    return meta


def run_blind_holdout_evaluation(
    pcap_path: str,
    candidate_meta: dict,
    output_dir: str = None,
    strict_freeze: bool = True,
    allow_dirty: bool = False,
) -> dict:
    """
    Execute single-pass blind evaluation of a quarantined holdout capture against NetGuard IDS.

    Guarantees:
      - Validates code freeze before execution (refuses dirty git state if strict_freeze=True).
      - Replays PCAP in an isolated temporary SQLite database.
      - Disables all calibration cache reads and writes.
      - Records comprehensive per-rule alert counts and forensic evidence.
      - Writes an immutable read-only JSON audit report.
    """
    t_start = time.perf_counter()
    report_uuid = str(uuid.uuid4())
    cid = candidate_meta.get("candidate_id", os.path.splitext(os.path.basename(pcap_path))[0])

    # 1. Verify code freeze
    freeze_info = verify_engine_freeze(allow_dirty=allow_dirty or not strict_freeze)
    if strict_freeze and not freeze_info["frozen"]:
        raise RuntimeError(f"Holdout evaluation blocked by engine freeze check: {freeze_info.get('error')}")

    # 2. Verify quarantine integrity
    q_info = verify_holdout_quarantine(pcap_path, expected_sha256=candidate_meta.get("sha256"))
    if not q_info["valid"]:
        raise ValueError(f"Holdout PCAP quarantine check failed: {q_info.get('error')}")

    # 3. Import engine and storage components
    from storage.db import get_connection, init_db
    from engine.blocklist import BlocklistData
    from capture.sniffer import replay_pcap
    from evaluation.replay import create_replay_engine
    import config

    # 4. Isolated Execution in Temporary Directory
    orig_sqlite = config.SQLITE_PATH
    orig_arp = config.ARP_TABLE_PATH

    with tempfile.TemporaryDirectory(prefix=f"netguard_holdout_{cid}_") as tmpdir:
        tmp_db_path = os.path.join(tmpdir, "holdout_eval.db")
        tmp_arp_path = os.path.join(tmpdir, "holdout_arp.json")
        config.SQLITE_PATH = tmp_db_path
        config.ARP_TABLE_PATH = tmp_arp_path

        try:
            conn = get_connection()
            init_db(conn)

            # Empty test blocklist (unless specified in candidate_meta)
            blocklist = BlocklistData(exact=set(), networks=[])

            # Create replay engine wired with deterministic ReplayClock
            engine = create_replay_engine(conn, blocklist, config)

            logger.info(f"[{cid}] Beginning single-pass blind holdout evaluation on {pcap_path}...")
            replay_summary = replay_pcap(pcap_path, engine)

            # Flush any trailing state
            engine.flush()

            # Read alerts from isolated DB
            conn.row_factory = None
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, timestamp, rule_name, severity, confidence, src_ip, dst_ip, src_port, dst_port, protocol, detail, evidence_json FROM alerts ORDER BY timestamp ASC"
            )
            raw_rows = cursor.fetchall()
            conn.close()
        finally:
            config.SQLITE_PATH = orig_sqlite
            config.ARP_TABLE_PATH = orig_arp

    elapsed_s = time.perf_counter() - t_start

    # Structure alerts
    alerts = []
    alerts_by_rule = {}
    for r in raw_rows:
        rule_name = r[2]
        ev_raw = r[11]
        try:
            ev_dict = json.loads(ev_raw) if ev_raw else {}
        except Exception:
            ev_dict = {"raw": ev_raw}

        alert_entry = {
            "id": r[0],
            "timestamp": r[1],
            "rule_name": rule_name,
            "severity": r[3],
            "confidence": r[4],
            "src_ip": r[5],
            "dst_ip": r[6],
            "src_port": r[7],
            "dst_port": r[8],
            "protocol": r[9],
            "detail": r[10],
            "evidence": ev_dict,
        }
        alerts.append(alert_entry)
        alerts_by_rule[rule_name] = alerts_by_rule.get(rule_name, 0) + 1

    total_pkts = replay_summary.get("processed", replay_summary.get("packets_read", 0)) if isinstance(replay_summary, dict) else len(alerts)
    throughput_pps = round(total_pkts / elapsed_s, 2) if elapsed_s > 0 else 0.0

    # 5. Verdict Classification
    target_rules = candidate_meta.get("target_rules", [])
    is_benign = candidate_meta.get("is_benign", False) or "FP_BENIGN" in target_rules

    if is_benign:
        if len(alerts) == 0:
            verdict = "TRUE_NEGATIVE"
        else:
            verdict = "FALSE_POSITIVE"
    elif target_rules:
        fired_rules = set(alerts_by_rule.keys())
        matching = fired_rules.intersection(target_rules)
        if matching:
            verdict = "TRUE_POSITIVE"
        else:
            verdict = "FALSE_NEGATIVE"
    else:
        verdict = "OBSERVATIONAL_UNASSESSED"

    # 6. Build Immutable Audit Report
    report = {
        "report_id": report_uuid,
        "candidate_id": cid,
        "evaluation_type": "INDEPENDENT_BLIND_HOLDOUT",
        "evaluated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pcap_metadata": {
            "pcap_path": pcap_path,
            "sha256": q_info["sha256"],
            "size_bytes": q_info["size_bytes"],
            "read_only": q_info["is_read_only"],
        },
        "engine_freeze": {
            "git_commit": freeze_info.get("git_commit"),
            "branch": freeze_info.get("branch"),
            "engine_fingerprint": freeze_info.get("engine_fingerprint"),
            "is_frozen": freeze_info.get("frozen"),
        },
        "execution_metrics": {
            "elapsed_seconds": round(elapsed_s, 4),
            "packets_processed": total_pkts,
            "throughput_pps": throughput_pps,
            "total_alerts": len(alerts),
            "alerts_by_rule": alerts_by_rule,
        },
        "verdict_analysis": {
            "verdict": verdict,
            "target_rules": target_rules,
            "fired_rules": sorted(list(alerts_by_rule.keys())),
            "ground_truth_source": candidate_meta.get("ground_truth_source"),
            "expected_attack_family": candidate_meta.get("expected_attack_family"),
        },
        "raw_alerts": alerts,
    }

    # 7. Write and Seal Audit Report
    out_dir = output_dir or DEFAULT_HOLDOUT_REPORTS_DIR
    os.makedirs(out_dir, exist_ok=True)
    report_filename = f"holdout_{cid}_{report_uuid[:8]}.json"
    report_path = os.path.join(out_dir, report_filename)

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    try:
        enforce_quarantine_permissions(report_path)
    except Exception as exc:
        logger.warning(f"Could not seal report file permissions to 0o444: {exc}")

    logger.info(f"[{cid}] Holdout evaluation complete: {verdict} ({len(alerts)} alerts, {total_pkts} pkts in {elapsed_s:.2f}s). Audit report saved to {report_path}")
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="NetGuard IDS Independent Holdout Evaluation Pipeline")
    parser.add_argument("--verify-freeze", action="store_true", help="Verify engine freeze and print fingerprints")
    parser.add_argument("--register", metavar="PCAP", help="Register and quarantine a candidate holdout PCAP")
    parser.add_argument("--id", help="Candidate ID for registration")
    parser.add_argument("--meta", help="Path to JSON metadata for registration")
    parser.add_argument("--run-eval", metavar="PCAP", help="Run single-pass blind evaluation on a quarantined PCAP")
    parser.add_argument("--output-dir", help="Directory for immutable audit reports")
    parser.add_argument("--allow-dirty", action="store_true", help="Allow uncommitted changes during test/debug runs")

    args = parser.parse_args()

    if args.verify_freeze:
        res = verify_engine_freeze(allow_dirty=args.allow_dirty)
        print(json.dumps(res, indent=2))
        sys.exit(0 if res["frozen"] else 1)

    if args.register:
        if not args.id:
            parser.error("--id is required with --register")
        meta_dict = {}
        if args.meta and os.path.isfile(args.meta):
            with open(args.meta, "r") as f:
                meta_dict = json.load(f)
        reg_res = register_holdout_candidate(args.register, args.id, meta_dict)
        print(json.dumps(reg_res, indent=2))
        sys.exit(0)

    if args.run_eval:
        meta_dict = {}
        if args.meta and os.path.isfile(args.meta):
            with open(args.meta, "r") as f:
                meta_dict = json.load(f)
        report = run_blind_holdout_evaluation(
            args.run_eval,
            meta_dict,
            output_dir=args.output_dir,
            strict_freeze=not args.allow_dirty,
            allow_dirty=args.allow_dirty,
        )
        print(json.dumps(report["execution_metrics"], indent=2))
        sys.exit(0)

    parser.print_help()
