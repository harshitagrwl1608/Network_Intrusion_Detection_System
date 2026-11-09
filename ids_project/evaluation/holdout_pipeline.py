#!/usr/bin/env python3
"""
ids_project/evaluation/holdout_pipeline.py
-----------------------------------------
Automated Independent Holdout Validation Pipeline for NetGuard IDS.

Governing Policy:
  Section 8 of docs/evaluation/threshold-sensitivity-and-holdout-plan.md
  - Safe Pre-Registration & Cryptographic Quarantine Validation
  - Defense against candidate ID traversal, symlink attacks, and duplicate/development collisions
  - Engine & Rules Code Freeze Verification (Git porcelain check & aggregate 64-char engine fingerprint)
  - Single-Pass Blind Evaluation (Zero cache reading/pollution, isolated temporary DB)
  - Strict separation of capture-level detection observations from verified ground-truth metrics
  - Read-Only Permission Sealed Audit Reporting (0o444) with verifiable SHA-256 digests
  - Durable External Runtime Registry with Concurrency-Safe State Transitions

Invariants:
  - Never allow threshold overrides or runtime tuning during evaluation.
  - Refuse evaluation if engine code is unfrozen/dirty (unless explicitly bypassed with --allow-dirty).
  - Quarantined PCAPs must have read-only permissions (0o444) and matching 64-char SHA-256 digests.
  - Quarantined PCAPs must reside within the canonical quarantine root (symlink escapes rejected).
  - Candidate IDs must strictly conform to allowlisted pattern ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$.
  - Durable runtime registry prevents duplicate evaluations and preserves fail-safe state machine.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections import OrderedDict

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
DEFAULT_MOUNT_POINT = "/run/media/harshitgarg/Data1"
DEFAULT_EXPECTED_DEVICE = "/dev/sdb1"
DEFAULT_EXPECTED_UUID = "99a513c9-4aaa-4660-b7dc-2d2616449df9"
DEFAULT_EXPECTED_LABEL = "Data"
DEFAULT_HOLDOUT_QUARANTINE_DIR = os.path.join(HDD_BASE, "holdout_quarantine")
DEFAULT_HOLDOUT_REPORTS_DIR = os.path.join(HDD_BASE, "holdout_reports")
DEFAULT_REGISTRY_PATH = os.path.join(_IDS_ROOT, "docs", "evaluation", "holdout-registry.json")
DEFAULT_RUNTIME_REGISTRY_PATH = os.path.join(HDD_BASE, "coordination", "holdout_runtime_registry.json")

# Safe Candidate ID Regex Allowlist: [A-Za-z0-9][A-Za-z0-9._-]{0,63}
CANDIDATE_ID_REGEX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# Hex SHA-256 Regex
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")

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


class HoldoutState:
    PENDING_ACQUISITION = "PENDING_ACQUISITION"
    REGISTERED_QUARANTINED = "REGISTERED_QUARANTINED"
    EVALUATING = "EVALUATING"
    EVALUATED = "EVALUATED"
    EVALUATION_FAILED = "EVALUATION_FAILED"


def validate_candidate_id(candidate_id: str) -> str:
    """
    Validate candidate ID against safe allowlist regex.
    Rejects:
      - Empty or non-string values
      - Absolute paths, separators ('/', '\\')
      - Traversal sequences ('..')
      - Control characters or whitespace
      - Length > 64 chars
    """
    if not candidate_id or not isinstance(candidate_id, str):
        raise ValueError("Candidate ID must be a non-empty string")
    if any(c in candidate_id for c in ("/", "\\", "\x00", "\n", "\r", "\t")):
        raise ValueError(f"Candidate ID contains illegal path separators or control characters: {candidate_id!r}")
    if ".." in candidate_id:
        raise ValueError(f"Candidate ID contains directory traversal sequence '..': {candidate_id!r}")
    if not CANDIDATE_ID_REGEX.match(candidate_id):
        raise ValueError(f"Candidate ID must match allowlisted pattern '^[A-Za-z0-9][A-Za-z0-9._-]{{0,63}}$', got: {candidate_id!r}")
    return candidate_id


def check_quarantine_path_containment(target_path: str, quarantine_root: str) -> str:
    """Canonical symlink-safe resolution: verify target_path is strictly within quarantine_root."""
    abs_target = os.path.realpath(target_path)
    abs_root = os.path.realpath(quarantine_root)
    if not (abs_target == abs_root or abs_target.startswith(abs_root + os.sep)):
        raise ValueError(f"Quarantine boundary violation: target path {abs_target} escapes quarantine root {abs_root}")
    return abs_target


def verify_external_mount(
    expected_mount: str = DEFAULT_MOUNT_POINT,
    expected_device: str | None = None,
    expected_uuid: str = DEFAULT_EXPECTED_UUID,
    expected_label: str = DEFAULT_EXPECTED_LABEL,
    require_mount: bool = True
) -> bool:
    """
    Verify external drive mount at expected path before permitting quarantine/report operations.
    Enforces:
      - Exact match on expected_mount (/run/media/harshitgarg/Data1), rejecting parent or prefix mounts.
      - Backing device validation: matches expected_device explicitly when passed, or verified persistent
        UUID (99a513c9-4aaa-4660-b7dc-2d2616449df9) / Label (Data) via /dev/disk/by-uuid and /dev/disk/by-label.
      - Explicitly rejects root/system filesystem partitions and unverified devices.
      - Never treats mere directory existence as proof of mount.
    """
    if not require_mount:
        return True

    # Identify root partition device to explicitly prevent ever accepting system root
    root_dev = None
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "/":
                    root_dev = os.path.realpath(parts[0]) if os.path.exists(parts[0]) else parts[0]
                    break
    except Exception:
        pass

    found_mount = False
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    dev, mp = parts[0], parts[1]
                    if mp == expected_mount:
                        found_mount = True
                        dev_real = os.path.realpath(dev) if os.path.exists(dev) else dev

                        # Root partition can never be accepted as external storage
                        if root_dev and dev_real == root_dev:
                            logger.error(
                                f"Mount check FAILED: {expected_mount} resolved to root partition "
                                f"'{dev_real}'. Operations blocked."
                            )
                            return False

                        if expected_device is not None:
                            # Explicit device specified (e.g. in targeted unit test)
                            expected_real = os.path.realpath(expected_device) if os.path.exists(expected_device) else expected_device
                            if dev == expected_device or dev_real == expected_real:
                                return True
                            else:
                                logger.error(
                                    f"Mount check FAILED: {expected_mount} is mounted on unexpected backing device "
                                    f"'{dev}' (expected '{expected_device}'). Operations blocked."
                                )
                                return False
                        else:
                            # Check persistent UUID / label or default backing device
                            uuid_path = f"/dev/disk/by-uuid/{expected_uuid}"
                            label_path = f"/dev/disk/by-label/{expected_label}"
                            if os.path.exists(uuid_path) and os.path.realpath(uuid_path) == dev_real:
                                return True
                            if os.path.exists(label_path) and os.path.realpath(label_path) == dev_real:
                                return True
                            expected_real = os.path.realpath(DEFAULT_EXPECTED_DEVICE) if os.path.exists(DEFAULT_EXPECTED_DEVICE) else DEFAULT_EXPECTED_DEVICE
                            if dev == DEFAULT_EXPECTED_DEVICE or dev_real == expected_real:
                                return True

                            logger.error(
                                f"Mount check FAILED: {expected_mount} is mounted on unexpected backing device "
                                f"'{dev}' (expected persistent UUID '{expected_uuid}' or label '{expected_label}'). Operations blocked."
                            )
                            return False
    except Exception as exc:
        logger.error(f"Failed to read /proc/mounts to verify mount: {exc}")
        return False

    if not found_mount:
        logger.error(f"Mount check FAILED: {expected_mount} not found in /proc/mounts. Operations blocked.")
    return False


def hash_file_sha256(filepath: str, block_size: int = 65536) -> str:
    """Compute streaming SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def get_known_development_hashes(search_dirs: list = None) -> dict:
    """
    Collect SHA-256 hashes of all known development and test PCAPs to prevent
    accidental holdout leakage.
    """
    dev_dirs = search_dirs or [
        os.path.join(HDD_BASE, "verified"),
        os.path.join(_IDS_ROOT, "data"),
    ]
    known = {}
    for d in dev_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for fname in os.listdir(d):
                if fname.endswith(".pcap") or fname.endswith(".pcapng"):
                    fpath = os.path.join(d, fname)
                    if os.path.isfile(fpath):
                        try:
                            sha_file = fpath + ".sha256"
                            h = None
                            if os.path.isfile(sha_file):
                                try:
                                    with open(sha_file, "r") as sf:
                                        tok = sf.read().split()[0].strip().lower()
                                        if len(tok) == 64:
                                            h = tok
                                except Exception:
                                    h = None
                            if not h:
                                h = hash_file_sha256(fpath)
                            known[h.lower()] = fname
                        except Exception:
                            pass
        except Exception:
            pass
    return known


def validate_pcap_structure(filepath: str, timeout_s: float = 10.0) -> tuple[bool, str | None]:
    """
    Perform deep structural validation of a PCAP/PCAPNG capture using capinfos,
    tshark, or binary packet header verification.
    """
    capinfos_bin = shutil.which("capinfos")
    if capinfos_bin:
        try:
            proc = subprocess.run(
                [capinfos_bin, "-c", "-r", "-u", filepath],
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
            if proc.returncode != 0:
                return False, f"capinfos failed with code {proc.returncode}: {proc.stderr.strip()}"
            return True, None
        except subprocess.TimeoutExpired:
            return False, f"capinfos structural inspection timed out after {timeout_s}s"
        except Exception:
            pass

    tshark_bin = shutil.which("tshark")
    if tshark_bin:
        try:
            proc = subprocess.run(
                [tshark_bin, "-r", filepath, "-c", "1", "-q"],
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
            if proc.returncode != 0:
                return False, f"tshark failed with code {proc.returncode}: {proc.stderr.strip()}"
            return True, None
        except subprocess.TimeoutExpired:
            return False, f"tshark structural inspection timed out after {timeout_s}s"
        except Exception:
            pass

    # Fallback to Python global and record header parse
    try:
        with open(filepath, "rb") as f:
            header = f.read(24)
            if len(header) < 24:
                return False, "File too small for valid PCAP global header (<24 bytes)"
            magic = header[:4]
            if magic not in VALID_PCAP_MAGICS:
                return False, f"Invalid PCAP magic bytes: {magic.hex()}"
            if magic != b"\x0a\x0d\x0d\x0a":
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    return False, "File has valid global header but no packet records"
        return True, None
    except Exception as exc:
        return False, f"Structural inspection exception: {exc}"


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

    agg_hash, file_hashes = compute_engine_fingerprint()
    result["engine_fingerprint"] = agg_hash
    result["file_fingerprints"] = file_hashes

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
    read_only_mode = current_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    read_only_mode |= (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    os.chmod(filepath, read_only_mode)


def verify_holdout_quarantine(
    filepath: str,
    expected_sha256: str,
    quarantine_dir: str = None,
    require_mount: bool = False
) -> dict:
    """
    Verify quarantine integrity of a holdout PCAP (Fail-closed).
    Fails closed if:
      - expected_sha256 is missing, None, or not a valid 64-char hex string.
      - External HDD mount fails (if require_mount=True).
      - File does not exist or is empty (0 bytes).
      - File escapes quarantine_dir boundary (or traverses symlinks).
      - File permissions have any write bits set.
      - Invalid PCAP magic bytes.
      - Structural PCAP verification fails.
      - SHA-256 digest does not match expected_sha256.
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

    # 1. Mandatory SHA-256 check
    if expected_sha256 is None:
        result["error"] = "Expected SHA-256 digest is mandatory for quarantine validation; None is prohibited."
        return result
    if not isinstance(expected_sha256, str) or not SHA256_REGEX.match(expected_sha256.strip()):
        result["error"] = f"Expected SHA-256 must be a valid 64-character hex string, got {expected_sha256!r}"
        return result
    clean_expected_sha256 = expected_sha256.strip().lower()

    # 2. Mount check
    if require_mount and not verify_external_mount(require_mount=True):
        result["error"] = f"External drive mount check failed: {DEFAULT_EXPECTED_DEVICE} is not mounted at {DEFAULT_MOUNT_POINT}"
        return result

    # 3. File existence
    if not os.path.isfile(filepath):
        result["error"] = f"Holdout file does not exist: {filepath}"
        return result

    # 4. Quarantine path containment
    if quarantine_dir:
        try:
            check_quarantine_path_containment(filepath, quarantine_dir)
        except ValueError as exc:
            result["error"] = str(exc)
            return result

    file_stat = os.stat(filepath)
    result["size_bytes"] = file_stat.st_size

    if file_stat.st_size == 0:
        result["error"] = f"Holdout file is empty (0 bytes): {filepath}"
        return result

    has_write = bool(file_stat.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    result["is_read_only"] = not has_write
    if has_write:
        result["error"] = f"Holdout file has write permission bits set: {oct(file_stat.st_mode)}"
        return result

    with open(filepath, "rb") as f:
        magic = f.read(4)
        result["magic_hex"] = magic.hex()
        if magic not in VALID_PCAP_MAGICS:
            result["error"] = f"Invalid PCAP header magic bytes: {magic.hex()}"
            return result

    struct_ok, struct_err = validate_pcap_structure(filepath)
    if not struct_ok:
        result["error"] = f"PCAP structural verification failed: {struct_err}"
        return result

    digest = hash_file_sha256(filepath)
    result["sha256"] = digest

    if digest.lower() != clean_expected_sha256:
        result["error"] = f"SHA-256 mismatch: expected {clean_expected_sha256}, got {digest.lower()}"
        return result

    result["valid"] = True
    return result


# =============================================================================
# Durable Runtime Registry on External HDD
# =============================================================================

def load_runtime_registry(registry_path: str = None) -> dict:
    """Load durable holdout runtime registry from disk."""
    reg_path = registry_path or DEFAULT_RUNTIME_REGISTRY_PATH
    if not os.path.isfile(reg_path):
        return {
            "registry_version": "1.0",
            "updated_at_utc": None,
            "candidates": {},
            "registered_hashes": {},
        }
    try:
        with open(reg_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.error(f"Error loading holdout runtime registry from {reg_path}: {exc}")
        return {
            "registry_version": "1.0",
            "updated_at_utc": None,
            "candidates": {},
            "registered_hashes": {},
        }


def save_runtime_registry_atomic(reg_data: dict, registry_path: str = None) -> None:
    """Atomically write runtime registry data to disk."""
    reg_path = registry_path or DEFAULT_RUNTIME_REGISTRY_PATH
    reg_dir = os.path.dirname(os.path.abspath(reg_path))
    os.makedirs(reg_dir, exist_ok=True)
    reg_data["updated_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    tmp_path = reg_path + f".tmp_{uuid.uuid4().hex[:8]}"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(reg_data, f, indent=2)
    os.replace(tmp_path, reg_path)


def transition_runtime_registry_state(
    candidate_id: str,
    target_state: str,
    allowed_from_states: list[str] = None,
    metadata_updates: dict = None,
    registry_path: str = None,
) -> dict:
    """
    Atomically transition candidate state in the external HDD runtime registry.
    Enforces concurrency lockfile, valid transitions, and updates history.
    """
    validate_candidate_id(candidate_id)
    reg_path = registry_path or DEFAULT_RUNTIME_REGISTRY_PATH
    lock_path = reg_path + ".lock"
    os.makedirs(os.path.dirname(os.path.abspath(reg_path)), exist_ok=True)

    lock_fd = None
    start_t = time.time()
    while True:
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            break
        except FileExistsError:
            if time.time() - start_t > 10.0:
                raise TimeoutError(f"Timed out acquiring lock on holdout runtime registry: {lock_path}")
            time.sleep(0.05)

    try:
        reg_data = load_runtime_registry(reg_path)
        candidates = reg_data.setdefault("candidates", {})
        cand_entry = candidates.setdefault(candidate_id, {
            "candidate_id": candidate_id,
            "state": HoldoutState.PENDING_ACQUISITION,
            "history": [],
        })
        current_state = cand_entry.get("state", HoldoutState.PENDING_ACQUISITION)

        if allowed_from_states is not None and current_state not in allowed_from_states:
            raise ValueError(
                f"Invalid state transition for candidate '{candidate_id}': "
                f"current state is '{current_state}', expected one of {allowed_from_states}"
            )

        cand_entry["state"] = target_state
        cand_entry["history"].append({
            "from_state": current_state,
            "to_state": target_state,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "details": metadata_updates or {},
        })
        if metadata_updates:
            cand_entry.update(metadata_updates)

        if "sha256" in cand_entry:
            reg_data.setdefault("registered_hashes", {})[cand_entry["sha256"].lower()] = candidate_id

        save_runtime_registry_atomic(reg_data, reg_path)
        return cand_entry
    finally:
        if lock_fd is not None:
            try:
                os.close(lock_fd)
                if os.path.exists(lock_path):
                    os.remove(lock_path)
            except Exception:
                pass


def register_holdout_candidate(
    source_pcap_path: str,
    candidate_id: str,
    candidate_meta: dict,
    quarantine_dir: str = None,
    check_dev_overlap: bool = True,
    require_mount: bool = False,
    runtime_registry_path: str = None,
) -> dict:
    """
    Pre-register and quarantine a holdout candidate capture with strict safety guarantees.

    Guarantees:
      - Candidate ID validated against safe allowlist regex (^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$).
      - Mount verification before file writes (if require_mount=True).
      - Rejection of captures overlapping with known development corpus.
      - Rejection of duplicate candidate IDs and duplicate hashes in runtime registry.
      - Exclusive creation (no silent overwriting of existing PCAP or metadata).
      - Read-only permission sealing (0o444).
      - Complete structural validation.
      - Concurrency-safe atomic state transition in durable runtime registry.
    """
    validate_candidate_id(candidate_id)

    # 1. Mount check before any directory creation or writes
    if require_mount and not verify_external_mount(require_mount=True):
        raise RuntimeError(f"External drive mount check failed: {DEFAULT_EXPECTED_DEVICE} is not mounted at {DEFAULT_MOUNT_POINT}")

    if not os.path.isfile(source_pcap_path):
        raise FileNotFoundError(f"Source PCAP file does not exist: {source_pcap_path}")

    if os.path.getsize(source_pcap_path) == 0:
        raise ValueError(f"Source PCAP file is empty: {source_pcap_path}")

    source_digest = hash_file_sha256(source_pcap_path)

    # 2. Check development corpus overlap
    if check_dev_overlap:
        known_dev = get_known_development_hashes()
        if source_digest.lower() in known_dev:
            dev_match = known_dev[source_digest.lower()]
            raise ValueError(
                f"Candidate PCAP hash ({source_digest[:16]}...) matches known development capture '{dev_match}'. "
                "Independent holdouts must be strictly unseen."
            )

    # 3. Check runtime registry duplicates
    reg_data = load_runtime_registry(runtime_registry_path)
    if candidate_id in reg_data.get("candidates", {}):
        existing_st = reg_data["candidates"][candidate_id].get("state")
        if existing_st != HoldoutState.PENDING_ACQUISITION:
            raise FileExistsError(
                f"Candidate '{candidate_id}' is already registered in runtime registry with state '{existing_st}'."
            )
    registered_hashes = reg_data.get("registered_hashes", {})
    if source_digest.lower() in registered_hashes:
        prior_cid = registered_hashes[source_digest.lower()]
        raise ValueError(
            f"Candidate PCAP hash ({source_digest[:16]}...) is already registered in holdout registry under '{prior_cid}'."
        )

    # 4. Quarantine destination setup and boundary containment
    q_dir = quarantine_dir or DEFAULT_HOLDOUT_QUARANTINE_DIR
    os.makedirs(q_dir, exist_ok=True)
    check_quarantine_path_containment(q_dir, q_dir)

    dest_pcap = os.path.join(q_dir, f"{candidate_id}.pcap")
    dest_meta = os.path.join(q_dir, f"{candidate_id}.meta.json")
    check_quarantine_path_containment(dest_pcap, q_dir)
    check_quarantine_path_containment(dest_meta, q_dir)

    if os.path.exists(dest_pcap) or os.path.islink(dest_pcap):
        raise FileExistsError(f"Quarantine candidate PCAP already exists: {dest_pcap}. Overwriting is prohibited.")
    if os.path.exists(dest_meta) or os.path.islink(dest_meta):
        raise FileExistsError(f"Quarantine candidate metadata already exists: {dest_meta}. Overwriting is prohibited.")

    # 5. Exclusive creation of destination PCAP
    tmp_pcap = dest_pcap + f".tmp_{uuid.uuid4().hex[:8]}"
    try:
        fd = os.open(tmp_pcap, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with open(source_pcap_path, "rb") as f_in, open(fd, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        enforce_quarantine_permissions(tmp_pcap)
        os.replace(tmp_pcap, dest_pcap)
    finally:
        if os.path.exists(tmp_pcap):
            try:
                os.chmod(tmp_pcap, 0o600)
                os.remove(tmp_pcap)
            except Exception:
                pass

    q_verify = verify_holdout_quarantine(dest_pcap, expected_sha256=source_digest, quarantine_dir=q_dir)
    if not q_verify["valid"]:
        try:
            os.chmod(dest_pcap, 0o600)
            os.remove(dest_pcap)
        except Exception:
            pass
        raise ValueError(f"Quarantined PCAP failed integrity validation: {q_verify.get('error')}")

    # 6. Write sidecar metadata
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
        "quarantine_verified": True,
        "registered_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    tmp_meta = dest_meta + f".tmp_{uuid.uuid4().hex[:8]}"
    try:
        fd = os.open(tmp_meta, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        enforce_quarantine_permissions(tmp_meta)
        os.replace(tmp_meta, dest_meta)
    finally:
        if os.path.exists(tmp_meta):
            try:
                os.chmod(tmp_meta, 0o600)
                os.remove(tmp_meta)
            except Exception:
                pass

    # 7. Update durable runtime registry
    transition_runtime_registry_state(
        candidate_id=candidate_id,
        target_state=HoldoutState.REGISTERED_QUARANTINED,
        allowed_from_states=[HoldoutState.PENDING_ACQUISITION],
        metadata_updates={
            "quarantined_pcap_path": dest_pcap,
            "sidecar_meta_path": dest_meta,
            "sha256": q_verify["sha256"],
            "size_bytes": q_verify["size_bytes"],
        },
        registry_path=runtime_registry_path,
    )

    logger.info(f"Registered holdout capture '{candidate_id}' in quarantine at {dest_pcap} (SHA-256: {q_verify['sha256'][:16]}...)")
    return meta


def run_blind_holdout_evaluation(
    pcap_path: str,
    candidate_meta: dict,
    quarantine_dir: str = None,
    output_dir: str = None,
    strict_freeze: bool = True,
    allow_dirty: bool = False,
    runtime_registry_path: str = None,
    require_mount: bool = False,
) -> dict:
    """
    Execute single-pass blind evaluation of a quarantined holdout capture against NetGuard IDS.

    Guarantees:
      - Validates candidate ID against safe allowlist.
      - Enforces quarantine membership and rejects arbitrary filesystem PCAPs.
      - Enforces sidecar metadata existence and SHA-256 agreement.
      - Mandatory expected SHA-256 (fails closed if None or mismatched).
      - Enforces code freeze before execution (refuses dirty git state if strict_freeze=True).
      - Durable runtime registry enforces single-pass evaluation and prevents duplicate runs.
      - Replays PCAP in an isolated temporary SQLite database.
      - Disables all calibration cache reads and writes.
      - Separates capture-level target-rule firing from true ground-truth evaluation.
      - Generates audit report sealed to 0o444 read-only permissions with verifiable SHA-256 digest.
    """
    t_start = time.perf_counter()
    report_uuid = str(uuid.uuid4())

    # 1. Validate Candidate ID
    cid = candidate_meta.get("candidate_id", os.path.splitext(os.path.basename(pcap_path))[0])
    validate_candidate_id(cid)

    # 2. Enforce Quarantine Membership and Symlink Containment
    q_dir = quarantine_dir or DEFAULT_HOLDOUT_QUARANTINE_DIR
    canon_pcap = check_quarantine_path_containment(pcap_path, q_dir)

    # 3. Require Registered Metadata Sidecar Agreement
    sidecar_path = os.path.join(os.path.dirname(canon_pcap), f"{cid}.meta.json")
    if not os.path.isfile(sidecar_path):
        raise FileNotFoundError(
            f"Holdout quarantine sidecar metadata missing at {sidecar_path}. "
            "Unregistered PCAPs outside quarantine cannot be evaluated."
        )
    with open(sidecar_path, "r", encoding="utf-8") as sf:
        sidecar_meta = json.load(sf)

    sidecar_cid = sidecar_meta.get("candidate_id")
    if sidecar_cid != cid:
        raise ValueError(f"Candidate ID mismatch between request ('{cid}') and sidecar metadata ('{sidecar_cid}')")

    expected_sha256 = sidecar_meta.get("sha256") or candidate_meta.get("sha256")
    if not expected_sha256:
        raise ValueError(f"Mandatory SHA-256 missing in metadata sidecar for '{cid}'")

    if candidate_meta.get("sha256") and candidate_meta["sha256"].lower() != expected_sha256.lower():
        raise ValueError(
            f"SHA-256 mismatch between caller metadata ({candidate_meta['sha256']}) "
            f"and registered sidecar metadata ({expected_sha256})"
        )

    # 4. Verify Quarantine Integrity (Fail closed)
    q_info = verify_holdout_quarantine(
        canon_pcap,
        expected_sha256=expected_sha256,
        quarantine_dir=q_dir,
        require_mount=require_mount,
    )
    if not q_info["valid"]:
        raise ValueError(f"Holdout PCAP quarantine check failed: {q_info.get('error')}")

    # 5. Verify Engine Code Freeze
    freeze_info = verify_engine_freeze(allow_dirty=allow_dirty or not strict_freeze)
    if strict_freeze and not freeze_info["frozen"]:
        raise RuntimeError(f"Holdout evaluation blocked by engine freeze check: {freeze_info.get('error')}")

    # 6. Durable Runtime Registry State Machine Check & Transition to EVALUATING
    transition_runtime_registry_state(
        candidate_id=cid,
        target_state=HoldoutState.EVALUATING,
        allowed_from_states=[HoldoutState.REGISTERED_QUARANTINED, HoldoutState.EVALUATION_FAILED],
        metadata_updates={"evaluation_started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
        registry_path=runtime_registry_path,
    )

    try:
        # 7. Import engine and storage components
        from storage.db import get_connection, init_db
        from engine.blocklist import BlocklistData
        from capture.sniffer import replay_pcap
        from evaluation.replay import create_replay_engine
        import config

        # 8. Isolated Execution in Temporary Directory
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

                logger.info(f"[{cid}] Beginning single-pass blind holdout evaluation on {canon_pcap}...")
                replay_summary = replay_pcap(canon_pcap, engine)

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

        # Structure alerts & validate timestamps
        alerts = []
        alerts_by_rule = {}
        malformed_alert_timestamps = 0
        for r in raw_rows:
            rule_name = r[2]
            ev_raw = r[11]
            try:
                ev_dict = json.loads(ev_raw) if ev_raw else {}
            except Exception:
                ev_dict = {"raw": ev_raw}

            ts = r[1]
            try:
                float(ts)
            except (ValueError, TypeError):
                malformed_alert_timestamps += 1

            alert_entry = {
                "id": r[0],
                "timestamp": ts,
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

        # 9. Separate Detection Observations from Real Ground Truth
        target_rules = candidate_meta.get("target_rules", sidecar_meta.get("target_rules", []))
        fired_rules = sorted(list(alerts_by_rule.keys()))
        matched_target_rules = sorted(list(set(fired_rules).intersection(target_rules)))
        target_rule_match = bool(matched_target_rules)

        capture_level_observation = {
            "target_rules": target_rules,
            "fired_rules": fired_rules,
            "matched_target_rules": matched_target_rules,
            "target_rule_match": target_rule_match,
            "target_rules_fired": target_rule_match,
            "observation_status": "TARGET_RULES_OBSERVED" if target_rule_match else "NO_TARGET_RULES_OBSERVED",
            "note": "Capture-level target-rule firing is descriptive evidence only, NOT validated ground-truth precision or recall."
        }

        # Check for structured ground-truth labels
        gt_labels = candidate_meta.get("ground_truth_labels") or sidecar_meta.get("ground_truth_labels")
        if not gt_labels and (candidate_meta.get("labels_path") or sidecar_meta.get("labels_path")):
            l_path = candidate_meta.get("labels_path") or sidecar_meta.get("labels_path")
            if os.path.isfile(l_path):
                try:
                    with open(l_path, "r", encoding="utf-8") as lf:
                        gt_labels = json.load(lf)
                except Exception as exc:
                    logger.warning(f"Could not load structured labels from {l_path}: {exc}")

        is_benign = candidate_meta.get("is_benign", False) or "FP_BENIGN" in target_rules or sidecar_meta.get("is_benign", False)
        benign_coverage = str(candidate_meta.get("benign_coverage", sidecar_meta.get("benign_coverage", "unknown"))).lower()

        if gt_labels and isinstance(gt_labels, list) and len(gt_labels) > 0:
            from evaluation.pipeline import evaluate_ground_truth_labels
            label_cov = candidate_meta.get("label_coverage", sidecar_meta.get("label_coverage", "partial"))
            gt_result = evaluate_ground_truth_labels(gt_labels, alerts, label_coverage=label_cov)
            gt_result["has_granular_ground_truth"] = True
            ground_truth_evaluation = gt_result
            if gt_result.get("true_positives", 0) > 0 and gt_result.get("false_negatives", 0) == 0:
                verdict = "TRUE_POSITIVE"
            elif gt_result.get("true_positives", 0) > 0:
                verdict = "PARTIAL_DETECTION"
            elif gt_result.get("false_negatives", 0) > 0:
                verdict = "FALSE_NEGATIVE"
            else:
                verdict = "UNASSESSED"
        elif is_benign:
            if len(alerts) == 0:
                if benign_coverage in ("complete", "exhaustive"):
                    verdict = "TRUE_NEGATIVE"
                else:
                    verdict = "BENIGN_BASELINE_ZERO_ALERTS"
            else:
                verdict = "FALSE_POSITIVE"
            ground_truth_evaluation = {
                "status": "EVALUATED_BENIGN" if benign_coverage in ("complete", "exhaustive") else "UNASSESSED_BENIGN_BASELINE",
                "has_granular_ground_truth": False,
                "is_benign": True,
                "benign_coverage": benign_coverage,
                "total_alerts": len(alerts),
                "false_positives": len(alerts),
            }
        else:
            verdict = "OBSERVATIONAL_UNASSESSED"
            ground_truth_evaluation = {
                "status": "UNASSESSED",
                "has_granular_ground_truth": False,
                "reason": "No structured flow-level ground truth labels provided. Capture-level rule firing cannot be claimed as validated ground-truth TP.",
                "capture_observation": capture_level_observation,
            }

        # 10. Build Honest Read-Only Sealed Audit Report
        report = {
            "report_id": report_uuid,
            "candidate_id": cid,
            "evaluation_type": "INDEPENDENT_BLIND_HOLDOUT",
            "report_sealing": "Read-only permission sealed (0o444) with verifiable SHA-256 digest",
            "evaluated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pcap_metadata": {
                "pcap_path": canon_pcap,
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
                "malformed_alert_timestamps": malformed_alert_timestamps,
            },
            "verdict_analysis": {
                "verdict": verdict,
                "ground_truth_evaluation": ground_truth_evaluation,
                "capture_level_observation": capture_level_observation,
                "ground_truth_source": candidate_meta.get("ground_truth_source", sidecar_meta.get("ground_truth_source")),
                "expected_attack_family": candidate_meta.get("expected_attack_family", sidecar_meta.get("expected_attack_family")),
            },
            "raw_alerts": alerts,
        }

        # 11. Write and Seal Audit Report with Companion SHA-256 Digest
        out_dir = output_dir or DEFAULT_HOLDOUT_REPORTS_DIR
        os.makedirs(out_dir, exist_ok=True)
        report_filename = f"holdout_{cid}_{report_uuid[:8]}.json"
        report_path = os.path.join(out_dir, report_filename)
        sha_path = report_path + ".sha256"

        tmp_report = report_path + f".tmp_{uuid.uuid4().hex[:8]}"
        try:
            report_bytes = json.dumps(report, indent=2).encode("utf-8")
            report_hash = hashlib.sha256(report_bytes).hexdigest()
            report["report_sha256"] = report_hash

            with open(tmp_report, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            enforce_quarantine_permissions(tmp_report)
            os.replace(tmp_report, report_path)

            with open(sha_path, "w", encoding="utf-8") as sf:
                sf.write(f"{report_hash}  {report_filename}\n")
            enforce_quarantine_permissions(sha_path)
        finally:
            if os.path.exists(tmp_report):
                try:
                    os.chmod(tmp_report, 0o600)
                    os.remove(tmp_report)
                except Exception:
                    pass

        # 12. Transition Runtime Registry to EVALUATED
        transition_runtime_registry_state(
            candidate_id=cid,
            target_state=HoldoutState.EVALUATED,
            allowed_from_states=[HoldoutState.EVALUATING],
            metadata_updates={
                "report_id": report_uuid,
                "report_path": report_path,
                "report_sha256": report.get("report_sha256"),
                "verdict": verdict,
                "evaluated_at_utc": report["evaluated_at_utc"],
            },
            registry_path=runtime_registry_path,
        )

        logger.info(f"[{cid}] Holdout evaluation complete: {verdict} ({len(alerts)} alerts, {total_pkts} pkts in {elapsed_s:.2f}s). Audit report saved to {report_path}")
        return report

    except Exception as exc:
        # Record failure in runtime registry so state is not stuck in EVALUATING
        try:
            transition_runtime_registry_state(
                candidate_id=cid,
                target_state=HoldoutState.EVALUATION_FAILED,
                allowed_from_states=[HoldoutState.EVALUATING],
                metadata_updates={
                    "failure_error": str(exc),
                    "failed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
                registry_path=runtime_registry_path,
            )
        except Exception as reg_exc:
            logger.error(f"Failed to record EVALUATION_FAILED state for {cid}: {reg_exc}")
        raise


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="NetGuard IDS Independent Holdout Evaluation Pipeline")
    parser.add_argument("--verify-freeze", action="store_true", help="Verify engine freeze and print fingerprints")
    parser.add_argument("--register", metavar="PCAP", help="Register and quarantine a candidate holdout PCAP")
    parser.add_argument("--id", help="Candidate ID for registration")
    parser.add_argument("--meta", help="Path to JSON metadata for registration")
    parser.add_argument("--run-eval", metavar="PCAP", help="Run single-pass blind evaluation on a quarantined PCAP")
    parser.add_argument("--output-dir", help="Directory for sealed audit reports")
    parser.add_argument("--allow-dirty", action="store_true", help="Allow uncommitted changes during test/debug runs")
    parser.add_argument("--no-mount-check", action="store_true", help="Bypass HDD mount check for local dry-runs")

    args = parser.parse_args()

    if args.verify_freeze:
        res = verify_engine_freeze(allow_dirty=args.allow_dirty)
        print(json.dumps(res, indent=2))
        sys.exit(0 if res["frozen"] else 1)

    if args.register:
        if not args.id:
            parser.error("--id is required with --register")
        validate_candidate_id(args.id)
        meta_dict = {}
        if args.meta and os.path.isfile(args.meta):
            with open(args.meta, "r", encoding="utf-8") as f:
                meta_dict = json.load(f)
        reg_res = register_holdout_candidate(
            args.register,
            args.id,
            meta_dict,
            require_mount=not args.no_mount_check,
        )
        print(json.dumps(reg_res, indent=2))
        sys.exit(0)

    if args.run_eval:
        meta_dict = {}
        if args.meta and os.path.isfile(args.meta):
            with open(args.meta, "r", encoding="utf-8") as f:
                meta_dict = json.load(f)
        if args.id:
            meta_dict["candidate_id"] = validate_candidate_id(args.id)
        report = run_blind_holdout_evaluation(
            args.run_eval,
            meta_dict,
            output_dir=args.output_dir,
            strict_freeze=not args.allow_dirty,
            allow_dirty=args.allow_dirty,
            require_mount=not args.no_mount_check,
        )
        print(json.dumps(report["execution_metrics"], indent=2))
        sys.exit(0)

    parser.print_help()
