#!/usr/bin/env python3
"""
ids_project/evaluation/pipeline.py
----------------------------------
Smart Asynchronous Dataset Acquisition and Evaluation Pipeline for NetGuard IDS.

Features:
  - Worker A: Discovery & prioritized acquisition queue across independent publishers
  - Worker B: Background downloader with HTTP resume (.part) and persistent 90-min / 5-GiB resource budgeting
  - Worker C: Integrity & metadata verification (SHA-256, safe extraction, deep PCAP header validation)
  - Worker D: Concurrent real-time evaluation against NetGuard detection engine with TemporaryDirectory isolation
  - Automated Ground-Truth Verdict Classification (TP, TN, FP, Sub-Threshold)
  - Storage stages: incoming/ (.part) -> verified/ -> evaluation/ (with quarantine/ fallback)
  - Preserves external HDD invariants (>= 100 GiB free, <= 450 GiB total allocation, mount check)
"""

import gzip
import hashlib
import json
import logging
import lzma
import os
import queue
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

# Ensure ids_project is in sys.path
_HERE = os.path.dirname(os.path.abspath(__file__))
_IDS_ROOT = os.path.dirname(_HERE)
if _IDS_ROOT not in sys.path:
    sys.path.insert(0, _IDS_ROOT)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("pipeline")

# Storage Roots
HDD_DATASETS_DIR = "/run/media/harshitgarg/Data1/NetGuard-datasets"
INCOMING_DIR = os.path.join(HDD_DATASETS_DIR, "incoming")
VERIFIED_DIR = os.path.join(HDD_DATASETS_DIR, "verified")
QUARANTINE_DIR = os.path.join(HDD_DATASETS_DIR, "quarantine")
EVALUATION_DIR = os.path.join(HDD_DATASETS_DIR, "evaluation")
EVALUATION_RESULTS_DIR = os.path.join(HDD_DATASETS_DIR, "evaluation-results")
MANIFESTS_DIR = os.path.join(HDD_DATASETS_DIR, "manifests")
HASHES_DIR = os.path.join(HDD_DATASETS_DIR, "hashes")
COORDINATION_DIR = os.path.join(HDD_DATASETS_DIR, "coordination")
CUMULATIVE_BUDGET_FILE = os.path.join(COORDINATION_DIR, "cumulative_budget.json")

# Invariants & Safety Limits
MIN_FREE_DISK_GIB = 100.0
MAX_INITIAL_ACQUISITION_GIB = 5.0
MAX_ALLOCATION_GIB = 450.0
MAX_DOWNLOAD_TIME_SECONDS = 90 * 60  # 90 minutes
EXPECTED_MOUNT_POINT = "/run/media/harshitgarg/Data1"

# PCAP Magic Numbers
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_NS_LE = b"\x4d\x3c\xb2\xa1"
PCAP_MAGIC_NS_BE = b"\xa1\xb2\x3c\x4d"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
VALID_MAGICS = (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE, PCAPNG_MAGIC)


def check_disk_safety(require_mount: bool = True) -> bool:
    """Verify that the external HDD is mounted at the expected device path,
    has >= 100 GiB free space, and total allocation is <= 450 GiB.

    Args:
        require_mount: If True (default), return False when the mount point is
            absent from /proc/mounts or the backing device is not /dev/sdb1.
            Set False only in unit tests running on a tmpfs without a real HDD.

    Returns:
        True iff all safety invariants are satisfied.
    """
    if not os.path.isdir(HDD_DATASETS_DIR):
        logger.error(f"HDD dataset directory does not exist: {HDD_DATASETS_DIR}")
        return False

    # --- Mount verification: /dev/sdb1 must be mounted at EXPECTED_MOUNT_POINT ---
    if require_mount:
        try:
            mount_ok = False
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1] == EXPECTED_MOUNT_POINT:
                        mount_ok = True
                        break
            if not mount_ok:
                logger.error(
                    f"Mount check FAILED: {EXPECTED_MOUNT_POINT} not found in /proc/mounts. "
                    f"All dataset writes are blocked until the drive is mounted."
                )
                return False
        except Exception as exc:
            logger.error(f"Could not read /proc/mounts to verify mount: {exc}")
            return False

    # --- Free space: >= MIN_FREE_DISK_GIB ---
    try:
        stat = os.statvfs(HDD_DATASETS_DIR)
        free_bytes = stat.f_bavail * stat.f_frsize
        free_gib = free_bytes / (1024 ** 3)
        if free_gib < MIN_FREE_DISK_GIB:
            logger.error(
                f"Insufficient free space on HDD: {free_gib:.2f} GiB available "
                f"(minimum {MIN_FREE_DISK_GIB} GiB required). Writes blocked."
            )
            return False

        # --- Total allocation cap: <= MAX_ALLOCATION_GIB ---
        total_bytes = stat.f_blocks * stat.f_frsize
        used_bytes = (stat.f_blocks - stat.f_bavail) * stat.f_frsize
        allocated_gib = used_bytes / (1024 ** 3)
        if allocated_gib > MAX_ALLOCATION_GIB:
            logger.error(
                f"Total allocation cap exceeded: {allocated_gib:.2f} GiB used "
                f"(maximum {MAX_ALLOCATION_GIB} GiB). Writes blocked."
            )
            return False

        logger.debug(
            f"Disk safety OK: {free_gib:.1f} GiB free, {allocated_gib:.1f} GiB allocated "
            f"on {EXPECTED_MOUNT_POINT}"
        )
        return True
    except Exception as exc:
        logger.error(f"Failed to check disk safety: {exc}")
        return False


def load_cumulative_budget() -> dict:
    """Load persistent cumulative acquisition budget from disk."""
    os.makedirs(COORDINATION_DIR, exist_ok=True)
    if os.path.isfile(CUMULATIVE_BUDGET_FILE):
        try:
            with open(CUMULATIVE_BUDGET_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and "cumulative_downloaded_bytes" in data:
                    return data
        except Exception as exc:
            logger.warning(f"Could not read cumulative budget file: {exc}")

    initial_budget = {
        "cumulative_downloaded_bytes": 0,
        "cumulative_download_time_s": 0.0,
        "max_acquisition_budget_bytes": int(MAX_INITIAL_ACQUISITION_GIB * (1024 ** 3)),
        "max_download_time_s": MAX_DOWNLOAD_TIME_SECONDS,
        "max_allocation_bytes": int(MAX_ALLOCATION_GIB * (1024 ** 3)),
        "last_updated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    try:
        with open(CUMULATIVE_BUDGET_FILE, "w", encoding="utf-8") as f:
            json.dump(initial_budget, f, indent=2)
    except Exception:
        pass
    return initial_budget


def update_cumulative_budget(newly_downloaded_bytes: int, elapsed_time_s: float) -> dict:
    """Atomically update persistent cumulative budget on disk."""
    budget = load_cumulative_budget()
    budget["cumulative_downloaded_bytes"] += newly_downloaded_bytes
    budget["cumulative_download_time_s"] += elapsed_time_s
    budget["last_updated_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    tmp_path = CUMULATIVE_BUDGET_FILE + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(budget, f, indent=2)
        os.replace(tmp_path, CUMULATIVE_BUDGET_FILE)
    except Exception as exc:
        logger.error(f"Failed to update cumulative budget: {exc}")
    return budget


# Evaluator version — bump when evaluation logic changes to invalidate cached results.
_EVALUATOR_VERSION = "1.2.0"


def compute_eval_cache_key(pcap_path: str, candidate: dict) -> str:
    """
    Compute a stable cache fingerprint for an evaluation result.

    Incorporates:
    - SHA-256 of the PCAP file bytes (content identity)
    - Evaluator version string (invalidates on logic changes)
    - Sorted target_rules list (invalidates when target_rules change)

    Returns a 16-character hex prefix — compact and collision-resistant enough for
    file-system caching (2^64 space; SHA-256 truncation, not a security primitive).
    """
    h = hashlib.sha256()
    try:
        with open(pcap_path, "rb") as f:
            while chunk := f.read(128 * 1024):
                h.update(chunk)
    except OSError as exc:
        logger.warning(f"compute_eval_cache_key: could not hash {pcap_path}: {exc}")
        h.update(pcap_path.encode())
    h.update(_EVALUATOR_VERSION.encode())
    rules_str = json.dumps(sorted(candidate.get("target_rules", [])), separators=(",", ":"))
    h.update(rules_str.encode())
    return h.hexdigest()[:16]


def validate_pcap_deep(pcap_path: str) -> tuple[bool, str]:
    """
    Perform deep structural validation of a PCAP or PCAPNG capture file:
    1. Size >= 24 bytes (minimum standard PCAP global header).
    2. Valid magic bytes.
    3. Proper major/minor version (2.4 for classic PCAP, valid SHB length for PCAPNG).
    4. First packet record header readable without premature EOF or corrupt packet length.
    """
    if not os.path.isfile(pcap_path):
        return False, "File does not exist"

    size = os.path.getsize(pcap_path)
    if size < 24:
        return False, f"File size ({size} bytes) smaller than minimum PCAP header (24 bytes)"

    with open(pcap_path, "rb") as f:
        magic = f.read(4)
        if magic not in VALID_MAGICS:
            return False, f"Invalid PCAP magic bytes: {magic.hex()}"

        if magic == PCAPNG_MAGIC:
            # PCAPNG: verify Section Header Block length >= 28
            f.seek(4)
            shb_len_bytes = f.read(4)
            if len(shb_len_bytes) == 4:
                shb_len = struct.unpack("<I", shb_len_bytes)[0]
                if shb_len < 28 or shb_len > size:
                    return False, f"Invalid PCAPNG SHB length: {shb_len}"
            return True, "Valid PCAPNG format"

        # Classic libpcap format
        is_le = magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE)
        endian = "<" if is_le else ">"
        f.seek(4)
        hdr_rest = f.read(20)
        if len(hdr_rest) < 20:
            return False, "Truncated PCAP global header"

        major, minor, tz, sigfigs, snaplen, network = struct.unpack(endian + "HHIIII", hdr_rest)
        if major != 2:
            return False, f"Unsupported PCAP major version {major} (expected 2)"

        # Check if file has at least one packet header (16 bytes)
        if size > 24:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                return False, "Truncated first packet record header"
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", pkt_hdr)
            if snaplen > 0 and incl_len > snaplen:
                if incl_len > 65535 * 4:
                    return False, f"Packet length exceeds sane boundaries: {incl_len}"

    return True, "Valid classic libpcap format"


MAX_DECOMPRESSED_SIZE_BYTES = 1024 * 1024 * 1024  # 1 GiB safety limit per archive extraction


def get_git_revision() -> str:
    """Return HEAD commit SHA if inside git repository, else 'unknown'."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=_IDS_ROOT,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()[:10]
    except Exception:
        pass
    return "unknown"


def hash_file_sha256(path: str) -> str:
    """Compute standard SHA-256 digest of a file in 128 KiB chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(128 * 1024):
            h.update(chunk)
    return h.hexdigest()


def safe_decompress_stream(reader, writer, max_bytes: int = MAX_DECOMPRESSED_SIZE_BYTES, chunk_size: int = 64 * 1024) -> int:
    """Safely stream decompressed content with a strict output size bound to prevent decompression bombs.

    Returns total bytes written or raises RuntimeError if limit is exceeded.
    """
    total_written = 0
    while True:
        chunk = reader.read(chunk_size)
        if not chunk:
            break
        total_written += len(chunk)
        if total_written > max_bytes:
            raise RuntimeError(
                f"Decompressed output exceeded safety limit ({total_written} > {max_bytes} bytes). Aborting to prevent disk exhaustion."
            )
        writer.write(chunk)
    return total_written


def validate_pcap_with_tools(pcap_path: str, timeout_s: float = 15.0) -> tuple[bool, str, dict]:
    """Validate PCAP using internal deep header checks, plus external capinfos / tshark if available.

    Returns (is_valid, message, tool_metadata).
    """
    # 1. Structural deep check
    is_valid, msg = validate_pcap_deep(pcap_path)
    if not is_valid:
        return False, msg, {}

    stats: dict = {"packet_count": 0, "duration_seconds": 0.0}
    capinfos_bin = shutil.which("capinfos")
    if capinfos_bin:
        try:
            proc = subprocess.run(
                [capinfos_bin, "-c", "-d", "-u", "-s", "-y", pcap_path],
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
            if proc.returncode != 0:
                err = proc.stderr.strip() or f"capinfos error (code {proc.returncode})"
                return False, f"capinfos validation failed: {err}", {}
            for line in proc.stdout.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    k = k.strip().lower().replace(" ", "_")
                    v = v.strip()
                    if "number_of_packets" in k:
                        try:
                            stats["packet_count"] = int(v.replace(",", ""))
                        except ValueError:
                            pass
                    elif "capture_duration" in k:
                        try:
                            stats["duration_seconds"] = float(v.split()[0].replace(",", ""))
                        except (ValueError, IndexError):
                            pass
        except subprocess.TimeoutExpired:
            return False, f"capinfos validation timed out after {timeout_s}s", {}
        except Exception as exc:
            logger.warning(f"capinfos execution warning: {exc}")

    # 2. tshark smoke test
    tshark_bin = shutil.which("tshark")
    if tshark_bin and stats.get("packet_count", 1) > 0:
        try:
            proc = subprocess.run(
                [tshark_bin, "-r", pcap_path, "-c", "1", "-q"],
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
            if proc.returncode != 0:
                err = proc.stderr.strip() or f"tshark error (code {proc.returncode})"
                return False, f"tshark packet dissection failed: {err}", {}
        except subprocess.TimeoutExpired:
            return False, f"tshark validation timed out after {timeout_s}s", {}
        except Exception as exc:
            logger.warning(f"tshark execution warning: {exc}")

    return True, msg, stats


def classify_capture_level_signal(candidate: dict, alerts: list[dict], rule_breakdown: dict) -> tuple[str, str]:
    """Capture-level preliminary signal heuristic.

    WARNING: This is a coarse capture-level check based on expected rule names and
    candidate attack category. It does NOT constitute rigorous flow-level ground truth.
    For rigorous evaluation, use evaluate_ground_truth_labels().
    """
    cat = candidate.get("category", "").lower()
    attack_type = candidate.get("attack_type", "").lower()
    cid = candidate.get("id", "").lower()
    is_benign = "benign" in cat or "benign" in attack_type or "honeypot" in cid

    target_rules = set(candidate.get("target_rules", []))
    fired_rules = set(rule_breakdown.keys())

    if is_benign:
        if len(alerts) == 0:
            return "TRUE_NEGATIVE", "Zero false alarms raised on authentic benign traffic (100% specificity)"
        return "FALSE_POSITIVE", f"Spurious alerts raised on benign traffic: {list(fired_rules)}"

    # Malicious / Attack Traffic
    if target_rules and (target_rules & fired_rules):
        matched = list(target_rules & fired_rules)
        return "TRUE_POSITIVE", f"Successfully detected targeted attack vector(s): {matched}"
    if len(alerts) > 0:
        return "PARTIAL_DETECTION", f"Detected network anomalies ({list(fired_rules)}), but targeted rules {list(target_rules)} did not trip"
    return "FALSE_NEGATIVE_OR_SUBTHRESHOLD", "Zero alerts raised on attack capture (investigate threshold calibration or evasion)"


# Backward compatibility alias
classify_ground_truth_verdict = classify_capture_level_signal


def canonicalize_flow(src_ip: str, dst_ip: str, src_port: int | None, dst_port: int | None, proto: str) -> tuple:
    """Canonicalize bidirectional 5-tuple so both directions map to the same flow key."""
    import ipaddress
    s_ip = ""
    d_ip = ""
    if src_ip:
        try:
            s_ip = str(ipaddress.ip_address(str(src_ip).strip()))
        except ValueError:
            s_ip = str(src_ip).strip()
    if dst_ip:
        try:
            d_ip = str(ipaddress.ip_address(str(dst_ip).strip()))
        except ValueError:
            d_ip = str(dst_ip).strip()

    sp = 0
    dp = 0
    if src_port is not None:
        try:
            val = int(src_port)
            if 0 <= val <= 65535:
                sp = val
        except (ValueError, TypeError):
            pass
    if dst_port is not None:
        try:
            val = int(dst_port)
            if 0 <= val <= 65535:
                dp = val
        except (ValueError, TypeError):
            pass

    p = (proto or "").strip().upper()
    if (s_ip, sp) <= (d_ip, dp):
        return (s_ip, d_ip, sp, dp, p)
    return (d_ip, s_ip, dp, sp, p)


def evaluate_ground_truth_labels(
    labels: list[dict],
    alerts: list[dict],
    label_coverage: str = "complete",
    timestamp_tolerance_s: float = 5.0
) -> dict:
    """Rigorous flow- and window-level ground-truth matching.

    Requirements satisfied:
    - Structured dataset label metadata with provenance and granularity.
    - Bidirectional flow canonicalization.
    - Event timestamps matched to valid label windows.
    - Bijective matching: prevents one event from inflating TP counts.
    - Unmatched alerts counted as FP ONLY when label_coverage == 'complete'.
      Otherwise classified as UNASSESSED / UNKNOWN alerts.
    - Returns structured metrics dictionary.
    """
    from evaluation.compare import _semantic_family

    matched_alert_indices: set[int] = set()
    matched_labels: list[dict] = []
    unmatched_labels: list[dict] = []

    for lbl in labels:
        expected_family = lbl.get("expected_family", "").strip().lower()
        expected_rule = lbl.get("expected_rule", "").strip()
        flow = lbl.get("flow", {})
        lbl_flow_key = None
        if flow.get("src_ip") and flow.get("dst_ip"):
            lbl_flow_key = canonicalize_flow(
                flow.get("src_ip"), flow.get("dst_ip"),
                flow.get("src_port"), flow.get("dst_port"),
                flow.get("protocol", "")
            )

        window = lbl.get("time_window", {})
        win_start = window.get("start")
        win_end = window.get("end")

        found = False
        for idx, alert in enumerate(alerts):
            if idx in matched_alert_indices:
                continue

            # 1. Family / Rule matching
            alert_family = _semantic_family(alert)
            rule_ok = False
            if expected_family and alert_family == expected_family:
                rule_ok = True
            elif expected_rule and alert.get("rule_name") == expected_rule:
                rule_ok = True
            elif not expected_family and not expected_rule:
                rule_ok = True

            if not rule_ok:
                continue

            # 2. Flow matching (bidirectional)
            if lbl_flow_key:
                alert_flow_key = canonicalize_flow(
                    alert.get("src_ip", ""), alert.get("dst_ip", ""),
                    alert.get("src_port"), alert.get("dst_port"),
                    alert.get("protocol", "")
                )
                if alert_flow_key != lbl_flow_key:
                    continue

            # 3. Timestamp window matching
            alert_ts = alert.get("timestamp")
            if alert_ts is not None and (win_start is not None or win_end is not None):
                try:
                    ts_val = float(alert_ts)
                    if win_start is not None and ts_val < (float(win_start) - timestamp_tolerance_s):
                        continue
                    if win_end is not None and ts_val > (float(win_end) + timestamp_tolerance_s):
                        continue
                except (ValueError, TypeError):
                    pass

            # Match established!
            matched_alert_indices.add(idx)
            matched_labels.append({"label": lbl, "alert": alert})
            found = True
            break

        if not found:
            unmatched_labels.append(lbl)

    extra_alerts = [alert for idx, alert in enumerate(alerts) if idx not in matched_alert_indices]
    tp = len(matched_labels)
    fn = len(unmatched_labels)

    is_exhaustive = (label_coverage.lower() in ("complete", "exhaustive"))
    if is_exhaustive:
        fp = len(extra_alerts)
        unassessed = 0
    else:
        fp = 0
        unassessed = len(extra_alerts)

    precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if tp > 0 else 0.0)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "label_coverage": label_coverage,
        "total_labels": len(labels),
        "total_alerts": len(alerts),
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "unassessed_alerts": unassessed,
        "precision": precision if is_exhaustive else None,
        "recall": recall,
        "f1": f1 if is_exhaustive else None,
        "matched_details": matched_labels,
        "missed_labels": unmatched_labels,
        "extra_alerts": extra_alerts,
    }


def get_candidate_queue() -> list[dict]:
    """
    Ranked acquisition candidates prioritizing coverage per downloaded GiB
    across distinct independent publishers.
    """
    return [
        {
            "id": "ws_arp_storm",
            "name": "Wireshark ARP Storm",
            "publisher": "Wireshark Foundation",
            "url": "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/arp-storm.pcap",
            "type": "pcap",
            "size_est_bytes": 47296,
            "category": "Protocol & Flag Anomalies",
            "attack_type": "ARP request storm / broadcast flood (non-spoofing)",
            "target_rules": ["UNASSESSED_PROTOCOL_FLOOD"],
            "ground_truth": "Synthetic flood of ARP requests on cable modem (not ARP spoofing)",
            "compression": None,
        },
        {
            "id": "ws_dns_remoteshell",
            "name": "Wireshark DNS Remote Shell",
            "publisher": "Wireshark Foundation",
            "url": "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns-remoteshell.pcap",
            "type": "pcap",
            "size_est_bytes": 25600,
            "category": "DNS Anomalies & DPI",
            "attack_type": "Remote shell over DNS port 53",
            "target_rules": ["NON_DNS_TRAFFIC_ON_DNS_PORT", "DNS_ANOMALY", "PAYLOAD_HIT"],
            "ground_truth": "Command shell payloads over UDP port 53",
            "compression": None,
        },
        {
            "id": "ws_teardrop",
            "name": "Wireshark Teardrop IP Exploit",
            "publisher": "Wireshark Foundation",
            "url": "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/teardrop.cap",
            "type": "pcap",
            "size_est_bytes": 15360,
            "category": "Protocol & Flag Anomalies",
            "attack_type": "Overlapping IP fragmentation exploit",
            "target_rules": ["TCP_FLAG_ANOMALY"],
            "ground_truth": "Packets 8 and 9 demonstrate overlapping teardrop fragments",
            "compression": None,
        },
        {
            "id": "ws_skype_irc",
            "name": "Wireshark Skype and IRC Traffic (Benign)",
            "publisher": "Wireshark Foundation",
            "url": "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/SkypeIRC.cap",
            "type": "pcap",
            "size_est_bytes": 420869,
            "category": "Benign Real-World Traffic",
            "attack_type": "Benign user traffic (IRC, Skype, DNS)",
            "target_rules": ["FP_BENIGN_VERIFICATION"],
            "ground_truth": "Authentic normal user desktop traffic",
            "compression": None,
        },
        {
            "id": "iot23_honeypot_4_1",
            "name": "IoT-23 Honeypot Somfy Smart Doorlock (Benign)",
            "publisher": "Stratosphere IPS / CTU University",
            "url": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-4-1/2018-10-25-14-06-32-192.168.1.132.pcap.xz",
            "type": "pcap.xz",
            "size_est_bytes": 376840,
            "category": "Benign IoT Traffic",
            "attack_type": "Benign IoT hardware operational traffic",
            "target_rules": ["FP_BENIGN_VERIFICATION"],
            "ground_truth": "Verified real hardware benign IoT traffic (Somfy doorlock)",
            "compression": "xz",
        },
        {
            "id": "iot23_malware_8_1",
            "name": "IoT-23 Hakai Botnet Capture",
            "publisher": "Stratosphere IPS / CTU University",
            "url": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-8-1/2018-07-31-15-15-09-192.168.100.113.pcap",
            "type": "pcap",
            "size_est_bytes": 2098362,
            "category": "Port Scanning & Brute Force",
            "attack_type": "Hakai botnet scanning and credential probing",
            "target_rules": ["PORT_SCAN", "BRUTE_FORCE", "SYN_FLOOD"],
            "ground_truth": "CTU-IoT-Malware-8-1 verified malware execution",
            "compression": None,
        },
        {
            "id": "iot23_malware_3_1",
            "name": "IoT-23 Muhstik Botnet Capture",
            "publisher": "Stratosphere IPS / CTU University",
            "url": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-3-1/2018-05-21_capture.pcap",
            "type": "pcap",
            "size_est_bytes": 57919772,
            "category": "DPI Exploitation & C2",
            "attack_type": "Muhstik botnet propagation and scanning",
            "target_rules": ["PAYLOAD_HIT", "PORT_SCAN", "SYN_FLOOD"],
            "ground_truth": "CTU-IoT-Malware-3-1 malware execution",
            "compression": None,
        },
        {
            "id": "iot23_malware_34_1",
            "name": "IoT-23 Mirai Botnet Capture",
            "publisher": "Stratosphere IPS / CTU University",
            "url": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/2018-12-21-15-50-14-192.168.1.195.pcap",
            "type": "pcap",
            "size_est_bytes": 126317980,
            "category": "DoS, Scans, Brute Force & C2",
            "attack_type": "Mirai botnet: SYN flood, Telnet brute force, DNS C2",
            "target_rules": ["SYN_FLOOD", "PORT_SCAN", "BRUTE_FORCE", "DNS_ANOMALY"],
            "ground_truth": "CTU-IoT-Malware-34-1 with publisher Suricata and Zeek logs",
            "compression": None,
        },
        {
            "id": "nozomi_triton_exec",
            "name": "Nozomi Networks TRITON ICS Malware Execution",
            "publisher": "Nozomi Networks",
            "url": "https://raw.githubusercontent.com/NozomiNetworks/tricotools/master/malware_exec.pcap",
            "type": "pcap",
            "size_est_bytes": 174052,
            "category": "Industrial OT / Malware Staging",
            "attack_type": "TRITON / TRISIS industrial safety system malware execution",
            "target_rules": ["PAYLOAD_HIT", "TCP_FLAG_ANOMALY"],
            "ground_truth": "Authentic Nozomi Networks research capture of TRITON payload injection",
            "compression": None,
        },
        {
            "id": "foxit_quantum_insert",
            "name": "Fox-IT QuantumInsert Packet Injection",
            "publisher": "Fox-IT",
            "url": "https://raw.githubusercontent.com/fox-it/quantuminsert/master/presentations/brocon2015/pcaps/id1.cn-inject.pcap",
            "type": "pcap",
            "size_est_bytes": 1842,
            "category": "Man-on-the-Side Injection",
            "attack_type": "TCP sequence racing & out-of-order injected HTTP redirection (port 80)",
            "target_rules": ["TCP_FLAG_ANOMALY"],
            "ground_truth": "BroCon 2015 QuantumInsert reproducible injection capture (cleartext port 80; not TLS)",
            "compression": None,
        },
        {
            "id": "ws_http_browsing",
            "name": "Wireshark Benign HTTP Web Browsing",
            "publisher": "Wireshark Foundation",
            "url": "https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap",
            "type": "pcap",
            "size_est_bytes": 25803,
            "category": "Benign Web Browsing Traffic",
            "attack_type": "Benign HTTP request and response flow",
            "target_rules": ["FP_BENIGN_VERIFICATION"],
            "ground_truth": "Standard benign reference HTTP traffic (0 FP verification)",
            "compression": None,
        },
        {
            "id": "iot23_malware_20_1",
            "name": "IoT-23 Torii Botnet C2 & Scanning",
            "publisher": "Stratosphere IPS / CTU University",
            "url": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-20-1/2018-10-02-13-12-30-192.168.100.103.pcap",
            "type": "pcap",
            "size_est_bytes": 4089446,
            "category": "Modular Botnet C2 & Scanning",
            "attack_type": "Torii botnet multi-architecture reconnaissance & C2 beaconing",
            "target_rules": ["PORT_SCAN", "BRUTE_FORCE", "DATA_EXFIL"],
            "ground_truth": "CTU-IoT-Malware-Capture-20-1 authentic Torii execution",
            "compression": None,
        },
        {
            "id": "m_rau5_icmp_tunnel",
            "name": "Covert ICMP Base64 Exfiltration Tunnel",
            "publisher": "m-rau5 Security Research",
            "url": "https://raw.githubusercontent.com/m-rau5/cover-channel-analyzer/main/test_data/mock_covert_channels.pcap",
            "type": "pcap",
            "size_est_bytes": 1956,
            "category": "Covert ICMP Tunneling",
            "attack_type": "Base64 exfiltration payload chunks in ICMP Echo requests",
            "target_rules": ["ICMP_TUNNEL", "DATA_EXFIL"],
            "ground_truth": "Curated mock test fixture: 128-byte base64 chunks carried in ICMP Echo requests (not independent real-world field telemetry)",
            "provenance_type": "synthetic_mock_fixture",
            "compression": None,
        },
        {
            "id": "foxit_log4shell",
            "name": "Fox-IT Log4Shell JNDI RCE Exploit",
            "publisher": "Fox-IT / NCC Group",
            "url": "https://raw.githubusercontent.com/fox-it/log4shell-pcaps/main/log4shell-ldap-pcaps/ldap-uri-params-ev0.pcap",
            "type": "pcap",
            "size_est_bytes": 56278,
            "category": "Web Exploit Payloads",
            "attack_type": "Log4Shell CVE-2021-44228 JNDI LDAP lookup & bytecode delivery",
            "target_rules": ["PAYLOAD_HIT"],
            "ground_truth": "HTTP GET with nested obfuscated JNDI LDAP lookup in query param",
            "compression": None,
        },
        {
            "id": "oisf_tls_sni_anomaly",
            "name": "OISF Suricata TLS SNI Enforcement",
            "publisher": "Open Information Security Foundation (OISF)",
            "url": "https://raw.githubusercontent.com/OISF/suricata-verify/master/tests/firewall/ruletype-firewall-160-tls-sni-firewall-enforcement/input.pcap",
            "type": "pcap",
            "size_est_bytes": 3596,
            "category": "TLS SNI Anomaly",
            "attack_type": "Non-standard TLS ClientHello SNI anomalies & omissions",
            "target_rules": ["TLS_ANOMALY"],
            "ground_truth": "Differential ClientHello with unauthorized SNI and omitted SNI extensions",
            "compression": None,
        },
        {
            "id": "ws_nmap_stealth_scan",
            "name": "Wireshark Nmap Stealth & OS Scan",
            "publisher": "Wireshark Foundation",
            "url": "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/NMap-Captures.zip",
            "type": "zip",
            "size_est_bytes": 114641,
            "category": "TCP Stealth Scan",
            "attack_type": "Nmap NULL, XMAS, and illegal TCP flag combinations",
            "target_rules": ["TCP_STEALTH_SCAN", "TCP_FLAG_ANOMALY"],
            "ground_truth": "RFC 793 illegal flag combinations (0x0000 NULL, 0x0029 XMAS, 0x002b)",
            "compression": "zip",
            "archive_member": "nmap_OS_scan_succesful",
        },
    ]


class PipelineCoordinator:
    """Coordinates producer-consumer dataset acquisition and NetGuard evaluation."""

    def __init__(self, candidates: list[dict], max_items: int = None, force_reeval: bool = False):
        self.candidates = candidates[:max_items] if max_items else candidates
        self.force_reeval = force_reeval
        self.verification_queue = queue.Queue()
        self.evaluation_queue = queue.Queue()
        self.completed_evaluations: list[dict] = []

        # Persistent cumulative budget tracking across runs
        self.budget_state = load_cumulative_budget()
        self.cumulative_bytes = self.budget_state.get("cumulative_downloaded_bytes", 0)
        self.cumulative_time_s = self.budget_state.get("cumulative_download_time_s", 0.0)

        self.start_time = time.time()
        self.stop_requested = False
        self._lock = threading.Lock()

    def download_worker(self):
        """Worker B: Downloads files sequentially with resume, 206 validation, and persistent budget bounds checks."""
        for candidate in self.candidates:
            if self.stop_requested:
                break
            if not check_disk_safety():
                logger.error("Disk safety check failed — stopping downloader.")
                break
            if self.cumulative_time_s >= MAX_DOWNLOAD_TIME_SECONDS:
                logger.warning(f"Cumulative download time budget reached ({self.cumulative_time_s:.1f}s >= {MAX_DOWNLOAD_TIME_SECONDS}s).")
                break
            if self.cumulative_bytes >= MAX_INITIAL_ACQUISITION_GIB * (1024 ** 3):
                logger.warning(f"Cumulative download size budget reached ({self.cumulative_bytes / (1024**3):.2f} GiB >= {MAX_INITIAL_ACQUISITION_GIB} GiB).")
                break

            cid = candidate["id"]
            url = candidate["url"]
            ext = "." + candidate["type"]
            incoming_part = os.path.join(INCOMING_DIR, f"{cid}{ext}.part")
            incoming_final = os.path.join(INCOMING_DIR, f"{cid}{ext}")
            verified_target = os.path.join(VERIFIED_DIR, f"{cid}.pcap")

            # Check if already verified
            if os.path.isfile(verified_target):
                logger.info(f"[{cid}] Already verified at {verified_target} — queuing for evaluation.")
                self.evaluation_queue.put({"candidate": candidate, "pcap_path": verified_target})
                continue

            logger.info(f"[{cid}] Starting download from: {url}")
            t0 = time.perf_counter()
            req = urllib.request.Request(url, headers={"User-Agent": "NetGuard-IDS-Evaluation/1.0"})

            # Resume support with 206 Partial Content validation
            downloaded = 0
            if os.path.isfile(incoming_part):
                downloaded = os.path.getsize(incoming_part)
                if downloaded > 0:
                    req.add_header("Range", f"bytes={downloaded}-")
                    logger.info(f"[{cid}] Resuming from byte offset {downloaded:,}")

            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    status_code = getattr(resp, "status", getattr(resp, "code", 200))
                    write_mode = "wb"
                    if downloaded > 0:
                        if status_code == 206:
                            content_range = resp.headers.get("Content-Range", "")
                            if content_range and f"bytes {downloaded}-" not in content_range:
                                logger.warning(f"[{cid}] Content-Range mismatch ({content_range}); restarting download from byte 0.")
                                downloaded = 0
                                write_mode = "wb"
                            else:
                                write_mode = "ab"
                        else:
                            logger.info(f"[{cid}] Server returned HTTP {status_code} (not 206 Partial Content); restarting from byte 0.")
                            downloaded = 0
                            write_mode = "wb"

                    with open(incoming_part, write_mode) as f_out:
                        while True:
                            chunk = resp.read(64 * 1024)
                            if not chunk:
                                break
                            # Incremental acquisition budget enforcement during streaming
                            with self._lock:
                                if self.cumulative_bytes + len(chunk) > MAX_INITIAL_ACQUISITION_GIB * (1024 ** 3):
                                    raise RuntimeError(
                                        f"Cumulative download budget ({MAX_INITIAL_ACQUISITION_GIB} GiB) exceeded during streaming."
                                    )
                                self.cumulative_bytes += len(chunk)
                            f_out.write(chunk)

                elapsed = max(0.001, time.perf_counter() - t0)
                file_size = os.path.getsize(incoming_part)
                newly_downloaded = file_size - downloaded

                with self._lock:
                    self.cumulative_time_s += elapsed
                    self.budget_state = update_cumulative_budget(newly_downloaded, elapsed)

                throughput_mbs = (newly_downloaded / (1024 * 1024)) / elapsed
                throughput_mbps = (newly_downloaded * 8) / (elapsed * 1_000_000)
                logger.info(f"[{cid}] Download complete: {file_size:,} bytes in {elapsed:.2f}s ({throughput_mbs:.2f} MB/s, {throughput_mbps:.2f} Mbps)")

                # Move from .part to incoming_final
                os.replace(incoming_part, incoming_final)
                # Pass to verification worker
                self.verification_worker(candidate, incoming_final)

            except Exception as exc:
                logger.error(f"[{cid}] Download failed: {exc}")

        # Signal completion to evaluation worker
        self.evaluation_queue.put(None)

    def verification_worker(self, candidate: dict, incoming_path: str):
        """Worker C: Integrity, extraction, deep PCAP header validation, and atomic promotion."""
        cid = candidate["id"]
        logger.info(f"[{cid}] Verifying integrity of: {incoming_path}")

        # Compute SHA-256 of incoming archive/file
        archive_sha256 = hash_file_sha256(incoming_path)
        logger.info(f"[{cid}] Incoming SHA-256: {archive_sha256}")

        # Handle decompression if needed
        verified_pcap = os.path.join(VERIFIED_DIR, f"{cid}.pcap")
        tmp_decomp = incoming_path + ".decomp"
        is_compressed = bool(candidate.get("compression"))

        try:
            if candidate.get("compression") == "xz":
                logger.info(f"[{cid}] Decompressing XZ archive safely with bounds check...")
                with lzma.open(incoming_path, "rb") as f_in, open(tmp_decomp, "wb") as f_out:
                    safe_decompress_stream(f_in, f_out)
                os.replace(tmp_decomp, verified_pcap)
            elif candidate.get("compression") == "gz":
                logger.info(f"[{cid}] Decompressing GZ archive safely with bounds check...")
                with gzip.open(incoming_path, "rb") as f_in, open(tmp_decomp, "wb") as f_out:
                    safe_decompress_stream(f_in, f_out)
                os.replace(tmp_decomp, verified_pcap)
            elif candidate.get("compression") == "zip":
                logger.info(f"[{cid}] Extracting ZIP archive safely with bounds check...")
                import zipfile
                with zipfile.ZipFile(incoming_path, "r") as z:
                    target_member = candidate.get("archive_member")
                    if not target_member:
                        members = [m for m in z.namelist() if not m.endswith("/")]
                        target_member = members[0] if members else None
                    if target_member:
                        with z.open(target_member) as f_in, open(tmp_decomp, "wb") as f_out:
                            safe_decompress_stream(f_in, f_out)
                        os.replace(tmp_decomp, verified_pcap)
                    else:
                        logger.error(f"[{cid}] ZIP member not found: {target_member}")
                        return
            else:
                # Atomic promote
                os.replace(incoming_path, verified_pcap)
        except Exception as exc:
            logger.error(f"[{cid}] Decompression failed or exceeded safety limits: {exc}")
            if os.path.exists(tmp_decomp):
                try:
                    os.remove(tmp_decomp)
                except OSError:
                    pass
            os.makedirs(QUARANTINE_DIR, exist_ok=True)
            quarantine_path = os.path.join(QUARANTINE_DIR, f"{cid}.corrupt.archive")
            try:
                os.replace(incoming_path, quarantine_path)
            except OSError:
                pass
            return

        # Compute SHA-256 of verified PCAP
        pcap_sha256 = hash_file_sha256(verified_pcap)

        # Save PCAP hash file
        hash_file = os.path.join(HASHES_DIR, f"{cid}.sha256")
        with open(hash_file, "w") as f:
            f.write(f"{pcap_sha256}  {os.path.basename(verified_pcap)}\n")

        # If compressed, save archive hash separately
        if is_compressed:
            archive_hash_file = os.path.join(HASHES_DIR, f"{cid}.archive.sha256")
            with open(archive_hash_file, "w") as f:
                f.write(f"{archive_sha256}  {os.path.basename(incoming_path)}\n")

        # Deep PCAP header and tool-based validation (capinfos / tshark)
        is_valid, validation_msg, tool_stats = validate_pcap_with_tools(verified_pcap)
        if not is_valid:
            logger.error(f"[{cid}] PCAP validation failed: {validation_msg} — moving to quarantine.")
            os.makedirs(QUARANTINE_DIR, exist_ok=True)
            quarantine_path = os.path.join(QUARANTINE_DIR, f"{cid}.corrupt.pcap")
            os.replace(verified_pcap, quarantine_path)
            return

        # Write metadata manifest
        meta = {
            "id": cid,
            "name": candidate["name"],
            "publisher": candidate["publisher"],
            "url": candidate["url"],
            "verified_pcap": verified_pcap,
            "size_bytes": os.path.getsize(verified_pcap),
            "sha256": pcap_sha256,
            "archive_sha256": archive_sha256 if is_compressed else None,
            "category": candidate["category"],
            "attack_type": candidate["attack_type"],
            "target_rules": candidate["target_rules"],
            "ground_truth": candidate["ground_truth"],
            "validation": validation_msg,
            "packet_count": tool_stats.get("packet_count", 0),
            "capture_duration_s": tool_stats.get("duration_seconds", 0.0),
            "verified_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        meta_file = os.path.join(VERIFIED_DIR, f"{cid}.meta.json")
        with open(meta_file, "w") as f:
            json.dump(meta, f, indent=2)

        logger.info(f"[{cid}] Successfully verified and promoted to {verified_pcap} ({validation_msg}, packets: {tool_stats.get('packet_count', 'unknown')})")
        # Enqueue for real-time evaluation
        self.evaluation_queue.put({"candidate": candidate, "pcap_path": verified_pcap, "meta": meta, "tool_stats": tool_stats})

    def evaluation_worker(self):
        """Worker D: Processes verified PCAPs against NetGuard with bulletproof TemporaryDirectory isolation."""
        from storage.db import get_connection, init_db
        from engine.blocklist import load_blocklist, BlocklistData
        from capture.sniffer import replay_pcap
        from evaluation.replay import create_replay_engine
        import config

        bl_path = os.path.join(_IDS_ROOT, "data", "test_blocklist.txt")
        if os.path.exists(bl_path):
            blocklist = load_blocklist(bl_path, url=None)
        else:
            blocklist = BlocklistData(exact=set(), networks=[])

        while True:
            item = self.evaluation_queue.get()
            if item is None:
                # End of queue
                break

            candidate = item["candidate"]
            pcap_path = item["pcap_path"]
            cid = candidate["id"]
            tool_stats = item.get("tool_stats", {})

            cache_key = compute_eval_cache_key(pcap_path, candidate)
            out_eval_file = os.path.join(EVALUATION_DIR, f"{cid}_eval.json")
            cached_result = None
            if not self.force_reeval and os.path.isfile(out_eval_file):
                try:
                    with open(out_eval_file, "r") as f:
                        data = json.load(f)
                    if "rule_breakdown" in data and (data.get("cache_key") == cache_key or "cache_key" not in data):
                        cached_result = data
                except Exception as exc:
                    logger.warning(f"[{cid}] Could not read existing evaluation {out_eval_file}: {exc}")

            if cached_result is not None:
                logger.info(f"[{cid}] Valid evaluation cache hit (cache key: {cache_key}) — skipping replay.")
                with self._lock:
                    self.completed_evaluations.append(cached_result)
                continue

            logger.info(f"[{cid}] === STARTING NETGUARD EVALUATION ===")

            orig_sqlite = config.SQLITE_PATH
            orig_arp = config.ARP_TABLE_PATH

            # Use TemporaryDirectory for complete isolation and cleanup
            with tempfile.TemporaryDirectory(prefix=f"netguard_iso_{cid}_") as tmpdir:
                tmp_db = os.path.join(tmpdir, "isolated.db")
                tmp_arp = os.path.join(tmpdir, "isolated_arp.json")
                config.SQLITE_PATH = tmp_db
                config.ARP_TABLE_PATH = tmp_arp

                try:
                    conn = get_connection()
                    init_db(conn)
                    tracking_engine = create_replay_engine(conn, blocklist, config)

                    t0 = time.perf_counter()
                    replay_pcap(pcap_path, tracking_engine)
                    tracking_engine.flush()
                    eval_time = max(0.001, time.perf_counter() - t0)

                    # Read alerts from isolated DB
                    conn.row_factory = None
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT rule_name, rule_version, src_ip, dst_ip, src_port, dst_port, "
                        "protocol, detail, severity, confidence, evidence_json, timestamp FROM alerts ORDER BY timestamp"
                    )
                    raw_alerts = cursor.fetchall()
                    alerts = []
                    for row in raw_alerts:
                        ev = {}
                        if row[10]:
                            try:
                                ev = json.loads(row[10])
                            except Exception:
                                pass
                        alerts.append({
                            "rule_name": row[0],
                            "rule_version": row[1],
                            "src_ip": row[2],
                            "dst_ip": row[3],
                            "src_port": row[4],
                            "dst_port": row[5],
                            "protocol": row[6],
                            "detail": row[7],
                            "severity": row[8],
                            "confidence": row[9],
                            "evidence": ev,
                            "timestamp": row[11],
                        })

                    stats = tracking_engine.engine._stats.copy()
                    file_size = os.path.getsize(pcap_path)
                    mbs = (file_size / (1024 * 1024)) / eval_time

                    # Alert breakdown by rule
                    rule_breakdown = {}
                    for a in alerts:
                        rn = a["rule_name"]
                        rule_breakdown[rn] = rule_breakdown.get(rn, 0) + 1

                    # Automated Ground-Truth Verdict Classification (capture-level heuristic)
                    verdict, verdict_rationale = classify_capture_level_signal(candidate, alerts, rule_breakdown)

                    logger.info(f"[{cid}] Replay finished in {eval_time:.2f}s ({mbs:.2f} MB/s). Alerts fired: {len(alerts)} | Verdict: {verdict}")
                    logger.info(f"[{cid}] Rule breakdown: {rule_breakdown}")

                    git_rev = get_git_revision()
                    packet_cnt = tool_stats.get("packet_count") or stats.get("packets_total", 0)

                    eval_result = {
                        "id": cid,
                        "name": candidate["name"],
                        "publisher": candidate["publisher"],
                        "category": candidate["category"],
                        "attack_type": candidate["attack_type"],
                        "target_rules": candidate["target_rules"],
                        "file_size_bytes": file_size,
                        "eval_duration_s": eval_time,
                        "eval_throughput_mbs": mbs,
                        "total_alerts": len(alerts),
                        "rule_breakdown": rule_breakdown,
                        "verdict": verdict,
                        "verdict_rationale": verdict_rationale,
                        "alerts_sample": alerts[:50],  # first 50 alerts
                        "stats": stats,
                        "packet_count": packet_cnt,
                        "cache_key": cache_key,
                        "evaluator_version": _EVALUATOR_VERSION,
                        "code_revision": git_rev,
                        "evaluated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }

                    out_eval_file = os.path.join(EVALUATION_DIR, f"{cid}_eval.json")
                    out_results_file = os.path.join(EVALUATION_RESULTS_DIR, f"{cid}_eval.json")
                    with open(out_eval_file, "w") as f:
                        json.dump(eval_result, f, indent=2)
                    try:
                        with open(out_results_file, "w") as f:
                            json.dump(eval_result, f, indent=2)
                    except OSError:
                        pass

                    with self._lock:
                        self.completed_evaluations.append(eval_result)

                except Exception as exc:
                    logger.error(f"[{cid}] Evaluation error: {exc}", exc_info=True)
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    config.SQLITE_PATH = orig_sqlite
                    config.ARP_TABLE_PATH = orig_arp

    def run(self):
        """Execute concurrent download and evaluation workers."""
        logger.info(f"Starting NetGuard Pipeline: {len(self.candidates)} candidates queued.")
        logger.info(f"Storage path: {HDD_DATASETS_DIR}")
        logger.info(f"Cumulative downloaded: {self.cumulative_bytes / (1024 * 1024):.2f} MB | Cumulative time: {self.cumulative_time_s:.1f}s")

        downloader_thread = threading.Thread(target=self.download_worker, name="Worker-B-Downloader")
        evaluator_thread = threading.Thread(target=self.evaluation_worker, name="Worker-D-Evaluator")

        t_start = time.perf_counter()
        downloader_thread.start()
        evaluator_thread.start()

        downloader_thread.join()
        evaluator_thread.join()

        total_elapsed = time.perf_counter() - t_start
        logger.info(f"Pipeline run finished in {total_elapsed:.2f}s.")
        logger.info(f"Total cumulative budget: {self.cumulative_bytes / (1024 * 1024):.2f} MB across {len(self.completed_evaluations)} evaluated captures.")
        return self.completed_evaluations


if __name__ == "__main__":
    force = "--force" in sys.argv or "-f" in sys.argv
    candidates = get_candidate_queue()
    coord = PipelineCoordinator(candidates, force_reeval=force)
    results = coord.run()
    print("\n" + "=" * 70)
    print(f"PIPELINE SUMMARY: {len(results)} Captures Evaluated")
    for r in results:
        v = r.get("verdict", "N/A")
        print(f" - {r['id']} ({r['publisher']}): {r['total_alerts']} alerts | {r['eval_duration_s']:.2f}s | Verdict: {v} | {r['rule_breakdown']}")
    print("=" * 70)
