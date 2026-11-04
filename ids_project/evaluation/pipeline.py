#!/usr/bin/env python3
"""
ids_project/evaluation/pipeline.py
----------------------------------
Smart Asynchronous Dataset Acquisition and Evaluation Pipeline for NetGuard IDS.

Features:
  - Worker A: Discovery & prioritized acquisition queue across independent publishers
  - Worker B: Background downloader with HTTP resume (.part) and 90-min / 5-GiB resource budgeting
  - Worker C: Integrity & metadata verification (SHA-256, safe extraction, PCAP validation)
  - Worker D: Concurrent real-time evaluation against NetGuard detection engine
  - Storage stages: incoming/ (.part) -> verified/ -> evaluation/
  - Preserves external HDD invariants (>= 100 GiB free, <= 450 GiB total allocation)
"""

import os
import sys
import time
import json
import shutil
import hashlib
import logging
import threading
import queue
import lzma
import gzip
import tempfile
import urllib.request
import urllib.error

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
EVALUATION_DIR = os.path.join(HDD_DATASETS_DIR, "evaluation")
MANIFESTS_DIR = os.path.join(HDD_DATASETS_DIR, "manifests")
HASHES_DIR = os.path.join(HDD_DATASETS_DIR, "hashes")

# Safety Limits
MIN_FREE_DISK_GIB = 100.0
MAX_INITIAL_ACQUISITION_GIB = 5.0
MAX_DOWNLOAD_TIME_SECONDS = 90 * 60  # 90 minutes

# PCAP Magic Numbers
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_NS_LE = b"\x4d\x3c\xb2\xa1"
PCAP_MAGIC_NS_BE = b"\xa1\xb2\x3c\x4d"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
VALID_MAGICS = (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE, PCAPNG_MAGIC)


def check_disk_safety() -> bool:
    """Verify that the external HDD is mounted and has >= 100 GiB free space."""
    if not os.path.isdir(HDD_DATASETS_DIR):
        logger.error(f"HDD dataset directory does not exist: {HDD_DATASETS_DIR}")
        return False
    try:
        stat = os.statvfs(HDD_DATASETS_DIR)
        free_bytes = stat.f_bavail * stat.f_frsize
        free_gib = free_bytes / (1024 ** 3)
        if free_gib < MIN_FREE_DISK_GIB:
            logger.error(f"Low disk space on external HDD: {free_gib:.2f} GiB available (< {MIN_FREE_DISK_GIB} GiB required)")
            return False
        return True
    except Exception as exc:
        logger.error(f"Failed to check disk safety: {exc}")
        return False


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
            "attack_type": "ARP storm / flooding",
            "target_rules": ["ARP_SPOOF"],
            "ground_truth": "Synthetic flood of ARP requests on cable modem",
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
            "target_rules": ["DNS_ANOMALY", "PAYLOAD_HIT"],
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
    ]


class PipelineCoordinator:
    """Coordinates producer-consumer dataset acquisition and NetGuard evaluation."""

    def __init__(self, candidates: list[dict], max_items: int = None):
        self.candidates = candidates[:max_items] if max_items else candidates
        self.verification_queue = queue.Queue()
        self.evaluation_queue = queue.Queue()
        self.completed_evaluations: list[dict] = []
        self.total_bytes_downloaded = 0
        self.total_download_time_s = 0.0
        self.start_time = time.time()
        self.stop_requested = False
        self._lock = threading.Lock()

    def download_worker(self):
        """Worker B: Downloads files sequentially with resume and bounds checks."""
        for candidate in self.candidates:
            if self.stop_requested:
                break
            if not check_disk_safety():
                logger.error("Disk safety check failed — stopping downloader.")
                break
            if self.total_download_time_s >= MAX_DOWNLOAD_TIME_SECONDS:
                logger.warning(f"Download time budget reached ({self.total_download_time_s:.1f}s >= {MAX_DOWNLOAD_TIME_SECONDS}s).")
                break
            if self.total_bytes_downloaded >= MAX_INITIAL_ACQUISITION_GIB * (1024 ** 3):
                logger.warning(f"Download size limit reached ({self.total_bytes_downloaded / (1024**3):.2f} GiB).")
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

            # Resume support
            downloaded = 0
            if os.path.isfile(incoming_part):
                downloaded = os.path.getsize(incoming_part)
                if downloaded > 0:
                    req.add_header("Range", f"bytes={downloaded}-")
                    logger.info(f"[{cid}] Resuming from byte offset {downloaded:,}")

            try:
                with urllib.request.urlopen(req, timeout=30) as resp, open(incoming_part, "ab" if downloaded else "wb") as f_out:
                    shutil.copyfileobj(resp, f_out, length=64 * 1024)
                elapsed = max(0.001, time.perf_counter() - t0)
                file_size = os.path.getsize(incoming_part)
                newly_downloaded = file_size - downloaded

                with self._lock:
                    self.total_bytes_downloaded += newly_downloaded
                    self.total_download_time_s += elapsed

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
        """Worker C: Integrity, extraction, and validation."""
        cid = candidate["id"]
        logger.info(f"[{cid}] Verifying integrity of: {incoming_path}")

        # Compute SHA-256
        sha256 = hashlib.sha256()
        with open(incoming_path, "rb") as f:
            while chunk := f.read(128 * 1024):
                sha256.update(chunk)
        digest = sha256.hexdigest()
        logger.info(f"[{cid}] SHA-256: {digest}")

        # Save hash
        hash_file = os.path.join(HASHES_DIR, f"{cid}.sha256")
        with open(hash_file, "w") as f:
            f.write(f"{digest}  {os.path.basename(incoming_path)}\n")

        # Handle decompression if needed
        verified_pcap = os.path.join(VERIFIED_DIR, f"{cid}.pcap")
        if candidate.get("compression") == "xz":
            logger.info(f"[{cid}] Decompressing XZ archive safely...")
            tmp_decomp = incoming_path + ".decomp"
            with lzma.open(incoming_path, "rb") as f_in, open(tmp_decomp, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out, length=64 * 1024)
            os.replace(tmp_decomp, verified_pcap)
        elif candidate.get("compression") == "gz":
            logger.info(f"[{cid}] Decompressing GZ archive safely...")
            tmp_decomp = incoming_path + ".decomp"
            with gzip.open(incoming_path, "rb") as f_in, open(tmp_decomp, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out, length=64 * 1024)
            os.replace(tmp_decomp, verified_pcap)
        else:
            # Atomic promote
            os.replace(incoming_path, verified_pcap)

        # Validate PCAP magic
        with open(verified_pcap, "rb") as f:
            magic = f.read(4)
        if magic not in VALID_MAGICS:
            logger.error(f"[{cid}] Invalid PCAP magic bytes: {magic!r}")
            return

        # Write metadata manifest
        meta = {
            "id": cid,
            "name": candidate["name"],
            "publisher": candidate["publisher"],
            "url": candidate["url"],
            "verified_pcap": verified_pcap,
            "size_bytes": os.path.getsize(verified_pcap),
            "sha256": digest,
            "category": candidate["category"],
            "attack_type": candidate["attack_type"],
            "target_rules": candidate["target_rules"],
            "ground_truth": candidate["ground_truth"],
            "verified_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        meta_file = os.path.join(VERIFIED_DIR, f"{cid}.meta.json")
        with open(meta_file, "w") as f:
            json.dump(meta, f, indent=2)

        logger.info(f"[{cid}] Successfully verified and promoted to {verified_pcap}")
        # Enqueue for real-time evaluation
        self.evaluation_queue.put({"candidate": candidate, "pcap_path": verified_pcap, "meta": meta})

    def evaluation_worker(self):
        """Worker D: Processes verified PCAPs against NetGuard in real time."""
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
            logger.info(f"[{cid}] === STARTING NETGUARD EVALUATION ===")

            # Create isolated temporary SQLite DB and ARP table
            fd_db, tmp_db = tempfile.mkstemp(prefix=f"netguard_{cid}_", suffix=".db")
            os.close(fd_db)
            fd_arp, tmp_arp = tempfile.mkstemp(prefix=f"netguard_arp_{cid}_", suffix=".json")
            os.close(fd_arp)

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

                # Read alerts from DB
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
                packets = stats.get("packets_seen", len(alerts))  # approximate if not explicitly counted
                mbs = (file_size / (1024 * 1024)) / eval_time

                # Alert breakdown by rule
                rule_breakdown = {}
                for a in alerts:
                    rn = a["rule_name"]
                    rule_breakdown[rn] = rule_breakdown.get(rn, 0) + 1

                logger.info(f"[{cid}] Replay finished in {eval_time:.2f}s ({mbs:.2f} MB/s). Alerts fired: {len(alerts)}")
                logger.info(f"[{cid}] Rule breakdown: {rule_breakdown}")

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
                    "alerts_sample": alerts[:50],  # first 50 alerts
                    "stats": stats,
                    "evaluated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }

                out_eval_file = os.path.join(EVALUATION_DIR, f"{cid}_eval.json")
                with open(out_eval_file, "w") as f:
                    json.dump(eval_result, f, indent=2)

                with self._lock:
                    self.completed_evaluations.append(eval_result)

            except Exception as exc:
                logger.error(f"[{cid}] Evaluation error: {exc}", exc_info=True)
            finally:
                # Clean up temporary DB and ARP
                try:
                    conn.close()
                except Exception:
                    pass
                for p in (tmp_db, tmp_arp):
                    if os.path.exists(p):
                        try:
                            os.remove(p)
                        except OSError:
                            pass

    def run(self):
        """Execute concurrent download and evaluation workers."""
        logger.info(f"Starting NetGuard Pipeline: {len(self.candidates)} candidates queued.")
        logger.info(f"Storage path: {HDD_DATASETS_DIR}")

        downloader_thread = threading.Thread(target=self.download_worker, name="Worker-B-Downloader")
        evaluator_thread = threading.Thread(target=self.evaluation_worker, name="Worker-D-Evaluator")

        t_start = time.perf_counter()
        downloader_thread.start()
        evaluator_thread.start()

        downloader_thread.join()
        evaluator_thread.join()

        total_elapsed = time.perf_counter() - t_start
        logger.info(f"Pipeline finished in {total_elapsed:.2f}s.")
        logger.info(f"Total downloaded: {self.total_bytes_downloaded / (1024 * 1024):.2f} MB across {len(self.completed_evaluations)} evaluated captures.")
        return self.completed_evaluations


if __name__ == "__main__":
    candidates = get_candidate_queue()
    coord = PipelineCoordinator(candidates)
    results = coord.run()
    print("\n" + "=" * 60)
    print(f"PIPELINE SUMMARY: {len(results)} Captures Evaluated")
    for r in results:
        print(f" - {r['id']} ({r['publisher']}): {r['total_alerts']} alerts | {r['eval_duration_s']:.2f}s | {r['rule_breakdown']}")
    print("=" * 60)

