"""
forensics/offline_analyzer.py
-----------------------------
Secure background PCAP / PCAPNG upload and isolated offline forensic analysis.
Ensures zero contamination of live monitoring alerts and tables by executing
replays in isolated per-job databases.
"""

import os
import sys
import time
import uuid
import json
import sqlite3
import hashlib
import logging
import threading
import concurrent.futures
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from storage.db import init_db
from capture.sniffer import replay_pcap
from engine.rules import RuleEngine
from engine.blocklist import load_blocklist

logger = logging.getLogger(__name__)

# Valid PCAP / PCAPNG magic numbers
VALID_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": "pcap (microsecond, big-endian)",
    b"\xd4\xc3\xb2\xa1": "pcap (microsecond, little-endian)",
    b"\xa1\xb2\x3c\x4d": "pcap (nanosecond, big-endian)",
    b"\x4d\x3c\xb2\xa1": "pcap (nanosecond, little-endian)",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}


def validate_pcap_header(file_path: str) -> tuple[bool, str, str]:
    """
    Validate PCAP/PCAPNG header format and magic bytes.
    Returns (is_valid, format_name, error_message).
    """
    if not os.path.isfile(file_path):
        return False, "", "File does not exist"

    size = os.path.getsize(file_path)
    if size < 24:
        return False, "", "File truncated: less than 24 bytes (minimum PCAP header size)"

    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
        if magic in VALID_PCAP_MAGICS:
            fmt = "pcapng" if magic == b"\x0a\x0d\x0d\x0a" else "pcap"
            return True, fmt, ""
        return False, "", f"Invalid magic header: {magic.hex()} (not a valid PCAP or PCAPNG capture)"
    except Exception as exc:
        return False, "", f"File read error: {exc}"


def compute_file_sha256(file_path: str) -> str:
    """Compute SHA-256 cryptographic digest of a file in streaming chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class OfflinePcapAnalyzer:
    """
    Orchestrates secure background PCAP analysis jobs in full isolation.
    """

    def __init__(self, main_conn=None, upload_dir: str = "storage/uploads", db=None, max_workers: int = 2,
                 blocklist: set | None = None, jobs_dir: str | None = None):
        self._main_conn = main_conn if main_conn is not None else db
        self._upload_dir = jobs_dir if jobs_dir is not None else upload_dir
        self._blocklist = blocklist
        self._active_jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._max_workers = max_workers
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="pcap-analyzer")
        os.makedirs(self._upload_dir, exist_ok=True)

    def set_connection(self, conn):
        with self._lock:
            self._main_conn = conn

    def create_job(self, original_filename: str, source_file_path: str) -> dict[str, Any]:
        """
        Validate uploaded capture file, register new job, and return job metadata.
        """
        is_valid, fmt, err = validate_pcap_header(source_file_path)
        if not is_valid:
            raise ValueError(f"Invalid capture file: {err}")

        file_size = os.path.getsize(source_file_path)
        file_sha256 = compute_file_sha256(source_file_path)

        job_id = f"job_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        safe_name = os.path.basename(original_filename).replace(" ", "_")
        dest_path = os.path.join(self._upload_dir, f"{job_id}_{safe_name}")

        # Atomic copy or rename to isolated storage directory
        if source_file_path != dest_path:
            import shutil
            shutil.copy2(source_file_path, dest_path)

        now = time.time()
        job_record = {
            "job_id": job_id,
            "filename": original_filename,
            "file_path": dest_path,
            "file_size": file_size,
            "sha256": file_sha256,
            "format": fmt,
            "status": "pending",
            "progress": 0.0,
            "total_packets": 0,
            "processed_packets": 0,
            "alert_count": 0,
            "duration_s": 0.0,
            "start_time": None,
            "end_time": None,
            "result_summary_json": None,
            "error_message": None,
            "created_at": now,
        }

        from storage.db import get_connection, _sqlite_lock
        try:
            conn = get_connection()
            with _sqlite_lock:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO pcap_jobs (
                        job_id, filename, file_path, file_size, sha256, format,
                        status, progress, total_packets, processed_packets, alert_count,
                        duration_s, start_time, end_time, result_summary_json, error_message, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        job_record["job_id"], job_record["filename"], job_record["file_path"],
                        job_record["file_size"], job_record["sha256"], job_record["format"],
                        job_record["status"], job_record["progress"], job_record["total_packets"],
                        job_record["processed_packets"], job_record["alert_count"], job_record["duration_s"],
                        job_record["start_time"], job_record["end_time"], job_record["result_summary_json"],
                        job_record["error_message"], job_record["created_at"],
                    )
                )
                conn.commit()
                cur.close()
            conn.close()
        except Exception as exc:
            logger.warning(f"Error persisting pcap_jobs row: {exc}")

        with self._lock:
            self._active_jobs[job_id] = job_record

        return job_record

    def run_job_async(self, job_id: str):
        """Submit offline job execution to the bounded worker pool."""
        return self._executor.submit(self._execute_job, job_id)

    def run_job_sync(self, job_id: str) -> dict[str, Any]:
        """Execute job synchronously on caller thread and return final job status."""
        self._execute_job(job_id)
        return self.get_job(job_id) or {}

    def _execute_job(self, job_id: str):
        """
        Execute PCAP replay in an isolated SQLite database to protect live monitoring.
        """
        job = self.get_job(job_id)
        if not job:
            return

        file_path = job["file_path"]
        isolated_db_path = f"/tmp/netguard_isolated_{job_id}.db"
        isolated_arp_path = f"/tmp/netguard_arp_{job_id}.json"
        isolated_spool_path = f"/tmp/netguard_spool_{job_id}.jsonl"

        start_t = time.time()
        self._update_job_status(job_id, status="running", start_time=start_t, progress=10.0)

        isolated_conn = None
        engine = None
        job_cfg = None
        try:
            # Create isolated database
            isolated_conn = sqlite3.connect(isolated_db_path, check_same_thread=False)
            isolated_conn.row_factory = sqlite3.Row
            init_db(isolated_conn)

            # Create isolated RuleEngine bound to isolated DB and isolated ARP table
            import types
            job_cfg = types.SimpleNamespace(**{k: getattr(config, k) for k in dir(config) if not k.startswith("__")})
            job_cfg.SQLITE_PATH = isolated_db_path
            job_cfg.ARP_TABLE_PATH = isolated_arp_path
            job_cfg.ALERT_SPOOL_PATH = isolated_spool_path

            threat_blocklist = self._blocklist if self._blocklist is not None else load_blocklist(getattr(job_cfg, "BLOCKLIST_PATH", config.BLOCKLIST_PATH))
            engine = RuleEngine(isolated_conn, threat_blocklist, job_cfg)

            def _on_progress(proc, tot, pct):
                progress_val = pct if pct is not None else min(95.0, round((proc / max(tot, 1)) * 100.0, 1))
                self._update_job_status(job_id, progress=progress_val, processed_packets=proc, total_packets=tot)

            # Replay PCAP with actual progress callbacks
            replay_res = replay_pcap(file_path, engine, progress_callback=_on_progress)
            processed = replay_res.get("processed", 0)
            total = replay_res.get("total", 0)

            # Flush engine to guarantee all alert writes and device writes complete
            engine.flush()
            isolated_conn.commit()

            end_t = time.time()
            duration = round(end_t - start_t, 2)

            # Extract results from isolated database
            cur = isolated_conn.cursor()
            cur.execute("SELECT COUNT(*) FROM alerts")
            alert_count = cur.fetchone()[0]

            cur.execute("SELECT rule_name, COUNT(*) as cnt FROM alerts GROUP BY rule_name ORDER BY cnt DESC")
            rule_counts = {r[0]: r[1] for r in cur.fetchall()}

            cur.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
            sev_counts = {r[0]: r[1] for r in cur.fetchall()}

            cur.execute("SELECT * FROM alerts ORDER BY timestamp ASC LIMIT 5000")
            sample_alerts = [dict(r) for r in cur.fetchall()]
            cur.close()

            summary = {
                "total_packets": total,
                "processed_packets": processed,
                "alert_count": alert_count,
                "duration_seconds": duration,
                "packets_per_sec": round(total / max(duration, 0.001), 1),
                "rule_breakdown": rule_counts,
                "severity_breakdown": sev_counts,
                "alerts": sample_alerts,
            }

            self._update_job_status(
                job_id,
                status="completed",
                progress=100.0,
                total_packets=total,
                processed_packets=processed,
                alert_count=alert_count,
                duration_s=duration,
                end_time=end_t,
                result_summary_json=json.dumps(summary),
            )
            logger.info(f"Offline PCAP job {job_id} completed successfully: {alert_count} alerts in {duration}s.")

        except Exception as exc:
            logger.error(f"Offline PCAP job {job_id} failed: {exc}", exc_info=True)
            self._update_job_status(
                job_id,
                status="failed",
                error_message=str(exc),
                end_time=time.time(),
            )
        finally:
            if engine:
                try:
                    engine.flush()
                except Exception:
                    pass
            if isolated_conn:
                try:
                    isolated_conn.close()
                except Exception:
                    pass
            # Clean up temporary isolated files
            for tmp_path in (isolated_db_path, isolated_arp_path, getattr(job_cfg, "ALERT_SPOOL_PATH", None)):
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass

    def _update_job_status(self, job_id: str, **kwargs):
        """Update job fields in memory and in main database."""
        with self._lock:
            if job_id in self._active_jobs:
                self._active_jobs[job_id].update(kwargs)

        from storage.db import get_connection, _sqlite_lock
        try:
            conn = get_connection()
            with _sqlite_lock:
                set_clauses = [f"{k} = ?" for k in kwargs.keys()]
                values = list(kwargs.values()) + [job_id]
                sql = f"UPDATE pcap_jobs SET {', '.join(set_clauses)} WHERE job_id = ?"
                cur = conn.cursor()
                cur.execute(sql, values)
                conn.commit()
                cur.close()
            conn.close()
        except Exception as exc:
            logger.debug(f"Job update note ({job_id}): {exc}")

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        """Fetch job details from DB or memory cache."""
        res = None
        with self._lock:
            if job_id in self._active_jobs:
                res = self._active_jobs[job_id].copy()

        if res is None:
            from storage.db import get_connection, _sqlite_lock
            try:
                conn = get_connection()
                with _sqlite_lock:
                    cur = conn.cursor()
                    cur.execute("SELECT * FROM pcap_jobs WHERE job_id = ?", (job_id,))
                    row = cur.fetchone()
                    cur.close()
                    res = dict(row) if row else None
                conn.close()
            except Exception as exc:
                logger.debug(f"Job fetch note ({job_id}): {exc}")

        if res and "result_summary_json" in res and res["result_summary_json"]:
            try:
                parsed = json.loads(res["result_summary_json"])
                if isinstance(parsed, dict):
                    if "alerts" in parsed:
                        res["alerts"] = parsed["alerts"]
                    if "rule_breakdown" in parsed:
                        res["rule_breakdown"] = parsed["rule_breakdown"]
                    if "severity_breakdown" in parsed:
                        res["severity_breakdown"] = parsed["severity_breakdown"]
            except Exception:
                pass

        return res

    def list_jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        """List historical PCAP analysis jobs."""
        if not self._main_conn:
            return list(self._active_jobs.values())
        cur = self._main_conn.cursor()
        cur.execute("SELECT * FROM pcap_jobs ORDER BY created_at DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        return rows

    def cleanup_job(self, job_id: str) -> bool:
        """Purge temporary storage files, isolated DB, and uploaded capture for a completed/failed job."""
        job = self.get_job(job_id)
        if not job:
            return False
        with self._lock:
            # Remove uploaded file
            file_path = job.get("file_path")
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception:
                    pass
            # Remove isolated database
            isolated_db_path = f"/tmp/netguard_isolated_{job_id}.db"
            if os.path.exists(isolated_db_path):
                try:
                    os.remove(isolated_db_path)
                except Exception:
                    pass
            # Clean up job record from active_jobs and database
            if job_id in self._active_jobs:
                del self._active_jobs[job_id]

            from storage.db import get_connection, _sqlite_lock
            try:
                conn = get_connection()
                with _sqlite_lock:
                    cur = conn.cursor()
                    cur.execute("DELETE FROM pcap_jobs WHERE job_id = ?", (job_id,))
                    conn.commit()
                    cur.close()
                conn.close()
            except Exception:
                pass
            return True

    def prune_expired_jobs(self, max_age_seconds: float = 86400):
        """Enforce disk retention policy by purging jobs older than max_age_seconds."""
        now = time.time()
        for job in self.list_jobs(limit=200):
            created_at = job.get("created_at") or 0.0
            if now - created_at > max_age_seconds:
                self.cleanup_job(job["job_id"])

    def shutdown(self, wait: bool = False):
        """Cleanly shutdown the worker pool."""
        self._executor.shutdown(wait=wait)
