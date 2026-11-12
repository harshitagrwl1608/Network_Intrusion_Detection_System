"""
forensics/pcap_retention.py
---------------------------
Optional bounded rotating PCAP storage ring-buffer for NetGuard IDS.
Splits captured packets into indexed PCAP segments with automatic rotation,
cryptographic SHA-256 hashing, and disk quota enforcement.
"""

import os
import sys
import time
import struct
import hashlib
import logging
import threading
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config

logger = logging.getLogger(__name__)

# Standard libpcap global header (24 bytes)
# magic=0xa1b2c3d4 (microsecond resolution), version=2.4, snaplen=65535, linktype=1 (Ethernet)
PCAP_GLOBAL_HEADER = struct.pack(
    "=IHHiIII",
    0xA1B2C3D4,  # magic number
    2, 4,        # major, minor version
    0,           # thiszone (GMT)
    0,           # sigfigs
    65535,       # snaplen
    1,           # linktype: DLT_EN10MB (Ethernet)
)


class PcapRetentionManager:
    """
    Manages continuous rotating PCAP ring-buffer storage on disk.
    Enforces maximum total storage limits by purging the oldest segments first.
    """

    def __init__(self, conn=None, storage_dir: str = "storage/pcaps",
                 enabled: bool | None = None, max_total_mb: int = 500,
                 segment_max_mb: int = 50, segment_duration_s: float = 300.0):
        self._conn = conn
        self._storage_dir = storage_dir
        self._enabled = enabled if enabled is not None else getattr(config, "PCAP_RETENTION_ENABLED", False)
        self._max_total_bytes = max_total_mb * 1024 * 1024
        self._segment_max_bytes = segment_max_mb * 1024 * 1024
        self._segment_duration_s = segment_duration_s

        self._lock = threading.Lock()
        self._active_segment_id: str | None = None
        self._active_file = None
        self._active_file_path: str | None = None
        self._active_start_time: float = 0.0
        self._active_packet_count: int = 0
        self._active_byte_size: int = 0
        self._hasher = None

        if self._enabled:
            os.makedirs(self._storage_dir, exist_ok=True)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def set_connection(self, conn):
        """Update DB connection."""
        with self._lock:
            self._conn = conn

    def get_active_segment_id(self) -> str | None:
        """Return the current active segment ID."""
        with self._lock:
            return self._active_segment_id

    def record_packet(self, pkt_bytes: bytes, capture_ts: float | None = None) -> tuple[str | None, int | None]:
        """
        Record a raw wire packet into the current rotating PCAP segment.
        Returns (segment_id, packet_index), or (None, None) if retention is disabled.
        """
        if not self._enabled or not pkt_bytes:
            return None, None

        ts = capture_ts if capture_ts is not None else time.time()
        with self._lock:
            now = time.time()
            # Check if active segment needs rotation
            if (self._active_file is None or
                    self._active_byte_size >= self._segment_max_bytes or
                    (now - self._active_start_time) >= self._segment_duration_s):
                self._rotate_segment_locked(now)

            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            length = len(pkt_bytes)
            # pcap record header: ts_sec, ts_usec, incl_len, orig_len (16 bytes)
            rec_hdr = struct.pack("=IIII", sec, usec, length, length)

            self._active_file.write(rec_hdr)
            self._active_file.write(pkt_bytes)
            self._active_file.flush()

            self._hasher.update(rec_hdr)
            self._hasher.update(pkt_bytes)

            pkt_idx = self._active_packet_count
            self._active_packet_count += 1
            self._active_byte_size += 16 + length

            return self._active_segment_id, pkt_idx

    def _rotate_segment_locked(self, now: float):
        """Close current segment and open a new segment."""
        if self._active_file is not None:
            self._close_active_segment_locked()

        os.makedirs(self._storage_dir, exist_ok=True)
        seg_id = f"seg_{int(now)}_{os.urandom(4).hex()}"
        file_path = os.path.join(self._storage_dir, f"{seg_id}.pcap")

        f = open(file_path, "wb")
        f.write(PCAP_GLOBAL_HEADER)
        f.flush()

        self._active_segment_id = seg_id
        self._active_file = f
        self._active_file_path = file_path
        self._active_start_time = now
        self._active_packet_count = 0
        self._active_byte_size = len(PCAP_GLOBAL_HEADER)
        self._hasher = hashlib.sha256()
        self._hasher.update(PCAP_GLOBAL_HEADER)

        if self._conn:
            try:
                cur = self._conn.cursor()
                cur.execute(
                    "INSERT INTO pcap_segments (segment_id, file_path, start_time, packet_count, byte_size, status, created_at) "
                    "VALUES (?, ?, ?, 0, ?, 'active', ?)",
                    (seg_id, file_path, now, self._active_byte_size, now)
                )
                self._conn.commit()
                cur.close()
            except Exception as exc:
                logger.warning(f"Could not record active pcap segment {seg_id}: {exc}")

        # Enforce quota after rotation
        self._enforce_retention_locked()

    def _close_active_segment_locked(self):
        """Finalize and close active PCAP segment."""
        if self._active_file is None:
            return
        try:
            self._active_file.close()
        except Exception:
            pass

        now = time.time()
        sha256_digest = self._hasher.hexdigest() if self._hasher else ""
        seg_id = self._active_segment_id

        if self._conn and seg_id:
            try:
                cur = self._conn.cursor()
                cur.execute(
                    "UPDATE pcap_segments SET end_time = ?, packet_count = ?, byte_size = ?, sha256 = ?, status = 'closed' "
                    "WHERE segment_id = ?",
                    (now, self._active_packet_count, self._active_byte_size, sha256_digest, seg_id)
                )
                self._conn.commit()
                cur.close()
            except Exception as exc:
                logger.warning(f"Could not update closed pcap segment {seg_id}: {exc}")

        self._active_file = None
        self._active_segment_id = None
        self._hasher = None

    def _enforce_retention_locked(self):
        """Check total storage volume across segments and purge oldest if over quota."""
        if not self._conn:
            return
        try:
            cur = self._conn.cursor()
            cur.execute("SELECT segment_id, file_path, byte_size FROM pcap_segments WHERE status != 'purged' ORDER BY created_at ASC")
            rows = cur.fetchall()
            total_bytes = sum(r[2] for r in rows)

            for seg_id, path, b_size in rows:
                if total_bytes <= self._max_total_bytes:
                    break
                # Do not delete currently active file
                if seg_id == self._active_segment_id:
                    continue

                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except OSError as exc:
                        logger.warning(f"Could not delete purged segment file {path}: {exc}")

                cur.execute("UPDATE pcap_segments SET status = 'purged' WHERE segment_id = ?", (seg_id,))
                total_bytes -= b_size
                logger.info(f"Purged oldest PCAP segment {seg_id} under storage quota.")

            self._conn.commit()
            cur.close()
        except Exception as exc:
            logger.warning(f"PCAP retention quota enforcement error: {exc}")

    def close(self):
        """Flush and close retention manager cleanly."""
        with self._lock:
            self._close_active_segment_locked()

    def get_segment_status(self, segment_id: str) -> dict[str, Any] | None:
        """Query status and file presence of a segment."""
        if not self._conn:
            return None
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM pcap_segments WHERE segment_id = ?", (segment_id,))
        row = cur.fetchone()
        cur.close()
        if not row:
            return None
        d = dict(row)
        d["file_exists"] = os.path.exists(d["file_path"]) if d.get("file_path") else False
        return d
