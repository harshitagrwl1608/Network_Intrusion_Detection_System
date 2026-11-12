"""
capture/metrics.py
------------------
High-performance, production-safe packet processing metrics for the NetGuard IDS
live capture pipeline.

Measures the actual number of packets processed by NetGuard's detection engine,
independently of packets transmitted by traffic generators (e.g. tcpreplay)
and packets received by the network interface (e.g. veth-rx).

Required Counters:
  1.  Packets delivered to the Scapy callback (callback_packets)
  2.  Successful packet extractions (extracted_packets)
  3.  Ignored or unsupported packets (ignored_packets)
  4.  Packets submitted to RuleEngine.check() (engine_submissions)
  5.  Successfully completed engine checks (completed_checks)
  6.  Extraction exceptions (extraction_exceptions)
  7.  Detection-engine exceptions (engine_exceptions)
  8.  Total processing time (total_processing_time)
  9.  Maximum and average packet processing time (max_latency, avg_latency)
  10. Current and peak processing PPS (current_pps, peak_pps for callback,
      extraction, and engine stages)

Performance Invariants:
  - Zero lock acquisitions on the packet hot path.
  - Zero memory allocations per packet (pre-allocated ring buffer for latency percentiles).
  - Nanosecond precision duration timing via time.perf_counter().
  - Strictly bounded O(1) memory guarantees (~160 KB for 20,000 latency samples).
  - Background reporter thread decouples 1-second logging, timeseries recording,
    and percentile calculations from the packet capture loop.
  - Detection semantics, thresholds, rule ordering, and alert behavior remain 100% unchanged.
"""

import os
import sys
import time
import json
import csv
import math
import logging
import threading
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Default ring buffer size for latency sampling (20,000 samples = ~160 KB RAM)
DEFAULT_LATENCY_RING_SIZE = 20_000


class PacketProcessingMetrics:
    """
    Thread-safe, low-overhead performance monitor for the live packet capture pipeline.
    """

    def __init__(self, latency_ring_size: int = DEFAULT_LATENCY_RING_SIZE, start_time: float | None = None):
        # Master lifecycle timestamps
        self._start_time: float = start_time if start_time is not None else time.monotonic()
        self._start_perf: float = time.perf_counter()
        self._stop_time: float | None = None

        # --- 10 Core Cumulative Counters (Hot Path Primitives) ---
        self._callback_packets: int = 0         # 1. Delivered to Scapy callback
        self._extracted_packets: int = 0        # 2. Successful extractions
        self._ignored_packets: int = 0          # 3. Ignored / unsupported (non-IP, non-ARP)
        self._engine_submissions: int = 0       # 4. Submitted to RuleEngine.check()
        self._completed_checks: int = 0         # 5. Successfully completed engine checks
        self._extraction_exceptions: int = 0    # 6. Extraction exceptions
        self._engine_exceptions: int = 0        # 7. Engine check exceptions
        self._total_processing_time: float = 0.0# 8. Cumulative packet processing seconds
        self._max_processing_time: float = 0.0  # 9a. Maximum single-packet latency seconds

        # --- Latency Sampling Ring Buffer (Bounded O(1) Memory) ---
        self._ring_size: int = max(10, latency_ring_size)
        self._latencies: list[float] = [0.0] * self._ring_size
        self._latency_idx: int = 0
        self._latency_sample_count: int = 0

        # --- Periodic 1-Second Rate Tracking ---
        self._last_tick_time: float = self._start_time
        self._last_tick_callback: int = 0
        self._last_tick_extracted: int = 0
        self._last_tick_completed: int = 0

        # Current 1-second instantaneous rates (PPS)
        self._current_callback_pps: float = 0.0
        self._current_extraction_pps: float = 0.0
        self._current_engine_pps: float = 0.0

        # Peak 1-second rates observed
        self._peak_callback_pps: float = 0.0
        self._peak_extraction_pps: float = 0.0
        self._peak_engine_pps: float = 0.0

        # --- Synchronization & Background Reporter ---
        self._state_lock = threading.Lock()
        self._reporter_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._reporter_interval_s: float = 1.0

        # In-memory timeseries history (1 sample per second, bounded)
        self._timeseries: list[dict[str, Any]] = []
        self._max_timeseries_points: int = 7200  # 2 hours at 1s intervals
        self._latest_point: dict[str, Any] = {}

    def is_reporter_running(self) -> bool:
        """Check if background reporter thread is active."""
        return self._reporter_thread is not None and self._reporter_thread.is_alive()

    def reset(self, start_time: float | None = None):
        """Reset all counters and timeseries for a fresh benchmark run."""
        with self._state_lock:
            now_mono = time.monotonic() if start_time is None else start_time
            self._start_time = now_mono
            self._start_perf = time.perf_counter()
            self._stop_time = None
            self._callback_packets = 0
            self._extracted_packets = 0
            self._ignored_packets = 0
            self._engine_submissions = 0
            self._completed_checks = 0
            self._extraction_exceptions = 0
            self._engine_exceptions = 0
            self._total_processing_time = 0.0
            self._max_processing_time = 0.0
            self._latencies = [0.0] * self._ring_size
            self._latency_idx = 0
            self._latency_sample_count = 0
            self._last_tick_time = now_mono
            self._last_tick_callback = 0
            self._last_tick_extracted = 0
            self._last_tick_completed = 0
            self._current_callback_pps = 0.0
            self._current_extraction_pps = 0.0
            self._current_engine_pps = 0.0
            self._peak_callback_pps = 0.0
            self._peak_extraction_pps = 0.0
            self._peak_engine_pps = 0.0
            self._timeseries.clear()
            self._latest_point = {}

    # -----------------------------------------------------------------------
    # Hot-Path Recording Methods (Zero Locks, Zero Allocations)
    # -----------------------------------------------------------------------

    def record_callback(self):
        """Record packet receipt at the Scapy/capture callback."""
        self._callback_packets += 1

    def record_extraction_success(self):
        """Record successful packet field extraction into a normalized record."""
        self._extracted_packets += 1

    def record_ignored(self):
        """Record non-IP/non-ARP or filtered packet safely ignored."""
        self._ignored_packets += 1

    def record_extraction_exception(self, exc: Exception | None = None):
        """Record an unhandled exception during packet extraction."""
        self._extraction_exceptions += 1

    def record_engine_submission(self):
        """Record packet record submission to RuleEngine.check()."""
        self._engine_submissions += 1

    def record_check_completed(self, duration_s: float):
        """
        Record successfully completed detection-engine check and duration.
        duration_s: time in seconds measured via time.perf_counter().
        """
        self._completed_checks += 1
        self._total_processing_time += duration_s

        if duration_s > self._max_processing_time:
            self._max_processing_time = duration_s

        # Ring buffer insertion (O(1), zero allocation)
        self._latencies[self._latency_idx] = duration_s
        self._latency_idx = (self._latency_idx + 1) % self._ring_size
        self._latency_sample_count += 1

    def record_engine_exception(self, exc: Exception | None = None, duration_s: float = 0.0):
        """Record an unhandled exception inside RuleEngine.check()."""
        self._engine_exceptions += 1
        if duration_s > 0:
            self._total_processing_time += duration_s
            if duration_s > self._max_processing_time:
                self._max_processing_time = duration_s

    # -----------------------------------------------------------------------
    # Periodic Rollup & Timeseries Tick (Called once per second)
    # -----------------------------------------------------------------------

    def tick(self, now: float | None = None) -> dict[str, Any]:
        """
        Compute 1-second delta rates, update peak metrics, and record timeseries point.
        Thread-safe; avoids division spikes if called in rapid succession.
        """
        with self._state_lock:
            if now is None:
                now = time.monotonic()

            dt = now - self._last_tick_time
            if dt < 0.2 and self._latest_point:
                return dict(self._latest_point)

            if dt <= 0.0001:
                dt = 0.0001

            curr_cb = self._callback_packets
            curr_ex = self._extracted_packets
            curr_cmp = self._completed_checks

            delta_cb = curr_cb - self._last_tick_callback
            delta_ex = curr_ex - self._last_tick_extracted
            delta_cmp = curr_cmp - self._last_tick_completed

            cb_pps = delta_cb / dt
            ex_pps = delta_ex / dt
            cmp_pps = delta_cmp / dt

            self._current_callback_pps = cb_pps
            self._current_extraction_pps = ex_pps
            self._current_engine_pps = cmp_pps

            if cb_pps > self._peak_callback_pps:
                self._peak_callback_pps = cb_pps
            if ex_pps > self._peak_extraction_pps:
                self._peak_extraction_pps = ex_pps
            if cmp_pps > self._peak_engine_pps:
                self._peak_engine_pps = cmp_pps

            self._last_tick_time = now
            self._last_tick_callback = curr_cb
            self._last_tick_extracted = curr_ex
            self._last_tick_completed = curr_cmp

            elapsed_total = now - self._start_time
            lat_stats = self._compute_latency_percentiles()

            point = {
                "timestamp_rel_s": round(elapsed_total, 2),
                "callback_pps": round(cb_pps, 1),
                "extraction_pps": round(ex_pps, 1),
                "engine_pps": round(cmp_pps, 1),
                "cumulative_callback": curr_cb,
                "cumulative_extracted": curr_ex,
                "cumulative_engine": curr_cmp,
                "avg_latency_us": lat_stats["avg_us"],
                "p50_latency_us": lat_stats["p50_us"],
                "p95_latency_us": lat_stats["p95_us"],
                "p99_latency_us": lat_stats["p99_us"],
                "max_latency_us": lat_stats["max_us"],
            }

            if len(self._timeseries) >= self._max_timeseries_points:
                self._timeseries.pop(0)
            self._timeseries.append(point)
            self._latest_point = point

            return point

    # -----------------------------------------------------------------------
    # Latency Percentiles Computation (Off Hot Path)
    # -----------------------------------------------------------------------

    def _compute_latency_percentiles(self) -> dict[str, float]:
        """
        Compute average, p50, p95, p99, and max latencies from the ring buffer.
        Returns latencies converted to microseconds (us).
        """
        n_samples = min(self._latency_sample_count, self._ring_size)
        if n_samples == 0:
            return {
                "avg_us": 0.0,
                "p50_us": 0.0,
                "p95_us": 0.0,
                "p99_us": 0.0,
                "max_us": 0.0,
            }

        # Take copy of valid samples
        if self._latency_sample_count < self._ring_size:
            sample = self._latencies[:n_samples]
        else:
            sample = list(self._latencies)

        sample.sort()
        n = len(sample)

        p50 = sample[int(n * 0.50)] * 1_000_000
        p95 = sample[min(int(n * 0.95), n - 1)] * 1_000_000
        p99 = sample[min(int(n * 0.99), n - 1)] * 1_000_000

        # Cumulative average across all completed checks
        tot_checks = self._completed_checks
        if tot_checks > 0:
            avg_us = (self._total_processing_time / tot_checks) * 1_000_000
        else:
            avg_us = 0.0

        max_us = self._max_processing_time * 1_000_000

        return {
            "avg_us": round(avg_us, 2),
            "p50_us": round(p50, 2),
            "p95_us": round(p95, 2),
            "p99_us": round(p99, 2),
            "max_us": round(max_us, 2),
        }

    # -----------------------------------------------------------------------
    # Background Reporter Lifecycle
    # -----------------------------------------------------------------------

    def start_reporter(self, interval_s: float = 1.0, logger_func: Callable[[str], None] | None = None):
        """Start the background reporter thread that emits periodic stats."""
        if self._reporter_thread is not None and self._reporter_thread.is_alive():
            return

        self._reporter_interval_s = max(0.2, interval_s)
        self._stop_event.clear()

        def _reporter_loop():
            log = logger_func or logger.info
            while not self._stop_event.is_set():
                if self._stop_event.wait(timeout=self._reporter_interval_s):
                    break
                try:
                    pt = self.tick()
                    log(
                        f"[METRICS] Live Capture: elapsed={pt['timestamp_rel_s']}s | "
                        f"Callback: {pt['callback_pps']} pps (total {pt['cumulative_callback']}) | "
                        f"Extracted: {pt['extraction_pps']} pps (total {pt['cumulative_extracted']}) | "
                        f"Engine: {pt['engine_pps']} pps (total {pt['cumulative_engine']}, peak {self._peak_engine_pps:.1f} pps) | "
                        f"Latency: avg={pt['avg_latency_us']}us, p95={pt['p95_latency_us']}us, p99={pt['p99_latency_us']}us, max={pt['max_latency_us']}us | "
                        f"Errors: ext={self._extraction_exceptions}, eng={self._engine_exceptions}"
                    )
                except Exception as e:
                    logger.error(f"Metrics reporter error: {e}")

        self._reporter_thread = threading.Thread(
            target=_reporter_loop, daemon=True, name="netguard-metrics-reporter"
        )
        self._reporter_thread.start()

    def stop_reporter(self):
        """Stop the background reporter thread and perform final tick."""
        self._stop_time = time.monotonic()
        self._stop_event.set()
        if self._reporter_thread is not None:
            self._reporter_thread.join(timeout=2.0)
            self._reporter_thread = None
        self.tick()

    # -----------------------------------------------------------------------
    # Snapshots & Reporting Deliverables
    # -----------------------------------------------------------------------

    def get_snapshot(self) -> dict[str, Any]:
        """
        Generate a comprehensive, serializable JSON metrics snapshot.
        Distinguishes callback throughput, extraction throughput, and
        completed detection-engine throughput.
        """
        now = self._stop_time or time.monotonic()
        elapsed = max(0.0001, now - self._start_time)
        failed_checks = self._extraction_exceptions + self._engine_exceptions
        lat_stats = self._compute_latency_percentiles()

        # Cumulative averages
        avg_cb_pps = self._callback_packets / elapsed
        avg_ex_pps = self._extracted_packets / elapsed
        avg_eng_pps = self._completed_checks / elapsed

        return {
            "timestamp": time.time(),
            "elapsed_seconds": round(elapsed, 3),
            "counters": {
                "callback_packets": self._callback_packets,
                "extracted_packets": self._extracted_packets,
                "ignored_packets": self._ignored_packets,
                "engine_submissions": self._engine_submissions,
                "completed_checks": self._completed_checks,
                "failed_checks": failed_checks,
                "extraction_exceptions": self._extraction_exceptions,
                "engine_exceptions": self._engine_exceptions,
            },
            "throughput": {
                "callback_pps_avg": round(avg_cb_pps, 2),
                "callback_pps_current": round(self._current_callback_pps, 2),
                "callback_pps_peak": round(self._peak_callback_pps, 2),
                "extraction_pps_avg": round(avg_ex_pps, 2),
                "extraction_pps_current": round(self._current_extraction_pps, 2),
                "extraction_pps_peak": round(self._peak_extraction_pps, 2),
                "engine_pps_avg": round(avg_eng_pps, 2),
                "engine_pps_current": round(self._current_engine_pps, 2),
                "engine_pps_peak": round(self._peak_engine_pps, 2),
            },
            "latency": {
                "total_processing_time_seconds": round(self._total_processing_time, 6),
                "avg_latency_us": lat_stats["avg_us"],
                "avg_latency_ms": round(lat_stats["avg_us"] / 1000.0, 4),
                "p50_latency_us": lat_stats["p50_us"],
                "p95_latency_us": lat_stats["p95_us"],
                "p95_latency_ms": round(lat_stats["p95_us"] / 1000.0, 4),
                "p99_latency_us": lat_stats["p99_us"],
                "p99_latency_ms": round(lat_stats["p99_us"] / 1000.0, 4),
                "max_latency_us": lat_stats["max_us"],
                "max_latency_ms": round(lat_stats["max_us"] / 1000.0, 4),
            },
            "integrity_checks": {
                "callback_equals_extracted_plus_ignored_plus_errors": (
                    self._callback_packets == (
                        self._extracted_packets + self._ignored_packets + self._extraction_exceptions
                    )
                ),
                "submissions_equal_extracted": (
                    self._engine_submissions == self._extracted_packets
                ),
                "submissions_equal_completed_plus_engine_exceptions": (
                    self._engine_submissions == (self._completed_checks + self._engine_exceptions)
                ),
            },
        }

    def save_json(self, filepath: str):
        """Save JSON metrics snapshot to disk atomically."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        snapshot = self.get_snapshot()
        tmp_file = f"{filepath}.tmp_{os.getpid()}"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
        os.replace(tmp_file, filepath)
        logger.info(f"Saved processing metrics snapshot to {filepath}")

    def save_timeseries_csv(self, throughput_path: str, latency_path: str):
        """Export in-memory timeseries records to structured CSV files."""
        os.makedirs(os.path.dirname(os.path.abspath(throughput_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(latency_path)), exist_ok=True)

        with self._state_lock:
            pts = list(self._timeseries)

        # 1. Throughput Timeseries CSV
        with open(throughput_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp_rel_s",
                "callback_pps",
                "extraction_pps",
                "engine_pps",
                "cumulative_callback",
                "cumulative_extracted",
                "cumulative_engine",
            ])
            for p in pts:
                writer.writerow([
                    p["timestamp_rel_s"],
                    p["callback_pps"],
                    p["extraction_pps"],
                    p["engine_pps"],
                    p["cumulative_callback"],
                    p["cumulative_extracted"],
                    p["cumulative_engine"],
                ])

        # 2. Latency Metrics CSV
        with open(latency_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp_rel_s",
                "avg_latency_us",
                "p50_latency_us",
                "p95_latency_us",
                "p99_latency_us",
                "max_latency_us",
            ])
            for p in pts:
                writer.writerow([
                    p["timestamp_rel_s"],
                    p["avg_latency_us"],
                    p["p50_latency_us"],
                    p["p95_latency_us"],
                    p["p99_latency_us"],
                    p["max_latency_us"],
                ])

        logger.info(f"Saved throughput timeseries to {throughput_path} ({len(pts)} rows)")
        logger.info(f"Saved latency metrics to {latency_path} ({len(pts)} rows)")

    def format_summary(self) -> str:
        """Return formatted human-readable summary of capture processing."""
        s = self.get_snapshot()
        c = s["counters"]
        t = s["throughput"]
        lat = s["latency"]

        lines = [
            "=" * 70,
            "  NETGUARD IDS — LIVE CAPTURE PROCESSING METRICS SUMMARY",
            "=" * 70,
            f"  Elapsed Duration           : {s['elapsed_seconds']}s",
            f"  Callback Packets Delivered : {c['callback_packets']:,}  (avg {t['callback_pps_avg']:,.1f} pps, peak {t['callback_pps_peak']:,.1f} pps)",
            f"  Successful Extractions     : {c['extracted_packets']:,}  (avg {t['extraction_pps_avg']:,.1f} pps, peak {t['extraction_pps_peak']:,.1f} pps)",
            f"  Ignored / Unsupported Pkts : {c['ignored_packets']:,}",
            f"  Engine Submissions         : {c['engine_submissions']:,}",
            f"  Completed Engine Checks    : {c['completed_checks']:,}  (avg {t['engine_pps_avg']:,.1f} pps, peak {t['engine_pps_peak']:,.1f} pps)",
            f"  Failed Checks              : {c['failed_checks']:,}  (extraction: {c['extraction_exceptions']}, engine: {c['engine_exceptions']})",
            "-" * 70,
            f"  Average Processing Latency : {lat['avg_latency_us']} us  ({lat['avg_latency_ms']} ms)",
            f"  Median (p50) Latency       : {lat['p50_latency_us']} us",
            f"  95th Percentile (p95)      : {lat['p95_latency_us']} us  ({lat['p95_latency_ms']} ms)",
            f"  99th Percentile (p99)      : {lat['p99_latency_us']} us  ({lat['p99_latency_ms']} ms)",
            f"  Maximum Latency            : {lat['max_latency_us']} us  ({lat['max_latency_ms']} ms)",
            "=" * 70,
        ]
        return "\n".join(lines)


# Global singleton instance for live capture
_ACTIVE_METRICS: PacketProcessingMetrics | None = None
_METRICS_LOCK = threading.Lock()


def get_active_metrics() -> PacketProcessingMetrics:
    """Return the active global PacketProcessingMetrics singleton."""
    global _ACTIVE_METRICS
    with _METRICS_LOCK:
        if _ACTIVE_METRICS is None:
            _ACTIVE_METRICS = PacketProcessingMetrics()
        return _ACTIVE_METRICS


def set_active_metrics(metrics: PacketProcessingMetrics | None) -> None:
    """Explicitly set or reset the active metrics instance."""
    global _ACTIVE_METRICS
    with _METRICS_LOCK:
        _ACTIVE_METRICS = metrics
