"""
parallel/pipeline.py
--------------------
Resource-aware parallel packet parsing and reordered stateful detection pipeline.
Preserves strict packet ordering for stateful sliding-window detection rules
via monotonic sequence tagging and a bounded reorder buffer.
"""

import os
import sys
import time
import heapq
import struct
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from capture.sniffer import _fast_extract, _extract, SCAPY_AVAILABLE
from parallel.profile import resolve_performance_profile

logger = logging.getLogger(__name__)


class ParallelReorderBuffer:
    """
    Bounded priority queue ensuring strictly ordered dispatch of parsed records.
    """

    def __init__(self, start_seq: int = 0, max_size: int = 1000):
        self._next_seq = start_seq
        self._max_size = max_size
        self._heap: list[tuple[int, dict | None]] = []
        self.dropped_records_count = 0
        self.gaps_skipped = 0

    @property
    def next_seq(self) -> int:
        return self._next_seq

    def push(self, seq_id: int, record: dict | None):
        """Insert a parsed record tagged with its sequence ID."""
        heapq.heappush(self._heap, (seq_id, record))

    def pop_ready(self) -> list[dict]:
        """
        Pop and return all contiguous records ready for sequential dispatch.
        Discards None records (unparseable / filtered packets) while advancing sequence.
        """
        ready = []
        while self._heap and self._heap[0][0] == self._next_seq:
            _, rec = heapq.heappop(self._heap)
            self._next_seq += 1
            if rec is not None:
                ready.append(rec)

        # Safety valve: if buffer exceeds max_size, advance to avoid deadlock on dropped packet
        if len(self._heap) > self._max_size:
            target_seq = self._heap[0][0]
            gap = target_seq - self._next_seq
            self.gaps_skipped += 1
            self.dropped_records_count += max(0, gap)
            logger.warning(
                f"Reorder buffer overflow ({len(self._heap)} > {self._max_size}). "
                f"Skipping gap of {gap} packets at seq {self._next_seq} to {target_seq}"
            )
            self._next_seq = target_seq
            while self._heap and self._heap[0][0] == self._next_seq:
                _, rec = heapq.heappop(self._heap)
                self._next_seq += 1
                if rec is not None:
                    ready.append(rec)

        return ready

    def is_empty(self) -> bool:
        return len(self._heap) == 0


def _parse_packet_item(item: tuple[int, bytes, float, int]) -> tuple[int, dict | None]:
    """
    Pure functional parser executed concurrently by worker threads.
    Args: (seq_id, raw_bytes, capture_ts, linktype)
    """
    seq_id, pkt_bytes, ts, linktype = item
    record = _fast_extract(pkt_bytes, ts, linktype=linktype)
    if record is not None and record.get("ip_fragmented") and SCAPY_AVAILABLE:
        try:
            from scapy.all import Ether, IP
            pkt = Ether(pkt_bytes) if linktype == 1 else IP(pkt_bytes)
            scapy_rec = _extract(pkt, capture_ts=ts)
            if scapy_rec:
                record = scapy_rec
        except Exception:
            pass
    elif record is None and SCAPY_AVAILABLE:
        try:
            from scapy.all import Ether, IP
            pkt = Ether(pkt_bytes) if linktype == 1 else IP(pkt_bytes)
            record = _extract(pkt, capture_ts=ts)
        except Exception:
            record = None
    return seq_id, record


def _parse_chunk_worker(chunk: list[tuple[int, bytes, float, int]]) -> list[tuple[int, dict | None]]:
    """Worker entry point to parse a chunk of packets."""
    return [_parse_packet_item(item) for item in chunk]


class ParallelCapturePipeline:
    """
    Multi-stage pipelined replay and capture runner:
    Stage 1: Ingestion & Sequence Tagging
    Stage 2: Parallel Parsing & Extraction Pool
    Stage 3: Ordered Reassembly Buffer
    Stage 4: Sequential Stateful Rule Evaluation & Flow Tracking
    """

    def __init__(self, rule_engine, flow_tracker=None, profile: str = "auto",
                 worker_count: int | None = None, chunk_size: int | None = None,
                 queue_max: int | None = None, reorder_max: int | None = None):
        self.rule_engine = rule_engine
        self.flow_tracker = flow_tracker
        self.profile_info = resolve_performance_profile(profile)

        self.workers = worker_count if worker_count is not None else self.profile_info["worker_count"]
        self.chunk_size = chunk_size if chunk_size is not None else self.profile_info["chunk_size"]
        reorder_cap = reorder_max if reorder_max is not None else self.profile_info["reorder_max"]
        self.reorder_buffer = ParallelReorderBuffer(max_size=reorder_cap)

    def replay_pcap(self, pcap_path: str) -> dict[str, Any]:
        """
        Replay binary PCAP through the parallel parsing and ordered detection pipeline.
        """
        if not os.path.isfile(pcap_path):
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        start_time = time.time()
        with open(pcap_path, "rb") as f:
            gh = f.read(24)
            if len(gh) < 24:
                raise ValueError("Truncated PCAP header")

            magic = gh[:4]
            if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                endian = ">"
            elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                endian = "<"
            else:
                raise ValueError(f"Unsupported PCAP magic: {magic.hex()}")

            is_nano = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
            network = struct.unpack(endian + "I", gh[20:24])[0]
            hdr_fmt = endian + "IIII"

            seq_id = 0
            current_chunk = []
            futures = []
            total_packets = 0
            processed_packets = 0

            with ThreadPoolExecutor(max_workers=self.workers) as executor:
                while True:
                    hdr_bytes = f.read(16)
                    if len(hdr_bytes) < 16:
                        break
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(hdr_fmt, hdr_bytes)
                    pkt_bytes = f.read(incl_len)
                    if len(pkt_bytes) < incl_len:
                        break

                    total_packets += 1
                    capture_ts = ts_sec + (ts_usec / 1e9 if is_nano else ts_usec / 1e6)
                    current_chunk.append((seq_id, pkt_bytes, capture_ts, network))
                    seq_id += 1

                    if len(current_chunk) >= self.chunk_size:
                        fut = executor.submit(_parse_chunk_worker, current_chunk)
                        futures.append(fut)
                        current_chunk = []

                        # Drain completed futures to avoid memory backlog
                        if len(futures) >= self.workers * 2:
                            done_fut = futures.pop(0)
                            parsed_items = done_fut.result()
                            for s_id, rec in parsed_items:
                                self.reorder_buffer.push(s_id, rec)
                            for rec in self.reorder_buffer.pop_ready():
                                if self.flow_tracker:
                                    self.flow_tracker.process_packet(rec)
                                self.rule_engine.check(rec)
                                processed_packets += 1

                # Submit remaining tail chunk
                if current_chunk:
                    futures.append(executor.submit(_parse_chunk_worker, current_chunk))

                # Drain all remaining futures in order
                for fut in futures:
                    parsed_items = fut.result()
                    for s_id, rec in parsed_items:
                        self.reorder_buffer.push(s_id, rec)
                    for rec in self.reorder_buffer.pop_ready():
                        if self.flow_tracker:
                            self.flow_tracker.process_packet(rec)
                        self.rule_engine.check(rec)
                        processed_packets += 1

        # Flush any stragglers in reorder buffer
        for rec in self.reorder_buffer.pop_ready():
            if self.flow_tracker:
                self.flow_tracker.process_packet(rec)
            self.rule_engine.check(rec)
            processed_packets += 1

        if self.flow_tracker:
            self.flow_tracker.flush()

        duration = round(time.time() - start_time, 3)
        pps = round(total_packets / max(duration, 0.001), 1)

        return {
            "total_packets": total_packets,
            "processed_packets": processed_packets,
            "dropped_records": self.reorder_buffer.dropped_records_count,
            "gaps_skipped": self.reorder_buffer.gaps_skipped,
            "duration_seconds": duration,
            "packets_per_sec": pps,
            "workers_used": self.workers,
            "profile": self.profile_info["profile"],
        }

    process_pcap_file = replay_pcap
