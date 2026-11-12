"""
tests/test_live_capture_metrics.py
----------------------------------
Unit and integration tests for NetGuard IDS live capture processing instrumentation.
Verifies all 10 required counters, latency percentiles, throughput rates,
thread-safety, bounded memory guarantees, JSON snapshots, and CSV timeseries.
"""

import os
import sys
import time
import json
import csv
import threading
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from capture.metrics import PacketProcessingMetrics, get_active_metrics, set_active_metrics


class TestPacketProcessingMetricsCounters:
    """Verifies all 10 required counters and performance metrics."""

    def test_01_initial_counter_state(self):
        m = PacketProcessingMetrics(latency_ring_size=1000)
        s = m.get_snapshot()
        c = s["counters"]
        assert c["callback_packets"] == 0
        assert c["extracted_packets"] == 0
        assert c["ignored_packets"] == 0
        assert c["engine_submissions"] == 0
        assert c["completed_checks"] == 0
        assert c["failed_checks"] == 0
        assert c["extraction_exceptions"] == 0
        assert c["engine_exceptions"] == 0
        assert s["latency"]["total_processing_time_seconds"] == 0.0
        assert s["latency"]["max_latency_us"] == 0.0

    def test_02_counters_hot_path_increments(self):
        m = PacketProcessingMetrics(latency_ring_size=1000)

        # 10 callback packets
        for _ in range(10):
            m.record_callback()

        # 7 extractions succeed
        for _ in range(7):
            m.record_extraction_success()
            m.record_engine_submission()

        # 2 ignored packets (e.g. non-IP/ARP)
        for _ in range(2):
            m.record_ignored()

        # 1 extraction exception
        m.record_extraction_exception(ValueError("corrupt packet header"))

        # Of the 7 submissions: 6 succeed, 1 fails in detection engine
        for i in range(6):
            m.record_check_completed(0.000100)  # 100 microseconds
        m.record_engine_exception(RuntimeError("rule error"), duration_s=0.000200)

        s = m.get_snapshot()
        c = s["counters"]
        assert c["callback_packets"] == 10
        assert c["extracted_packets"] == 7
        assert c["ignored_packets"] == 2
        assert c["extraction_exceptions"] == 1
        assert c["engine_submissions"] == 7
        assert c["completed_checks"] == 6
        assert c["engine_exceptions"] == 1
        assert c["failed_checks"] == 2  # 1 extraction + 1 engine

        # Integrity checks
        assert s["integrity_checks"]["callback_equals_extracted_plus_ignored_plus_errors"] is True
        assert s["integrity_checks"]["submissions_equal_extracted"] is True
        assert s["integrity_checks"]["submissions_equal_completed_plus_engine_exceptions"] is True

    def test_03_total_and_max_latency_recording(self):
        m = PacketProcessingMetrics(latency_ring_size=1000)

        m.record_callback()
        m.record_extraction_success()
        m.record_engine_submission()
        m.record_check_completed(0.000050)  # 50 us

        m.record_callback()
        m.record_extraction_success()
        m.record_engine_submission()
        m.record_check_completed(0.000250)  # 250 us (peak)

        m.record_callback()
        m.record_extraction_success()
        m.record_engine_submission()
        m.record_check_completed(0.000080)  # 80 us

        s = m.get_snapshot()
        lat = s["latency"]
        assert pytest.approx(lat["total_processing_time_seconds"], abs=1e-6) == 0.000380
        assert pytest.approx(lat["max_latency_us"], abs=0.1) == 250.0
        assert pytest.approx(lat["avg_latency_us"], abs=0.1) == (380.0 / 3)

    def test_04_latency_percentiles_calculation(self):
        # Insert known distribution: 100 samples from 1 us to 100 us
        m = PacketProcessingMetrics(latency_ring_size=1000)
        for i in range(1, 101):
            m.record_callback()
            m.record_extraction_success()
            m.record_engine_submission()
            m.record_check_completed(i / 1_000_000.0)

        s = m.get_snapshot()
        lat = s["latency"]
        assert pytest.approx(lat["p50_latency_us"], abs=2.0) == 50.0
        assert pytest.approx(lat["p95_latency_us"], abs=2.0) == 95.0
        assert pytest.approx(lat["p99_latency_us"], abs=2.0) == 99.0
        assert pytest.approx(lat["max_latency_us"], abs=0.1) == 100.0

    def test_05_bounded_memory_ring_buffer(self):
        # Ring buffer size = 100. Add 500 samples.
        ring_size = 100
        m = PacketProcessingMetrics(latency_ring_size=ring_size)

        for i in range(500):
            m.record_check_completed(0.000010)

        assert len(m._latencies) == ring_size
        assert m._latency_sample_count == 500
        # Snapshot still executes cleanly and bounded
        s = m.get_snapshot()
        assert s["counters"]["completed_checks"] == 500

    def test_06_current_and_peak_pps_rates(self):
        t0 = 1000.0
        m = PacketProcessingMetrics(latency_ring_size=1000, start_time=t0)

        # Simulate 12,000 packets delivered and processed in second 1
        for _ in range(12000):
            m.record_callback()
            m.record_extraction_success()
            m.record_engine_submission()
            m.record_check_completed(0.000010)

        pt1 = m.tick(now=t0 + 1.0)
        assert pt1["callback_pps"] == 12000.0
        assert pt1["extraction_pps"] == 12000.0
        assert pt1["engine_pps"] == 12000.0
        assert m._peak_engine_pps == 12000.0

        # Second 2: burst of 15,000 packets
        for _ in range(15000):
            m.record_callback()
            m.record_extraction_success()
            m.record_engine_submission()
            m.record_check_completed(0.000010)

        pt2 = m.tick(now=t0 + 2.0)
        assert pt2["engine_pps"] == 15000.0
        assert m._peak_engine_pps == 15000.0

        # Second 3: lower rate of 6,000 packets
        for _ in range(6000):
            m.record_callback()
            m.record_extraction_success()
            m.record_engine_submission()
            m.record_check_completed(0.000010)

        pt3 = m.tick(now=t0 + 3.0)
        assert pt3["engine_pps"] == 6000.0
        # Peak rate remains 15,000
        assert m._peak_engine_pps == 15000.0

    def test_07_thread_safety_multi_threaded_hot_path(self):
        m = PacketProcessingMetrics(latency_ring_size=5000)
        num_threads = 4
        packets_per_thread = 2500

        def worker():
            for _ in range(packets_per_thread):
                m.record_callback()
                m.record_extraction_success()
                m.record_engine_submission()
                m.record_check_completed(0.000020)

        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        s = m.get_snapshot()
        expected = num_threads * packets_per_thread
        assert s["counters"]["callback_packets"] == expected
        assert s["counters"]["extracted_packets"] == expected
        assert s["counters"]["completed_checks"] == expected

    def test_08_save_json_and_csv_deliverables(self, tmp_path):
        m = PacketProcessingMetrics(latency_ring_size=1000)
        for i in range(10):
            m.record_callback()
            m.record_extraction_success()
            m.record_engine_submission()
            m.record_check_completed(0.000050)
        m.tick(now=time.monotonic() + 1.0)

        json_file = str(tmp_path / "metrics.json")
        tp_csv = str(tmp_path / "throughput.csv")
        lat_csv = str(tmp_path / "latency.csv")

        m.save_json(json_file)
        m.save_timeseries_csv(tp_csv, lat_csv)

        assert os.path.exists(json_file)
        assert os.path.exists(tp_csv)
        assert os.path.exists(lat_csv)

        with open(json_file, "r") as f:
            data = json.load(f)
        assert "counters" in data
        assert "throughput" in data
        assert "latency" in data
        assert data["counters"]["completed_checks"] == 10

        with open(tp_csv, "r") as f:
            rows = list(csv.reader(f))
        assert len(rows) >= 2  # header + at least 1 point
        assert rows[0][0] == "timestamp_rel_s"
        assert rows[0][1] == "callback_pps"

        with open(lat_csv, "r") as f:
            lat_rows = list(csv.reader(f))
        assert len(lat_rows) >= 2
        assert lat_rows[0][0] == "timestamp_rel_s"
        assert lat_rows[0][1] == "avg_latency_us"

    def test_09_format_summary_readable(self):
        m = PacketProcessingMetrics(latency_ring_size=1000)
        m.record_callback()
        m.record_extraction_success()
        m.record_engine_submission()
        m.record_check_completed(0.000050)

        summary = m.format_summary()
        assert "NETGUARD IDS — LIVE CAPTURE PROCESSING METRICS SUMMARY" in summary
        assert "Callback Packets Delivered" in summary
        assert "Completed Engine Checks" in summary


class TestStartSniffInstrumentation:
    """Verifies that start_sniff correctly instruments the live packet callback."""

    def test_start_sniff_invokes_metrics(self, monkeypatch):
        from unittest.mock import MagicMock
        import capture.sniffer as sniffer_mod
        from scapy.all import Ether, IP, UDP, Raw

        # Build 3 sample packets (2 valid IP/UDP, 1 non-IP ARP or unknown)
        pkt1 = Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=1000, dport=2000) / Raw(load=b"test1")
        pkt2 = Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=1000, dport=2000) / Raw(load=b"test2")
        pkt3 = Ether(type=0x88f7)  # Precision Time Protocol (non-IP, non-ARP -> ignored)

        captured_packets = [pkt1, pkt2, pkt3]

        def fake_sniff(**kwargs):
            prn = kwargs.get("prn")
            for p in captured_packets:
                prn(p)

        monkeypatch.setattr(sniffer_mod, "sniff", fake_sniff)

        mock_engine = MagicMock()
        metrics = PacketProcessingMetrics(latency_ring_size=100)

        sniffer_mod.start_sniff(
            interface="fake0",
            rule_engine=mock_engine,
            metrics=metrics,
        )

        s = metrics.get_snapshot()
        c = s["counters"]
        assert c["callback_packets"] == 3
        assert c["extracted_packets"] == 2
        assert c["ignored_packets"] == 1
        assert c["engine_submissions"] == 2
        assert c["completed_checks"] == 2
        assert c["failed_checks"] == 0
        assert mock_engine.check.call_count == 2


class TestDashboardMetricsApi:
    """Verifies that the Flask /api/metrics route works."""

    def test_api_metrics_endpoint(self):
        from dashboard.app import app
        client = app.test_client()
        resp = client.get("/api/metrics")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "counters" in data
        assert "throughput" in data
        assert "latency" in data
        assert "callback_packets" in data["counters"]
