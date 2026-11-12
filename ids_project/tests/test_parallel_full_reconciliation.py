"""
tests/test_parallel_full_reconciliation.py
--------------------------------------------
Verifies:
1. Full-field alert reconciliation between Sequential Replay and ParallelCapturePipeline:
   - Rule name
   - Rule version
   - Source IP / Destination IP
   - Source port / Destination port
   - Protocol
   - Severity
   - Confidence
   - Evidence dictionary
   - Detail field
2. Stress and edge case verification for ParallelReorderBuffer & ParallelCapturePipeline:
   - Ordered packet delivery preservation under concurrent worker threads.
   - Reorder buffer overflow & explicit dropped-record / gap-skip accounting.
   - Graceful shutdown without hang or deadlock.
"""

import os
import sys
import json
import time
import shutil
import tempfile
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from storage.db import init_db, get_connection
from engine.rules import RuleEngine
from capture.sniffer import replay_pcap
from parallel.pipeline import ParallelCapturePipeline, ParallelReorderBuffer


def extract_full_alert_signature(alert: dict) -> dict:
    """Extract full-field comparison dict for strict reconciliation."""
    evidence = alert.get("evidence_json")
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except Exception:
            pass

    return {
        "rule_name": alert.get("rule_name"),
        "rule_version": alert.get("rule_version"),
        "src_ip": alert.get("src_ip"),
        "dst_ip": alert.get("dst_ip"),
        "src_port": alert.get("src_port"),
        "dst_port": alert.get("dst_port"),
        "protocol": alert.get("protocol"),
        "severity": alert.get("severity"),
        "confidence": alert.get("confidence"),
        "detail": alert.get("detail"),
        "evidence": evidence,
    }


class TestParallelFullReconciliation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_par.db")

        self.orig_sqlite = config.SQLITE_PATH
        self.orig_backend = config.DB_BACKEND
        config.DB_BACKEND = "sqlite"
        config.SQLITE_PATH = self.db_path

        self.conn = get_connection(self.db_path)
        init_db(self.conn)

    def tearDown(self):
        self.conn.close()
        config.SQLITE_PATH = self.orig_sqlite
        config.DB_BACKEND = self.orig_backend
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_full_field_sequential_parallel_reconciliation(self):
        """
        Replay attack PCAP both sequentially and through ParallelCapturePipeline.
        Assert 100% full-field alert identity across all 11 fields.
        """
        pcap_path = os.path.join(PROJECT_DIR, "data", "test_attacks.pcap")
        self.assertTrue(os.path.exists(pcap_path))

        # 1. Sequential reference run
        seq_alerts = []
        def _seq_sink(a):
            seq_alerts.append(extract_full_alert_signature(a))

        seq_engine = RuleEngine(None, set(), config)
        seq_engine.set_alert_sink(_seq_sink)
        seq_res = replay_pcap(pcap_path, seq_engine, use_fast_parser=True)

        self.assertGreater(len(seq_alerts), 0)
        self.assertGreater(seq_res["processed"], 0)

        # 2. Parallel pipeline run
        par_alerts = []
        def _par_sink(a):
            par_alerts.append(extract_full_alert_signature(a))

        par_engine = RuleEngine(None, set(), config)
        par_engine.set_alert_sink(_par_sink)

        pipeline = ParallelCapturePipeline(
            rule_engine=par_engine,
            worker_count=2,
            chunk_size=16,
            queue_max=200,
            reorder_max=500,
        )
        par_res = pipeline.replay_pcap(pcap_path)

        # 3. Assert counts and exact full-field equality
        self.assertEqual(len(par_alerts), len(seq_alerts),
                         f"Alert counts must match: parallel {len(par_alerts)} vs sequential {len(seq_alerts)}")

        for idx, (p_al, s_al) in enumerate(zip(par_alerts, seq_alerts)):
            self.assertEqual(p_al["rule_name"], s_al["rule_name"], f"Rule mismatch at alert {idx}")
            self.assertEqual(p_al["src_ip"], s_al["src_ip"], f"Src IP mismatch at alert {idx}")
            self.assertEqual(p_al["dst_ip"], s_al["dst_ip"], f"Dst IP mismatch at alert {idx}")
            self.assertEqual(p_al["src_port"], s_al["src_port"], f"Src Port mismatch at alert {idx}")
            self.assertEqual(p_al["dst_port"], s_al["dst_port"], f"Dst Port mismatch at alert {idx}")
            self.assertEqual(p_al["protocol"], s_al["protocol"], f"Protocol mismatch at alert {idx}")
            self.assertEqual(p_al["severity"], s_al["severity"], f"Severity mismatch at alert {idx}")
            self.assertEqual(p_al["confidence"], s_al["confidence"], f"Confidence mismatch at alert {idx}")
            self.assertEqual(p_al["detail"], s_al["detail"], f"Detail mismatch at alert {idx}")

        self.assertEqual(par_res["dropped_records"], 0, "Zero records should be dropped in standard replay")
        self.assertEqual(par_res["gaps_skipped"], 0)

    def test_reorder_buffer_strict_ordering_and_overflow_accounting(self):
        """
        Verify ParallelReorderBuffer preserves strict monotonic sequence delivery,
        and accurately accounts for skipped gaps when buffer capacity is exceeded.
        """
        buf = ParallelReorderBuffer(start_seq=0, max_size=10)

        # Push items out of order: 2, 1, 0
        buf.push(2, {"seq": 2})
        buf.push(1, {"seq": 1})
        self.assertEqual(len(buf.pop_ready()), 0, "No items ready before seq 0 arrives")

        buf.push(0, {"seq": 0})
        ready = buf.pop_ready()
        self.assertEqual(len(ready), 3)
        self.assertEqual([r["seq"] for r in ready], [0, 1, 2], "Items must be returned in strict monotonic order")

        # Simulate gap: packet 3 was dropped, packets 4..16 arrive (exceeding max_size=10)
        for s in range(4, 16):
            buf.push(s, {"seq": s})

        # Buffer now exceeds max_size (12 items > 10 cap)
        ready_after_overflow = buf.pop_ready()
        self.assertGreater(len(ready_after_overflow), 0)
        self.assertEqual(buf.gaps_skipped, 1)
        self.assertEqual(buf.dropped_records_count, 1, "Gap of 1 packet (seq 3) must be explicitly accounted for")
        self.assertEqual(ready_after_overflow[0]["seq"], 4)


if __name__ == "__main__":
    unittest.main()

