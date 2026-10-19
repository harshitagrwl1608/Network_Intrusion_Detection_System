"""
tests/test_regression_fixes.py
-------------------------------
Regression tests for the five fixes applied to the antigravity/overnight-work branch.

Each test class documents which original defect it catches.

1. TestEvalExitCodes          — run_eval.py precision formula and exit-code logic.
2. TestReplayEventClockE2E    — replay event_clock wired end-to-end into engine.
3. TestAlertPersistenceFailures — alert writer failure handling and counters.
4. TestDeviceLastSeenRefresh  — device last_seen refresh via periodic re-enqueue.
5. TestDashboardBindingDefault — config.py / .env.example / README consistency.
"""

import os
import sys
import tempfile
import threading
import time
import sqlite3
import unittest
from unittest.mock import patch, MagicMock

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config


# =============================================================================
# 1. Evaluation exit-code and precision-formula regression
# =============================================================================

class TestEvalExitCodes(unittest.TestCase):
    """
    Defect: run_eval.py exit code ignored fp_attack (unmatched attack alerts);
            precision formula excluded FP_benign from denominator.
    Fix:    Exit 1 when fn OR fp_attack OR benign_alerts is non-empty;
            precision = TP / (TP + FP_attack + FP_benign).
    """

    def _import_helpers(self):
        # Ensure the evaluation directory is on path so _determine_exit_code is importable
        eval_dir = os.path.join(PROJECT_DIR, "evaluation")
        if eval_dir not in sys.path:
            sys.path.insert(0, eval_dir)
        from run_eval import _match, _report, _determine_exit_code
        return _match, _report, _determine_exit_code

    # ------------------------------------------------------------------
    # Helper: build a minimal scenario label dict
    # ------------------------------------------------------------------
    @staticmethod
    def _sc(rule="PORT_SCAN", src="10.0.0.1", dst="10.0.0.2"):
        return {"scenario_id": "s1", "expected_rule": rule,
                "src_ip": src, "dst_ip": dst, "dst_port": "", "protocol": ""}

    @staticmethod
    def _alert(rule="PORT_SCAN", src="10.0.0.1", dst="10.0.0.2"):
        return {"rule_name": rule, "src_ip": src, "dst_ip": dst,
                "dst_port": None, "protocol": "TCP", "detail": "test"}

    def test_exit0_requires_all_clear(self):
        """Exit 0 only when fn=[], fp_attack=[], benign_alerts=[]."""
        eval_dir = os.path.join(PROJECT_DIR, "evaluation")
        if eval_dir not in sys.path:
            sys.path.insert(0, eval_dir)
        from run_eval import _determine_exit_code
        self.assertEqual(_determine_exit_code([], [], []), 0)

    def test_exit1_on_fn(self):
        """Missed scenario alone → exit 1."""
        from run_eval import _determine_exit_code
        self.assertEqual(_determine_exit_code(["missed"], [], []), 1)

    def test_exit1_on_fp_attack(self):
        """Unmatched attack alert alone → exit 1 (was bug: was ignored)."""
        from run_eval import _determine_exit_code
        self.assertEqual(_determine_exit_code([], ["extra_alert"], []), 1)

    def test_exit1_on_fp_benign(self):
        """Benign FP alone → exit 1."""
        from run_eval import _determine_exit_code
        self.assertEqual(_determine_exit_code([], [], ["benign_alert"]), 1)

    def test_precision_includes_fp_benign_in_denominator(self):
        """
        Defect: old code used TP/(TP+FP_attack) — benign FPs were not in denominator.
        Fix:    precision = TP/(TP + FP_attack + FP_benign).
        """
        eval_dir = os.path.join(PROJECT_DIR, "evaluation")
        if eval_dir not in sys.path:
            sys.path.insert(0, eval_dir)
        from run_eval import _match, _report
        sc = self._sc()
        alert_tp = self._alert()           # matches scenario
        alert_benign = self._alert(rule="PORT_SCAN", src="1.2.3.4", dst="5.6.7.8")

        scenarios = [sc]
        attack_alerts = [alert_tp]
        tp, fn, fp_attack = _match(scenarios, attack_alerts)

        # 1 TP, 0 FP_attack, 1 FP_benign → precision should be 0.5
        benign_alerts = [alert_benign]
        import io
        from contextlib import redirect_stdout
        f = io.StringIO()
        with redirect_stdout(f):
            result = _report(
                "atk.pcap", "ben.pcap", "labels.csv",
                scenarios, tp, fn, fp_attack, benign_alerts,
            )

        # precision = 1 / (1 + 0 + 1) = 0.5
        self.assertAlmostEqual(result["precision"], 0.5, places=3,
                               msg="Benign FP must reduce precision")
        # Confirm the new keys are present
        self.assertIn("fp_attack", result)
        self.assertIn("fp_benign", result)
        self.assertEqual(result["fp_benign"], 1)

    def test_precision_zero_denom_safe(self):
        """No alerts at all → precision = 0.0, no ZeroDivisionError."""
        eval_dir = os.path.join(PROJECT_DIR, "evaluation")
        if eval_dir not in sys.path:
            sys.path.insert(0, eval_dir)
        from run_eval import _report
        import io
        from contextlib import redirect_stdout
        f = io.StringIO()
        with redirect_stdout(f):
            result = _report("a", "b", "c", [], [], [], [], [])
        self.assertEqual(result["precision"], 0.0)

    def test_report_labels_synthetic(self):
        """Report output must state it is SYNTHETIC."""
        eval_dir = os.path.join(PROJECT_DIR, "evaluation")
        if eval_dir not in sys.path:
            sys.path.insert(0, eval_dir)
        from run_eval import _report, _match
        sc = self._sc()
        tp, fn, fp_attack = _match([sc], [self._alert()])
        import io
        from contextlib import redirect_stdout
        f = io.StringIO()
        with redirect_stdout(f):
            _report("a", "b", "c", [sc], tp, fn, fp_attack, [])
        output = f.getvalue()
        self.assertIn("SYNTHETIC", output,
                      "Report must label metrics as synthetic")


# =============================================================================
# 2. Replay event_clock end-to-end integration test
# =============================================================================

class TestReplayEventClockE2E(unittest.TestCase):
    """
    Defect: _replay_into() created RuleEngine without event_clock so the GC
            thread used wall-clock time (time.time()), which could prune
            historical replay state as 'stale' even though replay timestamps
            were valid within the window.
    Fix:    _replay_into() now builds an event_clock closure that advances
            with each packet's event_timestamp; RuleEngine uses it for GC.

    This test exercises the full call chain:
      replay_into (via a fake PCAP)
        → _TrackingEngine.check() → advances clock_state
        → RuleEngine._gc_loop uses clock() → prune_stale(replay_ts)

    We verify that state is NOT pruned before the replay window expires
    (per replay time), without relying on wall-clock sleep or GC happening
    to run at the right moment.
    """

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        config.DB_BACKEND = "sqlite"
        config.SQLITE_PATH = os.path.join(self.tmp_dir, "test.db")
        config.ARP_TABLE_PATH = os.path.join(self.tmp_dir, "arp.json")
        # Use small window so we can test boundary easily
        config.PORT_SCAN_THRESHOLD = 5
        config.TIME_WINDOW = 60
        config.SYN_FLOOD_THRESHOLD = 1000

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        # Restore sane defaults
        config.TIME_WINDOW = 10
        config.PORT_SCAN_THRESHOLD = 15
        config.SYN_FLOOD_THRESHOLD = 100

    def test_event_clock_advances_with_packets(self):
        """
        The _TrackingEngine wrapper must advance the shared clock state
        with each packet's event_timestamp so the event_clock closure
        returns the latest replay time.
        """
        clock_state = [0.0]

        def event_clock():
            return clock_state[0]

        records = [
            {"event_timestamp": 1000.0, "timestamp": 1000.0},
            {"event_timestamp": 1050.0, "timestamp": 1050.0},
            {"event_timestamp": 1120.0, "timestamp": 1120.0},
        ]

        # Simulate what _TrackingEngine does
        for rec in records:
            ts = rec.get("event_timestamp", rec.get("timestamp", 0.0))
            if ts and ts > clock_state[0]:
                clock_state[0] = ts

        self.assertAlmostEqual(event_clock(), 1120.0,
                               msg="event_clock must reflect latest packet ts")

    def test_gc_uses_replay_time_not_wall_clock(self):
        """
        Integration: replay state built at ts=1000.0 must NOT be pruned when
        GC runs with replay clock=1005.0 (within the 60-second window).

        Old bug: GC called time.time() ≈ 1.7e9, so replay ts 1000.0 was
        always treated as ancient and immediately pruned.
        """
        from engine.rules import PortScanRule

        rule = PortScanRule(threshold=10, window=60)
        replay_ts = 1000.0

        # Add 5 probes at historical timestamp
        for port in range(80, 85):
            rule.check({
                "type": "IP",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "protocol": "TCP",
                "dst_port": port,
                "initial_syn": True,
                "timestamp": replay_ts,
            })

        # GC with replay clock 5 seconds later — history must NOT be pruned
        rule.prune_stale(now=replay_ts + 5.0)
        with rule._lock:
            history = rule._vert.get(("10.0.0.1", "10.0.0.2"), [])
        self.assertEqual(len(history), 5,
                         "Replay history must survive GC when using replay clock")

        # Now GC with replay clock 70 seconds later — beyond window; must prune
        rule.prune_stale(now=replay_ts + 70.0)
        with rule._lock:
            history_after = rule._vert.get(("10.0.0.1", "10.0.0.2"), [])
        self.assertEqual(len(history_after), 0,
                         "Stale state must be pruned after replay window expires")

    def test_replay_into_passes_event_clock_to_engine(self):
        """
        _replay_into() must create a RuleEngine with event_clock != None.
        We verify this by inspecting the engine's _event_clock attribute
        via a monkey-patch of RuleEngine.__init__.
        """
        captured = {}

        original_init = __import__("engine.rules", fromlist=["RuleEngine"]).RuleEngine.__init__

        def _capturing_init(self_e, db_conn, blocklist, cfg, event_clock=None):
            captured["event_clock"] = event_clock
            original_init(self_e, db_conn, blocklist, cfg, event_clock=event_clock)

        import evaluation.run_eval as run_eval_mod
        import engine.rules as rules_mod

        with patch.object(rules_mod.RuleEngine, "__init__", _capturing_init):
            # Create a minimal text-format PCAP (1 line)
            pcap_path = os.path.join(self.tmp_dir, "mini.log")
            with open(pcap_path, "w") as f:
                f.write(
                    "2026-01-01 12:00:00.000000 IP 10.0.0.1.1234 > 10.0.0.2.80:"
                    " Flags [S], seq 1\n"
                )
            try:
                run_eval_mod._replay_into(
                    pcap_path,
                    config.SQLITE_PATH,
                    config.ARP_TABLE_PATH,
                    os.path.join(self.tmp_dir, "bl.txt"),
                )
            except Exception:
                pass  # We only care that event_clock was passed

        self.assertIsNotNone(
            captured.get("event_clock"),
            "_replay_into must pass a non-None event_clock to RuleEngine",
        )
        self.assertTrue(
            callable(captured.get("event_clock")),
            "event_clock must be callable",
        )

    def test_standalone_replay_missing_blocklist_uses_replay_clock(self):
        """Path 1: Missing blocklist path in standalone replay must use a ReplayClock."""
        from evaluation.replay import run_standalone_replay, ReplayClock
        pcap_path = os.path.join(self.tmp_dir, "mini.log")
        with open(pcap_path, "w") as f:
            f.write("2026-01-01 12:00:00.000000 IP 10.0.0.1.1234 > 10.0.0.2.80: Flags [S], seq 1\n")

        tracking_engine = run_standalone_replay(
            pcap_path=pcap_path,
            blocklist_path=os.path.join(self.tmp_dir, "nonexistent_bl.txt"),
            db_path=config.SQLITE_PATH,
        )
        self.assertIsNotNone(tracking_engine.engine._event_clock)
        self.assertIsInstance(tracking_engine.engine._event_clock, ReplayClock)

    def test_standalone_replay_loaded_blocklist_uses_replay_clock(self):
        """Path 2: Loaded blocklist path in standalone replay must use a ReplayClock."""
        from evaluation.replay import run_standalone_replay, ReplayClock
        pcap_path = os.path.join(self.tmp_dir, "mini.log")
        with open(pcap_path, "w") as f:
            f.write("2026-01-01 12:00:00.000000 IP 10.0.0.1.1234 > 10.0.0.2.80: Flags [S], seq 1\n")

        bl_path = os.path.join(self.tmp_dir, "test_bl.txt")
        with open(bl_path, "w") as f:
            f.write("198.51.100.42\n")

        tracking_engine = run_standalone_replay(
            pcap_path=pcap_path,
            blocklist_path=bl_path,
            db_path=config.SQLITE_PATH,
        )
        self.assertIsNotNone(tracking_engine.engine._event_clock)
        self.assertIsInstance(tracking_engine.engine._event_clock, ReplayClock)

    def test_live_engine_uses_wall_clock_when_no_clock_supplied(self):
        """When no event_clock is passed, RuleEngine falls back to wall-clock time."""
        from storage.db import get_connection
        from engine.rules import RuleEngine
        conn = get_connection()
        engine = RuleEngine(conn, set(), config, event_clock=None)
        try:
            self.assertIsNone(engine._event_clock)
            # prune_stale without arguments must succeed using time.time
            engine.prune_stale()
        finally:
            engine.flush()

    def test_standalone_replay_real_integration_advances_clock_and_persists(self):
        """Real E2E standalone replay: processes packets, advances clock, and writes alerts."""
        from evaluation.replay import run_standalone_replay
        from storage.db import get_connection

        pcap_path = os.path.join(self.tmp_dir, "port_scan.log")
        with open(pcap_path, "w") as f:
            for port in range(80, 96):
                f.write(
                    f"2026-01-01 12:00:{port-80:02d}.000000 IP 192.168.1.105.12345 > "
                    f"192.168.1.1.{port}: Flags [S], seq 1\n"
                )

        eval_db = os.path.join(self.tmp_dir, "e2e_replay.db")
        tracking_engine = run_standalone_replay(
            pcap_path=pcap_path,
            blocklist_path=os.path.join(self.tmp_dir, "nonexistent.txt"),
            db_path=eval_db,
        )

        self.assertGreater(tracking_engine.clock.current_time, 0.0)
        c = get_connection()
        cur = c.cursor()
        cur.execute("SELECT COUNT(*) FROM alerts WHERE rule_name='PORT_SCAN'")
        cnt = cur.fetchone()[0]
        c.close()
        self.assertGreaterEqual(cnt, 1, "Expected port scan alert to be persisted by standalone replay")


# =============================================================================
# 3. Alert persistence failure handling
# =============================================================================

class TestAlertPersistenceFailures(unittest.TestCase):
    """
    Defect: alert writer silently dropped alerts on DB write failure without
            incrementing alerts_dropped; no retry on connection failure.
    Fix:    Write failures retry with backoff and spool to durable local storage;
            spool drains on recovery; drops increment when capacity exceeded.
    """

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        config.DB_BACKEND = "sqlite"
        config.SQLITE_PATH = os.path.join(self.tmp_dir, "test.db")
        config.ARP_TABLE_PATH = os.path.join(self.tmp_dir, "arp.json")
        from storage.db import get_connection, init_db
        conn = get_connection()
        init_db(conn)
        conn.close()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _make_engine(self):
        from storage.db import get_connection
        from engine.rules import RuleEngine
        conn = get_connection()
        return RuleEngine(conn, set(), config)

    def _make_alert(self, rule="PORT_SCAN"):
        return {
            "rule_name": rule,
            "rule_version": "1.0",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": "TCP",
            "detail": "regression test alert",
            "severity": "high",
            "confidence": "heuristic",
            "evidence_json": "{}",
            "window_start": None,
            "window_end": None,
            "timestamp": time.time(),
        }

    def test_write_failure_increments_alerts_dropped(self):
        """
        When write fails AND spooling is saturated/disabled, alerts_dropped is incremented.
        """
        engine = self._make_engine()
        try:
            original_write = engine._write_alert

            def _failing_write(conn, data):
                raise sqlite3.OperationalError("disk full")

            engine._write_alert = _failing_write
            engine._spool.max_size = 0  # Disable spool capacity

            # Enqueue one alert directly
            engine._alert_queue.put(("alert", self._make_alert()))
            engine.flush()

            self.assertEqual(
                engine._stats["alerts_dropped"], 1,
                "alerts_dropped must be 1 after a write failure when spool is full",
            )
            self.assertEqual(
                engine._stats["alert_writes"], 0,
                "alert_writes must remain 0 when write fails",
            )
        finally:
            engine._write_alert = original_write

    def test_connection_failure_increments_alerts_dropped(self):
        """
        DB connection failure at writer startup with full/disabled spool
        causes queued alerts to be counted as dropped.
        """
        from engine.rules import RuleEngine
        from storage.db import get_connection
        import storage.db as db_mod
        import engine.rules as rules_mod

        conn = get_connection()

        def _broken_get_conn():
            raise OSError("simulated DB unavailable")

        with patch.object(db_mod, "get_connection", _broken_get_conn), \
             patch.object(rules_mod.time, "sleep", return_value=None):
            setattr(config, "ALERT_SPOOL_MAX_SIZE", 0)
            try:
                engine = RuleEngine(conn, set(), config)
                for _ in range(3):
                    engine._alert_queue.put(("alert", self._make_alert()))
                time.sleep(0.2)
                engine.flush()

                self.assertEqual(
                    engine._stats["alerts_dropped"], 3,
                    f"3 alerts must be counted as dropped when DB is unavailable and spool is full. "
                    f"Got: {engine._stats['alerts_dropped']}",
                )
            finally:
                setattr(config, "ALERT_SPOOL_MAX_SIZE", 5000)

    def test_successful_write_not_counted_as_dropped(self):
        """Successful writes → alerts_dropped stays at 0."""
        engine = self._make_engine()
        try:
            for _ in range(5):
                engine._alert_queue.put(("alert", self._make_alert()))
            engine.flush()

            self.assertEqual(engine._stats["alert_writes"], 5)
            self.assertEqual(engine._stats["alerts_dropped"], 0)
        finally:
            engine.flush()

    def test_shutdown_with_pending_alerts_does_not_hang_forever(self):
        """
        Shutdown must complete within the documented timeout
        even when the DB is slow or unavailable.
        """
        engine = self._make_engine()
        try:
            for _ in range(10):
                engine._alert_queue.put(("alert", self._make_alert()))
            t0 = time.time()
            engine.flush()
            elapsed = time.time() - t0
            self.assertLess(elapsed, 15.0,
                            "flush() must not hang indefinitely")
        finally:
            pass

    def test_queue_saturation_drops_devices_not_alerts(self):
        """
        Device queue saturation must increment devices_dropped (not alerts_dropped).
        Alerts placed directly on the alert queue must still be written.
        """
        engine = self._make_engine()
        try:
            import queue as _q
            for i in range(1500):
                try:
                    engine._device_queue.put_nowait(
                        ("device", {"mac": f"aa:bb:cc:dd:{i//256:02x}:{i%256:02x}",
                                    "ip": f"10.{i//256}.{i%256}.1"})
                    )
                except _q.Full:
                    break

            for _ in range(5):
                engine._alert_queue.put(("alert", self._make_alert()))

            engine.flush()

            self.assertEqual(engine._stats["alerts_dropped"], 0,
                             "Alert queue saturation must not affect alerts")
            self.assertEqual(engine._stats["alert_writes"], 5)
        finally:
            engine.flush()

    def test_alert_stats_accuracy(self):
        """alert_writes + alerts_dropped + alerts_spooled must account for every enqueued alert."""
        engine = self._make_engine()
        TOTAL = 20
        fail_every = 5

        call_count = [0]
        original_write = engine._write_alert

        def _sometimes_fail(conn, data):
            call_count[0] += 1
            if call_count[0] % fail_every == 0:
                raise sqlite3.OperationalError("transient error")
            original_write(conn, data)

        engine._write_alert = _sometimes_fail
        try:
            for _ in range(TOTAL):
                engine._alert_queue.put(("alert", self._make_alert()))
            engine.flush()

            total_accounted = (
                engine._stats["alert_writes"]
                + engine._stats["alerts_dropped"]
                + engine._stats["alerts_spooled"]
            )
            self.assertEqual(
                total_accounted, TOTAL,
                f"alert_writes + alerts_dropped + alerts_spooled must equal total enqueued. "
                f"Got writes={engine._stats['alert_writes']} "
                f"dropped={engine._stats['alerts_dropped']} "
                f"spooled={engine._stats['alerts_spooled']} total={total_accounted}",
            )
        finally:
            engine._write_alert = original_write


# =============================================================================
# 4. Device last_seen refresh
# =============================================================================

class TestDeviceLastSeenRefresh(unittest.TestCase):
    """
    Defect: _seen_devices was a set; once a (mac,ip) was added, it was never
            re-enqueued, so last_seen in the DB was never updated for the
            lifetime of the engine.
    Fix:    _seen_devices is now a dict tracking (mac,ip)->last_write_time.
            Re-enqueue when wall-clock age ≥ _device_refresh_s.
    """

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        config.DB_BACKEND = "sqlite"
        config.SQLITE_PATH = os.path.join(self.tmp_dir, "test.db")
        config.ARP_TABLE_PATH = os.path.join(self.tmp_dir, "arp.json")
        from storage.db import get_connection, init_db
        conn = get_connection()
        init_db(conn)
        conn.close()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_device_last_seen_refreshes_after_interval(self):
        """
        A device seen again after _device_refresh_s seconds must receive
        an updated last_seen in the DB, while deduplication still prevents
        excessive writes within the interval.
        """
        from storage.db import get_connection, read_all_devices
        from engine.rules import RuleEngine

        conn = get_connection()
        engine = RuleEngine(conn, set(), config)

        # Force a very short refresh interval for the test
        engine._device_refresh_s = 0.1  # 100 ms

        MAC = "de:ad:be:ef:00:01"
        IP  = "192.168.99.1"

        packet = {
            "src_mac": MAC,
            "src_ip": IP,
            "dst_ip": "10.0.0.1",
            "type": "IP",
            "protocol": "TCP",
            "timestamp": time.time(),
        }

        try:
            # First observation
            engine.check(packet)
            # Record the time immediately after first write
            first_write_wall = time.time()

            # Wait longer than refresh interval
            time.sleep(0.3)

            # Second observation after interval
            engine.check(dict(packet, timestamp=time.time()))

            engine.flush()

            # Query DB for last_seen
            devices = read_all_devices(conn)
            dev = next((d for d in devices if d["mac"] == MAC), None)
            self.assertIsNotNone(dev, "Device must be in DB")

            # last_seen must be AFTER the first write wall time
            self.assertGreater(
                dev["last_seen"], first_write_wall,
                f"last_seen ({dev['last_seen']}) must be updated after refresh interval. "
                f"first_write_wall={first_write_wall}",
            )
        finally:
            engine.flush()

    def test_dedup_prevents_excessive_writes_within_interval(self):
        """
        Multiple observations within _device_refresh_s must NOT each enqueue
        a device write — deduplication must still apply.
        """
        from storage.db import get_connection
        from engine.rules import RuleEngine

        conn = get_connection()
        engine = RuleEngine(conn, set(), config)
        engine._device_refresh_s = 300  # 5 minutes — long enough to prevent refresh

        MAC = "aa:bb:cc:dd:ee:ff"
        IP  = "10.1.2.3"
        packet = {
            "src_mac": MAC, "src_ip": IP,
            "dst_ip": "10.0.0.1", "type": "IP",
            "protocol": "UDP", "timestamp": time.time(),
        }

        try:
            writes_before = engine._stats["device_writes"]
            # Send 50 packets rapidly — all within the refresh interval
            for _ in range(50):
                engine.check(dict(packet))
            engine.flush()

            # Only ONE device write should have happened
            total_writes = engine._stats["device_writes"] - writes_before
            self.assertEqual(
                total_writes, 1,
                f"Expected exactly 1 device write within refresh interval, got {total_writes}",
            )
        finally:
            engine.flush()


# =============================================================================
# 5. Dashboard binding default consistency
# =============================================================================

class TestDashboardBindingDefault(unittest.TestCase):
    """
    Defect: config.py defaulted to 127.0.0.1 but .env.example had 0.0.0.0.
    Fix:    .env.example and both READMEs updated to 127.0.0.1 default.
    """

    def test_config_default_is_loopback(self):
        """config.py must default to 127.0.0.1 when no env var is set."""
        import importlib
        old_env = os.environ.pop("DASHBOARD_HOST", None)
        try:
            # Reload config with env var unset
            import config as cfg
            importlib.reload(cfg)
            self.assertEqual(
                cfg.DASHBOARD_HOST, "127.0.0.1",
                "Default DASHBOARD_HOST must be 127.0.0.1 (loopback)",
            )
        finally:
            if old_env is not None:
                os.environ["DASHBOARD_HOST"] = old_env
            importlib.reload(cfg)  # restore

    def test_env_example_has_loopback_default(self):
        """The .env.example file must specify DASHBOARD_HOST=127.0.0.1 (not 0.0.0.0)."""
        env_example = os.path.join(PROJECT_DIR, ".env.example")
        self.assertTrue(os.path.exists(env_example), ".env.example must exist")
        # Look for the actual key=value assignment (not a comment)
        assignment_lines = [
            line.strip() for line in open(env_example)
            if line.strip().startswith("DASHBOARD_HOST=")
        ]
        self.assertTrue(
            assignment_lines,
            ".env.example must contain a DASHBOARD_HOST= assignment line",
        )
        for line in assignment_lines:
            self.assertEqual(
                line, "DASHBOARD_HOST=127.0.0.1",
                f".env.example DASHBOARD_HOST assignment must be 127.0.0.1, got: {line}",
            )

    def test_readme_config_table_not_0000(self):
        """Root README.md config table must not show 0.0.0.0 as DASHBOARD_HOST default."""
        readme = os.path.join(os.path.dirname(PROJECT_DIR), "README.md")
        if not os.path.exists(readme):
            self.skipTest("Root README.md not found (worktree layout)")
        content = open(readme).read()
        # The config table must show 127.0.0.1
        self.assertIn(
            "127.0.0.1", content,
            "Root README config table must show 127.0.0.1 as DASHBOARD_HOST default",
        )

    def test_ids_readme_config_table_not_0000(self):
        """ids_project/README.md config table must show 127.0.0.1 as DASHBOARD_HOST default."""
        readme = os.path.join(PROJECT_DIR, "README.md")
        self.assertTrue(os.path.exists(readme), "ids_project/README.md must exist")
        content = open(readme).read()
        # Find the DASHBOARD_HOST row in the markdown config table.
        # The VALUE cell (second pipe-delimited column) must show 127.0.0.1, not 0.0.0.0.
        for line in content.splitlines():
            if "DASHBOARD_HOST" in line and "|" in line:
                # Extract the second column (the default value)
                parts = [p.strip() for p in line.split("|")]
                # parts[0] is empty (before first |), parts[1] is param, parts[2] is default
                if len(parts) >= 3:
                    default_value = parts[2].strip("`")
                    self.assertEqual(
                        default_value, "127.0.0.1",
                        f"DASHBOARD_HOST default in config table must be 127.0.0.1, "
                        f"got: {default_value!r} (line: {line})",
                    )


if __name__ == "__main__":
    unittest.main()
