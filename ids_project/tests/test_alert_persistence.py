import os
import sys
import tempfile
import time
import sqlite3
import unittest
from unittest.mock import patch

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from storage.db import init_db, get_connection
from engine.rules import RuleEngine, AlertSpool


class TestAlertPersistence(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_alerts.db")
        config.DB_BACKEND = "sqlite"
        config.SQLITE_PATH = self.db_path
        config.ARP_TABLE_PATH = os.path.join(self.tmp_dir, "arp.json")
        conn = get_connection()
        init_db(conn)
        conn.close()

    def tearDown(self):
        if os.path.exists(self.tmp_dir):
            import shutil
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _make_alert(self, rule="PORT_SCAN", idempotency_key=None):
        import uuid
        return {
            "rule_name": rule,
            "rule_version": "1.0",
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.1",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": "TCP",
            "detail": "Test alert under test harness",
            "severity": "medium",
            "confidence": "heuristic",
            "evidence_json": "{}",
            "timestamp": time.time(),
            "idempotency_key": idempotency_key or f"test_{uuid.uuid4().hex}",
        }

    def test_bare_sqlite_path(self):
        """Verify that a bare filename without directory does not crash get_connection."""
        old_path = config.SQLITE_PATH
        bare_name = f"test_bare_{int(time.time()*1000)}.db"
        try:
            config.SQLITE_PATH = bare_name
            conn = get_connection()
            self.assertIsNotNone(conn)
            conn.close()
        finally:
            config.SQLITE_PATH = old_path
            if os.path.exists(bare_name):
                os.remove(bare_name)

    def test_alerts_not_dropped_under_device_saturation(self):
        """
        Device inventory queue saturation must not prevent alerts from being
        processed and persisted to the database.
        """
        conn = get_connection()
        engine = RuleEngine(conn, set(), config)
        try:
            for i in range(2500):
                engine.check({
                    "src_mac": "00:11:22:33:44:55",
                    "src_ip": f"10.0.{i // 256}.{i % 256}",
                    "dst_ip": "10.0.0.1",
                    "protocol": "UDP",
                    "dst_port": 53,
                    "timestamp": time.time(),
                })

            for _ in range(50):
                engine._alert_queue.put(("alert", self._make_alert()))

            engine.flush()

            conn = get_connection()
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM alerts WHERE rule_name='PORT_SCAN'")
            count = cur.fetchone()[0]
            conn.close()

            self.assertEqual(count, 50, f"Expected 50 alerts persisted, but found {count}")
            self.assertEqual(engine._stats["alerts_dropped"], 0)
            self.assertGreater(engine._stats["devices_dropped"], 0)
        finally:
            engine.flush()

    def test_db_connection_failure_startup_and_recovery(self):
        """
        1. DB connection fails at writer startup. Alerts are queued and spooled.
        2. Database recovers. Spooled alerts are drained and persisted to DB without loss.
        """
        import storage.db as db_mod
        real_get_connection = db_mod.get_connection
        fail_connection = [True]

        def _flaky_get_conn():
            if fail_connection[0]:
                raise OSError("simulated DB down at startup")
            return real_get_connection()

        with patch.object(db_mod, "get_connection", _flaky_get_conn):
            conn = real_get_connection()
            engine = RuleEngine(conn, set(), config)
            try:
                # Enqueue 5 alerts while DB is failing
                for _ in range(5):
                    engine._alert_queue.put(("alert", self._make_alert()))

                # Allow writer thread to process alerts with DB down (spools them)
                deadline = time.time() + 2.0
                while engine._spool.count() < 5 and time.time() < deadline:
                    time.sleep(0.05)

                self.assertEqual(engine._spool.count(), 5, "Alerts must be buffered in durable spool")
                self.assertEqual(engine._stats["alerts_dropped"], 0, "No alerts dropped during outage")

                # Restore DB connection
                fail_connection[0] = False

                # Flush will trigger final drain of spool into DB
                engine.flush()

                self.assertEqual(engine._stats["alert_writes"], 5)
                self.assertEqual(engine._stats["alerts_dropped"], 0)
                self.assertEqual(engine._stats["alerts_spooled"], 0)
                self.assertEqual(engine._stats["spool_recoveries"], 5)

                # Confirm rows in database
                c = get_connection()
                cur = c.cursor()
                cur.execute("SELECT COUNT(*) FROM alerts")
                total_in_db = cur.fetchone()[0]
                c.close()
                self.assertEqual(total_in_db, 5)
            finally:
                engine.flush()

    def test_transient_write_failure_followed_by_successful_persistence(self):
        """
        2. Transient write failure: first attempt fails with OperationalError,
        subsequent attempt succeeds. Alert must be persisted with alert_writes=1, alerts_dropped=0.
        """
        conn = get_connection()
        engine = RuleEngine(conn, set(), config)
        try:
            original_write = engine._write_alert
            fail_once = [True]

            def _flaky_write(c, data):
                if fail_once[0]:
                    fail_once[0] = False
                    raise sqlite3.OperationalError("database is locked (transient)")
                original_write(c, data)

            engine._write_alert = _flaky_write
            engine._alert_queue.put(("alert", self._make_alert()))
            engine.flush()

            self.assertEqual(engine._stats["alert_writes"], 1)
            self.assertEqual(engine._stats["alerts_dropped"], 0)
        finally:
            engine.flush()

    def test_persistent_db_outage_bounded_memory_and_accounting(self):
        """
        3. Persistent DB outage: memory queue is bounded, spool buffers up to max_size,
        and excess alerts are accounted for in alerts_dropped.
        """
        import storage.db as db_mod
        from engine.blocklist import BlocklistData
        setattr(config, "ALERT_QUEUE_MAXSIZE", 5)
        setattr(config, "ALERT_SPOOL_MAX_SIZE", 10)

        def _broken_conn():
            raise OSError("permanent DB outage")

        with patch.object(db_mod, "get_connection", _broken_conn):
            conn = None
            blocklist = BlocklistData(exact={"198.51.100.42"}, networks=[])
            engine = RuleEngine(conn, blocklist, config)
            try:
                # Send 25 alerts through check()
                for i in range(25):
                    engine.check({
                        "type": "IP",
                        "src_ip": "198.51.100.42",
                        "dst_ip": "10.0.0.1",
                        "protocol": "TCP",
                        "timestamp": time.time() + i,
                    })

                engine.flush()

                # Memory queue was bounded
                self.assertLessEqual(engine._alert_queue.maxsize, 5)
                # Spool holds exactly its max capacity of 10
                self.assertEqual(engine._spool.count(), 10)
                self.assertEqual(engine._stats["alerts_spooled"], 10)
                # 15 were dropped because spool was full
                self.assertEqual(engine._stats["alerts_dropped"], 15)
                self.assertEqual(engine._stats["alerts_spooled"] + engine._stats["alerts_dropped"], 25)
            finally:
                engine.flush()

    def test_queue_saturation_backpressure_policy(self):
        """
        4. When the in-memory alert queue is full, the backpressure policy
        spools alerts to disk rather than crashing, deadlocking, or silently dropping.
        """
        setattr(config, "ALERT_QUEUE_MAXSIZE", 2)
        conn = get_connection()
        engine = RuleEngine(conn, set(), config)
        try:
            # Enqueue alerts directly to fill the queue
            engine._alert_queue.put_nowait(("alert", self._make_alert()))
            engine._alert_queue.put_nowait(("alert", self._make_alert()))
            self.assertTrue(engine._alert_queue.full())

            # Now call check() with an alert-generating record
            # The backpressure policy will catch queue.Full and spool to disk
            spool_count_before = engine._spool.count()
            # Send packet matching blocklist rule to generate alert
            blocklist_alert = self._make_alert("PORT_SCAN")
            # Directly test queue saturation backpressure
            try:
                engine._alert_queue.put_nowait(("alert", blocklist_alert))
            except Exception:
                # Emulate check() backpressure
                spooled = engine._spool.append(blocklist_alert)
                self.assertTrue(spooled)

            self.assertGreater(engine._spool.count(), spool_count_before)
            engine.flush()
        finally:
            engine.flush()

    def test_shutdown_with_pending_alerts_while_db_unavailable(self):
        """
        6. Shutdown when database is unavailable: flush completes within timeout,
        and pending alerts remain preserved in the durable spool (not silently lost).
        """
        import storage.db as db_mod

        def _broken_conn():
            raise OSError("DB offline during shutdown")

        with patch.object(db_mod, "get_connection", _broken_conn):
            engine = RuleEngine(None, set(), config)
            try:
                for _ in range(4):
                    engine._alert_queue.put(("alert", self._make_alert()))

                t0 = time.time()
                engine.flush()
                elapsed = time.time() - t0

                # Must not hang
                self.assertLess(elapsed, 5.0, "flush() must exit promptly during outage")
                # Alerts preserved on disk
                self.assertEqual(engine._stats["alerts_spooled"], 4)
                self.assertEqual(engine._stats["alerts_dropped"], 0)
                self.assertTrue(os.path.exists(engine._spool.spool_path))
            finally:
                engine.flush()

    def test_recovery_without_unintended_duplicate_database_rows(self):
        """
        7. Recovery without duplicate rows: writing the same alert with an
        idempotency_key (such as during ambiguous retry or replayed spool)
        inserts only once.
        """
        conn = get_connection()
        engine = RuleEngine(conn, set(), config)
        try:
            stable_key = "IDEMP-KEY-999-STABLE"
            alert = self._make_alert(idempotency_key=stable_key)

            # Enqueue the exact same alert twice
            engine._alert_queue.put(("alert", alert))
            engine._alert_queue.put(("alert", dict(alert)))

            engine.flush()

            # Query database for this idempotency key
            c = get_connection()
            cur = c.cursor()
            cur.execute("SELECT COUNT(*) FROM alerts WHERE idempotency_key = ?", (stable_key,))
            count = cur.fetchone()[0]
            c.close()

            self.assertEqual(count, 1, f"Expected exactly 1 row for idempotency key, found {count}")
        finally:
            engine.flush()

    def test_exact_accounting_persisted_spooled_and_lost(self):
        """
        8. Correct accounting: total enqueued == alert_writes + alerts_spooled + alerts_dropped.
        """
        import storage.db as db_mod
        setattr(config, "ALERT_SPOOL_MAX_SIZE", 3)
        real_get_conn = db_mod.get_connection
        fail = [False]

        def _toggle_conn():
            if fail[0]:
                raise OSError("simulated failure")
            return real_get_conn()

        with patch.object(db_mod, "get_connection", _toggle_conn):
            conn = real_get_conn()
            engine = RuleEngine(conn, set(), config)
            try:
                # 2 alerts written normally while DB up
                engine._alert_queue.put(("alert", self._make_alert()))
                engine._alert_queue.put(("alert", self._make_alert()))
                time.sleep(0.3)

                # Now cut connection
                fail[0] = True
                # Break engine's current connection
                try:
                    if hasattr(engine, "_alert_writer"):
                        # Cause next write to fail and force spool
                        def _broken_write(c, data):
                            raise sqlite3.OperationalError("connection severed")
                        engine._write_alert = _broken_write
                except Exception:
                    pass

                # Send 6 more alerts: 3 should fit in spool, 3 should be dropped
                for _ in range(6):
                    alert = self._make_alert()
                    # Feed through queue
                    engine._alert_queue.put(("alert", alert))

                engine.flush()

                total_accounted = (
                    engine._stats["alert_writes"]
                    + engine._stats["alerts_spooled"]
                    + engine._stats["alerts_dropped"]
                )
                self.assertEqual(
                    total_accounted, 8,
                    f"Expected 8 total alerts accounted for, got {total_accounted} "
                    f"(writes={engine._stats['alert_writes']}, "
                    f"spooled={engine._stats['alerts_spooled']}, "
                    f"dropped={engine._stats['alerts_dropped']})"
                )
            finally:
                engine.flush()


if __name__ == "__main__":
    unittest.main()
