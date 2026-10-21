"""Regression tests for in-place upgrades from pre-idempotency SQLite schemas."""

import os
import sqlite3
import sys
import tempfile
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from storage.db import init_db


class TestLegacyDatabaseMigration(unittest.TestCase):
    def test_existing_alerts_table_gets_idempotency_column_before_index(self):
        """Upgrade an existing database without losing rows or failing on index creation."""
        old_backend = config.DB_BACKEND
        old_sqlite_path = config.SQLITE_PATH
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "legacy_alerts.db")
            conn = sqlite3.connect(db_path)
            try:
                config.DB_BACKEND = "sqlite"
                config.SQLITE_PATH = db_path

                # Model the schema from before idempotency_key was introduced.
                conn.execute(
                    """
                    CREATE TABLE alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        rule_name TEXT NOT NULL,
                        rule_version TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        src_port INTEGER,
                        dst_port INTEGER,
                        protocol TEXT,
                        detail TEXT,
                        severity TEXT DEFAULT 'medium',
                        confidence TEXT DEFAULT 'heuristic',
                        evidence_json TEXT,
                        window_start REAL,
                        window_end REAL,
                        country TEXT,
                        country_code TEXT,
                        city TEXT
                    )
                    """
                )
                conn.execute(
                    "INSERT INTO alerts(timestamp, rule_name, src_ip, dst_ip, detail) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (100.0, "LEGACY_RULE", "192.0.2.10", "192.0.2.20", "keep this alert"),
                )
                conn.commit()

                # This previously failed before _migrate_columns() could add the new column.
                init_db(conn)

                columns = {
                    row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
                }
                self.assertIn("idempotency_key", columns)

                existing = conn.execute(
                    "SELECT timestamp, rule_name, detail FROM alerts WHERE id = 1"
                ).fetchone()
                self.assertEqual(
                    existing,
                    (100.0, "LEGACY_RULE", "keep this alert"),
                    "Existing alert data must survive the migration",
                )

                indexes = {
                    row[1]: row[2]
                    for row in conn.execute("PRAGMA index_list(alerts)").fetchall()
                }
                self.assertEqual(indexes.get("idx_alerts_idempotency"), 1)

                conn.execute(
                    "INSERT INTO alerts(timestamp, rule_name, idempotency_key) VALUES (?, ?, ?)",
                    (101.0, "NEW_RULE", "unique-key"),
                )
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        "INSERT INTO alerts(timestamp, rule_name, idempotency_key) VALUES (?, ?, ?)",
                        (102.0, "DUPLICATE_RULE", "unique-key"),
                    )
            finally:
                conn.close()
                config.DB_BACKEND = old_backend
                config.SQLITE_PATH = old_sqlite_path


if __name__ == "__main__":
    unittest.main()
