"""
tests/test_postgres_dialects.py
---------------------------------
Verifies SQL dialect compatibility between SQLite and PostgreSQL:
1. Validates PostgreSQL schemas (SCHEMA_PG, FORENSICS_SCHEMA_PG) have valid syntax
   (e.g., SERIAL instead of AUTOINCREMENT, DOUBLE PRECISION instead of REAL).
2. Verifies parameter placeholders switch correctly to %s when config.DB_BACKEND == 'postgres'
   across storage/db.py, storage/forensics_db.py, analytics/baselines.py, and notifications/outbox.py.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from storage.db import SCHEMA_SQL, SCHEMA_PG, write_alert
from storage.forensics_db import FORENSICS_SCHEMA_SQL, FORENSICS_SCHEMA_PG, write_packet_event, upsert_network_flow
from analytics.baselines import BaselineEngine, _is_postgres
from notifications.outbox import NotificationOutboxManager


class TestPostgresDialects(unittest.TestCase):
    def test_schema_syntax_differences(self):
        """Ensure PostgreSQL schemas use PostgreSQL data types and do not contain SQLite AUTOINCREMENT."""
        self.assertIn("SERIAL", SCHEMA_PG)
        self.assertIn("PRIMARY KEY", SCHEMA_PG)
        self.assertNotIn("AUTOINCREMENT", SCHEMA_PG)
        self.assertIn("DOUBLE PRECISION", SCHEMA_PG)

        self.assertIn("SERIAL", FORENSICS_SCHEMA_PG)
        self.assertIn("PRIMARY KEY", FORENSICS_SCHEMA_PG)
        self.assertNotIn("AUTOINCREMENT", FORENSICS_SCHEMA_PG)
        self.assertIn("DOUBLE PRECISION", FORENSICS_SCHEMA_PG)

    def test_parameter_placeholder_switching(self):
        """Verify queries emit %s placeholders when DB_BACKEND is set to postgres."""
        orig_backend = config.DB_BACKEND
        try:
            config.DB_BACKEND = "postgres"
            self.assertTrue(_is_postgres())

            mock_conn = MagicMock()
            mock_cur = MagicMock()
            mock_conn.cursor.return_value = mock_cur

            # 1. write_alert
            alert = {
                "rule_name": "PORT_SCAN",
                "src_ip": "1.2.3.4",
                "dst_ip": "5.6.7.8",
                "timestamp": 12345.0,
            }
            write_alert(mock_conn, alert)
            call_sql = mock_cur.execute.call_args[0][0]
            self.assertIn("%s", call_sql)
            self.assertNotIn("?", call_sql)

            # 2. write_packet_event
            mock_cur.reset_mock()
            event = {
                "event_id": "e1",
                "flow_id": "f1",
                "src_ip": "1.2.3.4",
                "dst_ip": "5.6.7.8",
                "protocol": "TCP",
            }
            write_packet_event(mock_conn, event)
            call_sql_event = mock_cur.execute.call_args[0][0]
            self.assertIn("%s", call_sql_event)
            self.assertNotIn("?", call_sql_event)

            # 3. upsert_network_flow
            mock_cur.reset_mock()
            flow = {
                "flow_id": "f1",
                "src_ip": "1.2.3.4",
                "dst_ip": "5.6.7.8",
            }
            upsert_network_flow(mock_conn, flow)
            call_sql_flow = mock_cur.execute.call_args[0][0]
            self.assertIn("%(flow_id)s", call_sql_flow)
            self.assertNotIn(":flow_id", call_sql_flow)

            # 4. baseline update_metric
            mock_cur.reset_mock()
            engine = BaselineEngine(conn=mock_conn)
            engine.update_metric("packets_per_sec", 100.0)
            call_sql_baseline = mock_cur.execute.call_args[0][0]
            self.assertIn("%s", call_sql_baseline)
            self.assertNotIn("?", call_sql_baseline)

            # 5. notification enqueue
            mock_cur.reset_mock()
            outbox = NotificationOutboxManager(conn=mock_conn, min_severity="low")
            outbox.enqueue_alert(alert, enabled_providers=["webhook"])
            call_sql_outbox = mock_cur.execute.call_args[0][0]
            self.assertIn("%s", call_sql_outbox)
            self.assertNotIn("?", call_sql_outbox)

        finally:
            config.DB_BACKEND = orig_backend


if __name__ == "__main__":
    unittest.main()
