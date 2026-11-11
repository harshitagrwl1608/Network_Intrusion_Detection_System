"""
storage/forensics_db.py
-----------------------
Database schema, migrations, and queries for NetGuard IDS Traffic Forensics,
Cases, Baselines, Notifications, and Offline PCAP Analysis.

Compatible with both SQLite and PostgreSQL backends.
"""

import os
import sys
import time
import json
import logging
import threading
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config

logger = logging.getLogger(__name__)

_sqlite_lock = threading.Lock()

# ---------------------------------------------------------------------------
# SQLite Schemas
# ---------------------------------------------------------------------------
FORENSICS_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS network_flows (
    flow_id          TEXT PRIMARY KEY,
    start_time       REAL NOT NULL,
    last_seen        REAL NOT NULL,
    src_ip           TEXT NOT NULL,
    dst_ip           TEXT NOT NULL,
    src_port         INTEGER,
    dst_port         INTEGER,
    protocol         TEXT NOT NULL,
    packet_count     INTEGER DEFAULT 1,
    byte_count       INTEGER DEFAULT 0,
    tcp_flags        TEXT,
    interface        TEXT,
    src_mac          TEXT,
    dst_mac          TEXT,
    direction        TEXT,
    hostname         TEXT,
    app_protocol     TEXT,
    dns_query        TEXT,
    http_method      TEXT,
    http_host        TEXT,
    http_uri         TEXT,
    tls_sni          TEXT,
    alert_count      INTEGER DEFAULT 0,
    last_alert_id    INTEGER,
    pcap_segment_id  TEXT
);

CREATE TABLE IF NOT EXISTS packet_events (
    event_id         TEXT PRIMARY KEY,
    timestamp        REAL NOT NULL,
    flow_id          TEXT NOT NULL,
    src_ip           TEXT NOT NULL,
    dst_ip           TEXT NOT NULL,
    src_port         INTEGER,
    dst_port         INTEGER,
    protocol         TEXT NOT NULL,
    packet_len       INTEGER NOT NULL,
    tcp_flags        INTEGER,
    payload_preview  TEXT,
    raw_hex          TEXT,
    alert_id         INTEGER,
    pcap_segment_id  TEXT,
    packet_index     INTEGER
);

CREATE TABLE IF NOT EXISTS pcap_segments (
    segment_id       TEXT PRIMARY KEY,
    file_path        TEXT NOT NULL,
    start_time       REAL NOT NULL,
    end_time         REAL,
    packet_count     INTEGER DEFAULT 0,
    byte_size        INTEGER DEFAULT 0,
    sha256           TEXT,
    status           TEXT DEFAULT 'active',
    created_at       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS pcap_jobs (
    job_id           TEXT PRIMARY KEY,
    filename         TEXT NOT NULL,
    file_path        TEXT NOT NULL,
    file_size        INTEGER NOT NULL,
    sha256           TEXT NOT NULL,
    format           TEXT NOT NULL,
    status           TEXT NOT NULL,
    progress         REAL DEFAULT 0.0,
    total_packets    INTEGER DEFAULT 0,
    processed_packets INTEGER DEFAULT 0,
    alert_count      INTEGER DEFAULT 0,
    duration_s       REAL DEFAULT 0.0,
    start_time       REAL,
    end_time         REAL,
    result_summary_json TEXT,
    error_message    TEXT,
    created_at       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    case_id          TEXT PRIMARY KEY,
    title            TEXT NOT NULL,
    severity         TEXT NOT NULL DEFAULT 'medium',
    status           TEXT NOT NULL DEFAULT 'open',
    assignee         TEXT,
    description      TEXT,
    tags             TEXT,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL,
    closed_at        REAL
);

CREATE TABLE IF NOT EXISTS case_alerts (
    case_id          TEXT NOT NULL,
    alert_id         INTEGER NOT NULL,
    added_at         REAL NOT NULL,
    PRIMARY KEY (case_id, alert_id)
);

CREATE TABLE IF NOT EXISTS case_notes (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id          TEXT NOT NULL,
    author           TEXT NOT NULL,
    note             TEXT NOT NULL,
    created_at       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS saved_searches (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    description      TEXT,
    query_params_json TEXT NOT NULL,
    created_at       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_baselines (
    metric_name      TEXT PRIMARY KEY,
    sample_count     INTEGER DEFAULT 0,
    rolling_median   REAL DEFAULT 0.0,
    mad              REAL DEFAULT 0.0,
    ewma             REAL DEFAULT 0.0,
    mean             REAL DEFAULT 0.0,
    std              REAL DEFAULT 0.0,
    p95              REAL DEFAULT 0.0,
    min_val          REAL DEFAULT 0.0,
    max_val          REAL DEFAULT 0.0,
    last_updated     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_anomalies (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        REAL NOT NULL,
    metric_name      TEXT NOT NULL,
    observed_value   REAL NOT NULL,
    expected_value   REAL NOT NULL,
    deviation_score  REAL NOT NULL,
    method           TEXT NOT NULL,
    confidence       TEXT NOT NULL,
    explanation      TEXT NOT NULL,
    related_flow_id  TEXT
);

CREATE TABLE IF NOT EXISTS notification_outbox (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    provider         TEXT NOT NULL,
    recipient        TEXT,
    subject          TEXT,
    message_body     TEXT NOT NULL,
    severity         TEXT NOT NULL,
    rule_name        TEXT,
    alert_id         INTEGER,
    status           TEXT NOT NULL DEFAULT 'pending',
    retry_count      INTEGER DEFAULT 0,
    max_retries      INTEGER DEFAULT 3,
    next_retry_at    REAL NOT NULL,
    sent_at          REAL,
    error_message    TEXT,
    created_at       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        REAL NOT NULL,
    user_identity    TEXT NOT NULL,
    action           TEXT NOT NULL,
    resource_type    TEXT NOT NULL,
    resource_id      TEXT,
    details_json     TEXT,
    ip_address       TEXT
);

CREATE TABLE IF NOT EXISTS system_settings (
    setting_key      TEXT PRIMARY KEY,
    value_json       TEXT NOT NULL,
    updated_at       REAL NOT NULL
);
"""

# ---------------------------------------------------------------------------
# PostgreSQL Schemas
# ---------------------------------------------------------------------------
FORENSICS_SCHEMA_PG = """
CREATE TABLE IF NOT EXISTS network_flows (
    flow_id          TEXT PRIMARY KEY,
    start_time       DOUBLE PRECISION NOT NULL,
    last_seen        DOUBLE PRECISION NOT NULL,
    src_ip           TEXT NOT NULL,
    dst_ip           TEXT NOT NULL,
    src_port         INTEGER,
    dst_port         INTEGER,
    protocol         TEXT NOT NULL,
    packet_count     INTEGER DEFAULT 1,
    byte_count       BIGINT DEFAULT 0,
    tcp_flags        TEXT,
    interface        TEXT,
    src_mac          TEXT,
    dst_mac          TEXT,
    direction        TEXT,
    hostname         TEXT,
    app_protocol     TEXT,
    dns_query        TEXT,
    http_method      TEXT,
    http_host        TEXT,
    http_uri         TEXT,
    tls_sni          TEXT,
    alert_count      INTEGER DEFAULT 0,
    last_alert_id    INTEGER,
    pcap_segment_id  TEXT
);

CREATE TABLE IF NOT EXISTS packet_events (
    event_id         TEXT PRIMARY KEY,
    timestamp        DOUBLE PRECISION NOT NULL,
    flow_id          TEXT NOT NULL,
    src_ip           TEXT NOT NULL,
    dst_ip           TEXT NOT NULL,
    src_port         INTEGER,
    dst_port         INTEGER,
    protocol         TEXT NOT NULL,
    packet_len       INTEGER NOT NULL,
    tcp_flags        INTEGER,
    payload_preview  TEXT,
    raw_hex          TEXT,
    alert_id         INTEGER,
    pcap_segment_id  TEXT,
    packet_index     INTEGER
);

CREATE TABLE IF NOT EXISTS pcap_segments (
    segment_id       TEXT PRIMARY KEY,
    file_path        TEXT NOT NULL,
    start_time       DOUBLE PRECISION NOT NULL,
    end_time         DOUBLE PRECISION,
    packet_count     INTEGER DEFAULT 0,
    byte_size        BIGINT DEFAULT 0,
    sha256           TEXT,
    status           TEXT DEFAULT 'active',
    created_at       DOUBLE PRECISION NOT NULL
);

CREATE TABLE IF NOT EXISTS pcap_jobs (
    job_id           TEXT PRIMARY KEY,
    filename         TEXT NOT NULL,
    file_path        TEXT NOT NULL,
    file_size        BIGINT NOT NULL,
    sha256           TEXT NOT NULL,
    format           TEXT NOT NULL,
    status           TEXT NOT NULL,
    progress         DOUBLE PRECISION DEFAULT 0.0,
    total_packets    INTEGER DEFAULT 0,
    processed_packets INTEGER DEFAULT 0,
    alert_count      INTEGER DEFAULT 0,
    duration_s       DOUBLE PRECISION DEFAULT 0.0,
    start_time       DOUBLE PRECISION,
    end_time         DOUBLE PRECISION,
    result_summary_json TEXT,
    error_message    TEXT,
    created_at       DOUBLE PRECISION NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    case_id          TEXT PRIMARY KEY,
    title            TEXT NOT NULL,
    severity         TEXT NOT NULL DEFAULT 'medium',
    status           TEXT NOT NULL DEFAULT 'open',
    assignee         TEXT,
    description      TEXT,
    tags             TEXT,
    created_at       DOUBLE PRECISION NOT NULL,
    updated_at       DOUBLE PRECISION NOT NULL,
    closed_at        DOUBLE PRECISION
);

CREATE TABLE IF NOT EXISTS case_alerts (
    case_id          TEXT NOT NULL,
    alert_id         INTEGER NOT NULL,
    added_at         DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (case_id, alert_id)
);

CREATE TABLE IF NOT EXISTS case_notes (
    id               SERIAL PRIMARY KEY,
    case_id          TEXT NOT NULL,
    author           TEXT NOT NULL,
    note             TEXT NOT NULL,
    created_at       DOUBLE PRECISION NOT NULL
);

CREATE TABLE IF NOT EXISTS saved_searches (
    id               SERIAL PRIMARY KEY,
    name             TEXT NOT NULL,
    description      TEXT,
    query_params_json TEXT NOT NULL,
    created_at       DOUBLE PRECISION NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_baselines (
    metric_name      TEXT PRIMARY KEY,
    sample_count     INTEGER DEFAULT 0,
    rolling_median   DOUBLE PRECISION DEFAULT 0.0,
    mad              DOUBLE PRECISION DEFAULT 0.0,
    ewma             DOUBLE PRECISION DEFAULT 0.0,
    mean             DOUBLE PRECISION DEFAULT 0.0,
    std              DOUBLE PRECISION DEFAULT 0.0,
    p95              DOUBLE PRECISION DEFAULT 0.0,
    min_val          DOUBLE PRECISION DEFAULT 0.0,
    max_val          DOUBLE PRECISION DEFAULT 0.0,
    last_updated     DOUBLE PRECISION NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_anomalies (
    id               SERIAL PRIMARY KEY,
    timestamp        DOUBLE PRECISION NOT NULL,
    metric_name      TEXT NOT NULL,
    observed_value   DOUBLE PRECISION NOT NULL,
    expected_value   DOUBLE PRECISION NOT NULL,
    deviation_score  DOUBLE PRECISION NOT NULL,
    method           TEXT NOT NULL,
    confidence       TEXT NOT NULL,
    explanation      TEXT NOT NULL,
    related_flow_id  TEXT
);

CREATE TABLE IF NOT EXISTS notification_outbox (
    id               SERIAL PRIMARY KEY,
    provider         TEXT NOT NULL,
    recipient        TEXT,
    subject          TEXT,
    message_body     TEXT NOT NULL,
    severity         TEXT NOT NULL,
    rule_name        TEXT,
    alert_id         INTEGER,
    status           TEXT NOT NULL DEFAULT 'pending',
    retry_count      INTEGER DEFAULT 0,
    max_retries      INTEGER DEFAULT 3,
    next_retry_at    DOUBLE PRECISION NOT NULL,
    sent_at          DOUBLE PRECISION,
    error_message    TEXT,
    created_at       DOUBLE PRECISION NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id               SERIAL PRIMARY KEY,
    timestamp        DOUBLE PRECISION NOT NULL,
    user_identity    TEXT NOT NULL,
    action           TEXT NOT NULL,
    resource_type    TEXT NOT NULL,
    resource_id      TEXT,
    details_json     TEXT,
    ip_address       TEXT
);

CREATE TABLE IF NOT EXISTS system_settings (
    setting_key      TEXT PRIMARY KEY,
    value_json       TEXT NOT NULL,
    updated_at       DOUBLE PRECISION NOT NULL
);
"""


def init_forensics_db(conn):
    """Initialise forensics tables, indexes, and migrations on the given connection."""
    schema = FORENSICS_SCHEMA_PG if config.DB_BACKEND == "postgres" else FORENSICS_SCHEMA_SQL
    with _sqlite_lock:
        cur = conn.cursor()
        for stmt in [s.strip() for s in schema.split(";") if s.strip()]:
            cur.execute(stmt)
        conn.commit()

        # Migrate alerts table with correlation columns
        _migrate_forensics_columns(conn, cur)
        _create_forensics_indexes(conn, cur)
        conn.commit()
        cur.close()


def _migrate_forensics_columns(conn, cur):
    """Add correlation columns to alerts table if missing."""
    col_type_str = "TEXT"
    col_type_int = "INTEGER"
    migrations = [
        ("alerts", "event_id", col_type_str),
        ("alerts", "flow_id", col_type_str),
        ("alerts", "pcap_segment_id", col_type_str),
        ("alerts", "packet_index", col_type_int),
        ("alerts", "assigned_case_id", col_type_str),
        ("alerts", "acknowledged", col_type_int),
        ("alerts", "status", col_type_str),
        ("packet_events", "raw_hex", col_type_str),
    ]
    for table, col, ctype in migrations:
        try:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ctype}")
        except Exception as exc:
            err = str(exc).lower()
            if "duplicate column" not in err and "already exists" not in err:
                logger.debug(f"Forensics column migration note ({table}.{col}): {exc}")


def _create_forensics_indexes(conn, cur):
    """Create query indexes for high-throughput forensic search and correlation."""
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON network_flows(last_seen DESC)",
        "CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON network_flows(src_ip)",
        "CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON network_flows(dst_ip)",
        "CREATE INDEX IF NOT EXISTS idx_flows_protocol ON network_flows(protocol)",
        "CREATE INDEX IF NOT EXISTS idx_packet_events_ts ON packet_events(timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_packet_events_flow ON packet_events(flow_id)",
        "CREATE INDEX IF NOT EXISTS idx_packet_events_alert ON packet_events(alert_id)",
        "CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)",
        "CREATE INDEX IF NOT EXISTS idx_outbox_status ON notification_outbox(status, next_retry_at)",
        "CREATE INDEX IF NOT EXISTS idx_anomalies_ts ON traffic_anomalies(timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_flow_id ON alerts(flow_id)",
    ]
    for idx_sql in indexes:
        try:
            cur.execute(idx_sql)
        except Exception as exc:
            err = str(exc).lower()
            if "already exists" not in err:
                logger.debug(f"Index creation note: {exc}")


# ---------------------------------------------------------------------------
# Flow Operations
# ---------------------------------------------------------------------------

def upsert_network_flow(conn, flow: dict):
    """Insert or update a network flow record."""
    full_flow = {
        "flow_id": flow["flow_id"],
        "start_time": flow.get("start_time", time.time()),
        "last_seen": flow.get("last_seen", time.time()),
        "src_ip": flow.get("src_ip", ""),
        "dst_ip": flow.get("dst_ip", ""),
        "src_port": flow.get("src_port"),
        "dst_port": flow.get("dst_port"),
        "protocol": flow.get("protocol", "IP"),
        "packet_count": flow.get("packet_count", 1),
        "byte_count": flow.get("byte_count", 0),
        "tcp_flags": flow.get("tcp_flags"),
        "interface": flow.get("interface"),
        "src_mac": flow.get("src_mac"),
        "dst_mac": flow.get("dst_mac"),
        "direction": flow.get("direction"),
        "hostname": flow.get("hostname"),
        "app_protocol": flow.get("app_protocol"),
        "dns_query": flow.get("dns_query"),
        "http_method": flow.get("http_method"),
        "http_host": flow.get("http_host"),
        "http_uri": flow.get("http_uri"),
        "tls_sni": flow.get("tls_sni"),
        "alert_count": flow.get("alert_count", 0),
        "last_alert_id": flow.get("last_alert_id"),
        "pcap_segment_id": flow.get("pcap_segment_id"),
    }
    if config.DB_BACKEND == "sqlite":
        sql = """
            INSERT INTO network_flows (
                flow_id, start_time, last_seen, src_ip, dst_ip, src_port, dst_port,
                protocol, packet_count, byte_count, tcp_flags, interface, src_mac, dst_mac,
                direction, hostname, app_protocol, dns_query, http_method, http_host,
                http_uri, tls_sni, alert_count, last_alert_id, pcap_segment_id
            )
            VALUES (
                :flow_id, :start_time, :last_seen, :src_ip, :dst_ip, :src_port, :dst_port,
                :protocol, :packet_count, :byte_count, :tcp_flags, :interface, :src_mac, :dst_mac,
                :direction, :hostname, :app_protocol, :dns_query, :http_method, :http_host,
                :http_uri, :tls_sni, :alert_count, :last_alert_id, :pcap_segment_id
            )
            ON CONFLICT(flow_id) DO UPDATE SET
                last_seen = excluded.last_seen,
                packet_count = network_flows.packet_count + excluded.packet_count,
                byte_count = network_flows.byte_count + excluded.byte_count,
                tcp_flags = COALESCE(excluded.tcp_flags, network_flows.tcp_flags),
                dns_query = COALESCE(excluded.dns_query, network_flows.dns_query),
                http_method = COALESCE(excluded.http_method, network_flows.http_method),
                http_host = COALESCE(excluded.http_host, network_flows.http_host),
                http_uri = COALESCE(excluded.http_uri, network_flows.http_uri),
                tls_sni = COALESCE(excluded.tls_sni, network_flows.tls_sni),
                alert_count = network_flows.alert_count + excluded.alert_count,
                last_alert_id = COALESCE(excluded.last_alert_id, network_flows.last_alert_id),
                pcap_segment_id = COALESCE(excluded.pcap_segment_id, network_flows.pcap_segment_id)
        """
        with _sqlite_lock:
            cur = conn.cursor()
            cur.execute(sql, full_flow)
            conn.commit()
            cur.close()
    else:
        # PostgreSQL parameterized upsert
        sql = """
            INSERT INTO network_flows (
                flow_id, start_time, last_seen, src_ip, dst_ip, src_port, dst_port,
                protocol, packet_count, byte_count, tcp_flags, interface, src_mac, dst_mac,
                direction, hostname, app_protocol, dns_query, http_method, http_host,
                http_uri, tls_sni, alert_count, last_alert_id, pcap_segment_id
            )
            VALUES (
                %(flow_id)s, %(start_time)s, %(last_seen)s, %(src_ip)s, %(dst_ip)s, %(src_port)s, %(dst_port)s,
                %(protocol)s, %(packet_count)s, %(byte_count)s, %(tcp_flags)s, %(interface)s, %(src_mac)s, %(dst_mac)s,
                %(direction)s, %(hostname)s, %(app_protocol)s, %(dns_query)s, %(http_method)s, %(http_host)s,
                %(http_uri)s, %(tls_sni)s, %(alert_count)s, %(last_alert_id)s, %(pcap_segment_id)s
            )
            ON CONFLICT(flow_id) DO UPDATE SET
                last_seen = EXCLUDED.last_seen,
                packet_count = network_flows.packet_count + EXCLUDED.packet_count,
                byte_count = network_flows.byte_count + EXCLUDED.byte_count,
                tcp_flags = COALESCE(EXCLUDED.tcp_flags, network_flows.tcp_flags),
                dns_query = COALESCE(EXCLUDED.dns_query, network_flows.dns_query),
                http_method = COALESCE(EXCLUDED.http_method, network_flows.http_method),
                http_host = COALESCE(EXCLUDED.http_host, network_flows.http_host),
                http_uri = COALESCE(EXCLUDED.http_uri, network_flows.http_uri),
                tls_sni = COALESCE(EXCLUDED.tls_sni, network_flows.tls_sni),
                alert_count = network_flows.alert_count + EXCLUDED.alert_count,
                last_alert_id = COALESCE(EXCLUDED.last_alert_id, network_flows.last_alert_id),
                pcap_segment_id = COALESCE(EXCLUDED.pcap_segment_id, network_flows.pcap_segment_id)
        """
        cur = conn.cursor()
        cur.execute(sql, full_flow)
        conn.commit()
        cur.close()


def batch_upsert_flows(conn, flows: list[dict]):
    """Batch upsert multiple flow summaries in a single transaction."""
    if not flows:
        return
    with _sqlite_lock:
        cur = conn.cursor()
        for f in flows:
            upsert_network_flow(conn, f)
        cur.close()


def query_network_flows(conn, filters: dict, page: int = 1, per_page: int = 50) -> dict[str, Any]:
    """
    Search and filter network flows on backend with pagination and sorting.
    Supports: src_ip, dst_ip, ip (either), port (either), protocol, date range,
    alerted_only, search keyword.
    """
    conditions = []
    params = []

    # IP filters (with optional CIDR / prefix match)
    if filters.get("src_ip"):
        conditions.append("src_ip LIKE ?")
        params.append(f"{filters['src_ip']}%")
    if filters.get("dst_ip"):
        conditions.append("dst_ip LIKE ?")
        params.append(f"{filters['dst_ip']}%")
    if filters.get("ip"):
        conditions.append("(src_ip LIKE ? OR dst_ip LIKE ?)")
        params.extend([f"{filters['ip']}%", f"{filters['ip']}%"])

    # Port filters
    if filters.get("src_port"):
        conditions.append("src_port = ?")
        params.append(int(filters["src_port"]))
    if filters.get("dst_port"):
        conditions.append("dst_port = ?")
        params.append(int(filters["dst_port"]))
    if filters.get("port"):
        conditions.append("(src_port = ? OR dst_port = ?)")
        p_val = int(filters["port"])
        params.extend([p_val, p_val])

    # Protocol
    if filters.get("protocol") and filters["protocol"].upper() != "ALL":
        conditions.append("protocol = ?")
        params.append(filters["protocol"].upper())

    # Date range
    if filters.get("start_time"):
        conditions.append("last_seen >= ?")
        params.append(float(filters["start_time"]))
    if filters.get("end_time"):
        conditions.append("start_time <= ?")
        params.append(float(filters["end_time"]))

    # Alerted status
    if filters.get("alerted_only") in (True, "true", "1"):
        conditions.append("alert_count > 0")

    # Keyword search across endpoints, hostnames, and queries
    if filters.get("query"):
        q = f"%{filters['query']}%"
        conditions.append(
            "(src_ip LIKE ? OR dst_ip LIKE ? OR dns_query LIKE ? OR http_host LIKE ? OR tls_sni LIKE ? OR flow_id LIKE ?)"
        )
        params.extend([q, q, q, q, q, q])

    where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""
    count_sql = f"SELECT COUNT(*) FROM network_flows{where_clause}"

    sort_field = filters.get("sort_by", "last_seen")
    sort_dir = "ASC" if str(filters.get("sort_dir", "desc")).lower() == "asc" else "DESC"
    allowed_sort = {"last_seen", "start_time", "packet_count", "byte_count", "alert_count", "protocol"}
    if sort_field not in allowed_sort:
        sort_field = "last_seen"

    offset = (max(1, page) - 1) * per_page
    query_sql = f"SELECT * FROM network_flows{where_clause} ORDER BY {sort_field} {sort_dir} LIMIT ? OFFSET ?"

    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(count_sql, params)
        total = cur.fetchone()[0]

        cur.execute(query_sql, params + [per_page, offset])
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page if per_page else 1,
        "flows": rows,
    }


def get_flow_by_id(conn, flow_id: str) -> dict | None:
    """Retrieve full detail for a single network flow."""
    sql = "SELECT * FROM network_flows WHERE flow_id = ?"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (flow_id,))
        row = cur.fetchone()
        cur.close()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Packet Events Operations (Selective Forensics)
# ---------------------------------------------------------------------------

def write_packet_event(conn, event: dict):
    """Insert a forensic packet event record."""
    if config.DB_BACKEND == "postgres":
        sql = """
            INSERT INTO packet_events (
                event_id, timestamp, flow_id, src_ip, dst_ip, src_port, dst_port,
                protocol, packet_len, tcp_flags, payload_preview, alert_id,
                pcap_segment_id, packet_index, raw_hex
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
    else:
        sql = """
            INSERT INTO packet_events (
                event_id, timestamp, flow_id, src_ip, dst_ip, src_port, dst_port,
                protocol, packet_len, tcp_flags, payload_preview, alert_id,
                pcap_segment_id, packet_index, raw_hex
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (
            event.get("event_id"),
            event.get("timestamp", time.time()),
            event.get("flow_id"),
            event.get("src_ip"),
            event.get("dst_ip"),
            event.get("src_port"),
            event.get("dst_port"),
            event.get("protocol"),
            event.get("packet_len", 0),
            event.get("tcp_flags"),
            event.get("payload_preview"),
            event.get("alert_id"),
            event.get("pcap_segment_id"),
            event.get("packet_index"),
            event.get("raw_hex"),
        ))
        conn.commit()
        cur.close()


def get_packet_events_for_flow(conn, flow_id: str, limit: int = 100) -> list[dict]:
    """Retrieve forensic packet events associated with a flow."""
    sql = "SELECT * FROM packet_events WHERE flow_id = ? ORDER BY timestamp ASC LIMIT ?"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (flow_id, limit))
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
    return rows


def get_packet_events_for_alert(conn, alert_id: int) -> list[dict]:
    """Retrieve forensic packet events directly linked to an alert."""
    sql = "SELECT * FROM packet_events WHERE alert_id = ? ORDER BY timestamp ASC"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (alert_id,))
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
    return rows


# ---------------------------------------------------------------------------
# Cases Operations
# ---------------------------------------------------------------------------

def create_case(conn, case_data: dict) -> str:
    """Create a new security investigation case."""
    import uuid
    case_id = case_data.get("case_id") or f"CASE-{uuid.uuid4().hex[:8].upper()}"
    now = time.time()
    sql = """
        INSERT INTO cases (case_id, title, severity, status, assignee, description, tags, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (
            case_id,
            case_data.get("title", "Untitled Incident"),
            case_data.get("severity", "medium"),
            case_data.get("status", "open"),
            case_data.get("assignee", "Unassigned"),
            case_data.get("description", ""),
            case_data.get("tags", ""),
            now,
            now,
        ))
        conn.commit()
        cur.close()
    return case_id


def get_case(conn, case_id: str) -> dict | None:
    """Fetch case detail along with attached alerts and notes."""
    case_sql = "SELECT * FROM cases WHERE case_id = ?"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(case_sql, (case_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            return None
        case = dict(row)

        # Fetch attached alert IDs and details
        alerts_sql = """
            SELECT a.* FROM alerts a
            JOIN case_alerts ca ON a.id = ca.alert_id
            WHERE ca.case_id = ?
            ORDER BY a.timestamp ASC
        """
        cur.execute(alerts_sql, (case_id,))
        case["alerts"] = [dict(r) for r in cur.fetchall()]

        # Fetch case notes
        notes_sql = "SELECT * FROM case_notes WHERE case_id = ? ORDER BY created_at ASC"
        cur.execute(notes_sql, (case_id,))
        case["notes"] = [dict(r) for r in cur.fetchall()]
        cur.close()
    return case


def list_cases(conn, status: str | None = None, limit: int = 50) -> list[dict]:
    """List cases with optional status filter."""
    if status and status.upper() != "ALL":
        sql = "SELECT * FROM cases WHERE status = ? ORDER BY updated_at DESC LIMIT ?"
        args = (status.lower(), limit)
    else:
        sql = "SELECT * FROM cases ORDER BY updated_at DESC LIMIT ?"
        args = (limit,)
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, args)
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
    return rows


def add_alert_to_case(conn, case_id: str, alert_id: int):
    """Associate an alert with an incident case."""
    now = time.time()
    sql = "INSERT OR IGNORE INTO case_alerts (case_id, alert_id, added_at) VALUES (?, ?, ?)"
    update_case_sql = "UPDATE cases SET updated_at = ? WHERE case_id = ?"
    update_alert_sql = "UPDATE alerts SET assigned_case_id = ? WHERE id = ?"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (case_id, alert_id, now))
        cur.execute(update_case_sql, (now, case_id))
        cur.execute(update_alert_sql, (case_id, alert_id))
        conn.commit()
        cur.close()


def add_case_note(conn, case_id: str, author: str, note: str):
    """Add an analyst note to a case."""
    now = time.time()
    sql = "INSERT INTO case_notes (case_id, author, note, created_at) VALUES (?, ?, ?, ?)"
    update_case_sql = "UPDATE cases SET updated_at = ? WHERE case_id = ?"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (case_id, author, note, now))
        cur.execute(update_case_sql, (now, case_id))
        conn.commit()
        cur.close()


def update_case_status(conn, case_id: str, status: str, assignee: str | None = None):
    """Transition case status and record update timestamp."""
    now = time.time()
    closed_at = now if status.lower() in ("resolved", "closed") else None
    if assignee:
        sql = "UPDATE cases SET status = ?, assignee = ?, updated_at = ?, closed_at = ? WHERE case_id = ?"
        args = (status.lower(), assignee, now, closed_at, case_id)
    else:
        sql = "UPDATE cases SET status = ?, updated_at = ?, closed_at = ? WHERE case_id = ?"
        args = (status.lower(), now, closed_at, case_id)
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, args)
        conn.commit()
        cur.close()


# ---------------------------------------------------------------------------
# Saved Searches Operations
# ---------------------------------------------------------------------------

def save_search(conn, name: str, description: str, query_params: dict) -> int:
    """Save a forensic search query for one-click re-use."""
    now = time.time()
    sql = "INSERT INTO saved_searches (name, description, query_params_json, created_at) VALUES (?, ?, ?, ?)"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (name, description, json.dumps(query_params), now))
        conn.commit()
        new_id = cur.lastrowid
        cur.close()
    return new_id


def list_saved_searches(conn) -> list[dict]:
    """Return all saved searches."""
    sql = "SELECT * FROM saved_searches ORDER BY created_at DESC"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql)
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
    for r in rows:
        try:
            r["query_params"] = json.loads(r.get("query_params_json", "{}"))
        except Exception:
            r["query_params"] = {}
    return rows


# ---------------------------------------------------------------------------
# Audit Logging Operations
# ---------------------------------------------------------------------------

def write_audit_log(conn, user_identity: str, action: str, resource_type: str,
                    resource_id: str = None, details: dict = None, ip_address: str = None):
    """Write an immutable audit trail record."""
    now = time.time()
    sql = """
        INSERT INTO audit_log (timestamp, user_identity, action, resource_type, resource_id, details_json, ip_address)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (
            now,
            user_identity or "anonymous",
            action,
            resource_type,
            resource_id,
            json.dumps(details or {}),
            ip_address or "127.0.0.1",
        ))
        conn.commit()
        cur.close()


def read_audit_log(conn, limit: int = 100) -> list[dict]:
    """Retrieve recent audit events."""
    sql = "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
    return rows


# ---------------------------------------------------------------------------
# System Settings Operations
# ---------------------------------------------------------------------------

def _is_postgres() -> bool:
    return getattr(config, "DB_BACKEND", "sqlite").lower() == "postgres"


def save_system_setting(conn, key: str, value: Any) -> None:
    """Persist system setting with JSON serialization."""
    now = time.time()
    v_json = json.dumps(value)
    if _is_postgres():
        sql = """
            INSERT INTO system_settings (setting_key, value_json, updated_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (setting_key) DO UPDATE SET
                value_json = EXCLUDED.value_json,
                updated_at = EXCLUDED.updated_at
        """
    else:
        sql = "INSERT OR REPLACE INTO system_settings (setting_key, value_json, updated_at) VALUES (?, ?, ?)"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (key, v_json, now))
        conn.commit()
        cur.close()


def get_system_setting(conn, key: str, default: Any = None) -> Any:
    """Retrieve JSON-deserialized system setting."""
    param = "%s" if _is_postgres() else "?"
    sql = f"SELECT value_json FROM system_settings WHERE setting_key = {param}"
    with _sqlite_lock:
        cur = conn.cursor()
        cur.execute(sql, (key,))
        row = cur.fetchone()
        cur.close()
    if row and row[0]:
        try:
            return json.loads(row[0])
        except Exception:
            return row[0]
    return default
    for r in rows:
        try:
            r["details"] = json.loads(r.get("details_json", "{}"))
        except Exception:
            r["details"] = {}
    return rows

