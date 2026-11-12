"""
ids_project/tests/test_kql_subnets_and_semantics.py
---------------------------------------------------
Comprehensive test suite verifying:
1. Exact mathematical CIDR subnet compilation and SQLite UDF execution
   across /0, /8, /16, /24, /25, /30, /31, /32, and IPv6 (/32, /48, /64).
2. PostgreSQL inet operator compilation (<<=).
3. Field mapping: dns_query, http_host, http_uri, tls_sni mapped to network_flows columns.
4. Full lexer consumption (unrecognized syntax / trailing characters raising KqlParseError).
5. Truth table for alerted and is_alerted boolean semantics.
"""

import os
import sys
import sqlite3
import pytest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from forensics.kql_parser import parse_kql_to_sql, KqlParseError, WHITELISTED_FIELDS
from storage.db import _py_cidr_match


def test_sqlite_udf_mathematical_cidr_accuracy():
    """Verify that _py_cidr_match accurately enforces mathematical subnet boundaries."""
    # /25 boundary: 192.168.1.128/25 covers 192.168.1.128 - 192.168.1.255
    assert _py_cidr_match("192.168.1.150", "192.168.1.128/25") is True
    assert _py_cidr_match("192.168.1.254", "192.168.1.128/25") is True
    assert _py_cidr_match("192.168.1.50", "192.168.1.128/25") is False
    assert _py_cidr_match("192.168.1.127", "192.168.1.128/25") is False

    # /30 boundary: 10.0.0.4/30 covers 10.0.0.4 - 10.0.0.7
    assert _py_cidr_match("10.0.0.4", "10.0.0.4/30") is True
    assert _py_cidr_match("10.0.0.5", "10.0.0.4/30") is True
    assert _py_cidr_match("10.0.0.7", "10.0.0.4/30") is True
    assert _py_cidr_match("10.0.0.3", "10.0.0.4/30") is False
    assert _py_cidr_match("10.0.0.8", "10.0.0.4/30") is False

    # /0 boundary: matches all IPv4
    assert _py_cidr_match("8.8.8.8", "0.0.0.0/0") is True
    assert _py_cidr_match("192.168.1.1", "0.0.0.0/0") is True

    # /32 boundary: single IP exact match
    assert _py_cidr_match("10.1.1.1", "10.1.1.1/32") is True
    assert _py_cidr_match("10.1.1.2", "10.1.1.1/32") is False

    # IPv6 boundaries
    assert _py_cidr_match("2001:db8::1", "2001:db8::/32") is True
    assert _py_cidr_match("2001:db9::1", "2001:db8::/32") is False
    assert _py_cidr_match("fe80::1ff:fe23:4567", "fe80::/64") is True

    # IPv6 non-byte / non-nibble-aligned prefixes (/52, /57, /120)
    assert _py_cidr_match("2001:db8:0:0f00::1", "2001:db8::/52") is True
    assert _py_cidr_match("2001:db8:0:f000::1", "2001:db8::/52") is False
    assert _py_cidr_match("2001:db8:0:007f::1", "2001:db8::/57") is True
    assert _py_cidr_match("2001:db8:0:0080::1", "2001:db8::/57") is False
    assert _py_cidr_match("2001:db8::ff", "2001:db8::/120") is True
    assert _py_cidr_match("2001:db8::100", "2001:db8::/120") is False


def test_sqlite_in_database_cidr_query():
    """Verify cidr_match UDF registered in live SQLite connection filters rows correctly."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.create_function("cidr_match", 2, _py_cidr_match)
    cur = conn.cursor()
    cur.execute("CREATE TABLE test_flows (id INT, src_ip TEXT)")
    cur.executemany("INSERT INTO test_flows VALUES (?, ?)", [
        (1, "192.168.1.5"),
        (2, "192.168.1.130"),
        (3, "192.168.1.200"),
        (4, "10.0.0.5"),
        (5, "10.0.0.15"),
    ])
    conn.commit()

    # Query /25 subnet (should only return IDs 2 and 3)
    sql, params = parse_kql_to_sql('src_ip: "192.168.1.128/25"', backend="sqlite")
    cur.execute(f"SELECT id FROM test_flows WHERE {sql}", params)
    matched = [r["id"] for r in cur.fetchall()]
    assert matched == [2, 3]

    # Query /30 subnet (10.0.0.4/30 should only return ID 4)
    sql, params = parse_kql_to_sql('src_ip: "10.0.0.4/30"', backend="sqlite")
    cur.execute(f"SELECT id FROM test_flows WHERE {sql}", params)
    matched = [r["id"] for r in cur.fetchall()]
    assert matched == [4]

    conn.close()


def test_kql_cidr_compilation_sqlite_and_postgres():
    """Test SQL compilation for both SQLite and PostgreSQL backends."""
    cidrs = [
        "0.0.0.0/0",
        "10.0.0.0/8",
        "172.16.0.0/16",
        "192.168.1.0/24",
        "192.168.1.128/25",
        "10.0.0.4/30",
        "10.0.0.0/31",
        "192.168.1.1/32",
        "2001:db8::/32",
        "2001:db8:85a3::/48",
        "fe80::/64",
    ]
    for cidr in cidrs:
        query = f'src_ip: "{cidr}"'
        sql_sqlite, params_sqlite = parse_kql_to_sql(query, backend="sqlite")
        assert "cidr_match(src_ip, ?)" in sql_sqlite
        assert params_sqlite == [cidr]

        sql_pg, params_pg = parse_kql_to_sql(query, backend="postgres")
        assert "(src_ip::inet <<= %s::inet)" in sql_pg
        assert params_pg == [cidr]


def test_kql_single_ip_and_invalid_cidr():
    """Verify single IPv4/IPv6 address exact matching and invalid CIDR rejection."""
    # Single IPv4 exact match
    sql_v4, params_v4 = parse_kql_to_sql('src_ip: "192.168.1.50"', backend="sqlite")
    assert "src_ip = ?" in sql_v4
    assert params_v4 == ["192.168.1.50"]

    # Single IPv6 exact match
    sql_v6, params_v6 = parse_kql_to_sql('dst_ip == "2001:db8::cafe"', backend="postgres")
    assert "dst_ip = %s" in sql_v6
    assert params_v6 == ["2001:db8::cafe"]

    # Non-byte aligned IPv6 compilation
    sql_57, params_57 = parse_kql_to_sql('src_ip: "2001:db8::/57"', backend="sqlite")
    assert "cidr_match(src_ip, ?)" in sql_57
    assert params_57 == ["2001:db8::/57"]

    # Invalid CIDRs must raise KqlParseError
    with pytest.raises(KqlParseError):
        parse_kql_to_sql('src_ip: "999.999.999.999/24"')

    with pytest.raises(KqlParseError):
        parse_kql_to_sql('src_ip: "192.168.1.1/33"')

    with pytest.raises(KqlParseError):
        parse_kql_to_sql('src_ip: "2001:db8::/129"')


def test_kql_cidr_negative_matching():
    """Test negative CIDR filtering (src_ip != cidr)."""
    query = 'src_ip != "192.168.1.0/24"'
    sql_sqlite, params_sqlite = parse_kql_to_sql(query, backend="sqlite")
    assert "NOT cidr_match(src_ip, ?)" in sql_sqlite
    assert params_sqlite == ["192.168.1.0/24"]

    sql_pg, params_pg = parse_kql_to_sql(query, backend="postgres")
    assert "NOT (src_ip::inet <<= %s::inet)" in sql_pg
    assert params_pg == ["192.168.1.0/24"]


def test_kql_field_mapping_network_flows():
    """Verify dns_query, http_host, http_uri, tls_sni map directly to network_flows columns."""
    for field in ("dns_query", "http_host", "http_uri", "tls_sni"):
        assert WHITELISTED_FIELDS[field]["type"] == "string"
        assert WHITELISTED_FIELDS[field]["column"] == field

        query = f'{field}: "malicious"'
        sql, params = parse_kql_to_sql(query, backend="sqlite")
        assert f"{field} LIKE ?" in sql
        assert params == ["%malicious%"]


def test_kql_payload_event_field_mapping():
    """Verify payload and payload_preview map to packet_events subqueries."""
    for field in ("payload", "payload_preview"):
        assert WHITELISTED_FIELDS[field]["type"] == "event_field"
        assert WHITELISTED_FIELDS[field]["column"] == "payload_preview"

        query = f'{field} contains "eval("'
        sql, params = parse_kql_to_sql(query, backend="sqlite")
        assert "flow_id IN (SELECT flow_id FROM packet_events WHERE payload_preview LIKE ? AND flow_id IS NOT NULL)" in sql
        assert params == ["%eval(%"]


def test_full_lexer_consumption():
    """Verify that unparsed trailing characters or invalid syntax raise KqlParseError."""
    # Trailing unrecognized symbols
    with pytest.raises(KqlParseError):
        parse_kql_to_sql('src_ip == "10.0.0.1" @@@ invalid')

    # Unrecognized symbol at start
    with pytest.raises(KqlParseError):
        parse_kql_to_sql('$$$ src_ip == "10.0.0.1"')

    # Incomplete comparison
    with pytest.raises(KqlParseError):
        parse_kql_to_sql('src_ip == ')


def test_alerted_truth_table():
    """Verify full truth table for alerted and is_alerted."""
    truth_cases = [
        ("alerted : true", "alert_count > 0"),
        ("alerted == true", "alert_count > 0"),
        ("alerted : false", "alert_count = 0"),
        ("alerted == false", "alert_count = 0"),
        ("alerted != true", "alert_count = 0"),
        ("alerted != false", "alert_count > 0"),
        ("is_alerted : true", "alert_count > 0"),
        ("is_alerted == true", "alert_count > 0"),
        ("is_alerted : false", "alert_count = 0"),
        ("is_alerted == false", "alert_count = 0"),
        ("is_alerted != true", "alert_count = 0"),
        ("is_alerted != false", "alert_count > 0"),
    ]
    for q, expected in truth_cases:
        sql, params = parse_kql_to_sql(q, backend="sqlite")
        assert expected in sql, f"Query '{q}' failed: expected '{expected}' in '{sql}'"
        assert params == []

