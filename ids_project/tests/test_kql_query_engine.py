"""Unit tests for Traffic Explorer KQL engine and query assistant."""

import os
import sys
import pytest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from forensics.kql_parser import (
    KqlLexer,
    KqlParser,
    parse_kql_to_sql,
    generate_kql_from_intent,
    WHITELISTED_FIELDS,
    VALID_OPERATORS,
)


def test_kql_allowed_fields_and_operators():
    assert "src_ip" in WHITELISTED_FIELDS
    assert "dst_ip" in WHITELISTED_FIELDS
    assert "dst_port" in WHITELISTED_FIELDS
    assert "protocol" in WHITELISTED_FIELDS
    assert "alerted" in WHITELISTED_FIELDS
    assert ":" in VALID_OPERATORS
    assert "!=" in VALID_OPERATORS
    assert "contains" in VALID_OPERATORS


def test_kql_lexer_simple_tokens():
    lexer = KqlLexer('src_ip : "10.0.0.1" and dst_port : 443')
    tokens = lexer.tokenize()
    assert len(tokens) == 8
    assert tokens[0].value == "src_ip"
    assert tokens[1].value == ":"
    assert tokens[2].value == "10.0.0.1"
    assert tokens[3].value == "and"
    assert tokens[4].value == "dst_port"
    assert tokens[5].value == ":"
    assert tokens[6].value == 443


def test_kql_parser_ast_structure():
    parser = KqlParser('src_ip : "192.168.1.5" or protocol : "UDP"')
    ast = parser.parse()
    assert ast is not None
    assert ast.op == "OR"
    assert ast.left.field == "src_ip"
    assert ast.left.value == "192.168.1.5"
    assert ast.right.field == "protocol"
    assert ast.right.value == "UDP"


def test_kql_parenthesized_expressions():
    query = '(protocol : "TCP" and dst_port : 80) or (protocol : "UDP" and dst_port : 53)'
    parser = KqlParser(query)
    ast = parser.parse()
    assert ast.op == "OR"
    assert ast.left.op == "AND"
    assert ast.right.op == "AND"


def test_parse_kql_to_sql_sqlite():
    query = 'src_ip : "10.0.0.5" and dst_port : 443'
    sql, params = parse_kql_to_sql(query, dialect="sqlite")
    assert "src_ip = ?" in sql
    assert "dst_port = ?" in sql
    assert "AND" in sql
    assert params == ["10.0.0.5", 443]


def test_parse_kql_to_sql_cidr():
    query = 'src_ip : "192.168.1.0/24"'
    sql, params = parse_kql_to_sql(query, dialect="sqlite")
    assert "cidr_match(src_ip, ?)" in sql
    assert params == ["192.168.1.0/24"]

    sql_pg, params_pg = parse_kql_to_sql(query, dialect="postgres")
    assert "(src_ip::inet <<= %s::inet)" in sql_pg
    assert params_pg == ["192.168.1.0/24"]


def test_parse_kql_to_sql_contains_and_startswith():
    query = 'dns_query contains "evil" and protocol startswith "TC"'
    sql, params = parse_kql_to_sql(query, dialect="sqlite")
    assert "dns_query LIKE ?" in sql
    assert "protocol LIKE ?" in sql
    assert params == ["%evil%", "TC%"]


def test_parse_kql_to_sql_boolean_alerted():
    query = 'is_alerted : true'
    sql, params = parse_kql_to_sql(query, dialect="sqlite")
    assert "alert_count > 0" in sql
    assert params == []

    query_clean = 'is_alerted : false'
    sql2, params2 = parse_kql_to_sql(query_clean, dialect="sqlite")
    assert "alert_count = 0" in sql2
    assert params2 == []


def test_parse_kql_syntax_error():
    with pytest.raises(ValueError):
        parse_kql_to_sql('src_ip "10.0.0.1"')

    with pytest.raises(ValueError, match="Unknown field 'invalid_field'"):
        parse_kql_to_sql('invalid_field : 123')


def test_kql_injection_prevention():
    # Attempt SQL injection through string payload
    malicious = 'src_ip : "10.0.0.1; DROP TABLE network_flows; --"'
    sql, params = parse_kql_to_sql(malicious, dialect="sqlite")
    # Must use parameterized placeholder, NEVER raw string interpolation
    assert "src_ip = ?" in sql
    assert params == ["10.0.0.1; DROP TABLE network_flows; --"]
    assert "DROP TABLE" not in sql


def test_generate_kql_from_intent_ip():
    intent = "Find all traffic involving IP 10.64.85.221"
    kql = generate_kql_from_intent(intent)
    assert 'src_ip : "10.64.85.221"' in kql or 'dst_ip : "10.64.85.221"' in kql


def test_generate_kql_from_intent_port():
    intent = "Find all connections to port 443"
    kql = generate_kql_from_intent(intent)
    assert 'dst_port : 443' in kql


def test_generate_kql_from_intent_suspicious():
    intent = "Show suspicious alerted flows"
    kql = generate_kql_from_intent(intent)
    assert "alerted : true" in kql


def test_generate_kql_from_intent_protocol():
    intent = "Find high packet volume UDP traffic"
    kql = generate_kql_from_intent(intent)
    assert 'protocol : "UDP"' in kql
