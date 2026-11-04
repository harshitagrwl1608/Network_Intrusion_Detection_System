#!/usr/bin/env python3
"""
NetGuard Evaluation Database Inspector MCP Server.
Provides read-only JSON-RPC 2.0 stdio MCP interface for SQLite evaluation inspection:
- evaluation_db_summary
- evaluation_db_query_alerts
- evaluation_db_rule_statistics

Hardened for security:
- Strict path validation and traversal prevention.
- Preserves explicit SQLite read-only URI mode (mode=ro).
- Parameterized queries and strict identifier whitelisting to prevent SQL injection.
- Enforced limit bounding (1 <= limit <= 500).
- Graceful handling of locked or malformed databases.
"""

import json
import os
import re
import sqlite3
import sys

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.abspath(os.path.join(SCRIPTS_DIR, ".."))


def find_workspace_root():
    d = PLUGIN_DIR
    while d and d != os.path.dirname(d):
        if os.path.exists(os.path.join(d, ".git")):
            return d
        d = os.path.dirname(d)
    return PLUGIN_DIR


WORKSPACE_ROOT = find_workspace_root()
MAX_DB_SIZE_BYTES = 500 * 1024 * 1024  # 500 MB limit


def validate_and_resolve_db_path(raw_path: str) -> tuple[str | None, str | None]:
    """Validates, resolves, and verifies boundaries for SQLite database path."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None, "Database path must be a non-empty string."

    candidate = os.path.expanduser(raw_path.strip())

    if not os.path.isabs(candidate):
        if os.path.isfile(candidate):
            resolved = os.path.abspath(candidate)
        else:
            cand_ws = os.path.join(WORKSPACE_ROOT, candidate)
            if os.path.isfile(cand_ws):
                resolved = os.path.abspath(cand_ws)
            else:
                return None, f"Database file not found: {raw_path}"
    else:
        if not os.path.isfile(candidate):
            return None, f"Database file not found: {raw_path}"
        resolved = os.path.abspath(candidate)

    real_path = os.path.realpath(resolved)

    allowed_roots = [
        os.path.realpath(WORKSPACE_ROOT),
        "/tmp",
        "/var/tmp"
    ]
    if not any(real_path == ar or real_path.startswith(ar + os.sep) for ar in allowed_roots):
        return None, f"Access denied: path '{raw_path}' resolves outside allowed workspace boundaries."

    try:
        sz = os.path.getsize(real_path)
        if sz > MAX_DB_SIZE_BYTES:
            return None, f"Database file exceeds maximum size limit of 500 MB ({sz} bytes)."
    except OSError as e:
        return None, f"Cannot access database file: {e}"

    return real_path, None


def is_safe_identifier(name: str) -> bool:
    """Verifies that a table or column name contains only safe alphanumeric/underscore characters."""
    return bool(re.match(r"^[a-zA-Z0-9_]{1,64}$", name))


# Tool implementations
def tool_db_summary(db_path: str):
    real_path, err = validate_and_resolve_db_path(db_path)
    if err:
        return {"error": err}

    try:
        conn = sqlite3.connect(f"file:{real_path}?mode=ro", uri=True, timeout=5.0)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        raw_tables = [row[0] for row in cursor.fetchall()]

        table_info = {}
        for tbl in raw_tables:
            if not is_safe_identifier(tbl):
                continue
            cursor.execute(f"SELECT COUNT(*) FROM \"{tbl}\";")
            count = cursor.fetchone()[0]
            cursor.execute(f"PRAGMA table_info(\"{tbl}\");")
            cols = [{"name": c[1], "type": c[2]} for c in cursor.fetchall()]
            table_info[tbl] = {"row_count": count, "columns": cols}

        conn.close()
        return {
            "db_path": real_path,
            "tables": table_info
        }
    except Exception as e:
        return {"error": f"Database error: {str(e)}"}


def tool_db_query_alerts(db_path: str, rule_name: str = None, limit: int = 50):
    real_path, err = validate_and_resolve_db_path(db_path)
    if err:
        return {"error": err}

    # Validate and clamp limit
    try:
        limit = max(1, min(int(limit), 500))
    except (ValueError, TypeError):
        limit = 50

    # Validate rule_name if provided
    if rule_name is not None:
        if not isinstance(rule_name, str) or not is_safe_identifier(rule_name):
            return {"error": "Invalid rule_name parameter: must be an alphanumeric identifier."}

    try:
        conn = sqlite3.connect(f"file:{real_path}?mode=ro", uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Check if alerts table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts';")
        if not cursor.fetchone():
            conn.close()
            return {"error": "Table 'alerts' does not exist in database."}

        query = "SELECT * FROM alerts"
        params = []
        if rule_name:
            query += " WHERE rule_name = ?"
            params.append(rule_name)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = []
        for r in cursor.fetchall():
            d = dict(r)
            if "evidence_json" in d and isinstance(d["evidence_json"], str):
                try:
                    d["evidence"] = json.loads(d["evidence_json"])
                except Exception:
                    pass
            elif "evidence" in d and isinstance(d["evidence"], str):
                try:
                    d["evidence"] = json.loads(d["evidence"])
                except Exception:
                    pass
            rows.append(d)

        conn.close()
        return {
            "db_path": real_path,
            "matched_alerts": len(rows),
            "alerts": rows
        }
    except Exception as e:
        return {"error": f"Query error: {str(e)}"}


def tool_db_rule_statistics(db_path: str):
    real_path, err = validate_and_resolve_db_path(db_path)
    if err:
        return {"error": err}

    try:
        conn = sqlite3.connect(f"file:{real_path}?mode=ro", uri=True, timeout=5.0)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts';")
        if not cursor.fetchone():
            conn.close()
            return {"error": "Table 'alerts' does not exist in database."}

        cursor.execute(
            "SELECT rule_name, severity, COUNT(*) FROM alerts GROUP BY rule_name, severity ORDER BY COUNT(*) DESC;"
        )
        stats = []
        for rule_name, severity, count in cursor.fetchall():
            stats.append({"rule_name": rule_name, "severity": severity, "count": count})

        cursor.execute(
            "SELECT COUNT(DISTINCT src_ip), COUNT(DISTINCT dst_ip), MIN(timestamp), MAX(timestamp), COUNT(*) FROM alerts;"
        )
        unique_src, unique_dst, min_ts, max_ts, total = cursor.fetchone()

        conn.close()
        return {
            "db_path": real_path,
            "total_alerts": total,
            "unique_source_ips": unique_src,
            "unique_dest_ips": unique_dst,
            "first_alert_time": min_ts,
            "last_alert_time": max_ts,
            "rule_breakdown": stats
        }
    except Exception as e:
        return {"error": f"Statistics error: {str(e)}"}


# MCP Server Schema Definitions
TOOLS_SCHEMA = [
    {
        "name": "evaluation_db_summary",
        "description": "Inspect SQLite evaluation database schema, tables, and row counts in read-only mode.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "db_path": {"type": "string", "description": "Path to the SQLite .db file."}
            },
            "required": ["db_path"]
        }
    },
    {
        "name": "evaluation_db_query_alerts",
        "description": "Query detection alerts with optional filtering by rule_name and parameterized limits (1..500).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "db_path": {"type": "string", "description": "Path to the SQLite .db file."},
                "rule_name": {"type": "string", "description": "Optional rule identifier to filter by (e.g. PORT_SCAN)."},
                "limit": {"type": "integer", "description": "Maximum number of alerts to return (default 50, max 500)."}
            },
            "required": ["db_path"]
        }
    },
    {
        "name": "evaluation_db_rule_statistics",
        "description": "Compute alert counts per rule, unique attackers/targets, and time ranges across evaluation database.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "db_path": {"type": "string", "description": "Path to the SQLite .db file."}
            },
            "required": ["db_path"]
        }
    }
]


def handle_request(req):
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "netguard-eval-db-mcp",
                    "version": "1.1.0"
                }
            }
        }
    elif method == "notifications/initialized":
        return None
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": TOOLS_SCHEMA
            }
        }
    elif method == "tools/call":
        params = req.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})

        try:
            if tool_name == "evaluation_db_summary":
                out = tool_db_summary(args.get("db_path"))
            elif tool_name == "evaluation_db_query_alerts":
                out = tool_db_query_alerts(
                    args.get("db_path"),
                    args.get("rule_name"),
                    args.get("limit", 50)
                )
            elif tool_name == "evaluation_db_rule_statistics":
                out = tool_db_rule_statistics(args.get("db_path"))
            else:
                out = {"error": f"Unknown tool: {tool_name}"}
        except Exception as e:
            out = {"error": f"Tool execution failed: {str(e)}"}

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(out, indent=2)
                    }
                ]
            }
        }
    elif method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {}
        }
    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}"
            }
        }


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue

        resp = handle_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
