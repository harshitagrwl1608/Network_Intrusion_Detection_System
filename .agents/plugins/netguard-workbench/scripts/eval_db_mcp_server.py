#!/usr/bin/env python3
"""
NetGuard Evaluation Database Inspector MCP Server.
Provides read-only JSON-RPC 2.0 stdio MCP interface for SQLite evaluation inspection:
- evaluation_db_summary
- evaluation_db_query_alerts
- evaluation_db_rule_statistics
"""

import json
import os
import sqlite3
import sys

# Tool implementations
def tool_db_summary(db_path: str):
    if not os.path.isfile(db_path):
        return {"error": f"Database file not found: {db_path}"}

    try:
        conn = sqlite3.connect(f"file:{os.path.abspath(db_path)}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]

        table_info = {}
        for tbl in tables:
            cursor.execute(f"SELECT COUNT(*) FROM \"{tbl}\";")
            count = cursor.fetchone()[0]
            cursor.execute(f"PRAGMA table_info(\"{tbl}\");")
            cols = [{"name": c[1], "type": c[2]} for c in cursor.fetchall()]
            table_info[tbl] = {"row_count": count, "columns": cols}

        conn.close()
        return {
            "db_path": os.path.abspath(db_path),
            "tables": table_info
        }
    except Exception as e:
        return {"error": f"Database error: {str(e)}"}


def tool_db_query_alerts(db_path: str, rule_name: str = None, limit: int = 50):
    if not os.path.isfile(db_path):
        return {"error": f"Database file not found: {db_path}"}

    try:
        conn = sqlite3.connect(f"file:{os.path.abspath(db_path)}?mode=ro", uri=True)
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
        params.append(min(limit, 200))

        cursor.execute(query, params)
        rows = []
        for r in cursor.fetchall():
            d = dict(r)
            if "evidence" in d and isinstance(d["evidence"], str):
                try:
                    d["evidence"] = json.loads(d["evidence"])
                except Exception:
                    pass
            rows.append(d)

        conn.close()
        return {
            "db_path": os.path.abspath(db_path),
            "matched_alerts": len(rows),
            "alerts": rows
        }
    except Exception as e:
        return {"error": f"Query error: {str(e)}"}


def tool_db_rule_statistics(db_path: str):
    if not os.path.isfile(db_path):
        return {"error": f"Database file not found: {db_path}"}

    try:
        conn = sqlite3.connect(f"file:{os.path.abspath(db_path)}?mode=ro", uri=True)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts';")
        if not cursor.fetchone():
            conn.close()
            return {"error": "Table 'alerts' does not exist in database."}

        cursor.execute("SELECT rule_name, severity, COUNT(*) FROM alerts GROUP BY rule_name, severity ORDER BY COUNT(*) DESC;")
        stats = []
        for rule_name, severity, count in cursor.fetchall():
            stats.append({"rule_name": rule_name, "severity": severity, "count": count})

        cursor.execute("SELECT COUNT(DISTINCT src_ip), COUNT(DISTINCT dst_ip), MIN(timestamp), MAX(timestamp), COUNT(*) FROM alerts;")
        unique_src, unique_dst, min_ts, max_ts, total = cursor.fetchone()

        conn.close()
        return {
            "db_path": os.path.abspath(db_path),
            "total_alerts": total,
            "unique_source_ips": unique_src,
            "unique_dest_ips": unique_dst,
            "first_alert_time": min_ts,
            "last_alert_time": max_ts,
            "rule_breakdown": stats
        }
    except Exception as e:
        return {"error": f"Statistics error: {str(e)}"}


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
        "description": "Query alerts from a NetGuard evaluation database with optional rule_name filtering.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "db_path": {"type": "string", "description": "Path to the SQLite .db file."},
                "rule_name": {"type": "string", "description": "Optional rule name filter (e.g. SYN_FLOOD)."},
                "limit": {"type": "integer", "description": "Maximum number of alerts to return (default 50)."}
            },
            "required": ["db_path"]
        }
    },
    {
        "name": "evaluation_db_rule_statistics",
        "description": "Aggregate alert statistics by rule name, severity, and IP counts from an evaluation database.",
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
                    "version": "1.0.0"
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
                out = tool_db_query_alerts(args.get("db_path"), args.get("rule_name"), args.get("limit", 50))
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
