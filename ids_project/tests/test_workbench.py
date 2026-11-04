"""
Unit and integration tests for NetGuard Engineering Workbench (.agents/plugins/netguard-workbench).
Validates lifecycle hooks, MCP servers, manifest integrity, and safety guards.
"""

import json
import os
import subprocess
import pytest

WORKBENCH_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", ".agents", "plugins", "netguard-workbench")
)
SCRIPTS_DIR = os.path.join(WORKBENCH_DIR, "scripts")


def run_script(script_name, input_data):
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    proc = subprocess.Popen(
        ["python3", script_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = proc.communicate(json.dumps(input_data))
    assert proc.returncode == 0, f"{script_name} failed with stderr: {stderr}"
    return json.loads(stdout.strip()) if stdout.strip() else {}


# --- 1. Lifecycle Hook Tests ---

def test_session_start_hook():
    res = run_script("session_start.py", {})
    assert "injectSteps" in res
    assert len(res["injectSteps"]) > 0
    sys_msg = res["injectSteps"][0].get("systemMessage", {}).get("systemMessage", "")
    assert "NetGuard Engineering Workbench Initialized" in sys_msg
    assert "RuleEngine.rules" in sys_msg


def test_pre_tool_guard_blocks_prohibited_commands():
    blocked_commands = [
        "git push origin main",
        "git push origin HEAD:main",
        "git push -f",
        "git push --force origin antigravity/overnight-work",
        "git reset --hard HEAD~1",
        "git branch -D test_branch",
        "git branch --delete test_branch",
        "git push origin --delete old_branch",
        "git clean -fdx",
        "rm -rf ids_project/evaluation/datasets",
        "rm -rf /",
        "rm -rf ids_project",
        "bash -c 'git push -f origin main'",
    ]

    for cmd in blocked_commands:
        payload = {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}}
        res = run_script("pre_tool_guard.py", payload)
        assert res.get("decision") == "deny", f"Failed to deny prohibited command: {cmd}"
        assert "NetGuard Workbench Guardrail" in res.get("reason", "")


def test_pre_tool_guard_allows_safe_operations():
    allowed_commands = [
        "git status",
        "git diff",
        "git log -n 5 --oneline",
        "git push origin antigravity/overnight-work",
        "pytest ids_project/tests",
        "python3 ids_project/evaluation/run_eval.py",
        "ls -la",
        "mkdir -p tmp_dir",
    ]

    for cmd in allowed_commands:
        payload = {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}}
        res = run_script("pre_tool_guard.py", payload)
        assert res.get("decision") == "allow", f"Failed to allow safe command: {cmd}"


def test_post_tool_logger_redacts_secrets():
    payload = {
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "curl -H 'Authorization: Bearer secret_api_token_12345' https://api.example.com"}
        },
        "stepIdx": 42
    }
    res = run_script("post_tool_logger.py", payload)
    assert res == {}

    # Verify audit log contains redacted entry
    log_file = os.path.join(WORKBENCH_DIR, "logs", "workbench_audit.log")
    assert os.path.exists(log_file)
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert any("step_idx\": 42" in l for l in lines)
        assert not any("secret_api_token_12345" in l for l in lines)


def test_pre_invocation_hook():
    res = run_script("pre_invocation.py", {"invocationNum": 2})
    assert "injectSteps" in res
    assert len(res["injectSteps"]) > 0
    ephem = res["injectSteps"][0].get("ephemeralMessage", "")
    assert "19-rule inventory" in ephem


def test_stop_hook_safe_termination_non_looping():
    payload = {
        "terminationReason": "NO_TOOL_CALL",
        "fullyIdle": True,
        "executionNum": 1
    }
    res = run_script("stop_checkpoint.py", payload)
    # Critical invariant: must NOT return continue
    assert res.get("decision") == "allow"
    assert "checkpoint saved" in res.get("reason", "").lower()

    checkpoint_file = os.path.join(WORKBENCH_DIR, "logs", "checkpoint.json")
    assert os.path.exists(checkpoint_file)
    with open(checkpoint_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data.get("termination_reason") == "NO_TOOL_CALL"


# --- 2. MCP Server Tests ---

def test_pcap_mcp_server_protocol_and_tools():
    script_path = os.path.join(SCRIPTS_DIR, "pcap_mcp_server.py")
    test_pcap = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "data", "test_attacks.pcap")
    )

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "pcap_metadata", "arguments": {"pcap_path": test_pcap}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "protocol_distribution", "arguments": {"pcap_path": test_pcap}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "tcp_flags", "arguments": {"pcap_path": test_pcap}}},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "dataset_hash_verify", "arguments": {"file_path": test_pcap}}},
    ]

    proc = subprocess.Popen(
        ["python3", script_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    in_text = "\n".join(json.dumps(r) for r in requests) + "\n"
    stdout, stderr = proc.communicate(in_text)
    assert proc.returncode == 0, f"MCP failed: {stderr}"

    responses = [json.loads(line) for line in stdout.strip().splitlines() if line.strip()]
    assert len(responses) == 6

    # 1. initialize
    assert responses[0]["result"]["serverInfo"]["name"] == "netguard-pcap-mcp"
    # 2. tools/list
    tools = [t["name"] for t in responses[1]["result"]["tools"]]
    assert "pcap_metadata" in tools
    assert "tcp_flags" in tools
    assert "dns_inventory" in tools
    # 3. pcap_metadata
    meta = json.loads(responses[2]["result"]["content"][0]["text"])
    assert meta["total_packets"] > 0
    assert meta["duration_seconds"] > 0
    # 4. protocol_distribution
    proto = json.loads(responses[3]["result"]["content"][0]["text"])
    assert "protocol_breakdown" in proto
    # 5. tcp_flags
    flags = json.loads(responses[4]["result"]["content"][0]["text"])
    assert "flag_distribution" in flags
    # 6. dataset_hash_verify
    hashes = json.loads(responses[5]["result"]["content"][0]["text"])
    assert len(hashes["sha256"]) == 64


def test_eval_db_mcp_server_summary_and_stats():
    script_path = os.path.join(SCRIPTS_DIR, "eval_db_mcp_server.py")
    test_db = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "storage", "alerts.db")
    )

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "evaluation_db_summary", "arguments": {"db_path": test_db}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "evaluation_db_rule_statistics", "arguments": {"db_path": test_db}}},
    ]

    proc = subprocess.Popen(
        ["python3", script_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    in_text = "\n".join(json.dumps(r) for r in requests) + "\n"
    stdout, stderr = proc.communicate(in_text)
    assert proc.returncode == 0, f"MCP failed: {stderr}"

    responses = [json.loads(line) for line in stdout.strip().splitlines() if line.strip()]
    assert len(responses) == 4
    summary = json.loads(responses[2]["result"]["content"][0]["text"])
    assert "tables" in summary
    assert "alerts" in summary["tables"]


# --- 3. Workbench Plugin Structure Tests ---

def test_plugin_directory_structure():
    assert os.path.isfile(os.path.join(WORKBENCH_DIR, "plugin.json"))
    assert os.path.isfile(os.path.join(WORKBENCH_DIR, "README.md"))
    assert os.path.isfile(os.path.join(WORKBENCH_DIR, "hooks.json"))
    assert os.path.isfile(os.path.join(WORKBENCH_DIR, "mcp_config.json"))
    assert os.path.isfile(os.path.join(WORKBENCH_DIR, "rules", "AGENTS.md"))

    agents = [
        "pcap-analyst.md",
        "detection-rule-engineer.md",
        "dataset-researcher.md",
        "suricata-validator.md",
        "zeek-analyst.md",
        "performance-auditor.md",
        "regression-qa-reviewer.md",
        "independent-security-auditor.md",
    ]
    for a in agents:
        assert os.path.isfile(os.path.join(WORKBENCH_DIR, "agents", a)), f"Missing agent: {a}"

    skills = [
        "pcap-forensics",
        "dataset-acquisition",
        "dataset-deduplication",
        "suricata-validation",
        "zeek-analysis",
        "rule-review",
        "memory-performance-audit",
        "reproducible-evaluation",
        "forensic-reporting",
    ]
    for s in skills:
        assert os.path.isfile(os.path.join(WORKBENCH_DIR, "skills", s, "SKILL.md")), f"Missing skill: {s}"
