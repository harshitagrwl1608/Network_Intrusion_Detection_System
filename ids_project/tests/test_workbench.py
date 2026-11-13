"""
Unit, integration, and adversarial tests for NetGuard Engineering Workbench (.agents/plugins/netguard-workbench).
Validates lifecycle hooks, MCP servers, manifest integrity, defense-in-depth safeguards, and failure modes.
"""

import json
import os
import subprocess
import pytest

WORKBENCH_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", ".agents", "plugins", "netguard-workbench")
)
SCRIPTS_DIR = os.path.join(WORKBENCH_DIR, "scripts")
PROJECT_ROOT = os.path.abspath(os.path.join(WORKBENCH_DIR, "..", "..", ".."))


def run_script(script_name, input_data, raw_input=None):
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    proc = subprocess.Popen(
        ["python3", script_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if raw_input is not None:
        stdin_text = raw_input
    else:
        stdin_text = json.dumps(input_data)
    stdout, stderr = proc.communicate(stdin_text)
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
        "git push --force-with-lease origin antigravity/overnight-work",
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


def test_pre_tool_guard_blocks_advanced_bypass_attempts():
    """Tests evasion attempts using global flags, env vars, refspecs, nested shells, and interpreters."""
    bypass_attempts = [
        "git -C . push origin main",
        "git -C /tmp -c user.email=x push origin main",
        "git --git-dir=.git push origin main",
        "git --work-tree=. push origin HEAD:main",
        "git -C /tmp reset --hard",
        "GIT_DIR=.git git push origin main",
        "env -i git push origin main",
        "sudo git push origin main",
        "git push origin +refs/heads/main",
        "git push origin +antigravity/overnight-work",
        "git push origin :main",
        "git push origin :refs/heads/main",
        "git push --mirror origin",
        "git checkout -B main",
        "git switch -b main",
        "bash -c 'git reset --hard'",
        "eval 'git push origin main'",
        "python3 -c \"import os; os.system('git push origin main')\"",
        "python3 -c \"import subprocess; subprocess.run(['git', 'reset', '--hard'])\"",
        "node -e \"require('child_process').execSync('git push origin main')\"",
        "git status && git reset --hard",
        "git status; git push origin main",
    ]

    for cmd in bypass_attempts:
        payload = {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}}
        res = run_script("pre_tool_guard.py", payload)
        assert res.get("decision") == "deny", f"Failed to block bypass attempt: {cmd}"


def test_pre_tool_guard_fail_closed_on_malformed_and_empty_input():
    """Critical safety test: guarantees PreToolUse fails closed on all invalid inputs."""
    invalid_inputs = [
        "",                  # Empty stdin
        "   ",               # Whitespace stdin
        "{bad json",         # Malformed JSON
        "12345",             # Non-object JSON
        json.dumps([]),      # Array JSON
        json.dumps({"toolCall": "not_a_dict"}),
        json.dumps({"toolCall": {"name": "run_command"}}),  # Missing args
        json.dumps({"toolCall": {"name": "run_command", "args": {}}}),  # Missing CommandLine
        json.dumps({"toolCall": {"name": "run_command", "args": {"CommandLine": ""}}}),  # Empty CommandLine
        json.dumps({"toolCall": {"name": "run_command", "args": {"CommandLine": "   "}}}),  # Blank CommandLine
    ]

    for raw in invalid_inputs:
        res = run_script("pre_tool_guard.py", {}, raw_input=raw)
        assert res.get("decision") == "deny", f"Failed to fail-closed on invalid input: {raw!r}"
        assert "Guardrail" in res.get("reason", "")


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
        "python3 -c \"print('Hello safe execution')\"",
    ]

    for cmd in allowed_commands:
        payload = {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}}
        res = run_script("pre_tool_guard.py", payload)
        assert res.get("decision") == "allow", f"Failed to allow safe command: {cmd}"


def test_native_git_pre_push_hook():
    """Tests the native client-side Git pre-push hook installed in .git/hooks/pre-push."""
    hook_script = os.path.join(SCRIPTS_DIR, "git_pre_push.py")
    assert os.path.isfile(hook_script)

    def run_pre_push(lines):
        p = subprocess.run(
            ["python3", hook_script, "origin", "https://github.com/example/repo.git"],
            input=lines,
            text=True,
            capture_output=True,
        )
        return p.returncode, p.stderr

    # Prohibit push to main
    rc, err = run_pre_push("refs/heads/feature 1111 refs/heads/main 2222\n")
    assert rc != 0
    assert "Direct push to protected branch" in err

    # Prohibit deletion of main
    rc, err = run_pre_push("(delete) 0000000000000000000000000000000000000000 refs/heads/main 2222\n")
    assert rc != 0
    assert "Deletion of protected branch" in err

    # Allow push to authorized branch
    rc, err = run_pre_push("refs/heads/antigravity/overnight-work 1111 refs/heads/antigravity/overnight-work 2222\n")
    assert rc == 0


def test_post_tool_logger_redacts_secrets_and_uses_single_path():
    payload = {
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "curl -H 'Authorization: Bearer secret_api_token_12345' https://api.example.com"}
        },
        "stepIdx": 42
    }
    res = run_script("post_tool_logger.py", payload)
    assert res == {}

    # Verify audit log is located in WORKBENCH_DIR/logs/workbench_audit.log (no duplicated paths)
    log_file = os.path.join(WORKBENCH_DIR, "logs", "workbench_audit.log")
    assert os.path.exists(log_file)
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert any("step_idx\": 42" in l for l in lines)
        assert not any("secret_api_token_12345" in l for l in lines)
        # Ensure command arguments were NOT recorded in log (only first token 'curl')
        assert not any("https://api.example.com" in l for l in lines)


def test_post_tool_logger_secret_sanitizer():
    import sys
    if SCRIPTS_DIR not in sys.path:
        sys.path.insert(0, SCRIPTS_DIR)
    from post_tool_logger import sanitize

    assert "[REDACTED]" in sanitize("api_key=AIzaSyD1234567890abcdefg")
    assert "[REDACTED]" in sanitize("secret: MySuperSecretKey123")
    assert "[REDACTED]" in sanitize("Authorization: Bearer my_super_secret_token_12345")
    assert "[REDACTED_GH_TOKEN]" in sanitize("ghp_123456789012345678901234567890123456")
    assert "[REDACTED_JWT]" in sanitize("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak_this")


def test_pre_invocation_hook():
    res = run_script("pre_invocation.py", {"invocationNum": 2})
    assert "injectSteps" in res
    assert len(res["injectSteps"]) > 0
    ephem = res["injectSteps"][0].get("ephemeralMessage", "")
    assert "Rule Governance" in ephem


import contextlib


@contextlib.contextmanager
def preserve_active_run():
    """Preserve live active_run.json manifest across test executions."""
    active_run_file = os.path.join(WORKBENCH_DIR, "logs", "active_run.json")
    original_data = None
    if os.path.exists(active_run_file):
        try:
            with open(active_run_file, "r", encoding="utf-8") as f:
                original_data = f.read()
        except OSError:
            pass
    try:
        yield active_run_file
    finally:
        if original_data is not None:
            try:
                with open(active_run_file, "w", encoding="utf-8") as f:
                    f.write(original_data)
            except OSError:
                pass
        elif os.path.exists(active_run_file):
            try:
                os.remove(active_run_file)
            except OSError:
                pass


def test_stop_hook_safe_termination_non_looping():
    logs_dir = os.path.join(WORKBENCH_DIR, "logs")
    backup_file = os.path.join(logs_dir, "active_run.backup.json")
    with preserve_active_run() as active_run_file:
        if os.path.exists(active_run_file):
            os.remove(active_run_file)
        # Also remove the backup so there is truly no active run to recover
        backup_existed = os.path.exists(backup_file)
        backup_content = None
        if backup_existed:
            with open(backup_file, "r", encoding="utf-8") as f:
                backup_content = f.read()
            os.remove(backup_file)
        try:
            payload = {
                "terminationReason": "NO_TOOL_CALL",
                "fullyIdle": True,
                "executionNum": 1
            }
            res = run_script("stop_checkpoint.py", payload)
            # When no active run exists, must return allow
            assert res.get("decision") == "allow"
            assert "checkpoint saved" in res.get("reason", "").lower()

            checkpoint_file = os.path.join(WORKBENCH_DIR, "logs", "checkpoint.json")
            assert os.path.exists(checkpoint_file)
            with open(checkpoint_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                assert data.get("termination_reason") == "NO_TOOL_CALL"
        finally:
            if backup_existed and backup_content is not None:
                with open(backup_file, "w", encoding="utf-8") as f:
                    f.write(backup_content)


def test_stop_hook_active_before_deadline_continues():
    """Active run before deadline must return decision: continue with next action."""
    import time
    with preserve_active_run() as active_run_file:
        future_deadline = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 7200))
        manifest = {
            "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "deadline_utc": future_deadline,
            "duration_seconds": 21600,
            "status": "running",
            "cancel_requested": False,
            "last_checkpoint_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "current_workstream": "Workstream A: Pipeline Hardening",
            "next_work_item": "Validate PCAP buffer boundaries"
        }
        with open(active_run_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        payload = {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True, "executionNum": 2}
        res = run_script("stop_checkpoint.py", payload)
        assert res.get("decision") == "continue"
        assert "DO NOT STOP EARLY" in res.get("reason", "")
        assert "Workstream A: Pipeline Hardening" in res.get("reason", "")
        assert "Validate PCAP buffer boundaries" in res.get("reason", "")


def test_stop_hook_expired_deadline_completes():
    """When deadline has passed, Stop hook must return allow and mark status completed."""
    import time
    with preserve_active_run() as active_run_file:
        past_deadline = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60))
        manifest = {
            "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 21660)),
            "deadline_utc": past_deadline,
            "duration_seconds": 21600,
            "status": "running",
            "cancel_requested": False,
            "last_checkpoint_utc": past_deadline,
            "current_workstream": "Final Wrapup",
            "next_work_item": "Produce final execution proof"
        }
        with open(active_run_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        payload = {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True, "executionNum": 5}
        res = run_script("stop_checkpoint.py", payload)
        assert res.get("decision") == "allow"
        assert "deadline reached" in res.get("reason", "").lower()
        with open(active_run_file, "r", encoding="utf-8") as f:
            updated = json.load(f)
            assert updated.get("status") == "completed"
            assert "completed_at_utc" in updated


def test_stop_hook_explicit_cancellation_honored():
    """When cancellation is requested or signaled, Stop hook must return allow and mark cancelled."""
    import time
    with preserve_active_run() as active_run_file:
        future_deadline = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 7200))
        manifest = {
            "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "deadline_utc": future_deadline,
            "duration_seconds": 21600,
            "status": "running",
            "cancel_requested": True,
            "last_checkpoint_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "current_workstream": "Workstream B: Datasets"
        }
        with open(active_run_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        payload = {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True, "executionNum": 3}
        res = run_script("stop_checkpoint.py", payload)
        assert res.get("decision") == "allow"
        assert "cancelled" in res.get("reason", "").lower()
        with open(active_run_file, "r", encoding="utf-8") as f:
            updated = json.load(f)
            assert updated.get("status") == "cancelled"
            assert "cancelled_at_utc" in updated


def test_stop_hook_error_handling_graceful():
    """Corrupted primary AND no valid backup must gracefully allow termination without crash."""
    logs_dir = os.path.join(WORKBENCH_DIR, "logs")
    backup_file = os.path.join(logs_dir, "active_run.backup.json")
    with preserve_active_run() as active_run_file:
        # Write corrupt primary
        with open(active_run_file, "w", encoding="utf-8") as f:
            f.write("{invalid-corrupt-json")
        # Ensure no valid backup exists so the hook truly has no recoverable state
        backup_existed = os.path.exists(backup_file)
        backup_content = None
        if backup_existed:
            with open(backup_file, "r", encoding="utf-8") as f:
                backup_content = f.read()
            os.remove(backup_file)
        try:
            payload = {"terminationReason": "ERROR", "error": "corrupt test", "fullyIdle": True, "executionNum": 4}
            res = run_script("stop_checkpoint.py", payload)
            assert res.get("decision") == "allow"
        finally:
            if backup_existed and backup_content is not None:
                with open(backup_file, "w", encoding="utf-8") as f:
                    f.write(backup_content)


def test_stop_hook_corrupt_manifest_with_valid_backup_continues():
    """Corrupted primary manifest with a recoverable backup must continue if deadline not reached."""
    import time
    logs_dir = os.path.join(WORKBENCH_DIR, "logs")
    backup_file = os.path.join(logs_dir, "active_run.backup.json")
    with preserve_active_run() as active_run_file:
        future_deadline = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 7200))
        valid_backup = {
            "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "deadline_utc": future_deadline,
            "duration_seconds": 21600,
            "status": "running",
            "cancel_requested": False,
            "current_workstream": "Recovered Workstream",
            "next_work_item": "Resume pipeline audit",
        }
        # Write corrupt primary
        with open(active_run_file, "w", encoding="utf-8") as f:
            f.write("{corrupt!!}")
        # Write valid backup
        with open(backup_file, "w", encoding="utf-8") as f:
            json.dump(valid_backup, f, indent=2)
        try:
            payload = {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True, "executionNum": 10}
            res = run_script("stop_checkpoint.py", payload)
            assert res.get("decision") == "continue", f"Expected continue with backup, got: {res}"
            assert "DO NOT STOP EARLY" in res.get("reason", "")
        finally:
            if os.path.exists(backup_file):
                os.remove(backup_file)


def test_stop_hook_missing_deadline_field_allows_termination():
    """An active run manifest with a missing deadline_utc must allow termination."""
    import time
    with preserve_active_run() as active_run_file:
        manifest = {
            "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            # deadline_utc intentionally omitted
            "duration_seconds": 21600,
            "status": "running",
            "cancel_requested": False,
            "current_workstream": "Some Workstream",
        }
        with open(active_run_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        payload = {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True, "executionNum": 11}
        res = run_script("stop_checkpoint.py", payload)
        assert res.get("decision") == "allow"
        assert "deadline" in res.get("reason", "").lower()


def test_stop_hook_invalid_deadline_string_allows_termination():
    """An active run manifest with an unparseable deadline_utc must allow termination."""
    import time
    with preserve_active_run() as active_run_file:
        manifest = {
            "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "deadline_utc": "not-a-valid-timestamp",
            "duration_seconds": 21600,
            "status": "running",
            "cancel_requested": False,
            "current_workstream": "Some Workstream",
        }
        with open(active_run_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        payload = {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True, "executionNum": 12}
        res = run_script("stop_checkpoint.py", payload)
        assert res.get("decision") == "allow"
        assert "deadline" in res.get("reason", "").lower()


def test_stop_hook_manifest_path_uses_progress_ledger_field():
    """Manifest with progress_ledger_path must use that path for next-work-item lookup."""
    import time
    import tempfile
    logs_dir = os.path.join(WORKBENCH_DIR, "logs")
    with preserve_active_run() as active_run_file:
        future_deadline = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 7200))
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as ledger_f:
            ledger_path = ledger_f.name
            json.dump({"exact_next_action": "run-ledger-next-item"}, ledger_f)
        try:
            manifest = {
                "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "deadline_utc": future_deadline,
                "duration_seconds": 21600,
                "status": "running",
                "cancel_requested": False,
                "current_workstream": "Ledger Test Workstream",
                "progress_ledger_path": ledger_path,
            }
            with open(active_run_file, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
            payload = {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True, "executionNum": 13}
            res = run_script("stop_checkpoint.py", payload)
            assert res.get("decision") == "continue"
            assert "run-ledger-next-item" in res.get("reason", "")
        finally:
            os.unlink(ledger_path)


def test_stop_hook_atomic_write_creates_backup():
    """Stop hook continuation must leave behind a recoverable backup of the previous manifest."""
    import time
    logs_dir = os.path.join(WORKBENCH_DIR, "logs")
    backup_file = os.path.join(logs_dir, "active_run.backup.json")
    with preserve_active_run() as active_run_file:
        future_deadline = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 7200))
        manifest = {
            "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "deadline_utc": future_deadline,
            "duration_seconds": 21600,
            "status": "running",
            "cancel_requested": False,
            "current_workstream": "Atomic Write Workstream",
            "next_work_item": "verify backup creation",
        }
        with open(active_run_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        # Remove any previous backup
        if os.path.exists(backup_file):
            os.remove(backup_file)
        payload = {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True, "executionNum": 14}
        res = run_script("stop_checkpoint.py", payload)
        assert res.get("decision") == "continue"
        # Backup must have been created
        assert os.path.exists(backup_file), "Backup file not created after continuation"
        with open(backup_file, "r", encoding="utf-8") as f:
            backup_data = json.load(f)
        assert backup_data.get("status") == "running"
        # Cleanup
        if os.path.exists(backup_file):
            os.remove(backup_file)


def test_stop_hook_missing_ledger_does_not_crash():
    """Missing progress_ledger_path file must not crash the hook; fallback message used."""
    import time
    with preserve_active_run() as active_run_file:
        future_deadline = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 7200))
        manifest = {
            "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "deadline_utc": future_deadline,
            "duration_seconds": 21600,
            "status": "running",
            "cancel_requested": False,
            "current_workstream": "Missing Ledger Workstream",
            "progress_ledger_path": "/nonexistent/path/to/ledger.json",
        }
        with open(active_run_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        payload = {"terminationReason": "NO_TOOL_CALL", "fullyIdle": True, "executionNum": 15}
        res = run_script("stop_checkpoint.py", payload)
        assert res.get("decision") == "continue"
        assert "DO NOT STOP EARLY" in res.get("reason", "")


# --- 2. MCP Server Tests ---

def test_pcap_mcp_server_protocol_and_tools():
    script_path = os.path.join(SCRIPTS_DIR, "pcap_mcp_server.py")
    test_pcap = os.path.join(PROJECT_ROOT, "ids_project", "data", "test_attacks.pcap")

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


def test_pcap_mcp_server_path_traversal_prevention():
    """Verifies that PCAP MCP server rejects traversal outside allowed workspace roots."""
    script_path = os.path.join(SCRIPTS_DIR, "pcap_mcp_server.py")
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "pcap_metadata", "arguments": {"pcap_path": "/etc/shadow"}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "pcap_metadata", "arguments": {"pcap_path": "../../../../../etc/passwd"}}},
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
    assert proc.returncode == 0

    responses = [json.loads(line) for line in stdout.strip().splitlines() if line.strip()]
    res2 = json.loads(responses[1]["result"]["content"][0]["text"])
    assert "error" in res2

    res3 = json.loads(responses[2]["result"]["content"][0]["text"])
    assert "error" in res3


def test_pcap_mcp_server_external_dataset_access():
    """Verifies that PCAP MCP server permits access to external datasets root on /dev/sdb1."""
    ext_dir = "/run/media/harshitgarg/Data1/NetGuard-datasets/verified"
    if not os.path.isdir(ext_dir):
        pytest.skip("External datasets directory not mounted")

    test_file = os.path.join(ext_dir, "ws_teardrop.pcap")
    if not os.path.isfile(test_file):
        pytest.skip("ws_teardrop.pcap not present on external drive")

    script_path = os.path.join(SCRIPTS_DIR, "pcap_mcp_server.py")
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "pcap_metadata", "arguments": {"pcap_path": test_file}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "dataset_hash_verify", "arguments": {"file_path": test_file}}},
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
    assert proc.returncode == 0

    responses = [json.loads(line) for line in stdout.strip().splitlines() if line.strip()]
    res_meta = json.loads(responses[1]["result"]["content"][0]["text"])
    assert "error" not in res_meta
    assert res_meta.get("total_packets") == 17

    res_hash = json.loads(responses[2]["result"]["content"][0]["text"])
    assert "error" not in res_hash
    assert len(res_hash.get("sha256", "")) == 64


def _make_eval_db(tmp_path):
    """Create a throwaway evaluation database for the MCP tests.

    The MCP tests must not depend on a developer-populated
    ``ids_project/storage/alerts.db``: that file is gitignored and absent from a
    clean checkout, which made these tests fail for reasons unrelated to the
    server being tested.
    """
    import sqlite3

    db_path = os.path.join(str(tmp_path), "eval.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE alerts ("
        "id INTEGER PRIMARY KEY, timestamp REAL, rule_name TEXT, severity TEXT, "
        "src_ip TEXT, dst_ip TEXT, evidence_json TEXT)"
    )
    conn.executemany(
        "INSERT INTO alerts "
        "(timestamp, rule_name, severity, src_ip, dst_ip, evidence_json) "
        "VALUES (?,?,?,?,?,?)",
        [
            (1000.0, "PORT_SCAN", "high", "192.0.2.10", "192.0.2.50", '{"ports": 12}'),
            (1001.0, "SYN_FLOOD", "critical", "192.0.2.11", "192.0.2.50", "{}"),
        ],
    )
    conn.commit()
    conn.close()
    return db_path


def test_eval_db_mcp_server_summary_and_stats(tmp_path):
    script_path = os.path.join(SCRIPTS_DIR, "eval_db_mcp_server.py")
    test_db = _make_eval_db(tmp_path)

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


def test_eval_db_mcp_server_sql_injection_defense(tmp_path):
    """Verifies that evaluation DB server sanitizes identifiers and prevents arbitrary SQL injection."""
    script_path = os.path.join(SCRIPTS_DIR, "eval_db_mcp_server.py")
    test_db = _make_eval_db(tmp_path)

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "evaluation_db_query_alerts",
                "arguments": {
                    "db_path": test_db,
                    "rule_name": "PORT_SCAN' OR 1=1 --",
                    "limit": 10
                }
            }
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "evaluation_db_query_alerts",
                "arguments": {
                    "db_path": test_db,
                    "limit": -5
                }
            }
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "evaluation_db_summary",
                "arguments": {
                    "db_path": "../../../../../etc/passwd"
                }
            }
        }
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
    assert proc.returncode == 0

    responses = [json.loads(line) for line in stdout.strip().splitlines() if line.strip()]

    # Request 2: Injection attempt in rule_name should be rejected with error
    res2 = json.loads(responses[1]["result"]["content"][0]["text"])
    assert "error" in res2
    assert "Invalid rule_name" in res2["error"]

    # Request 3: Negative limit clamped to positive
    res3 = json.loads(responses[2]["result"]["content"][0]["text"])
    assert "matched_alerts" in res3

    # Request 4: Traversal path rejected
    res4 = json.loads(responses[3]["result"]["content"][0]["text"])
    assert "error" in res4
    assert "Access denied" in res4["error"] or "not found" in res4["error"]


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
