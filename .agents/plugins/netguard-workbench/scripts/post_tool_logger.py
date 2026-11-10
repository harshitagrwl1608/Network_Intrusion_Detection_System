#!/usr/bin/env python3
"""
PostToolUse Audit Logger for NetGuard Engineering Workbench.
Records sanitized operational events without leaking tokens, arguments, or secrets.
Features bounded retention, safe rotation, and thread/process-safe file locking.
"""

import fcntl
import json
import os
import re
import sys
import time

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.abspath(os.path.join(SCRIPTS_DIR, ".."))
LOGS_DIR = os.path.join(PLUGIN_DIR, "logs")
AUDIT_LOG_FILE = os.path.join(LOGS_DIR, "workbench_audit.log")

MAX_LOG_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_BACKUP_COUNT = 3


def sanitize(text: str) -> str:
    """Sanitizes text by stripping API keys, tokens, JWTs, and passwords."""
    if not isinstance(text, str):
        text = str(text)

    # Redact Bearer tokens (with or without colon/equal)
    text = re.sub(
        r"(?i)\b(bearer)\s+([a-zA-Z0-9_\-\.]{8,})",
        r"\1 [REDACTED]",
        text,
    )
    # Redact key-value credentials
    text = re.sub(
        r"(?i)\b(api[_-]?key|secret|token|password|auth|credential|access[_-]?key)\s*([:=]|\s+)\s*['\"]?([a-zA-Z0-9_\-\.]{8,})['\"]?",
        r"\1\2[REDACTED]",
        text,
    )
    # Redact GitHub tokens
    text = re.sub(
        r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}|gho_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36})",
        "[REDACTED_GH_TOKEN]",
        text,
    )
    # Redact JWTs
    text = re.sub(
        r"ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "[REDACTED_JWT]",
        text,
    )
    # Redact cloud keys
    text = re.sub(r"\b(AKIA[0-9A-Z]{16})\b", "[REDACTED_AWS_KEY]", text)
    text = re.sub(r"\b(AIza[0-9A-Za-z-_]{35})\b", "[REDACTED_GCP_KEY]", text)
    return text


def rotate_logs_if_needed():
    """Rotates log file if it exceeds MAX_LOG_SIZE_BYTES."""
    try:
        if not os.path.exists(AUDIT_LOG_FILE):
            return
        if os.path.getsize(AUDIT_LOG_FILE) < MAX_LOG_SIZE_BYTES:
            return

        for i in range(MAX_BACKUP_COUNT - 1, 0, -1):
            src = f"{AUDIT_LOG_FILE}.{i}"
            dst = f"{AUDIT_LOG_FILE}.{i + 1}"
            if os.path.exists(src):
                os.replace(src, dst)

        first_backup = f"{AUDIT_LOG_FILE}.1"
        os.replace(AUDIT_LOG_FILE, first_backup)
    except Exception:
        pass


def write_audit_entry(entry: dict):
    """Safely appends entry to audit log with file locking and rotation."""
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        rotate_logs_if_needed()

        payload_line = json.dumps(entry) + "\n"
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            except (OSError, AttributeError):
                pass
            f.write(payload_line)
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except (OSError, AttributeError):
                pass
    except Exception:
        # Failure to write audit log must never crash the tool pipeline
        pass


def main():
    try:
        data = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    except Exception:
        data = {}

    tool_call = data.get("toolCall", {}) if isinstance(data, dict) else {}
    tool_name = tool_call.get("name", "unknown") if isinstance(tool_call, dict) else "unknown"
    step_idx = data.get("stepIdx", 0) if isinstance(data, dict) else 0
    has_error = bool(data.get("error")) if isinstance(data, dict) else False

    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "step_idx": step_idx,
        "tool": tool_name,
        "status": "error" if has_error else "ok",
    }

    if tool_name == "run_command" and isinstance(tool_call, dict):
        cmd = tool_call.get("args", {}).get("CommandLine", "")
        # Record strictly the base program name to avoid leaking arguments or data
        first_token = cmd.strip().split()[0] if cmd.strip() else ""
        entry["summary"] = sanitize(f"Executed command starting with: {first_token}")

    write_audit_entry(entry)

    # PostToolUse requires empty JSON object on stdout
    json.dump({}, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
