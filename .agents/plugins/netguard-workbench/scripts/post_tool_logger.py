#!/usr/bin/env python3
"""
PostToolUse Audit Logger for NetGuard Engineering Workbench.
Records sanitized operational and validation events without leaking tokens or secrets.
"""

import json
import os
import re
import sys
import time

def sanitize(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    # Redact key-value pairs
    text = re.sub(
        r"(?i)(api[_-]?key|secret|token|password|bearer|auth|credential)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{8,})['\"]?",
        r"\1=[REDACTED]",
        text,
    )
    # Redact GitHub tokens
    text = re.sub(
        r"(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})",
        "[REDACTED_GH_TOKEN]",
        text,
    )
    # Redact JWTs
    text = re.sub(
        r"ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "[REDACTED_JWT]",
        text,
    )
    return text


def main():
    try:
        data = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    except Exception:
        data = {}

    tool_call = data.get("toolCall", {})
    tool_name = tool_call.get("name", "unknown")
    step_idx = data.get("stepIdx", 0)
    has_error = bool(data.get("error"))

    # Log summary
    log_dir = os.path.join(os.getcwd(), ".agents", "plugins", "netguard-workbench", "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "workbench_audit.log")

    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "step_idx": step_idx,
        "tool": tool_name,
        "status": "error" if has_error else "ok",
    }

    if tool_name == "run_command":
        cmd = tool_call.get("args", {}).get("CommandLine", "")
        # Record only base program or sanitized command prefix
        first_token = cmd.strip().split()[0] if cmd.strip() else ""
        entry["summary"] = sanitize(f"Executed command starting with: {first_token}")

    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

    # PostToolUse requires empty JSON object on stdout
    json.dump({}, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
