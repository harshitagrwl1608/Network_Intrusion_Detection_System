#!/usr/bin/env python3
"""
Stop Hook for NetGuard Engineering Workbench.
Saves a durable checkpoint, records termination reason, and ensures safe termination
without generating an infinite continuation loop.
"""

import json
import os
import sys
import time

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.abspath(os.path.join(SCRIPTS_DIR, ".."))
LOGS_DIR = os.path.join(PLUGIN_DIR, "logs")
CHECKPOINT_FILE = os.path.join(LOGS_DIR, "checkpoint.json")


def main():
    try:
        data = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    except Exception:
        data = {}

    term_reason = data.get("terminationReason", "UNKNOWN") if isinstance(data, dict) else "UNKNOWN"
    error_msg = data.get("error", "") if isinstance(data, dict) else ""
    fully_idle = data.get("fullyIdle", True) if isinstance(data, dict) else True
    exec_num = data.get("executionNum", 1) if isinstance(data, dict) else 1

    record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "execution_num": exec_num,
        "termination_reason": term_reason,
        "fully_idle": fully_idle,
        "error": error_msg,
        "workbench_status": "standby"
    }

    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)
    except Exception:
        pass

    # IMPORTANT: Never return unconditional "continue". Always return "allow" to allow normal loop termination.
    response = {
        "decision": "allow",
        "reason": f"NetGuard checkpoint saved successfully (reason: {term_reason})."
    }

    json.dump(response, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
