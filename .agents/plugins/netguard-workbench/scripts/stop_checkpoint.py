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


def main():
    try:
        data = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    except Exception:
        data = {}

    term_reason = data.get("terminationReason", "UNKNOWN")
    error_msg = data.get("error", "")
    fully_idle = data.get("fullyIdle", True)
    exec_num = data.get("executionNum", 1)

    checkpoint_dir = os.path.join(os.getcwd(), ".agents", "plugins", "netguard-workbench", "logs")
    os.makedirs(checkpoint_dir, exist_ok=True)
    checkpoint_file = os.path.join(checkpoint_dir, "checkpoint.json")

    record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "execution_num": exec_num,
        "termination_reason": term_reason,
        "fully_idle": fully_idle,
        "error": error_msg,
        "workbench_status": "standby"
    }

    try:
        with open(checkpoint_file, "w", encoding="utf-8") as f:
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
