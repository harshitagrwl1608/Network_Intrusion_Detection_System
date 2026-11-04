#!/usr/bin/env python3
"""
SessionStart Hook for NetGuard Engineering Workbench.
Reads repository state, current branch, autonomous campaign state, and injects context into the session.
"""

import json
import os
import subprocess
import sys


def get_git_info():
    try:
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        status = subprocess.check_output(
            ["git", "status", "--porcelain"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        clean = "clean" if not status else f"{len(status.splitlines())} modified/untracked files"
        return branch, commit, clean
    except Exception:
        return "unknown", "unknown", "unknown"


def get_autonomy_state():
    state_file = os.path.join(os.getcwd(), "docs", "autonomy", "state.json")
    if os.path.exists(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data
        except Exception:
            pass
    return None


def main():
    try:
        payload = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    except Exception:
        payload = {}

    branch, commit, clean = get_git_info()
    autonomy = get_autonomy_state()

    msg_lines = [
        "### NetGuard Engineering Workbench Initialized",
        f"- **Git Branch**: `{branch}` (`{commit}`) [{clean}]",
        "- **Detection Rules**: Strictly enforcing 19 registered rules in `RuleEngine.rules`.",
        "- **Authorized Feature Branch**: `antigravity/overnight-work`.",
    ]

    if autonomy:
        status = autonomy.get("status", "unknown")
        cycle = autonomy.get("current_cycle", "?")
        target = autonomy.get("total_cycles_target", "?")
        locked = autonomy.get("implementation_lock", False)
        msg_lines.append(f"- **Autonomy Mission**: {status} (Cycle {cycle}/{target}, Lock: {locked})")

    context_msg = "\n".join(msg_lines)

    result = {
        "injectSteps": [
            {
                "systemMessage": {
                    "systemMessage": context_msg,
                    "metadata": {
                        "user_markdown": context_msg
                    }
                }
            }
        ]
    }
    json.dump(result, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
