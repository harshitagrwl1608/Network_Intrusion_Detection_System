#!/usr/bin/env python3
"""
PreInvocation Hook for NetGuard Engineering Workbench.
Supplies concise workspace context and reminders prior to model inference.
"""

import json
import sys


def main():
    try:
        data = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    except Exception:
        data = {}

    inv_num = data.get("invocationNum", 0)

    # Inject ephemeral reminder for model focus
    reminder = (
        "NetGuard Workbench Invariants: "
        "Rule Governance (every rule distinct, justified, tested, maintainable) | "
        "Authorized branch 'antigravity/overnight-work' | "
        "Network telemetry boundary: packet PCAP over endpoint EVTX."
    )

    response = {
        "injectSteps": [
            {
                "ephemeralMessage": reminder
            }
        ]
    }

    json.dump(response, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()

