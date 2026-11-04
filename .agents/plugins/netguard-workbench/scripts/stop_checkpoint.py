#!/usr/bin/env python3
"""
Stop Hook for NetGuard Engineering Workbench.
Enforces deadline-aware autonomous continuation during active engineering runs.
When an active run is in progress and deadline has not elapsed, returns decision: continue
with the remaining time and next work item to prevent premature completion.
When the deadline has passed, cancellation is requested, or no run is active, allows termination.
"""

from datetime import datetime, timezone
import json
import os
import sys
import time

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.abspath(os.path.join(SCRIPTS_DIR, ".."))
LOGS_DIR = os.path.join(PLUGIN_DIR, "logs")
CHECKPOINT_FILE = os.path.join(LOGS_DIR, "checkpoint.json")
ACTIVE_RUN_FILE = os.path.join(LOGS_DIR, "active_run.json")
PROGRESS_LEDGER_FILE = "/run/media/harshitgarg/Data1/NetGuard-datasets/coordination/phase4_progress_ledger.json"


def parse_iso_utc(ts_str: str) -> float:
    """Parse ISO UTC timestamp string into epoch seconds."""
    clean = ts_str.replace("Z", "+00:00")
    dt = datetime.fromisoformat(clean)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def format_iso_utc(epoch_s: float | None = None) -> str:
    """Format epoch seconds (or now) as ISO UTC string."""
    if epoch_s is None:
        dt = datetime.now(timezone.utc)
    else:
        dt = datetime.fromtimestamp(epoch_s, timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json_safe(path: str) -> dict | None:
    """Safely load JSON file or return None."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def get_next_work_item(active_run: dict) -> str:
    """Determine the next actionable work item from active run or progress ledger."""
    if active_run.get("next_work_item"):
        return str(active_run["next_work_item"])

    # Fallback to persistent ledger on secondary HDD if available
    ledger = load_json_safe(PROGRESS_LEDGER_FILE)
    if isinstance(ledger, dict) and ledger.get("exact_next_action"):
        return str(ledger["exact_next_action"])

    workstream = active_run.get("current_workstream", "Continuous Engineering & Validation")
    return f"Continue {workstream} (adaptive workstream cycling: pipeline, captures, detection rules, adversarial tests, performance)"


def main():
    try:
        data = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    except Exception:
        data = {}

    term_reason = data.get("terminationReason", "UNKNOWN") if isinstance(data, dict) else "UNKNOWN"
    error_msg = data.get("error", "") if isinstance(data, dict) else ""
    fully_idle = data.get("fullyIdle", True) if isinstance(data, dict) else True
    exec_num = data.get("executionNum", 1) if isinstance(data, dict) else 1
    now_epoch = time.time()
    now_iso = format_iso_utc(now_epoch)

    os.makedirs(LOGS_DIR, exist_ok=True)

    # 1. Inspect active_run.json
    active_run = load_json_safe(ACTIVE_RUN_FILE)

    # Case A: Inactive manifest or non-running status
    if not active_run or not isinstance(active_run, dict):
        record = {
            "timestamp": now_iso,
            "execution_num": exec_num,
            "termination_reason": term_reason,
            "fully_idle": fully_idle,
            "error": error_msg,
            "active_run_status": None,
            "decision": "allow",
            "workbench_status": "standby"
        }
        try:
            with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2)
        except Exception:
            pass

        response = {
            "decision": "allow",
            "reason": f"NetGuard checkpoint saved successfully (reason: {term_reason}; no active autonomous run)."
        }
        json.dump(response, sys.stdout)
        sys.exit(0)

    run_status = active_run.get("status", "unknown")
    cancel_requested = bool(active_run.get("cancel_requested", False))

    # Case B: Cancellation explicitly requested or indicated in terminationReason
    is_cancel_signal = (
        cancel_requested or
        "cancel" in str(term_reason).lower() or
        "abort" in str(term_reason).lower()
    )

    if is_cancel_signal:
        active_run["status"] = "cancelled"
        active_run["cancelled_at_utc"] = now_iso
        active_run["last_checkpoint_utc"] = now_iso
        try:
            with open(ACTIVE_RUN_FILE, "w", encoding="utf-8") as f:
                json.dump(active_run, f, indent=2)
        except Exception:
            pass

        record = {
            "timestamp": now_iso,
            "execution_num": exec_num,
            "termination_reason": term_reason,
            "fully_idle": fully_idle,
            "error": error_msg,
            "active_run_status": "cancelled",
            "decision": "allow",
            "workbench_status": "cancelled"
        }
        try:
            with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2)
        except Exception:
            pass

        response = {
            "decision": "allow",
            "reason": f"NetGuard autonomous run cancelled (reason: {term_reason}). Checkpoint saved."
        }
        json.dump(response, sys.stdout)
        sys.exit(0)

    # If run already completed or cancelled earlier
    if run_status != "running":
        record = {
            "timestamp": now_iso,
            "execution_num": exec_num,
            "termination_reason": term_reason,
            "fully_idle": fully_idle,
            "error": error_msg,
            "active_run_status": run_status,
            "decision": "allow",
            "workbench_status": run_status
        }
        try:
            with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2)
        except Exception:
            pass

        response = {
            "decision": "allow",
            "reason": f"NetGuard autonomous run already {run_status}. Termination permitted."
        }
        json.dump(response, sys.stdout)
        sys.exit(0)

    # 2. Parse deadline and compute remaining seconds
    deadline_utc_str = active_run.get("deadline_utc")
    try:
        if not deadline_utc_str:
            raise ValueError("active_run.json missing 'deadline_utc' field")
        deadline_epoch = parse_iso_utc(deadline_utc_str)
        remaining_seconds = deadline_epoch - now_epoch
    except Exception as exc:
        # Error parsing deadline: record error and allow termination
        record = {
            "timestamp": now_iso,
            "execution_num": exec_num,
            "termination_reason": term_reason,
            "fully_idle": fully_idle,
            "error": f"Failed to parse active run deadline: {exc}",
            "active_run_status": "error",
            "decision": "allow",
            "workbench_status": "error"
        }
        try:
            with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2)
        except Exception:
            pass

        response = {
            "decision": "allow",
            "reason": f"NetGuard active run deadline parse failure ({exc}); allowing termination."
        }
        json.dump(response, sys.stdout)
        sys.exit(0)

    # Case C: Deadline reached
    if remaining_seconds <= 0:
        active_run["status"] = "completed"
        active_run["completed_at_utc"] = now_iso
        active_run["last_checkpoint_utc"] = now_iso
        try:
            with open(ACTIVE_RUN_FILE, "w", encoding="utf-8") as f:
                json.dump(active_run, f, indent=2)
        except Exception:
            pass

        record = {
            "timestamp": now_iso,
            "execution_num": exec_num,
            "termination_reason": term_reason,
            "fully_idle": fully_idle,
            "error": error_msg,
            "active_run_status": "completed",
            "remaining_seconds": 0.0,
            "decision": "allow",
            "workbench_status": "completed"
        }
        try:
            with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2)
        except Exception:
            pass

        duration_s = active_run.get("duration_seconds", 21600)
        response = {
            "decision": "allow",
            "reason": f"NetGuard six-hour autonomous run deadline reached ({duration_s}s elapsed). Final checkpoint saved."
        }
        json.dump(response, sys.stdout)
        sys.exit(0)

    # Case D: Active run before deadline — INJECT CONTINUATION
    current_workstream = active_run.get("current_workstream", "Continuous Engineering & Validation")
    next_item = get_next_work_item(active_run)
    checkpoints_count = active_run.get("checkpoint_count", 0) + 1

    active_run["last_checkpoint_utc"] = now_iso
    active_run["checkpoint_count"] = checkpoints_count
    try:
        with open(ACTIVE_RUN_FILE, "w", encoding="utf-8") as f:
            json.dump(active_run, f, indent=2)
    except Exception:
        pass

    record = {
        "timestamp": now_iso,
        "execution_num": exec_num,
        "termination_reason": term_reason,
        "fully_idle": fully_idle,
        "error": error_msg,
        "active_run_status": "running",
        "remaining_seconds": round(remaining_seconds, 1),
        "current_workstream": current_workstream,
        "next_work_item": next_item,
        "decision": "continue",
        "workbench_status": "running"
    }
    try:
        with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)
    except Exception:
        pass

    rem_hours = remaining_seconds / 3600.0
    rem_mins = remaining_seconds / 60.0
    continuation_message = (
        f"AUTONOMOUS RUN ACTIVE — DO NOT STOP EARLY.\n"
        f"Remaining Duration: {remaining_seconds:.0f}s ({rem_hours:.2f} hours / {rem_mins:.1f} minutes) until deadline {deadline_utc_str}.\n"
        f"Current Workstream: {current_workstream}\n"
        f"Next Action: {next_item}\n"
        f"Invariant: The six-hour clock is a strict execution objective. Continue executing autonomous engineering tasks."
    )

    response = {
        "decision": "continue",
        "reason": continuation_message
    }
    json.dump(response, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
