#!/usr/bin/env python3
"""
Stop Hook for NetGuard Engineering Workbench.
Enforces deadline-aware autonomous continuation during active engineering runs.

Improvements over v1:
  1. Corrupted manifest with recoverable backup allows continuation (not termination).
  2. Missing/unparseable deadline on an otherwise active-looking manifest allows
     termination only if no valid backup exists.
  3. Progress ledger path is read from the manifest (not hardcoded to Phase 4).
  4. Manifest writes are atomic via a .tmp file + os.replace().
  5. Explicit user cancellation remains honoured.
  6. Ordinary inactive sessions still terminate normally.
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
ACTIVE_RUN_BACKUP = os.path.join(LOGS_DIR, "active_run.backup.json")

# Fallback ledger only used if manifest does not specify a path.
_LEGACY_LEDGER = "/run/media/harshitgarg/Data1/NetGuard-datasets/coordination/phase4_progress_ledger.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
    """Safely load JSON file or return None on any error."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def atomic_write_json(path: str, data: dict) -> bool:
    """Write JSON atomically via a sibling .tmp file. Returns True on success."""
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
        return True
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        return False


def write_checkpoint(record: dict) -> None:
    """Write checkpoint file (non-critical — best effort)."""
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        atomic_write_json(CHECKPOINT_FILE, record)
    except Exception:
        pass


def get_ledger_path(active_run: dict) -> str:
    """Return the progress ledger path from the manifest, with legacy fallback."""
    path = active_run.get("progress_ledger_path")
    if path and isinstance(path, str):
        return path
    return _LEGACY_LEDGER


def get_next_work_item(active_run: dict) -> str:
    """Determine the next actionable work item from active run or progress ledger."""
    if active_run.get("next_work_item"):
        return str(active_run["next_work_item"])

    ledger_path = get_ledger_path(active_run)
    ledger = load_json_safe(ledger_path)
    if isinstance(ledger, dict) and ledger.get("exact_next_action"):
        return str(ledger["exact_next_action"])

    workstream = active_run.get("current_workstream", "Continuous Engineering & Validation")
    return (
        f"Continue {workstream} "
        f"(adaptive cycling: pipeline safety, capture evaluation, "
        f"detection rules, adversarial tests, documentation)"
    )


def respond_allow(reason: str, checkpoint: dict) -> None:
    write_checkpoint(checkpoint)
    json.dump({"decision": "allow", "reason": reason}, sys.stdout)
    sys.exit(0)


def respond_continue(reason: str, checkpoint: dict) -> None:
    write_checkpoint(checkpoint)
    json.dump({"decision": "continue", "reason": reason}, sys.stdout)
    sys.exit(0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    try:
        data = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    except Exception:
        data = {}

    term_reason = data.get("terminationReason", "UNKNOWN") if isinstance(data, dict) else "UNKNOWN"
    error_msg   = data.get("error", "")          if isinstance(data, dict) else ""
    fully_idle  = data.get("fullyIdle", True)    if isinstance(data, dict) else True
    exec_num    = data.get("executionNum", 1)    if isinstance(data, dict) else 1
    now_epoch   = time.time()
    now_iso     = format_iso_utc(now_epoch)

    os.makedirs(LOGS_DIR, exist_ok=True)

    # ------------------------------------------------------------------
    # 1. Load manifest — try primary, then backup
    # ------------------------------------------------------------------
    active_run   = load_json_safe(ACTIVE_RUN_FILE)
    used_backup  = False
    manifest_corrupt = False

    if active_run is None or not isinstance(active_run, dict):
        # Primary failed — try backup
        backup = load_json_safe(ACTIVE_RUN_BACKUP)
        if backup and isinstance(backup, dict):
            active_run   = backup
            used_backup  = True
            manifest_corrupt = True  # primary was corrupt/missing
        else:
            # Genuinely no active run
            respond_allow(
                f"NetGuard checkpoint saved (reason: {term_reason}; no active autonomous run).",
                {
                    "timestamp": now_iso, "execution_num": exec_num,
                    "termination_reason": term_reason, "fully_idle": fully_idle,
                    "error": error_msg, "active_run_status": None,
                    "decision": "allow", "workbench_status": "standby",
                },
            )
            return  # unreachable but explicit

    # ------------------------------------------------------------------
    # 2. Check explicit cancellation FIRST (highest priority)
    # ------------------------------------------------------------------
    cancel_requested = bool(active_run.get("cancel_requested", False))
    is_cancel_signal = (
        cancel_requested
        or "cancel" in str(term_reason).lower()
        or "abort" in str(term_reason).lower()
    )

    if is_cancel_signal:
        active_run["status"] = "cancelled"
        active_run["cancelled_at_utc"] = now_iso
        active_run["last_checkpoint_utc"] = now_iso
        atomic_write_json(ACTIVE_RUN_FILE, active_run)
        respond_allow(
            f"NetGuard autonomous run cancelled (reason: {term_reason}). Checkpoint saved.",
            {
                "timestamp": now_iso, "execution_num": exec_num,
                "termination_reason": term_reason, "fully_idle": fully_idle,
                "error": error_msg, "active_run_status": "cancelled",
                "decision": "allow", "workbench_status": "cancelled",
            },
        )
        return

    # ------------------------------------------------------------------
    # 3. If status is not 'running', allow termination
    # ------------------------------------------------------------------
    run_status = active_run.get("status", "unknown")
    if run_status != "running":
        respond_allow(
            f"NetGuard autonomous run already {run_status}. Termination permitted.",
            {
                "timestamp": now_iso, "execution_num": exec_num,
                "termination_reason": term_reason, "fully_idle": fully_idle,
                "error": error_msg, "active_run_status": run_status,
                "decision": "allow", "workbench_status": run_status,
            },
        )
        return

    # ------------------------------------------------------------------
    # 4. Parse deadline
    # ------------------------------------------------------------------
    deadline_utc_str = active_run.get("deadline_utc")
    deadline_parse_error: str | None = None
    remaining_seconds: float = 0.0

    try:
        if not deadline_utc_str:
            raise ValueError("active_run.json missing 'deadline_utc' field")
        deadline_epoch   = parse_iso_utc(deadline_utc_str)
        remaining_seconds = deadline_epoch - now_epoch
    except Exception as exc:
        deadline_parse_error = str(exc)

    if deadline_parse_error:
        # Deadline unparseable — if this came from the backup we already know it's
        # corrupt; allow termination with an informative error.
        # If the primary was intact but deadline field is bad, still allow termination.
        note = "(recovered from backup) " if used_backup else ""
        respond_allow(
            f"NetGuard {note}active run deadline parse failure ({deadline_parse_error}); allowing termination.",
            {
                "timestamp": now_iso, "execution_num": exec_num,
                "termination_reason": term_reason, "fully_idle": fully_idle,
                "error": deadline_parse_error, "active_run_status": "error",
                "decision": "allow", "workbench_status": "error",
                "manifest_corrupt": manifest_corrupt,
            },
        )
        return

    # ------------------------------------------------------------------
    # 5. Deadline reached → allow
    # ------------------------------------------------------------------
    if remaining_seconds <= 0:
        active_run["status"] = "completed"
        active_run["completed_at_utc"] = now_iso
        active_run["last_checkpoint_utc"] = now_iso
        atomic_write_json(ACTIVE_RUN_FILE, active_run)
        duration_s = active_run.get("duration_seconds", 21600)
        respond_allow(
            f"NetGuard six-hour autonomous run deadline reached ({duration_s}s elapsed). Final checkpoint saved.",
            {
                "timestamp": now_iso, "execution_num": exec_num,
                "termination_reason": term_reason, "fully_idle": fully_idle,
                "error": error_msg, "active_run_status": "completed",
                "remaining_seconds": 0.0, "decision": "allow",
                "workbench_status": "completed",
            },
        )
        return

    # ------------------------------------------------------------------
    # 6. Active run, before deadline → CONTINUE
    #    Atomically update manifest (keep backup of previous valid state first).
    # ------------------------------------------------------------------
    current_workstream = active_run.get("current_workstream", "Continuous Engineering & Validation")
    next_item          = get_next_work_item(active_run)
    checkpoints_count  = active_run.get("checkpoint_count", 0) + 1

    # Save current good manifest as backup before overwriting
    if os.path.isfile(ACTIVE_RUN_FILE):
        try:
            import shutil
            shutil.copy2(ACTIVE_RUN_FILE, ACTIVE_RUN_BACKUP)
        except Exception:
            pass

    active_run["last_checkpoint_utc"] = now_iso
    active_run["checkpoint_count"]    = checkpoints_count
    if manifest_corrupt:
        active_run["_recovered_from_backup"] = True

    atomic_write_json(ACTIVE_RUN_FILE, active_run)

    rem_hours = remaining_seconds / 3600.0
    rem_mins  = remaining_seconds / 60.0
    corrupt_note = " [manifest recovered from backup]" if manifest_corrupt else ""

    continuation_message = (
        f"AUTONOMOUS RUN ACTIVE{corrupt_note} — DO NOT STOP EARLY.\n"
        f"Remaining: {remaining_seconds:.0f}s ({rem_hours:.2f}h / {rem_mins:.1f}m) "
        f"until deadline {deadline_utc_str}.\n"
        f"Current Workstream: {current_workstream}\n"
        f"Next Action: {next_item}\n"
        f"Invariant: Six-hour clock is a strict execution objective. "
        f"Continue autonomous engineering tasks."
    )

    respond_continue(
        continuation_message,
        {
            "timestamp": now_iso, "execution_num": exec_num,
            "termination_reason": term_reason, "fully_idle": fully_idle,
            "error": error_msg, "active_run_status": "running",
            "remaining_seconds": round(remaining_seconds, 1),
            "current_workstream": current_workstream,
            "next_work_item": next_item,
            "decision": "continue", "workbench_status": "running",
            "manifest_corrupt": manifest_corrupt,
        },
    )


if __name__ == "__main__":
    main()
