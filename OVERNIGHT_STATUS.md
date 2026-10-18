# NetGuard IDS — Overnight Engineering Status Report

**Branch:** `antigravity/overnight-work`  
**Tracking Remote:** `origin/antigravity/overnight-work`  
**Current Commit:** `5d22fba` (base)  
**Session Started:** 2026-10-19 01:42:10 +05:30  
**Status:** In Progress (Cycle 1 Complete)

---

## Cycle 1: Priority 0 — Reliable Alert Persistence

### 1. Root Cause Hypothesis
Under the initial architecture (`5d22fba`):
- `RuleEngine` shared a single bounded queue (`maxsize=2000`) for both device inventory updates (`task="device"`) and security alerts (`task="alert"`).
- Every packet with `src_mac` and `src_ip` caused a separate `device` enqueue. A burst of network traffic quickly saturated the 2,000-item queue.
- When full, `_enqueue()` logged a warning and dropped the item immediately via `put_nowait()`. This caused critical security alerts to be silently dropped.
- `flush()` used `put_nowait(("stop", None))` (which failed when full) and waited at most 5 seconds without waiting on pending alert writes, risking premature exit during shutdown.
- `storage/db.py:get_connection()` used `os.makedirs(os.path.dirname(config.SQLITE_PATH), exist_ok=True)`. When `config.SQLITE_PATH` was a bare filename (e.g., `"alerts.db"`), `os.path.dirname()` returned `""`, raising `FileNotFoundError: [Errno 2] No such file or directory: ''`.

### 2. Implementation
- **Queue Separation:** Created a dedicated unbounded `_alert_queue` (ensuring alerts are never dropped) and a separate bounded `_device_queue` (`maxsize=1000`).
- **Device Deduplication:** Maintained `_seen_devices` set of `(mac, ip)` to enqueue device updates only once per engine lifetime, drastically cutting queue pressure.
- **Writer Threads:** Split worker threads into `_alert_writer` (every alert guaranteed to be written) and `_device_writer` (drains device updates; drops counted in metrics without affecting alerts).
- **Health Metrics:** Added `_stats` dictionary tracking `alert_writes`, `device_writes`, `alerts_dropped` (0), `devices_dropped`, and `shutdown_timeout`.
- **Reliable Shutdown:** In `flush()`, sent stop sentinels to both queues and joined `_alert_writer` with a 10s hard timeout, logging detailed shutdown stats.
- **Bare SQLite Path Fix:** Updated `storage/db.py` to `d = os.path.dirname(config.SQLITE_PATH) or "."` before `os.makedirs()`.

### 3. Files Changed
- `ids_project/storage/db.py`
- `ids_project/engine/rules.py`
- `ids_project/tests/test_alert_persistence.py` (New regression test suite)

### 4. Commands Executed & Test Results
- `python3 -m unittest ids_project/tests/test_alert_persistence.py`
  - Before fix: `FAILED (failures=1, errors=1)` — 40 alerts dropped out of 50 under device traffic burst; `FileNotFoundError` on bare SQLite path.
  - After fix: `OK (Ran 2 tests in 1.492s)` — 50/50 alerts persisted, 0 alerts dropped, bare SQLite path safely opened.
- `git diff --check`: Exit code 0 (clean formatting, no whitespace errors).

### 5. Review & Verification
- Dedicated regression test confirmed zero dropped alerts under queue saturation.
- No secrets or credentials committed.
- Main branch untouched (work performed in isolated worktree tracking `antigravity/overnight-work`).

---

## Remaining Backlog & Next Cycle
- **Cycle 2:** Priority 1 — TCP Port Scan Detection Semantics (restrict to initial TCP SYN packets, verify UDP & ACK-only negatives, preserve scan histories).
