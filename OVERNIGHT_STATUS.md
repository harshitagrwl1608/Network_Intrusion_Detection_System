# NetGuard IDS — Overnight Engineering Status Report

**Branch:** `antigravity/overnight-work`  
**Tracking Remote:** `origin/antigravity/overnight-work`  
**Base Commit:** `5d22fba`  
**Cycle 1 Commit:** `73c281f`  
**Session Started:** 2026-10-19 01:42:10 +05:30  
**Status:** In Progress (Cycle 2 Complete)

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
- Commit: `73c281f` (pushed to `origin/antigravity/overnight-work`).

---

## Cycle 2: Priority 1 — Detection Correctness (PortScanRule & TCP SYN Semantics)

### 1. Root Cause Hypothesis
- In `PortScanRule.check()`: `if protocol == "TCP" and not record.get("syn_flag"): return None`. For UDP packets, `protocol == "TCP"` evaluated to `False`, bypassing the check completely. Consequently, any UDP packet with `dst_port` was counted toward both vertical and horizontal TCP scan histories, firing false-positive scan alerts on legitimate UDP traffic (e.g. multi-port DNS queries).
- SYN-ACK packets (TCP flags 0x12) were treated as scan attempts because `bool(flags & 0x02)` was true, mistaking server replies for probe attempts.
- In `SynFloodRule.check()`: the guard did not check `protocol == "TCP"`, allowing non-TCP packets to affect SYN flood state.

### 2. Implementation
- In `ids_project/engine/rules.py`:
  - `PortScanRule`: Enforced explicit `if protocol != "TCP": return None`. Added check for `initial_syn` (SYN=1, ACK=0), ensuring ACK-only and SYN-ACK server responses are ignored. Preserved both vertical and horizontal histories atomically.
  - `SynFloodRule`: Enforced `if record.get("protocol") != "TCP": return None` and `initial_syn` validation.
- In `ids_project/capture/sniffer.py`:
  - Extracted `initial_syn = bool(flags & 0x02) and not bool(flags & 0x10)` in `_parse_packet()` for Scapy TCP packets.
  - Initialized `initial_syn = False` on ARP and UDP packets.
- Added regression test suite: `ids_project/tests/test_port_scan_detection.py` covering:
  - UDP packets negative (no scan alert)
  - TCP ACK-only negative (no scan alert)
  - TCP SYN-ACK server responses negative (no scan alert)
  - Pure initial SYN probes positive (triggers scan alert)
  - SynFloodRule rejects UDP and SYN-ACK traffic

### 3. Files Changed
- `ids_project/engine/rules.py`
- `ids_project/capture/sniffer.py`
- `ids_project/tests/test_port_scan_detection.py` (New regression test suite)

### 4. Commands Executed & Test Results
- `python3 -m unittest ids_project/tests/test_port_scan_detection.py`
  - Before fix: `FAILED (failures=3)` — False positives on UDP, SYN-ACK, and SYN flood.
  - After fix: `OK (Ran 5 tests in 0.001s)`.
- `python3 -m unittest discover ids_project/tests`
  - Result: `Ran 7 tests in 1.455s — OK`.
- `git diff --check`: Exit code 0.

---

## Remaining Backlog & Next Cycle
- **Cycle 3:** Priority 1 — DNS Anomaly Rule Fixes (`DNS_FREQ_THRESHOLD=0` handling, narrow allowlist scope to entropy only, protect against repeated alerts).
