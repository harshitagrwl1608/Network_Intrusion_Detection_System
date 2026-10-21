# NetGuard IDS — Overnight Engineering Status Report

**Branch:** `antigravity/overnight-work`  
**Tracking Remote:** `origin/antigravity/overnight-work`  
**Base Commit:** `5d22fba`  
**Cycle 1 Commit:** `73c281f`  
**Cycle 2 Commit:** `d788522`  
**Cycle 3 Commit:** `84f7534`  
**Cycle 4 Commit:** `bfdf511`  
**Cycle 5 Commit:** `30dbec7`  
**Cycle 6 Commit:** `b2e327b`
**Session Started:** 2026-10-19 01:42:10 +05:30  
**Status:** Completed (6 of 6 Cycles Completed)

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
- `python3 -m unittest ids_project/tests/test_alert_persistence.py`: OK (50/50 alerts persisted, 0 dropped).
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
- Added regression test suite: `ids_project/tests/test_port_scan_detection.py`.

### 3. Files Changed
- `ids_project/engine/rules.py`
- `ids_project/capture/sniffer.py`
- `ids_project/tests/test_port_scan_detection.py` (New regression test suite)

### 4. Commands Executed & Test Results
- `python3 -m unittest ids_project/tests/test_port_scan_detection.py`: OK (5 tests passed).
- Commit: `d788522` (pushed to `origin/antigravity/overnight-work`).

---

## Cycle 3: Priority 1 — DNS Anomaly & ARP Spoofing Detection Correctness

### 1. Root Cause Hypothesis
- **DNS Frequency with Threshold Zero:** In `DnsRule.check()`, `high_freq = query_count >= self._freq_threshold`. When `DNS_FREQ_THRESHOLD=0` (documented in `.env.example` as the switch to disable frequency detection), `query_count >= 0` evaluated to `True` on the very first query for any domain, triggering false alerts on standard single DNS requests.
- **DGA Allowlist Over-broad Suppression:** `if any(dl.endswith(w) for w in _DGA_WHITELIST_SUFFIXES): return None` returned immediately before length and frequency checks. This completely blindfolded DNS tunneling detection (`too_long`) if the attacker encapsulated payloads under a known suffix (e.g., `*.amazonaws.com`).
- **ARP Spoofing Alert Storms:** `ArpSpoofRule.check()` fired an alert for every single conflicting ARP frame without cooldown, saturating alert storage during duplicate gratuitous ARP packets or network flapping.

### 2. Implementation
- In `ids_project/engine/rules.py`:
  - `DnsRule`: Guarded frequency detection with `self._freq_threshold > 0 and query_count >= self._freq_threshold`, properly disabling the check when set to 0.
  - `DnsRule`: Restructured allowlist to set `entropy_exempt = True` exclusively for the Shannon entropy calculation, while keeping excessive length (`too_long`) and query frequency (`high_freq`) fully operational under allowed suffixes.
  - `ArpSpoofRule`: Added `ALERT_COOLDOWN_S = 120.0` and `_cooldown` tracking per IP, suppressing duplicate alerts within the cooldown window while ensuring initial conflicts always alert.
- Added regression test suite: `ids_project/tests/test_dns_and_arp_detection.py`.

### 3. Files Changed
- `ids_project/engine/rules.py`
- `ids_project/tests/test_dns_and_arp_detection.py` (New regression test suite)

### 4. Commands Executed & Test Results
- `python3 -m unittest ids_project/tests/test_dns_and_arp_detection.py`: OK (3 tests passed).
- Commit: `84f7534` (pushed to `origin/antigravity/overnight-work`).

---

## Cycle 4: Priority 2 — Deterministic PCAP Replay and Historical Log Parsing

### 1. Root Cause Hypothesis
- **Full-date tcpdump Text Logs:** README documented `tcpdump -tttt -nn -r file.pcap > file.log`, which generates timestamps formatted as `YYYY-MM-DD HH:MM:SS.frac`. The parser regex strictly required starting with `HH:MM:SS`, skipping 100% of full-date lines and silently producing 0 processed records.
- **Historical State Pruning by GC Loop:** `RuleEngine._gc_loop` ran every 10 seconds and passed wall-clock `time.time()` to `rule.prune_stale(now)`. During offline replay of historical captures (timestamps in past years or synthetic epoch fixtures), the wall clock caused active sliding-window state to be pruned mid-replay.

### 2. Implementation
- In `ids_project/capture/sniffer.py`:
  - Extended `_replay_text_log` regex to match optional `YYYY-MM-DD` date prefix alongside `HH:MM:SS[.frac]`.
  - Added timestamp parser handling `%Y-%m-%d %H:%M:%S.%f`, `%Y-%m-%d %H:%M:%S`, `%H:%M:%S.%f`, and `%H:%M:%S`.
  - Extracted initial SYN (`[S]`) vs SYN-ACK (`[S.]`) for text-based replays.
- In `ids_project/engine/rules.py`:
  - Added `event_clock` parameter to `RuleEngine.__init__` and `_gc_loop`, allowing replay tools to pass a packet-progress clock instead of wall-clock time.
- Added regression test suite: `ids_project/tests/test_pcap_replay_and_parsing.py`.

### 3. Files Changed
- `ids_project/capture/sniffer.py`
- `ids_project/engine/rules.py`
- `ids_project/tests/test_pcap_replay_and_parsing.py` (New regression test suite)

### 4. Commands Executed & Test Results
- `python3 -m unittest ids_project/tests/test_pcap_replay_and_parsing.py`: OK (2 tests passed).
- Commit: `bfdf511` (pushed to `origin/antigravity/overnight-work`).

---

## Cycle 5: Priority 2 — Repeatable Isolated Evaluation Runner

### 1. Root Cause Hypothesis
- In earlier versions, evaluation against attack and benign captures reused a fixed `/tmp` SQLite DB and shared ARP table state across runs without clean resets.
- If an attack PCAP contaminated the ARP table, subsequent benign replays would falsely flag ARP spoofing alerts.
- There was no single automated command that created fresh isolated DBs/ARP state for both attack and benign evaluation, computed TP/FN/FP metrics against labelled ground truth, and cleaned up temporary artifacts safely.

### 2. Implementation
- Created `ids_project/evaluation/run_eval.py`:
  - Dynamically provisions fresh temporary SQLite databases and isolated ARP JSON state per phase (`_fresh_tmp_db()`, `_fresh_tmp_arp()`).
  - Replays attack PCAP into isolated attack DB; matches alerts bijectively against scenario manifest `test_labels.csv`.
  - Replays benign PCAP into isolated benign DB; ensures zero false-positive alerts on benign traffic.
  - Computes Precision, Recall, F1, and per-rule breakdown (TP/FN/FP).
  - Automatically unlinks temporary DB and ARP files upon completion.
  - Exits 0 on clean pass (100% scenario recall, 0 benign false positives).
- Added regression test suite: `ids_project/tests/test_run_eval.py`.

### 3. Files Changed
- `ids_project/evaluation/run_eval.py`
- `ids_project/tests/test_run_eval.py` (New regression test suite)

### 4. Commands Executed & Test Results
- `python3 evaluation/run_eval.py`:
  - Scenarios: 11/11 True Positives (100.0% Recall, 100.0% Precision, 100.0% F1).
  - Per-rule breakdown: ARP_SPOOF (1/1), BLOCKLIST (1/1), DNS_ANOMALY (2/2), PAYLOAD_HIT (4/4), PORT_SCAN (2/2), SYN_FLOOD (1/1).
  - Benign traffic false positives: 0.
  - Exit code: 0.
- Commit: `30dbec7` (pushed to `origin/antigravity/overnight-work`).

---

## Cycle 6: Priority 3 — Investigation Interface, Security Hardening, and CI

### 1. Root Cause Hypothesis
- **Unrendered Evidence in Dashboard:** While `evidence_json` was persisted in SQLite/Postgres for each alert, the investigation API (`api_alert_detail`) never parsed or exposed the structured dictionary, leaving analysts without actionable forensic details in the investigation modal.
- **Insecure Default Network Exposure:** `DASHBOARD_HOST` defaulted to `0.0.0.0`, exposing the unauthenticated SOC dashboard, investigation modal, and classification APIs to any device on the local network (LAN / Wi-Fi).
- **Outdated Documentation:** `ids_project/README.md` contained outdated rule explanations (described vertical scanning only for `PORT_SCAN`, listed stale DNS length threshold 50 instead of 60, omitted query-frequency rules) and recommended binding Flask directly to `0.0.0.0`.
- **Missing Automated CI:** The repository had no continuous integration workflow to guarantee regression prevention on future pushes and pull requests.

### 2. Implementation
- In `ids_project/dashboard/app.py`:
  - Parsed `evidence_json` in `api_alert_detail` into a structured dictionary `alert["evidence"]`.
  - Updated rule explanations to accurately describe vertical and horizontal port scans, DoS initial SYN bursts, and multi-vector DNS anomalies (entropy, length, frequency).
- In `ids_project/dashboard/templates/index.html` & `static/dashboard.js`:
  - Added a dedicated "Structured Evidence" section to the investigation modal that renders formatted JSON evidence for analysts.
- In `ids_project/config.py`:
  - Hardened default `DASHBOARD_HOST` to `127.0.0.1` (localhost only) while preserving `.env` overrides.
- In `ids_project/README.md`:
  - Corrected core detection rule table with exact thresholds, both vertical/horizontal port scans, and DNS frequency checks.
  - Added instructions for `python evaluation/run_eval.py` and local dashboard launch.
- Added GitHub Actions CI: `.github/workflows/ci.yml` running unit tests and evaluation runner.
- Added regression test suite: `ids_project/tests/test_dashboard_api.py`.

### 3. Files Changed
- `ids_project/config.py`
- `ids_project/dashboard/app.py`
- `ids_project/dashboard/templates/index.html`
- `ids_project/dashboard/static/dashboard.js`
- `ids_project/README.md`
- `.github/workflows/ci.yml`
- `ids_project/tests/test_dashboard_api.py`

### 4. Commands Executed & Test Results
- `python3 -m unittest ids_project/tests/test_dashboard_api.py`: OK (2 tests passed).
- `python3 -m unittest discover ids_project/tests`: OK (15 tests passed).
- `python3 evaluation/run_eval.py`: OK (11/11 scenarios, 0 benign FPs, exit 0).
- `git diff --check`: Exit code 0.


---

## Cycle 7: Priority 1 Enhancement — Durable Alert Spooling & Idempotent Recovery

### 1. Root Cause Hypothesis & Goal
- Under extended database outages, connection loss, or queue saturation, alerts must not be discarded.
- In-memory queuing alone risks data loss if the process exits or crashes during a prolonged DB failure.
- Spooling failed/unwritten alerts to local durable storage (JSONL file) with automatic background draining and recovery upon DB reconnection guarantees alert durability.
- Alerts need idempotency keys to ensure that retrying or recovering spooled alerts never results in duplicate records in SQLite or PostgreSQL.

### 2. Implementation
- In `ids_project/engine/rules.py`:
  - Added `AlertSpool` for atomic, append-only spooling to `alerts_spool.jsonl`.
  - Added background spool draining on DB recovery with backoff.
  - Added `alerts_spooled` and `spool_recoveries` statistics to `RuleEngine`.
- In `ids_project/storage/db.py`:
  - Added `idempotency_key` column with unique index to `alerts` table in both SQLite and PostgreSQL schemas.
  - Used `INSERT OR IGNORE` (SQLite) and `ON CONFLICT (idempotency_key) DO NOTHING` (PostgreSQL) for idempotent writes.
- In `ids_project/evaluation/replay.py`:
  - Added `TrackingReplayEngine` wrapping `RuleEngine` to supply packet event timestamps to GC and stateful detection.
- In `ids_project/evaluation/run_eval.py`:
  - Wired replay tracking engine and finalized strict precision reporting and exit code semantics.
- Replaced outdated `NetGuard_IDS_Post_Update_Review.md` with `NetGuard_IDS_Deep_Review_5d22fba.md`.
- In `ids_project/tests/test_alert_persistence.py` & `ids_project/tests/test_regression_fixes.py`:
  - Added comprehensive test suites verifying spooling, failover, recovery, and idempotency (48 tests passing).

### 3. Files Changed
- `NetGuard_IDS_Post_Update_Review.md` (replaced)
- `NetGuard_IDS_Deep_Review_5d22fba.md` (added)
- `ids_project/engine/rules.py`
- `ids_project/evaluation/replay.py`
- `ids_project/evaluation/run_eval.py`
- `ids_project/storage/db.py`
- `ids_project/tests/test_alert_persistence.py`
- `ids_project/tests/test_regression_fixes.py`

### 4. Commands Executed & Test Results
- `python3 -m unittest discover ids_project/tests`: OK (48 tests passed in ~52s).
- `python3 ids_project/evaluation/run_eval.py`: OK (11/11 scenarios, 0 benign FPs, 100% Precision, 100% Recall, 100% F1, exit 0).
- `git diff --check`: Exit code 0.

---

## Cycle 8: Priority 1 Engine Enhancement — Multi-Vector Detection, New Rules & Extended Evaluation

### 1. Root Cause Hypothesis & Goal
- **Auth Service Brute-Force Blindspot:** Existing rules tracked port scans across distinct ports or hosts, but rapid repeated connection attempts to a single authentication service (SSH 22, RDP 3389, SMB 445, MySQL 3306) did not meet port-scan diversity thresholds and were missed.
- **Low-and-Slow Scan Evasion:** The 10-second window in `PortScanRule` allowed stealthy reconnaissance (e.g. 1 probe every 1.5s) to evade detection.
- **RST Flood Denial-of-Service:** Connection teardown attacks using high-rate TCP RST packets were not tracked in connection flood rules.
- **DNS Subdomain Data Exfiltration:** DNS tunneling that encodes exfiltrated data across many distinct subdomains under a single parent needed dedicated tracking and priority over generic query frequency.
- **Extended DPI Coverage:** Web applications face XXE, SSTI, Shellshock, deserialization, and HTTP response splitting/header injection attacks that require signature coverage.
- **Evaluation Integration:** New detection rules and signatures needed synthetic PCAP generation and scenario manifest tracking to guarantee 100% precision and recall without false positives.

### 2. Implementation
- In `ids_project/engine/rules.py`:
  - Added `BruteForceRule`: stateful tracking of initial SYNs to authentication ports (`_BRUTE_FORCE_AUTH_PORTS`) with sliding window and alert cooldown.
  - Added `SlowPortScanRule`: stateful tracking of vertical and horizontal scans over an extended window (120s) with higher threshold (30 ports/hosts).
  - Extended `SynFloodRule`: added RST flood detection with configurable `rst_threshold` and `rst_window`.
  - Extended `DnsRule`: added subdomain exfiltration detection (`DNS_EXFIL`) prioritized over generic query frequency.
  - Scaled severity in `PortScanRule` based on scan breadth.
  - Extended `PayloadRule`: added XXE, SSTI, Shellshock, Java deserialization, and CRLF header injection signatures.
  - Registered all new rules in `RuleEngine` orchestrator.
- In `ids_project/config.py`:
  - Added tuneable settings: `BRUTE_FORCE_THRESHOLD`, `BRUTE_FORCE_WINDOW`, `SLOW_SCAN_THRESHOLD`, `SLOW_SCAN_WINDOW`, `RST_FLOOD_THRESHOLD`, `DNS_SUBDOMAIN_THRESHOLD`, `DNS_SUBDOMAIN_WINDOW`.
- In `ids_project/tests/test_new_rules_cycle8.py`:
  - Added 43 unit and regression tests covering all new rules, evasion cases, and edge behaviors.
- In `ids_project/evaluation/generate_test_pcap.py` & `run_eval.py`:
  - Anchored paths to project root for deterministic generation regardless of invocation CWD.
  - Added attack scenarios S21 to S27 (SSH brute force, slow port scan, RST flood, DNS subdomain exfil, XXE, Shellshock, deserialization).
  - Added benign negative scenarios ensuring zero false positives on slow scans, normal SSH, corporate DNS, and normal RSTs.
  - Registered new rules and settings in evaluation metadata.

### 3. Files Changed
- `ids_project/config.py`
- `ids_project/engine/rules.py`
- `ids_project/tests/test_new_rules_cycle8.py`
- `ids_project/evaluation/generate_test_pcap.py`
- `ids_project/evaluation/run_eval.py`
- `ids_project/evaluation/scenarios/test_labels.csv`
- `ids_project/data/test_attacks.pcap`
- `ids_project/data/test_benign.pcap`

### 4. Commands Executed & Test Results
- `python3 -m unittest discover ids_project/tests`: OK (158 tests passed in 47.4s).
- `python3 ids_project/evaluation/run_eval.py`: OK (27/27 scenarios, 0 benign FPs, 100% Precision, 100% Recall, 100% F1, exit 0).
- `git diff --check`: Exit code 0.

---

## Cycle 9: Priority 1 Engine Enhancement — TCP Flag Anomaly & Malformed Packet Detection

### 1. Root Cause Hypothesis & Goal
- **Malformed Packet Exploits & Fingerprinting:** Attackers craft illegal TCP flag combinations to fingerprint operating system network stacks, exploit protocol parser bugs, or bypass stateless firewall filters (e.g. `SYN+FIN`, `SYN+RST`, `ALL_FLAGS`/Kamikaze probes).
- **Stealth Probe Disambiguation:** `TcpStealthScanRule` detects scans across 15+ ports using FIN/NULL/Xmas probes. However, single or isolated packets with conflicting flags (e.g. `SYN+FIN`) should be flagged immediately without needing a 15-probe scan threshold, while cleanly exempting Xmas probes (`0x29`) that are handled by `TcpStealthScanRule` to prevent double-alerting.
- **Alert Flood Prevention:** Stateful per-(source, anomaly_type) cooldown is required to avoid alert storms if a malformed flood is directed at a target.

### 2. Implementation
- In `ids_project/engine/rules.py`:
  - Implemented `TcpFlagAnomalyRule`:
    - Checks for `ALL_FLAGS` (0x3F), `SYN+FIN` (0x03), `SYN+RST` (0x06), standalone `PSH_WITHOUT_ACK` (0x08), and standalone `URG_WITHOUT_ACK` (0x20).
    - Explicitly exempts Xmas scan probes (`_FIN | _PSH | _URG = 0x29`) and pure FIN probes handled by `TcpStealthScanRule`.
    - Enforces a 60-second alert cooldown per `(src_ip, anomaly_type)` with LRU capacity pruning (5,000 states).
    - Registered `TcpFlagAnomalyRule` in `RuleEngine.rules` right after `BlocklistRule`.
- In `ids_project/tests/test_tcp_flag_anomaly.py`:
  - Added unit test suite (9 tests) verifying detection of SYN+FIN, SYN+RST, Kamikaze, unacknowledged PSH, legitimate flag exemptions (SYN, SYN-ACK, ACK, PSH-ACK, FIN-ACK, RST, RST-ACK, ECN, Xmas), cooldown enforcement, and memory bounding.
- In `ids_project/evaluation/generate_test_pcap.py` & `run_eval.py`:
  - Added Scenario S28: `TCP_FLAG_ANOMALY` (SYN+FIN packet evasion).
  - Registered `TcpFlagAnomalyRule` in `known_rules` and `_run_metadata()`.

### 3. Files Changed
- `ids_project/engine/rules.py`
- `ids_project/tests/test_tcp_flag_anomaly.py` (New test suite)
- `ids_project/evaluation/generate_test_pcap.py`
- `ids_project/evaluation/run_eval.py`
- `ids_project/evaluation/scenarios/test_labels.csv`
- `ids_project/data/test_attacks.pcap`

### 4. Commands Executed & Test Results
- `python3 -m unittest ids_project/tests/test_tcp_flag_anomaly.py`: OK (9 tests passed).
- `python3 -m unittest discover ids_project/tests`: OK (167 tests passed in 51.7s).
- `python3 ids_project/evaluation/run_eval.py`: OK (28/28 scenarios, 0 benign FPs, 0 unmatched attack alerts, 100% Precision, 100% Recall, 100% F1, exit 0).
- `git diff --check`: Exit code 0.

---

## Final Session Summary & Checklist
- **Session Stop Condition:** Completed Cycle 8 and Cycle 9 enhancements, comprehensive tests, and clean evaluation.
- **Total Cycles Completed:** 9
- **All Applicable Regression Tests:** 167 unit tests passing + automated PCAP evaluation passing cleanly with 100% precision & recall (28/28 scenarios).
