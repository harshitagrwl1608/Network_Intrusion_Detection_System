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

## Cycle 10: Targeted ICMP Echo Flood Detection (`IcmpFloodRule`)

### 1. Root Cause Hypothesis & Goal
- **Single-Host ICMP Flood Gap:** `IcmpSweepRule` detects horizontal reconnaissance where an attacker sends ICMP echo requests to 12+ *distinct destination hosts*. However, if an attacker focuses an intense volumetric ping flood (50+ packets in <5s) against a *single target host*, `IcmpSweepRule` records only 1 distinct destination and never triggers an alert.
- **Protocol & Direction Specificity:** An effective ping flood rule must only count inbound Echo Requests (IPv4 type 8, code 0; IPv6 type 128, code 0) targeting a destination, ignoring Echo Replies (type 0 / type 129), TTL expired, and Unreachable messages.
- **Stateful Cooldown & Resource Safety:** High-rate ping floods can quickly exhaust memory or alert channels if not bounded. The rule needs a 30s cooldown per `(src_ip, dst_ip)` pair, bounded state with LRU pruning, and clean integration into `RuleEngine`.

### 2. Implementation
- In `ids_project/config.py`:
  - Added `ICMP_FLOOD_THRESHOLD = int(os.getenv("ICMP_FLOOD_THRESHOLD", 50))`
  - Added `ICMP_FLOOD_WINDOW = int(os.getenv("ICMP_FLOOD_WINDOW", 5))`
- In `ids_project/engine/rules.py`:
  - Implemented `IcmpFloodRule`:
    - Tracks timestamps of ICMP Echo Requests (IPv4 type 8 / IPv6 type 128) per `(src_ip, dst_ip)`.
    - Disregards non-echo ICMP types (echo replies, unreachables, redirects).
    - Alerts with severity `medium` when count exceeds `threshold` in `window` seconds.
    - Implements a 30s alert cooldown per `(src_ip, dst_ip)` pair and bounded deque/dict memory management.
    - Wired into `RuleEngine.rules` and `prune_stale()`.
- In `ids_project/tests/test_icmp_flood.py`:
  - Added unit test suite (7 tests) covering threshold triggers, sub-threshold traffic, non-echo ICMP ignores, alert cooldown, IPv6 echo floods, pruning, and trusted host exemptions.
- In `ids_project/evaluation/generate_test_pcap.py` & `run_eval.py`:
  - Added attack scenario S29: 60 ICMP echo requests targeting single destination in 2s (`ICMP_FLOOD`).
  - Added benign negative scenario: 15 ICMP echo requests over 5s (well below threshold 50).
  - Registered `IcmpFloodRule` in `known_rules` and evaluation engine configuration.

### 3. Files Changed
- `ids_project/config.py`
- `ids_project/engine/rules.py`
- `ids_project/tests/test_icmp_flood.py` (New test suite)
- `ids_project/evaluation/generate_test_pcap.py`
- `ids_project/evaluation/run_eval.py`
- `ids_project/evaluation/scenarios/test_labels.csv`
- `ids_project/data/test_attacks.pcap`
- `ids_project/data/test_benign.pcap`

### 4. Commands Executed & Test Results
- `python3 -m unittest ids_project/tests/test_icmp_flood.py`: OK (7 tests passed).
- `python3 -m unittest discover ids_project/tests`: OK (174 tests passed in 47.5s).
- `python3 ids_project/evaluation/run_eval.py`: OK (29/29 scenarios, 0 benign FPs, 0 unmatched attack alerts, 100% Precision, 100% Recall, 100% F1, exit 0).
- `git diff --check`: Exit code 0.

## Cycle 11: Multi-Pass URL Decoding & Evasion Hardening in `PayloadRule`

### 1. Root Cause Hypothesis & Goal
- **Multi-Pass / Double URL Encoding Evasion:** Single-pass URL decoding (`unquote_to_bytes()`) only decodes the outer percent-encoding wrapper. Attackers evade DPI filters by double-encoding attack vectors (e.g. `%252e%252e%252f` -> `%2e%2e%2f` -> `../`, or `%2555NION%2520SELECT` -> `%55NION%20SELECT` -> `UNION SELECT`).
- **Null-Byte Poisoning:** Attackers use null-bytes (`%00` or raw `\x00`) to split words (`/bin/s\x00h`) or terminate string checks while bypassing keyword filters. Normalizing payloads via null-byte stripping (`null_byte_stripped`) and token space-normalization (`null_byte_normalized`) closes these evasion paths.
- **Inline SQL Comment Obfuscation:** In SQL injection, inline comments (`/**/` or `/*comment*/`) act as whitespace in database engines but fail basic `\s+` regex boundaries (e.g. `UNION/**/SELECT`). Collapsing SQL comments to spaces (`comment_normalized`) allows canonical keyword matching without ReDoS vulnerabilities.

### 2. Implementation
- In `ids_project/engine/rules.py`:
  - Implemented `_multi_unquote(data, max_passes=3)` for iterative decoding until a fixed-point is reached.
  - Bumped `PayloadRule.rule_version` to `"1.5"`.
  - Added Windows path traversal indicators (`win.ini`, `boot.ini`) to `PATH_TRAVERSAL` signature.
  - In `PayloadRule.check()`:
    - Generated multi-pass URL-decoded views (`"multi_pass_decoded"`) for standard and form-encoded data.
    - Generated null-byte stripped (`"null_byte_stripped"`) and null-byte space-normalized (`"null_byte_normalized"`) views.
    - Generated inline SQL comment-collapsed views (`"comment_normalized"`).
    - Preserved first-match precedence so raw and single-decoded views maintain their canonical representations.
- In `ids_project/tests/test_payload_detection.py`:
  - Added 7 unit tests verifying double URL-encoded SQLi, double URL-encoded path traversal, triple URL-encoded command injection, null-byte word splitting, null-byte token separation, and SQL inline comment evasion.
- In `ids_project/evaluation/generate_test_pcap.py`:
  - Added attack scenario S30: `PAYLOAD_HIT` via double URL-encoded path traversal (`%252e%252e/%252e%252e/%2565%2574%2563/%2570%2561%2573%2573%2577%2564`).
  - Added benign negative scenario: `gen_benign_encoded_urls` with benign percent-encoded search queries and email tags.

### 3. Files Changed
- `ids_project/engine/rules.py`
- `ids_project/tests/test_payload_detection.py`
- `ids_project/evaluation/generate_test_pcap.py`
- `ids_project/evaluation/scenarios/test_labels.csv`
- `ids_project/data/test_attacks.pcap`
- `ids_project/data/test_benign.pcap`

### 4. Commands Executed & Test Results
- `python3 -m unittest ids_project/tests/test_payload_detection.py`: OK (19 tests passed).
- `python3 -m unittest discover ids_project/tests`: OK (181 tests passed in 48.5s).
- `python3 ids_project/evaluation/run_eval.py`: OK (30/30 scenarios, 0 benign FPs, 0 unmatched attack alerts, 100% Precision, 100% Recall, 100% F1, exit 0).
- `git diff --check`: Exit code 0.

## Cycle 12: Outbound Data Exfiltration & Sensitive Archive Detection (`DataExfiltrationRule`)

### 1. Root Cause Hypothesis & Goal
- **High-Volume Outbound Data Exfiltration:** Compromised hosts (via web shells, malware, or compromised credentials) exfiltrate large quantities of data to external command-and-control (C2) servers or drops. Existing volumetric flood rules (e.g. `SynFloodRule`, `PortScanRule`) track inbound connection packet rates, but do not track aggregate outbound payload volume from internal RFC1918 hosts to external internet IPs.
- **Sensitive Database & Archive Signatures:** Attackers commonly dump and exfiltrate database backups (SQLite: `SQLite format 3\x00`) or compressed archives (ZIP: `PK\x03\x04`, 7-Zip: `7z\xbc\xaf\x27\x1c`, GZIP: `\x1f\x8b\x08`, TAR: `ustar`) over raw sockets or non-standard ports. Detecting these signatures on outbound flows provides immediate, high-confidence detection.
- **RFC-1918 & Traffic Direction Scoping:** Must strictly monitor outbound traffic (internal `src_ip` -> external `dst_ip`), while exempting internal-to-internal LAN transfers (e.g. local NAS or gateway backups), DNS queries (monitored by `DnsRule`), multicast/broadcast, and `TRUSTED_HOSTS`.

### 2. Implementation
- In `ids_project/config.py`:
  - Added `DATA_EXFIL_BYTE_THRESHOLD = int(os.getenv("DATA_EXFIL_BYTE_THRESHOLD", 50000))` (50 KB in window).
  - Added `DATA_EXFIL_WINDOW = int(os.getenv("DATA_EXFIL_WINDOW", 30))` (30 seconds).
- In `ids_project/engine/rules.py`:
  - Enhanced `_is_internal(ip)` with explicit RFC-1918, loopback, and link-local CIDR ranges (`_INTERNAL_NETWORKS`), correctly treating external test/public IPs as external endpoints.
  - Implemented `DataExfiltrationRule`:
    - Tracks sliding-window outbound payload volume per `(src_ip, dst_ip)` flow using `max(len(payload), max(0, ip_len - 40))` to account for wire packet sizes across TCP segments.
    - Inspects outbound payloads for sensitive database dumps (`SQLite format 3\x00`) and compressed archives (`PK\x03\x04`, `7z\xbc\xaf\x27\x1c`, `\x1f\x8b\x08`, `ustar`).
    - Implements a 60-second alert cooldown per `(src_ip, dst_ip)` to avoid alert storms during continuous multi-megabyte transfers.
    - Limits tracked flows to 5,000 with LRU eviction and integrates with `prune_stale()`.
    - Wired into `RuleEngine.rules`.
- In `ids_project/tests/test_data_exfiltration.py`:
  - Created test suite (10 unit tests) covering volumetric thresholds, sub-threshold transfers, internal LAN exemption, inbound download exemption, SQLite dump detection, ZIP archive detection, port 53 exemption, trusted host exemption, alert cooldown, and stale flow pruning.
- In `ids_project/evaluation/generate_test_pcap.py` & `run_eval.py`:
  - Registered `DataExfiltrationRule` in evaluation known rules and metadata settings.
  - Added attack scenario S31: 60KB outbound data transfer to external IP `203.0.113.85:9001` (`DATA_EXFIL`).
  - Added benign negative scenario: 5 small HTTP requests (2.5KB total) to external host staying well below threshold.

### 3. Files Changed
- `ids_project/config.py`
- `ids_project/engine/rules.py`
- `ids_project/tests/test_data_exfiltration.py` (New test suite)
- `ids_project/evaluation/generate_test_pcap.py`
- `ids_project/evaluation/run_eval.py`
- `ids_project/evaluation/scenarios/test_labels.csv`
- `ids_project/data/test_attacks.pcap`
- `ids_project/data/test_benign.pcap`

### 4. Commands Executed & Test Results
- `python3 -m unittest ids_project/tests/test_data_exfiltration.py`: OK (10 tests passed).
- `python3 -m unittest discover ids_project/tests`: OK (191 tests passed in 47.0s).
- `python3 ids_project/evaluation/run_eval.py`: OK (31/31 scenarios, 0 benign FPs, 0 unmatched attack alerts, 100% Precision, 100% Recall, 100% F1, exit 0).
- `git diff --check`: Exit code 0.

## Cycle 13: Targeted UDP Packet Burst Detection (`UdpFloodRule`)

### 1. Root Cause Hypothesis & Goal
- **UDP Volumetric Floods vs. Multi-Port Scans:** `UdpScanRule` detects port-probing activity across distinct ports (`len(ports) >= threshold`), but fails to alert when an attacker bombards a single UDP service (e.g., DNS port 53, SIP port 5060, gaming port 27015, or random high ports) with dozens or hundreds of UDP packets in a short window.
- **Flood Differentiation & Exemptions:** Legitimate high-rate UDP traffic includes DNS queries/responses, DHCP lease negotiation, and NTP time sync. To prevent false positives, `UdpFloodRule` must explicitly exempt packets originating from known protocol server ports (DNS: 53, DHCP: 67/68, NTP: 123) and `TRUSTED_HOSTS`, while tracking sliding-window packet counts per `(src_ip, dst_ip)`.
- **Alert Flood Prevention:** Must enforce an alert cooldown (60 seconds) per host pair to prevent alert storms during sustained DDoS bursts.

### 2. Implementation
- In `ids_project/config.py`:
  - Added `UDP_FLOOD_THRESHOLD = int(os.getenv("UDP_FLOOD_THRESHOLD", 50))` (50 UDP packets in window).
  - Added `UDP_FLOOD_WINDOW = int(os.getenv("UDP_FLOOD_WINDOW", 5))` (5-second sliding window).
- In `ids_project/engine/rules.py`:
  - Implemented `UdpFloodRule`:
    - Tracks sliding-window timestamps of UDP packets per `(src_ip, dst_ip)`.
    - Exempts server response ports 53, 67, 68, 123 and `_is_trusted(src_ip)`.
    - Triggers `high` severity alert when `len(history) >= threshold` (50 packets in 5s).
    - Enforces 60-second cooldown per `(src_ip, dst_ip)`.
    - Bound flow table to 4,096 entries and implemented `prune_stale(now)`.
    - Registered `UdpFloodRule` in `RuleEngine.rules`.
- In `ids_project/tests/test_udp_flood.py`:
  - Created 7 comprehensive unit tests verifying threshold firing, sub-threshold silence, server port exemptions (DNS, NTP, DHCP), cooldown suppression, trusted host exemption, and stale flow pruning.
- In `ids_project/evaluation/generate_test_pcap.py` & `run_eval.py`:
  - Registered `UdpFloodRule` and metadata settings in `run_eval.py`.
  - Added attack scenario S32: 60 UDP packets targeting port 5060 on `192.168.1.1` in 1.8s (`UDP_FLOOD`).
  - Added benign negative scenario: 15 UDP packets over 5s staying well below the 50-packet threshold.
  - Regenerated test PCAPs (1,130 attack packets, 774 benign packets) and labels (32 scenarios).

### 3. Files Changed
- `ids_project/config.py`
- `ids_project/engine/rules.py`
- `ids_project/tests/test_udp_flood.py` (New test suite)
- `ids_project/evaluation/generate_test_pcap.py`
- `ids_project/evaluation/run_eval.py`
- `ids_project/evaluation/scenarios/test_labels.csv`
- `ids_project/data/test_attacks.pcap`
- `ids_project/data/test_benign.pcap`
- `OVERNIGHT_STATUS.md`

### 4. Commands Executed & Test Results
- `python3 -m unittest ids_project/tests/test_udp_flood.py`: OK (7 tests passed).
- `python3 -m unittest discover ids_project/tests`: OK (198 tests passed in 46.8s).
- `python3 ids_project/evaluation/run_eval.py`: OK (32/32 scenarios, 0 benign FPs, 0 unmatched attack alerts, 100% Precision, 100% Recall, 100% F1, exit 0).
- `git diff --check`: Exit code 0.

## Cycle 14: Automated Reconnaissance Scanner & Sensitive File Probing (`PayloadRule` Expansion)

### 1. Root Cause Hypothesis & Goal
- **Automated Web Reconnaissance Scanning:** Threat actors systematically scan web services using automated offensive security scanners (`sqlmap`, `nikto`, `gobuster`, `dirbuster`, `nuclei`, `masscan`, `wpscan`, `acunetix`, `nessus`, `openvas`, `arachni`). These tools generate distinct `User-Agent` headers and probe tokens that should immediately trigger high-confidence detection.
- **Sensitive Configuration & Credential Exposure Probing:** Automated bots and human adversaries actively probe web roots for sensitive configuration files (`.env`, `.env.local`, `.env.production`), version control directories (`.git/config`, `.git/HEAD`, `.svn/entries`), SSH private keys (`id_rsa`, `id_ed25519`), cloud credentials (`.aws/credentials`, `.aws/config`), and CMS config backups (`wp-config.php`, `web.config`). Probing for these endpoints indicates targeted reconnaissance.
- **Remote Download Cradles & Interactive Shells:** Adversaries attempting command injection or web shell execution frequently invoke download-and-execute cradles (`curl ... | sh`, `wget ... | bash`, PowerShell `IEX (New-Object Net.WebClient).DownloadString(...)`, or socket redirection like `0<&196;exec 196<>/dev/tcp/` and `mkfifo /tmp/`).
- **Precision Requirements:** Must alert with `high` severity on attack payloads while strictly avoiding false positives on legitimate web traffic (standard browser `User-Agent` strings, regular URLs, query parameters like `?env=prod`, and safe HTTP assets).

### 2. Implementation
- In `ids_project/engine/rules.py`:
  - Added `SCANNER_PROBE` signature to `_PAYLOAD_SIGNATURES`:
    - Matches prominent automated scanner User-Agents and markers (`sqlmap`, `nikto`, `gobuster`, `dirbuster`, `dirsearch`, `wfuzz`, `ffuf`, `nuclei`, `masscan`, `wpscan`, `acunetix`, `nessus`, `openvas`, `arachni`, `Mozilla/5.00 (Nikto`, `nmap scripting engine`).
  - Added `SENSITIVE_FILE_PROBE` signature to `_PAYLOAD_SIGNATURES`:
    - Matches HTTP methods (`GET`, `POST`, `HEAD`, `OPTIONS`) targeting `.env`, `.git/(config|HEAD)`, `.svn/entries`, `id_rsa`, `id_ed25519`, `.aws/(credentials|config)`, `wp-config.php`, and `web.config`.
  - Added `REVERSE_SHELL_CRADLE` signature to `_PAYLOAD_SIGNATURES`:
    - Matches piped shell downloads (`curl ... | sh`, `wget ... | bash`), PowerShell downloadstring/encoded cradles, and FIFO socket redirection.
  - Bumped `PayloadRule.rule_version` from `"1.5"` to `"1.6"`.
- In `ids_project/tests/test_payload_detection.py`:
  - Added 4 new test methods covering scanner User-Agents, sensitive file probes, reverse shell cradles, and benign negative requests.
  - All 23 payload tests pass in 0.014s.
- In `ids_project/evaluation/generate_test_pcap.py` & `run_eval.py`:
  - Added Scenario S33: Automated scanner probe (`sqlmap` User-Agent) probing `/.env` on `192.168.1.1:80` (`PAYLOAD_HIT`).
  - Added benign negative scenario `gen_benign_normal_http_assets`: Legitimate web browser requests with standard Firefox/Chrome User-Agents fetching `/index.html` and `/static/css/app.css`.
  - Regenerated test PCAPs (1,131 attack packets, 776 benign packets) and labels (33 scenarios).

### 3. Files Changed
- `ids_project/engine/rules.py`
- `ids_project/tests/test_payload_detection.py`
- `ids_project/evaluation/generate_test_pcap.py`
- `ids_project/evaluation/scenarios/test_labels.csv`
- `ids_project/data/test_attacks.pcap`
- `ids_project/data/test_benign.pcap`
- `OVERNIGHT_STATUS.md`

### 4. Commands Executed & Test Results
- `python3 -m unittest ids_project/tests/test_payload_detection.py`: OK (23 tests passed in 0.014s).
- `python3 -m unittest discover ids_project/tests`: OK (202 tests passed in 47.3s).
- `python3 ids_project/evaluation/run_eval.py`: OK (33/33 scenarios, 0 benign FPs, 0 unmatched attack alerts, 100% Precision, 100% Recall, 100% F1, exit 0).
- `git diff --check`: Exit code 0.

## Cycle 15: Low-Entropy DNS Tunneling & Encoded Data Chunk Detection (`DnsRule` Expansion)

### 1. Root Cause Hypothesis & Goal
- **Low-Entropy DNS Exfiltration & Tunneling Evasion:** Covert DNS C2 frameworks (e.g., `iodine`, `dnscat2`, Cobalt Strike DNS beacons) and custom exfiltration scripts transmit structured data using hexadecimal chunks (`[0-9a-f]{24,}`). Because hex encoding only utilizes 16 distinct characters, the Shannon entropy of ASCII text encoded in hex is strictly bounded (typically 2.8–3.5 bits/char), successfully evading standard Shannon entropy thresholds (`DNS_ENTROPY_THRESHOLD = 3.8`).
- **Length & Frequency Bypasses:** If an adversary restricts chunk size to 24–36 characters, the total query name stays well below query length limits (`DNS_QUERY_MAX_LEN = 50`), and low-frequency queries (e.g. single-query exfiltration of credentials or keys) bypass frequency and subdomain burst thresholds (`20` queries).
- **Precision Requirements:** Must detect contiguous hex chunks (≥24 characters with both digits and hex letters) on non-allowlisted domains, while exempting legitimate CDN suffixes (`_DGA_WHITELIST_SUFFIXES`), hyphenated UUIDs (e.g. `123e4567-e89b-12d3-a456-426614174000`), purely alphabetic words, and numeric strings.

### 2. Implementation
- In `ids_project/engine/rules.py`:
  - Added hex-encoded chunk inspection to `DnsRule.check()`:
    - Scans `entropy_labels` through the registrable boundary.
    - Matches candidate labels with `len(lbl) >= 24`, full regex match on `[0-9a-f]{24,}`, and at least one digit and one hex letter (`[a-f]`).
    - Exempts domains under `_DGA_WHITELIST_SUFFIXES`.
    - Triggers `high` severity alert under `sub_type = "DNS_TUNNEL"` with detail `hex_encoded_chunk='...' (len=... ≥ 24)`.
    - Bumped `DnsRule.rule_version` from `"1.6"` to `"1.7"`.
- In `ids_project/tests/test_dns_and_arp_detection.py`:
  - Added 4 unit tests verifying low-entropy hex chunk detection, allowlisted CDN exemption, hyphenated UUID exemption, and long alphabetic label exemption.
  - All 16 tests in suite pass in 0.018s.
- In `ids_project/evaluation/generate_test_pcap.py` & `run_eval.py`:
  - Added Scenario S34: Hex-encoded credential chunk `61646d696e3a70617373776f7264.covert.net` (entropy=3.08 < 3.8, len=39 < 50) → `DNS_ANOMALY`.
  - Added benign negative scenario `gen_benign_uuid_dns`: Service discovery query with UUID `123e4567-e89b-12d3-a456-426614174000.consul` (len=43 < 50, contains hyphens) → 0 false positives.
  - Regenerated test PCAPs (1,132 attack packets, 777 benign packets) and labels (34 scenarios).

### 3. Files Changed
- `ids_project/engine/rules.py`
- `ids_project/tests/test_dns_and_arp_detection.py`
- `ids_project/evaluation/generate_test_pcap.py`
- `ids_project/evaluation/scenarios/test_labels.csv`
- `ids_project/data/test_attacks.pcap`
- `ids_project/data/test_benign.pcap`
- `OVERNIGHT_STATUS.md`

### 4. Commands Executed & Test Results
- `python3 -m unittest ids_project/tests/test_dns_and_arp_detection.py`: OK (16 tests passed in 0.018s).
- `python3 -m unittest discover ids_project/tests`: OK (206 tests passed in 46.5s).
- `python3 ids_project/evaluation/run_eval.py`: OK (34/34 scenarios, 0 benign FPs, 0 unmatched attack alerts, 100% Precision, 100% Recall, 100% F1, exit 0).
- `git diff --check`: Exit code 0.

---

## Final Session Summary & Checklist
- **Session Stop Condition:** Completed Cycles 8, 9, 10, 11, 12, 13, 14, and 15 enhancements, comprehensive tests, and clean evaluation.
- **Total Cycles Completed:** 15
- **All Applicable Regression Tests:** 206 unit tests passing + automated PCAP evaluation passing cleanly with 100% precision & recall (34/34 scenarios).
