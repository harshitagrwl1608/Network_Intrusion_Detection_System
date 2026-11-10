# NetGuard IDS — Testing and Data Sources

---

## 1. Test Suite Overview

The test suite contains **854 tests** across **42 test modules** (43 entries in `ids_project/tests/`,
counting one `__pycache__` directory). Tests are grouped into two categories:

| Category | Count | Description |
|---|---|---|
| Synthetic unit tests | ~780 | Rule logic, edge cases, benign suppression, evasion resistance |
| Integration / PCAP tests | ~74 | Replay-based, ground-truth validation, evaluation pipeline |

**Run all tests:**
```bash
python3 -m pytest ids_project/tests/ -q
# Expected: 854 passed
```

---

## 2. Test Modules

| Module | Focus |
|---|---|
| `test_adversarial_evasion_stress.py` | Evasion resistance stress tests for DPI and scan rules |
| `test_alert_evidence_schema.py` | Validates alert `evidence_json` schema completeness |
| `test_alert_persistence.py` | SQLite write, read, dedup (idempotency_key) correctness |
| `test_blocklist_path_handling.py` | Blocklist load, missing file, stale refresh |
| `test_ciciot2023_inventory.py` | CICIoT2023 PCAP inventory and hash verification |
| `test_clear_http_tls.py` | `CLEAR_HTTP_ON_TLS_PORT` detection and benign suppression |
| `test_compare.py` | Side-by-side rule comparison utilities |
| `test_dashboard_api.py` | Flask REST API endpoint tests |
| `test_data_exfiltration.py` | `DATA_EXFIL` threshold and web-traffic exemption |
| `test_dataset_hash_verify.py` | SHA-256 hash verification for all benchmark datasets |
| `test_db_migration.py` | SQLite schema migration forward compatibility |
| `test_dns_and_arp_detection.py` | `DNS_ANOMALY` subtypes and `ARP_SPOOF` |
| `test_evaluation_artifacts.py` | Evaluation report artifact schema validation |
| `test_evaluation_pipeline.py` | End-to-end evaluation pipeline (`run_eval.py`) |
| `test_finite_rule_timestamps.py` | Guards against `NaN` and `Inf` timestamps entering rules |
| `test_ground_truth_benchmark.py` | Ground-truth matching and flow deduplication logic |
| `test_holdout_pipeline.py` | Holdout dataset registry and tracking |
| `test_icmp_flood.py` | `ICMP_FLOOD` threshold and flood window |
| `test_icmp_sweep_detection.py` | `ICMP_SWEEP` with trusted host exemptions |
| `test_icmp_tunnel.py` | `ICMP_TUNNEL` entropy and size thresholds |
| `test_ip_fragment_anomaly.py` | `IP_FRAGMENT_ANOMALY` Teardrop and overlap detection |
| `test_irc_c2_beaconing.py` | `IRC_C2_BEACONING` beaconing pattern detection |
| `test_memory_and_lru_bounds.py` | LRU eviction, `OrderedDict` bounding, memory leak prevention |
| `test_new_rules_cycle8.py` | Integration tests for newer rules (SYN_FLOOD RST, DISTRIBUTED_SYN_FLOOD, BRUTE_FORCE, SLOW_PORT_SCAN) |
| `test_non_dns_on_dns_port.py` | `NON_DNS_TRAFFIC_ON_DNS_PORT` protocol detection |
| `test_payload_detection.py` | 76 tests for all 18 PAYLOAD_HIT signatures, HTTP parser context, TLS suppression |
| `test_pcap_replay_and_parsing.py` | PCAP replay engine (`replay.py`) and binary parser correctness |
| `test_pcap_to_alert_matrix.py` | Per-PCAP → per-rule alert matrix verification |
| `test_port_scan_detection.py` | `PORT_SCAN` vertical/horizontal, trusted host exemptions |
| `test_regression_fixes.py` | Regression tests for previously fixed bugs |
| `test_reporting_standard.py` | 11-gate `EvaluationValidator` gate checks |
| `test_rule_governance_invariants.py` | Enforces the 23-rule registry, unique names, LRU O(1) bounds |
| `test_run_eval.py` | Runs `run_eval.py` and verifies 42 TP / 0 FP |
| `test_tcp_flag_anomaly.py` | `TCP_FLAG_ANOMALY` invalid flag combinations |
| `test_tcp_stealth_scan_detection.py` | `TCP_STEALTH_SCAN` FIN/NULL/Xmas |
| `test_tcp_zero_window.py` | `TCP_ZERO_WINDOW` threshold and multi-flow corroboration |
| `test_tls_anomaly.py` | `TLS_ANOMALY` version and handshake checks |
| `test_udp_flood.py` | `UDP_FLOOD` and QUIC web threshold |
| `test_udp_scan_detection.py` | `UDP_SCAN` threshold |
| `test_workbench.py` | Workbench-level integration tests |
| `test_audit_v3/` | Subdirectory: audit v3 ground-truth verification tests |
| `test_audit_v3_1/` | Subdirectory: audit v3.1 refinement tests |

---

## 3. Synthetic Scenario Evaluation

The file `ids_project/evaluation/run_eval.py` runs **42 hand-crafted synthetic attack scenarios**
using a small synthetic PCAP (`ids_project/data/test_attacks.pcap`) against the full rule engine,
then verifies that **zero false positives** fire against benign traffic (`ids_project/data/test_benign.pcap`).

**Command:**
```bash
python3 ids_project/evaluation/run_eval.py
```

**Expected output summary:**
```
Total attack alerts:    42
Total FP_benign alerts: 0
[OK] Zero false positives on benign traffic.
```

> [!NOTE]
> The 42 synthetic scenarios are purpose-built controlled tests. They use crafted packets
> that trivially trigger detection thresholds. They do not represent realistic attack complexity
> or validate against external ground truth. See Section 4 for real-world dataset testing.

---

## 4. Ground-Truth Benchmark Datasets

The 22-PCAP ground-truth benchmark (`scripts/evaluation/run_ground_truth_benchmark.py`) covers three
families of real-world network captures.

### 4.1 GeNIS Dataset (12 captures)

**Source:** GeNIS (Generated Network Intrusion Scenario) dataset — a controlled, lab-generated
multi-protocol attack dataset with **flow-level ground truth** labels in `genis-ground-truth.csv`.

**Location:** `data/external_benchmarks/genis/`

| Capture ID | Scenario | Category | Size |
|---|---|---|---|
| `genis_attack_bruteforce_smb` | SMB brute force | Attack | 15.7 MB |
| `genis_attack_bruteforce_ssh_ftp` | SSH+FTP brute force | Attack | 28.9 MB |
| `genis_attack_bruteforce_ssh` | SSH brute force | Attack | 17.7 MB |
| `genis_attack_dos_hulk` | HTTP Hulk DoS | Attack | 158 MB |
| `genis_attack_dos_icmp` | ICMP flood DoS | Attack | 1,329 MB |
| `genis_attack_dos_pushack` | TCP PSH+ACK flood DoS | Attack | 896 MB |
| `genis_attack_dos_slowloris` | Slowloris TCP DoS | Attack | 91.5 MB |
| `genis_attack_dos_udp` | UDP flood DoS | Attack | 893 MB |
| `genis_benign_admin_activity` | Admin SSH/HTTP | Benign (FP check) | 1.4 MB |
| `genis_benign_background_activity` | Background OS traffic | Benign (FP check) | 29.7 MB |
| `genis_benign_user_activity` | Web browsing, email | Benign (FP check) | 319 MB |

**Ground truth type:** Flow-level labels (StartTime, Proto, SrcAddr, Sport, DstAddr, Dport, Label).
Match algorithm: timestamp ± 2s, both endpoint IPs, both ports, protocol, bidirectional.

### 4.2 CICIoT2023 Dataset (7 captures)

**Source:** Canadian Institute for Cybersecurity IoT attack dataset 2023.

**Location:** `data/ciciot2023_eval/`

| Capture ID | Scenario | Target Rules |
|---|---|---|
| `ciciot_pingsweep` | ICMP ping sweep recon | `ICMP_SWEEP` |
| `ciciot_sqli` | SQL injection web exploit | `PAYLOAD_HIT` |
| `ciciot_xss` | Cross-site scripting | `PAYLOAD_HIT` |
| `ciciot_cmdinj` | OS command injection + reverse shell | `PAYLOAD_HIT`, `NON_DNS_TRAFFIC_ON_DNS_PORT` |
| `ciciot_upload` | Arbitrary file upload / PHP webshell | `PAYLOAD_HIT` |
| `ciciot_browserhijack` | Browser hijacking + UDP flood | `PAYLOAD_HIT`, `UDP_FLOOD` |
| `ciciot_bruteforce` | SSH brute force + ARP poisoning | `BRUTE_FORCE`, `ARP_SPOOF` |

**Ground truth type:** Capture-level category label only (no per-flow timestamps).
Match type: alert presence on the expected rule during capture replay.

### 4.3 Additional Captures (3 captures)

| Capture ID | Source | Scenario | Target Rule |
|---|---|---|---|
| `benign_iot23_doorlock` | CTU-IoT-23 | Somfy smart doorlock operational traffic (benign FP check) | FP verification |
| `attack_ws_teardrop` | Wireshark sample library | Teardrop overlapping IP fragment crash exploit | `IP_FRAGMENT_ANOMALY` |
| `attack_ws_dns_remoteshell` | Wireshark sample library | Interactive command shell over DNS port 53 | `NON_DNS_TRAFFIC_ON_DNS_PORT` |
| `attack_foxit_log4shell` | Fox-IT | CVE-2021-44228 Log4Shell JNDI LDAP RCE | `PAYLOAD_HIT` |

> [!NOTE]
> The Fox-IT Log4Shell capture is a real-world exploit PCAP from the Fox-IT Log4Shell honeypot dataset.
> The Wireshark samples are from the Wireshark wiki sample capture library.

---

## 5. Synthetic Test PCAPs

The following PCAPs are committed to the repository for unit testing and evaluation:

| File | Location | Purpose |
|---|---|---|
| `test_attacks.pcap` | `ids_project/data/` | 42 synthetic attack scenarios for `run_eval.py` |
| `test_benign.pcap` | `ids_project/data/` | Benign traffic for FP verification in `run_eval.py` |
| `test.pcap` | Repository root | Small test capture (legacy, do not remove) |
| `test2.pcap` | Repository root | Small test capture (legacy, do not remove) |

> [!CAUTION]
> Do not add real-world network captures from your own infrastructure to the repository.
> These may contain sensitive data and would bloat the repository significantly.

---

## 6. External Dataset Storage

Large external benchmark PCAPs are stored on a removable drive and are **not** committed to git:

- **Mount path:** `/run/media/harshitgarg/Data1/NetGuard-datasets/verified/`
- **Affected captures:** `benign_iot23_doorlock`, `attack_ws_teardrop`, `attack_ws_dns_remoteshell`, `attack_foxit_log4shell`
- **Requirement:** Mount the drive before running the full benchmark

The dataset registry with SHA-256 hashes is in `docs/evaluation/dataset-registry.md`.

---

## 7. Dataset Hash Verification

The `test_dataset_hash_verify.py` test verifies SHA-256 hashes of all datasets listed in
`data/external_benchmarks/ground_truth/manifest.csv`. Runs automatically as part of the test suite.

External-drive-only datasets are skipped when the drive is not mounted (gracefully detected via path existence check).

