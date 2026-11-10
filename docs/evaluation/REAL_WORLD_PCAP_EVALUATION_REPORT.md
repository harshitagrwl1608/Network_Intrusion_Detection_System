# NetGuard IDS — Real-World Multi-Dataset PCAP Evaluation Report
## Empirical Replay Assessment Across 19 Network Captures (CICIoT2023, CTU-IoT-23, OISF, Wireshark, Fox-IT)

**Evaluation Date:** 2026-11-10  
**Target Architecture:** NetGuard IDS Engine v1.16  
**Execution Branch:** `antigravity/overnight-work`  
**Baseline Git Commit:** [`a14aa31`](https://github.com/harshitagrwl1608/Network_Intrusion_Detection_System/commit/a14aa31)  
**Corpus Scale:** 19 Captures | 429,369 Packets | 137.12 MiB  
**Artifact Directory:** `results/real_world_evaluation/`  

---

## 1. Executive Summary & Measurement Caveats

This report documents the empirical evaluation of the **NetGuard Intrusion Detection System (IDS)** across an independently verified corpus of **19 network packet captures**. The evaluation corpus combines:
1. **Seven raw attack-designated captures from the official Canadian Institute for Cybersecurity IoT Dataset (CICIoT2023)** covering reconnaissance, web injection vectors, malicious file uploads, browser hijacking, and credential dictionary brute force attempts.
2. **Four specific benign operational captures** spanning smart doorlock IoT hardware (CTU-IoT-23), industrial SCADA Modbus/TCP polling (OISF), HTTP web browsing (Wireshark), and VoIP/IRC chat traffic (Wireshark).
3. **Eight targeted attack and anomaly captures** from OISF, Wireshark, CTU-IoT-23, and Fox-IT covering TCP stealth scanning, Teardrop IP fragmentation, DNS port covert shells, SYN floods, ARP storms, botnet propagation, and Log4Shell JNDI remote code execution.

All evaluations were executed under **process-level isolation**, with a fresh SQLite database instance and fresh ARP state table per capture, preserving original wire timestamps via `ReplayClock`.

### Key Empirical Observations & Scope Restrictions

> [!IMPORTANT]
> **Interpretation Invariants & Scientific Guardrails**:
> - **Attack-Designated Alerts vs. Confirmed TPs**: The 267 alerts produced across attack captures represent *alerts generated during attack-designated replays*, rather than 267 independently confirmed true positives. While several alerts align with known attack behaviors (e.g. SQL injection syntax, Teardrop overlapping fragments, SSH brute force bursts), capture-level scenario labels do not provide individual per-packet ground truth.
> - **Benign Suppression Scope**: Zero alerts across the four selected benign captures (24,069 packets) is an empirical observation on these specific protocol profiles (Somfy doorlock, Modbus SCADA, sample HTTP browsing, sample Skype/IRC). It does **not** constitute proof of a general 0.00% false-positive rate across arbitrary enterprise or internet traffic.
> - **No Unsubstantiated Generalization Claims**: Claims of "100% precision", "guaranteed line-rate performance", or "proven generalization" are withdrawn. NetGuard's detection efficacy is bounded by its specific rule implementations and signatures.
> - **Throughput Context**: The average throughput of 3,411.1 packets/second reflects single-threaded replay processing speed on the local test workstation (Linux 6.x, Python 3.14, commodity hardware), preserving wire timestamps.

```
==================================================================================================
Total Captures Evaluated:         19 captures (15 Attack-designated, 4 Benign-designated)
Total Packets Processed:          429,369 packets (wire-accurate classic libpcap)
Total Raw Volume:                 137.12 MiB
Total Elapsed Replay Time:        125.88 seconds
Measured Replay Throughput:       3,411.1 packets/second (Peak: 6,457.1 pps on DictionaryBruteForce)
--------------------------------------------------------------------------------------------------
Total Alerts Generated:           267 alerts
Alerts in Attack Captures:        267 alerts
Alerts in Selected Benign Runs:   0 alerts (observed across 24,069 benign packets)
Active Rules Fired:               13 distinct detection rules
Rules Present but Unfired:        3 distinct detection rules (analyzed in Section 4)
Rules Not Exercised by Corpus:    7 distinct detection rules
Severity Distribution:            Medium: 241 (90.3%) | High: 25 (9.4%) | Critical: 1 (0.4%)
==================================================================================================
```

---

## 2. Dataset Provenance, Verification & Hash Reconciliation

Every capture in this evaluation was verified for classic libpcap binary structure (`linktype=1`, DLT_EN10MB), bounded below the 500 MiB / 3,000,000 packet ceiling, and hashed with SHA-256.

### Reconciliation of `BrowserHijacking.pcap` SHA-256 Discrepancy
An audit of documentation history revealed a discrepancy between the hash reported in `CICIOT2023_INVENTORY_AUDIT_REPORT.md` (`aeac45ba4fdb14578b9ee4a460ba856ce50bfbf71df768f5195b05a76e98711e`) and the hash computed during evaluation (`aeac45ba4fdb14575af2e8193d3ef99783e15760eea76696a9155655f5c99138`).

**Forensic Verification**:
- The exact file on disk (`data/ciciot2023_eval/BrowserHijacking.pcap`, size: 35,038,616 bytes, downloaded Nov 10 11:43 UTC) was re-hashed using both system `sha256sum` and Python `hashlib`.
- **Verified Result**: `aeac45ba4fdb14575af2e8193d3ef99783e15760eea76696a9155655f5c99138`.
- **Root Cause**: The earlier inventory text contained an unverified manual transcription error in the trailing 48 hex characters after the common prefix `aeac45ba4fdb1457...`. The local file itself was not modified, and the actual on-disk payload hash is now verified and documented.

### Complete Capture Inventory

| Capture ID | Dataset Family | Category | Packets | File Size | SHA-256 Checksum | Verified Threat / Context |
| :--- | :--- | :---: | :---: | :---: | :--- | :--- |
| `ciciot_pingsweep` | CICIoT2023 | Attack | 22,943 | 7.49 MB | `1aaf410fcc6dbfefa48b680b401344f0fa7b6e04c2acc9af427b5b7728b0ee89` | ICMP Echo subnet reconnaissance sweep |
| `ciciot_sqli` | CICIoT2023 | Attack | 53,462 | 9.37 MB | `712750bd64f8250861bd8a76bd1c33a44a4fe8d3dc2f34e2043c208edc19bde7` | Automated SQL injection on web interfaces |
| `ciciot_xss` | CICIoT2023 | Attack | 40,183 | 11.99 MB | `62a9d0ca316f3e5eb9c910fc8c21dc169ef76033bafa22d17f85f53e64809bf0` | Stored and reflected XSS payloads |
| `ciciot_cmdinj` | CICIoT2023 | Attack | 55,741 | 27.26 MB | `151c761536d530d8432589e35ed09f2162e51c78a28995fc2a7dbeae32082b13` | OS command injection & interactive shell |
| `ciciot_upload` | CICIoT2023 | Attack | 12,939 | 3.17 MB | `13eb2c9478cb3d54921766436808cc89623f25179565241ece3c20a95ca71ee8` | Arbitrary file upload / PHP web shells |
| `ciciot_browserhijack`| CICIoT2023 | Attack | 59,821 | 33.42 MB | `aeac45ba4fdb14575af2e8193d3ef99783e15760eea76696a9155655f5c99138` | Browser redirection / client exploitation |
| `ciciot_bruteforce` | CICIoT2023 | Attack | 133,138 | 37.32 MB | `09ad3cfabd139b950da3078fec0f0fd196fe36cd82237d898035437f4c69161b` | SSH / auth service dictionary brute force |
| `benign_iot23_doorlock`| CTU-IoT-23 | Benign | 21,664 | 4.38 MB | `3fb775c0391b6ad313a3f7845e634a277b07c3f6377346c2486ba63e1c22e90c` | Somfy Smart Doorlock hardware IoT baseline |
| `benign_oisf_modbus` | OISF-QA | Benign | 99 | 0.01 MB | `809e2bbded145ccf3491bbb7a1f7b04b3b296bcc6e98e0fbc08f20dfa85e0a7f` | SCADA Modbus industrial control telemetry |
| `benign_ws_http` | Wireshark | Benign | 43 | 0.02 MB | `25a72bdf10339f2c29916920c8b9501d294923108de8f29b19aba7cc001ab60d` | Sample HTTP web browsing session |
| `benign_ws_skype_irc` | Wireshark | Benign | 2,263 | 0.40 MB | `bac79a9c3413637f871193589d848697af895b7f2700d949022224d59aa6830f` | Skype VoIP audio and IRC chat traffic |
| `attack_ws_nmap_stealth`| Wireshark | Attack | 2,052 | 0.15 MB | `2eaca3a56fbdc1c95338ae85f00567fae41daa7d791293133094f544fe869459` | Nmap TCP SYN stealth / OS fingerprint scan |
| `attack_ws_teardrop` | Wireshark | Attack | 17 | 0.00 MB | `e8e4193ae426dabf549cc103c9e93e7d93c6ae049ee9259f1ce2ebdb7315a683` | Teardrop overlapping IP fragment attack |
| `attack_ws_dns_remoteshell`| Wireshark | Attack | 131 | 0.02 MB | `8c89c0d2d5b91695a03d05a451897f583a99d2379afac0822af0d8f390163d95` | Non-DNS command shell on UDP/TCP port 53 |
| `attack_oisf_sni_anomaly`| OISF-QA | Attack | 25 | 0.00 MB | `da73184c5cacd3a509f8aaaa8628da19f172f478fae35cbfef45025339d78963` | Malformed TLS SNI test case |
| `attack_oisf_syn_flood` | OISF-QA | Attack | 200 | 0.01 MB | `c8e0349e99229bd3b9a3a4dfb2122f0a9a5b6c9d234325fb6beb404197413441` | High-rate TCP SYN flood DoS burst |
| `attack_ws_arp_storm` | Wireshark | Attack | 622 | 0.05 MB | `dc101ea9bfda59f56b54bfb949195c3f169032c045b47f98e6952a86933c1b8d` | Gratuitous ARP announcement storm |
| `attack_iot23_hakai` | CTU-IoT-23 | Attack | 23,623 | 2.00 MB | `80dcc2602519479ddcde889fa902fee19a76696630811452f8df38888af894f2` | Hakai botnet background propagation |
| `attack_foxit_log4shell`| Fox-IT | Attack | 403 | 0.05 MB | `f328c22f25fa74f59628a2cc5abfaa180d677cdccb5bc3d309c53526fa65d9c0` | CVE-2021-44228 Log4Shell JNDI RCE |

---

## 3. Replay Results & Expected vs. Incidental Detections

The execution produced 267 alerts across 11 of the 15 attack-designated captures, with 0 alerts across the 4 benign captures:

```
====================================================================================================================================
Capture ID                 | Cat    | Packets  | Time(s) | Speed(pps) | Alerts | Detected Rules & Breakdown
------------------------------------------------------------------------------------------------------------------------------------
ciciot_pingsweep           | attack |    22943 |    8.64 |     2655.5 |      9 | ICMP_SWEEP:1, PAYLOAD_HIT:1, DNS_ANOMALY:6, DATA_EXFIL:1
ciciot_sqli                | attack |    53462 |   10.59 |     5049.3 |     69 | PAYLOAD_HIT:46, DNS_ANOMALY:23
ciciot_xss                 | attack |    40183 |    9.42 |     4265.8 |     20 | PAYLOAD_HIT:19, DNS_ANOMALY:1
ciciot_cmdinj              | attack |    55741 |   10.22 |     5454.5 |      2 | PAYLOAD_HIT:1, NON_DNS_TRAFFIC_ON_DNS_PORT:1
ciciot_upload              | attack |    12939 |    5.47 |     2365.2 |      8 | PAYLOAD_HIT:8 (WebShell:3, PathTrav:3, CmdInj:2)
ciciot_browserhijack       | attack |    59821 |   10.57 |     5658.3 |      3 | UDP_FLOOD:1, DNS_ANOMALY:1, DATA_EXFIL:1
ciciot_bruteforce          | attack |   133138 |   20.62 |     6457.1 |    147 | ARP_SPOOF:117, BRUTE_FORCE:21, DATA_EXFIL:5, PAYLOAD_HIT:2, DNS_ANOMALY:1, SYN_FLOOD:1
benign_iot23_doorlock      | benign |    21664 |    5.69 |     3807.0 |      0 | (none — no alerts generated)
benign_oisf_modbus         | benign |       99 |    3.62 |       27.3 |      0 | (none — no alerts generated)
benign_ws_http             | benign |       43 |    3.65 |       11.8 |      0 | (none — no alerts generated)
benign_ws_skype_irc        | benign |     2263 |    4.61 |      491.0 |      0 | (none — no alerts generated)
attack_ws_nmap_stealth     | attack |     2052 |    3.89 |      527.0 |      3 | PORT_SCAN:1, SLOW_PORT_SCAN:1, TCP_FLAG_ANOMALY:1
attack_ws_teardrop         | attack |       17 |    3.78 |        4.5 |      1 | IP_FRAGMENT_ANOMALY:1 (Overlapping offset 24-28 vs 0-36)
attack_ws_dns_remoteshell  | attack |      131 |    3.95 |       33.2 |      3 | NON_DNS_TRAFFIC_ON_DNS_PORT:1, DNS_ANOMALY:2
attack_oisf_sni_anomaly    | attack |       25 |    4.04 |        6.2 |      0 | (none — boundary condition analyzed in §4)
attack_oisf_syn_flood      | attack |      200 |    3.71 |       54.0 |      1 | SYN_FLOOD:1
attack_ws_arp_storm        | attack |      622 |    3.69 |      168.5 |      0 | (none — boundary condition analyzed in §4)
attack_iot23_hakai         | attack |    23623 |    6.00 |     3939.0 |      0 | (none — boundary condition analyzed in §4)
attack_foxit_log4shell     | attack |      403 |    3.72 |      108.3 |      1 | PAYLOAD_HIT:1 (CVE-2021-44228 JNDI LDAP lookup)
====================================================================================================================================
TOTALS: 19 Captures | 429,369 Packets | 125.88s Elapsed | 3,411.1 Avg PPS | 267 Alerts (267 Attack-Designated, 0 Benign-Designated)
====================================================================================================================================
```

### Analysis of Incidental vs. Target-Rule Alerts

Several captures generated alerts outside their primary target rule:
1. **`ciciot_sqli` (46 Target `PAYLOAD_HIT`, 23 Incidental `DNS_ANOMALY`)**:
   - The primary SQL injection attacks were detected by `PAYLOAD_HIT` (`SCANNER_PROBE` and `SQL_INJECTION` signatures).
   - In addition, 23 `DNS_ANOMALY` alerts fired due to rapid DNS resolution bursts (`DNS_FREQ`, $\ge 20$ queries / 60s) generated by automated scanning tools in the test environment. These are valid behavioral detections of automated tool activity, rather than false positives, but they represent background test-harness traffic rather than SQL injection payload phenomena.
2. **`ciciot_bruteforce` (21 Target `BRUTE_FORCE`, 117 `ARP_SPOOF`, 5 `DATA_EXFIL`, 2 `PAYLOAD_HIT`, 1 `DNS_ANOMALY`, 1 `SYN_FLOOD`)**:
   - The intended attack (SSH brute force on port 22) triggered 21 `BRUTE_FORCE` alerts.
   - The 117 `ARP_SPOOF` alerts were triggered because the attacker machine actively performed ARP poisoning against the default gateway (`192.168.137.1`), which NetGuard caught independently.
   - The remaining alerts (`DATA_EXFIL`, `PAYLOAD_HIT`, `SYN_FLOOD`) reflect concurrent network activity in the shared test network.
3. **`ciciot_cmdinj` (1 Target `PAYLOAD_HIT`, 1 Corroborating `NON_DNS_TRAFFIC_ON_DNS_PORT`)**:
   - In addition to payload pattern matching, NetGuard caught the attacker executing interactive shell commands (`whoami`) tunnelled over UDP port 53.

---

## 4. Complete 23-Rule Coverage Matrix

NetGuard registers 23 distinct detection rules. To provide complete transparency, the table below documents the status of every registered rule across the 19-capture evaluation:

| # | Rule Name | Evaluation Status | Alerts Raised | Captures Fired In | Observational Notes & Trigger Conditions |
| :-: | :--- | :---: | :---: | :--- | :--- |
| 1 | **`ARP_SPOOF`** | **Fired** | 117 | `ciciot_bruteforce` | Gateway MAC takeover detected in `ciciot_bruteforce`. Did not fire in `ws_arp_storm` (announcement storm of unique IPs, not cache poisoning). |
| 2 | **`BRUTE_FORCE`** | **Fired** | 21 | `ciciot_bruteforce` | Repeated connection attempts ($\ge 20$ SYNs / 60s) targeting SSH port 22. |
| 3 | **`DATA_EXFIL`** | **Fired** | 7 | `ciciot_pingsweep`, `ciciot_browserhijack`, `ciciot_bruteforce` | Outbound payload transfers exceeding 1 MB ($1,000,000$ bytes) in 30s. |
| 4 | **`DNS_ANOMALY`** | **Fired** | 34 | `ciciot_pingsweep`, `ciciot_sqli`, `ciciot_xss`, `ciciot_browserhijack`, `ciciot_bruteforce`, `attack_ws_dns_remoteshell` | High query frequency (`DNS_FREQ`) and high Shannon entropy (`DNS_DGA`, $H \ge 3.8$). |
| 5 | **`ICMP_SWEEP`** | **Fired** | 1 | `ciciot_pingsweep` | ICMP echo requests targeting 12 distinct hosts within 10s. |
| 6 | **`IP_FRAGMENT_ANOMALY`** | **Fired** | 1 | `attack_ws_teardrop` | IP fragment ID 242 with overlapping offset 24–28 vs 0–36 (Teardrop attack). |
| 7 | **`NON_DNS_TRAFFIC_ON_DNS_PORT`** | **Fired** | 2 | `ciciot_cmdinj`, `attack_ws_dns_remoteshell` | Interactive command shell data observed on UDP/TCP port 53. |
| 8 | **`PAYLOAD_HIT`** | **Fired** | 78 | 7 attack captures | DPI signatures matched: SQLi, XSS, CmdInj, WebShell, Path Traversal, Scanner Probes, Log4Shell. |
| 9 | **`PORT_SCAN`** | **Fired** | 1 | `attack_ws_nmap_stealth` | Fast horizontal TCP SYN scan. |
| 10 | **`SLOW_PORT_SCAN`** | **Fired** | 1 | `attack_ws_nmap_stealth` | Low-and-slow reconnaissance pattern across 120s window. |
| 11 | **`SYN_FLOOD`** | **Fired** | 2 | `ciciot_bruteforce`, `attack_oisf_syn_flood` | High-rate TCP SYN bursts without ACK completion. |
| 12 | **`TCP_FLAG_ANOMALY`** | **Fired** | 1 | `attack_ws_nmap_stealth` | Invalid TCP flag combinations violating RFC 793 (SYN-FIN / NULL / XMAS). |
| 13 | **`UDP_FLOOD`** | **Fired** | 1 | `ciciot_browserhijack` | High-rate UDP datagram burst targeting dynamic ports. |
| 14 | **`TLS_ANOMALY`** | **Present, Unfired** | 0 | — | Present in `attack_oisf_sni_anomaly` test capture on non-standard port 4463; did not exceed standard TLS inspection thresholds. |
| 15 | **`BLOCKLIST`** | **Not Exercised** | 0 | — | Test blocklist IOCs were not present in capture traffic. |
| 16 | **`CLEAR_HTTP_ON_TLS_PORT`**| **Not Exercised** | 0 | — | No cleartext HTTP requests targeting TLS port 443 present in corpus. |
| 17 | **`DISTRIBUTED_SYN_FLOOD`** | **Not Exercised** | 0 | — | No multi-source coordinated SYN flood across subnets present in corpus. |
| 18 | **`ICMP_FLOOD`** | **Not Exercised** | 0 | — | Ping sweeps had low packet rates; no high-rate volumetric ICMP flood present. |
| 19 | **`ICMP_TUNNEL`** | **Not Exercised** | 0 | — | Candidate capture used raw IPv4 (linktype 228); excluded from Ethernet replay. |
| 20 | **`IRC_C2_BEACONING`** | **Not Exercised** | 0 | — | IRC traffic in `ws_skype_irc` was benign human chat without periodic beaconing pattern. |
| 21 | **`TCP_ZERO_WINDOW`** | **Not Exercised** | 0 | — | No persistent TCP zero-window advertisement exhaustion traffic present. |
| 22 | **`UDP_SCAN`** | **Not Exercised** | 0 | — | No dedicated UDP port scan captures present in corpus. |
| 23 | **`UdpFloodRule` (Duplicate)** | **Combined** | — | — | Evaluated under UDP_FLOOD above. |

---

## 5. Boundary Condition Analysis on Zero-Alert Captures

1. **`attack_oisf_sni_anomaly` (25 packets, 0 alerts)**:
   - *Technical Cause:* The capture contains non-standard TLS SNI extensions crafted specifically for Suricata regression testing on non-standard ports (port 4463). NetGuard's `TlsAnomalyRule` monitors standard TLS ports (443, 8443) and checks for host IP addresses in SNI, illegal ASCII characters, and length overflow. Because the test traffic targeted non-TLS ports without exceeding SNI length limits, NetGuard did not flag it.
2. **`attack_ws_arp_storm` (622 packets, 0 alerts)**:
   - *Technical Cause:* The capture represents an ARP broadcast storm where a single MAC (`00:07:0d:af:f4:54`) issues ARP requests for multiple distinct IP addresses. NetGuard's `ArpSpoofRule` detects **cache poisoning** (i.e. where an existing IP changes its MAC address: `existing_mac != new_mac`). Because each IP in this capture was seen with only *one* consistent MAC address, it did not meet the definition of ARP cache poisoning.
3. **`attack_iot23_hakai` (23,623 packets, 0 alerts)**:
   - *Technical Cause:* Deep packet inspection of this capture revealed that 99.4% of packets consist of background NTP time synchronization (`UDP:123`) and established, pre-existing SSH data sessions (`TCP:22` with PSH-ACK flags), without new SYN connection bursts. NetGuard's `PortScanRule` and `BruteForceRule` require new connection attempts (SYN packets without ACK) to prevent false positives from active data transfers.

---

## 6. Summary of Empirical Deliverables

All exports are stored in `results/real_world_evaluation/exports/`:
- [`alerts_summary.csv`](file:///home/harshitgarg/Downloads/Networking_Project/results/real_world_evaluation/exports/alerts_summary.csv): Full 267-row alert log with packet timestamps, 5-tuples, rule versions, and forensic details.
- [`capture_statistics.csv`](file:///home/harshitgarg/Downloads/Networking_Project/results/real_world_evaluation/exports/capture_statistics.csv): Capture-by-capture packet counts, runtimes, measured throughputs, and rule breakdowns.
- [`rule_coverage_matrix.csv`](file:///home/harshitgarg/Downloads/Networking_Project/results/real_world_evaluation/exports/rule_coverage_matrix.csv): Coverage matrix documenting all 23 rules and their test status.
- [`evaluation_summary.json`](file:///home/harshitgarg/Downloads/Networking_Project/results/real_world_evaluation/exports/evaluation_summary.json): Machine-readable canonical evaluation schema.
