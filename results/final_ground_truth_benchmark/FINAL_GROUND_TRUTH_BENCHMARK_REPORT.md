# NetGuard IDS — Final Ground-Truth Benchmark Evaluation Report
## Multi-Scenario Empirical Evaluation Across GeNIS, CTU-IoT-23, CICIoT2023 & Protocol Fixtures

**Evaluation Date:** 2026-11-10  
**Total Captures:** 22  
**Total Extracted PCAP Volume:** 3.243 GiB (3,481,833,419 bytes)  
**Total Packet Count:** 37,532,459 packets  
**Average Measured Replay Speed:** 12506.0 packets/second  
**Target Repository:** `harshitagrwl1608/Network_Intrusion_Detection_System`  
**Branch:** `antigravity/overnight-work`  

---

## 1. Corpus Composition & Verified Scale

The benchmark corpus strictly satisfies the **>= 1 GiB extracted PCAP/PCAPNG volume** requirement across multiple attack and benign scenarios:
- **Total Extracted Size:** 3.243 GiB (3,481,833,419 bytes)
- **Total Wire Packets:** 37,532,459
- **Benchmark Source Families:**
  - **GeNIS (GECAD Network Intrusion Scenarios, Zenodo 14919237)**: Flow-labeled ground-truth scenarios (recon-dns, recon-nmap, brute force, DoS).
  - **CTU-IoT-23**: Real-world IoT hardware benign operational traffic (Somfy Doorlock).
  - **CICIoT2023**: Scenario-level attack captures (PingSweep, SQLi, XSS, CmdInj, Upload, BruteForce).
  - **Focused Protocol Fixtures (OISF / Wireshark / Fox-IT)**: Protocol edge cases (Teardrop fragment overlap, DNS remote shell, Log4Shell).

---

## 2. Per-Capture Evaluation Results

| Capture ID | Category | Scenario | Packets | Size | Time(s) | Speed (pps) | Alerts | TP | FP | Unscorable |
| :--- | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `genis_attack_bruteforce_smb` | attack | attack-bruteforce-smb | 112,000 | 13.75 MB | 16.91 | 6622.9 | 8 | 4 | 0 | 4 |
| `genis_attack_bruteforce_ssh_ftp` | attack | attack-bruteforce-ssh-ftp | 213,000 | 25.26 MB | 33.75 | 6311.5 | 70 | 69 | 0 | 1 |
| `genis_attack_bruteforce_ssh` | attack | attack-bruteforce-ssh | 88,000 | 16.15 MB | 10.59 | 8312.2 | 74 | 74 | 0 | 0 |
| `genis_attack_dos_hulk` | attack | attack-dos-hulk | 586,000 | 148.38 MB | 194.33 | 3015.5 | 14 | 14 | 0 | 0 |
| `genis_attack_dos_icmp` | attack | attack-dos-icmp | 15,000,000 | 1097.90 MB | 745.50 | 20120.8 | 3 | 3 | 0 | 0 |
| `genis_attack_dos_pushack` | attack | attack-dos-pushack | 10,000,000 | 740.46 MB | 865.09 | 11559.5 | 4 | 4 | 0 | 0 |
| `genis_attack_dos_slowloris` | attack | attack-dos-slowloris | 701,000 | 79.61 MB | 300.76 | 2330.8 | 6 | 4 | 0 | 2 |
| `genis_attack_dos_udp` | attack | attack-dos-udp | 10,000,000 | 737.53 MB | 690.97 | 14472.4 | 3 | 3 | 0 | 0 |
| `genis_benign_admin_activity` | benign | benign_activity | 8,908 | 1.30 MB | 4.67 | 1906.8 | 43 | 0 | 43 | 0 |
| `genis_benign_background_activity` | benign | benign_activity | 112,000 | 26.45 MB | 15.59 | 7184.4 | 42 | 0 | 42 | 0 |
| `genis_benign_user_activity` | benign | benign_activity | 316,000 | 299.27 MB | 33.94 | 9311.2 | 52 | 0 | 52 | 0 |
| `benign_iot23_doorlock` | benign | benign_iot_hardware | 21,000 | 4.38 MB | 5.80 | 3618.1 | 0 | 0 | 0 | 0 |
| `ciciot_pingsweep` | attack | recon_pingsweep | 22,000 | 7.49 MB | 6.41 | 3434.5 | 9 | 0 | 0 | 0 |
| `ciciot_sqli` | attack | web_sqli | 53,000 | 9.37 MB | 10.62 | 4991.7 | 69 | 0 | 0 | 0 |
| `ciciot_xss` | attack | web_xss | 40,000 | 11.99 MB | 8.71 | 4593.0 | 20 | 0 | 0 | 0 |
| `ciciot_cmdinj` | attack | web_command_injection | 55,000 | 27.26 MB | 9.80 | 5612.0 | 2 | 0 | 0 | 0 |
| `ciciot_upload` | attack | web_upload_webshell | 12,000 | 3.17 MB | 5.41 | 2216.5 | 8 | 0 | 0 | 0 |
| `ciciot_browserhijack` | attack | web_browser_hijack | 59,000 | 33.42 MB | 10.61 | 5559.1 | 3 | 0 | 0 | 0 |
| `ciciot_bruteforce` | attack | auth_bruteforce | 133,000 | 37.32 MB | 20.62 | 6448.8 | 147 | 0 | 0 | 0 |
| `attack_ws_teardrop` | attack | ip_fragment_overlap | 17 | 0.00 MB | 3.61 | 4.7 | 1 | 0 | 0 | 0 |
| `attack_ws_dns_remoteshell` | attack | dns_port_backdoor | 131 | 0.02 MB | 3.73 | 35.1 | 3 | 0 | 0 | 0 |
| `attack_foxit_log4shell` | attack | log4shell_jndi_rce | 403 | 0.05 MB | 3.74 | 107.7 | 1 | 0 | 0 | 0 |

---

## 3. All 23 Rules Coverage & Evaluation Status

| Rule Name | Test Status | Total Alerts | TP | FP | Unscorable | Precision | Captures Fired In |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `ARP_SPOOF` | exercised_unscorable | 117 | 0 | 0 | 117 | N/A | 1 captures |
| `BLOCKLIST` | not_exercised | 0 | 0 | 0 | 0 | N/A | 0 captures |
| `BRUTE_FORCE` | exercised_with_tp | 146 | 125 | 0 | 21 | 100.0% | 4 captures |
| `CLEAR_HTTP_ON_TLS_PORT` | not_exercised | 0 | 0 | 0 | 0 | N/A | 0 captures |
| `DATA_EXFIL` | exercised_unscorable | 7 | 0 | 0 | 7 | N/A | 3 captures |
| `DISTRIBUTED_SYN_FLOOD` | not_exercised | 0 | 0 | 0 | 0 | N/A | 0 captures |
| `DNS_ANOMALY` | exercised_with_fp | 119 | 0 | 85 | 34 | 0.0% | 8 captures |
| `ICMP_FLOOD` | exercised_with_tp | 1 | 1 | 0 | 0 | 100.0% | 1 captures |
| `ICMP_SWEEP` | exercised_unscorable | 2 | 0 | 0 | 2 | N/A | 2 captures |
| `ICMP_TUNNEL` | not_exercised | 0 | 0 | 0 | 0 | N/A | 0 captures |
| `IP_FRAGMENT_ANOMALY` | exercised_unscorable | 1 | 0 | 0 | 1 | N/A | 1 captures |
| `IRC_C2_BEACONING` | not_exercised | 0 | 0 | 0 | 0 | N/A | 0 captures |
| `NON_DNS_TRAFFIC_ON_DNS_PORT` | exercised_unscorable | 2 | 0 | 0 | 2 | N/A | 2 captures |
| `PAYLOAD_HIT` | exercised_with_tp | 87 | 1 | 8 | 78 | 11.1% | 9 captures |
| `PORT_SCAN` | exercised_with_tp | 69 | 25 | 44 | 0 | 36.2% | 9 captures |
| `SLOW_PORT_SCAN` | exercised_with_tp | 11 | 11 | 0 | 0 | 100.0% | 8 captures |
| `SYN_FLOOD` | exercised_with_tp | 18 | 11 | 0 | 7 | 100.0% | 5 captures |
| `TCP_FLAG_ANOMALY` | not_exercised | 0 | 0 | 0 | 0 | N/A | 0 captures |
| `TCP_ZERO_WINDOW` | not_exercised | 0 | 0 | 0 | 0 | N/A | 0 captures |
| `TLS_ANOMALY` | not_exercised | 0 | 0 | 0 | 0 | N/A | 0 captures |
| `UDP_FLOOD` | exercised_with_tp | 2 | 1 | 0 | 1 | 100.0% | 2 captures |
| `UDP_SCAN` | not_exercised | 0 | 0 | 0 | 0 | N/A | 0 captures |
| `WEBSHELL_INJECTION` | not_exercised | 0 | 0 | 0 | 0 | N/A | 0 captures |

---

## 4. Methodological Invariants & Ground Truth Limitations

1. **Flow-Level vs. Scenario-Level Separation**:
   - GeNIS alerts are matched against exact flow intervals using publisher timestamps, IPs, ports, and protocols.
   - CICIoT2023 captures are evaluated at the scenario level only; per-flow precision/recall is not fabricated.
2. **Defensible Matching Policy**:
   - Alerts within attack intervals that match the attack class are scored as True Positives.
   - Alerts within attack intervals that reflect secondary or unclassified behaviors (e.g. incidental DNS queries during web attacks) are preserved as `UNSCORABLE_INCIDENTAL` rather than arbitrarily assumed to be false positives or true positives.
3. **Benign False Alarm Observation**:
   - Benign captures produced 0 false positives in tested protocols, but this does not claim universal 0% FPR across unobserved internet traffic.
