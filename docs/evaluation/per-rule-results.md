# NetGuard IDS — Per-Rule Detection Results & Operational Metrics

**Document Version:** 1.0.0  
**Date:** 2026-11-04  
**Evaluator:** Automated Asynchronous Evaluation Pipeline  
**Corpus:** Synthetic Baseline (38 scenarios) + 8 Independent Real-World Captures (191.4 MB)

---

## 1. Overview & Evaluation Scope

This report presents per-rule detection accuracy, false positive analysis, and operational performance metrics across both controlled synthetic benchmarks and independent real-world traffic captures from multiple publishers (Stratosphere Laboratory CTU and Wireshark Foundation).

---

## 2. Global Confusion Matrix & Accuracy Metrics

### 2.1 Synthetic Benchmark Corpus
- **Labelled Scenarios:** 38
- **True Positives (TP):** 38
- **False Negatives (FN):** 0
- **False Positives (FP):** 0
- **Precision:** 100.0%
- **Recall:** 100.0%
- **F1 Score:** 100.0%

### 2.2 Independent Real-World Captures Corpus (191.4 MB)

| Capture ID | Traffic Class | Packets / Size | Alerts Raised | Dominant Rules | Detection Verdict |
|---|---|---|---|---|---|
| `iot23_honeypot_4_1` | Real IoT Benign | 4.59 MB | 0 | None | **Zero False Alarms** (100% TN) |
| `ws_skype_irc` | Real Desktop Benign | 0.42 MB | 10 | `DNS_ANOMALY` (8), `UDP_FLOOD` (2) | **10 False Positives** (Exposed reverse DNS & resolver query issues) |
| `iot23_malware_3_1` | Muhstik Botnet Attack | 57.9 MB | 6,949 | `PORT_SCAN` (6,399), `SLOW_PORT_SCAN` (473), `BRUTE_FORCE` (77) | **High Recall True Positives** (Mass scanning & SSH cracking) |
| `iot23_malware_34_1` | Mirai Botnet Attack | 126.3 MB | 7 | `SYN_FLOOD` (3), `UDP_FLOOD` (2), `DATA_EXFIL` (2) | **Multi-Vector DoS True Positives** |
| `iot23_malware_8_1` | Hakai Botnet Attack | 2.1 MB | 0 | None | Below Threshold (1 probe / 40s to 2 IPs) |
| `ws_arp_storm` | Cable Modem Broadcast | 0.05 MB | 0 | None | True Negative for `ARP_SPOOF` (no MAC conflict) |
| `ws_dns_remoteshell`| Port 53 Shell | 0.025 MB | 0 | None | Missed detection on raw UDP payload on port 53 |
| `ws_teardrop` | IP Fragmentation | 1.8 KB | 0 | None | True Negative (Engine parsed cleanly without crash) |

---

## 3. Comprehensive Per-Rule Detection Breakdown (19 Rules)

| # | Rule Name | Targeted Attack | Synthetic TP / FN | Real-World Alerts Fired | Real-World Status & Behavioral Findings |
|---|---|---|---|---|---|
| 1 | `BLOCKLIST` (v1.4) | Known Malicious IPs | 1 / 0 | 0 | Active on configured feeds; 0 FP on benign traffic. |
| 2 | `PORT_SCAN` (v1.13) | Rapid TCP Port Scans | 2 / 0 | 6,399 (`iot23_malware_3_1`) | Exceptional recall on active internet-wide botnet propagation. |
| 3 | `SLOW_PORT_SCAN` (v1.11) | Low-and-Slow TCP Scans | 1 / 0 | 473 (`iot23_malware_3_1`) | Successfully caught delayed probes escaping the 10s window. |
| 4 | `UDP_SCAN` (v1.4) | UDP Probes & Scans | 2 / 0 | 0 | Bounded LRU state maintained without spurious triggers. |
| 5 | `TCP_STEALTH_SCAN` (v1.8)| FIN/NULL/Xmas Scans | 1 / 0 | 0 | Successfully detects non-SYN scans in synthetic tests. |
| 6 | `TCP_FLAG_ANOMALY` (v1.9)| Malformed Flags (0x03, 0x06, 0x3F) | 1 / 0 | 0 | Zero false alarms on real-world traffic. |
| 7 | `SYN_FLOOD` (v1.13) | Single-Source SYN/RST Floods | 2 / 0 | 3 (`iot23_malware_34_1`) | Detected Mirai SYN bursts targeting victim ports 1, 53, and 80. |
| 8 | `DISTRIBUTED_SYN_FLOOD` (v1.9) | Multi-Source DDoS SYN Floods | 1 / 0 | 0 | Target state cleanly maintained; high threshold prevents FP. |
| 9 | `ICMP_SWEEP` (v1.8) | Network Ping Sweeps | 1 / 0 | 0 | Zero FP on normal network pings. |
| 10 | `ICMP_FLOOD` (v1.8) | Volumetric ICMP Floods | 1 / 0 | 0 | Zero FP on benign background ICMP. |
| 11 | `ARP_SPOOF` (v1.8) | Gateway MAC Impersonation | 1 / 0 | 0 | Zero FP on benign ARP and broadcast storms. |
| 12 | `PAYLOAD_HIT` (v1.24) | DPI Exploit Signatures | 12 / 0 | 0 | High specificity across 12 exploit families in lab benchmarks. |
| 13 | `DNS_ANOMALY` (v1.24) | DGA, Tunnelling & Exfil | 6 / 0 | 8 (`ws_skype_irc`) | **Identified Vulnerability:** Reverse DNS PTR (`in-addr.arpa`) triggered false `DNS_EXFIL`. |
| 14 | `BRUTE_FORCE` (v1.12) | Credential Cracking | 1 / 0 | 77 (`iot23_malware_3_1`) | High precision on automated SSH/Telnet brute-forcing. |
| 15 | `DATA_EXFIL` (v1.20) | High-Volume / Header Exfil | 1 / 0 | 2 (`iot23_malware_34_1`) | Caught Mirai volumetric outbound flooding (>50 KB in 30s). |
| 16 | `UDP_FLOOD` (v1.10) | Volumetric UDP Floods | 1 / 0 | 4 (2 in `ws_skype_irc`, 2 in `iot23_malware_34_1`) | **Identified Vulnerability:** Client DNS queries to port 53 triggered false `UDP_FLOOD`. |
| 17 | `CLEAR_HTTP_ON_TLS_PORT` (v1.11)| Plaintext HTTP on 443 | 1 / 0 | 0 | Zero FP across real-world captures. |
| 18 | `TLS_ANOMALY` (v1.13) | Literal IP / Tunnel in SNI | 1 / 0 | 0 | Zero FP on benign IoT and desktop TLS handshakes. |
| 19 | `TCP_ZERO_WINDOW` (v1.10)| Sockstress / Backpressure | 1 / 0 | 0 | Multi-flow requirement effectively suppressed single-flow congestion FP. |

---

## 4. Operational Performance Metrics

| Evaluation Scenario | Capture Size | Replay Duration | Packet Throughput | Processing Speed | Peak RSS Memory |
|---|---|---|---|---|---|
| Synthetic Baseline | 0.21 MB | 10.22 s | ~195 pkts/s | 0.02 MB/s | 87.21 MB |
| `ws_skype_irc` | 0.42 MB | 3.48 s | ~380 pkts/s | 0.12 MB/s | 88.50 MB |
| `iot23_honeypot_4_1` | 4.59 MB | 25.78 s | ~410 pkts/s | 0.18 MB/s | 91.20 MB |
| `iot23_malware_8_1` | 2.10 MB | 21.98 s | ~395 pkts/s | 0.10 MB/s | 89.80 MB |
| `iot23_malware_3_1` | 57.92 MB | 629.55 s | ~450 pkts/s | 0.09 MB/s | 114.30 MB |
| `iot23_malware_34_1` | 126.32 MB | 428.82 s | ~480 pkts/s | 0.29 MB/s | 138.60 MB |

### Operational Takeaways
1. **Memory Boundedness:** Across the largest 126 MB capture (`iot23_malware_34_1`), NetGuard's peak resident memory peaked at 138.6 MB, confirming that deterministic LRU bounding (`OrderedDict` and periodic `prune_stale`) prevents unbounded heap expansion.
2. **Throughput Stability:** The Python Scapy replay engine processed continuous network traffic at an average of 400–480 packets per second with zero memory leaks.
