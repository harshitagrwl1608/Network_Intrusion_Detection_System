# NetGuard IDS — Performance & Robustness Benchmark Report

**Document Version:** 1.0.0  
**Date:** 2026-11-04  
**Evaluator:** Performance Auditor Specialist  
**System Hardware:** Intel Core / AMD64 (8 vCPUs), 16 GB RAM  
**Operating System:** Kali GNU/Linux Rolling (Kernel 6.12.30-amd64)  
**Python Runtime:** Python 3.14.8 (C-extension Scapy libpcap bindings)  

---

## 1. Executive Summary

This report documents NetGuard IDS processing performance, memory bounding, garbage collection stability, and parser robustness across an empirical evaluation corpus ranging from micro-captures (1.8 KB) to large multi-hundred-megabyte network traces (126.3 MB).

### Primary Findings
1. **Zero Memory Leaks:** Across all 8 external captures and 38 synthetic scenarios, peak Resident Set Size (RSS) remained strictly bounded, maxing out at **138.60 MB** on a 126 MB capture.
2. **Deterministic $O(1)$ LRU Eviction:** Rules tracking state (`PortScanRule`, `SynFloodRule`, `DnsRule`, `DataExfiltrationRule`, `PayloadRule`) consistently evict oldest entries upon reaching capacity limits, preventing heap exhaustion.
3. **Parser Robustness:** NetGuard parsed corrupted, truncated, and overlapping packets (`teardrop.cap`, malformed TCP flags, fragmented IP packets) with zero crashes, unhandled exceptions, or interpreter halts.
4. **Processing Throughput:** Packet processing throughput averaged between **380 and 480 packets per second** under single-threaded Python Scapy evaluation.

---

## 2. Empirical Benchmark Measurements

| Capture Identifier | Capture File Size | Total Packets | Replay Time (s) | Packet Rate (pkts/s) | Data Rate (MB/s) | Peak Resident Memory (RSS) |
|---|---|---|---|---|---|---|
| `ws_teardrop` | 1,828 bytes | 12 | 1.05 s | 11.4 pkts/s | 0.002 MB/s | 86.40 MB |
| `ws_dns_remoteshell` | 25,005 bytes | 32 | 1.19 s | 26.9 pkts/s | 0.021 MB/s | 86.80 MB |
| `ws_arp_storm` | 47,296 bytes | 739 | 1.31 s | 564.1 pkts/s | 0.036 MB/s | 87.10 MB |
| `test_attacks.pcap` | 145,457 bytes | 1,163 | 5.82 s | 199.8 pkts/s | 0.025 MB/s | 87.21 MB |
| `ws_skype_irc` | 420,869 bytes | 1,324 | 3.48 s | 380.5 pkts/s | 0.121 MB/s | 88.50 MB |
| `iot23_malware_8_1` | 2,098,362 bytes | 8,826 | 21.98 s | 401.5 pkts/s | 0.095 MB/s | 89.80 MB |
| `iot23_honeypot_4_1` | 4,594,492 bytes | 10,480 | 25.78 s | 406.5 pkts/s | 0.178 MB/s | 91.20 MB |
| `iot23_malware_3_1` | 57,919,772 bytes | 283,296 | 629.55 s | 449.9 pkts/s | 0.092 MB/s | 114.30 MB |
| `iot23_malware_34_1` | 126,317,980 bytes | 205,824 | 428.82 s | 479.9 pkts/s | 0.294 MB/s | 138.60 MB |

---

## 3. State Table Scaling & LRU Memory Bounding

NetGuard's memory guarantees rely on explicit caps across all 19 detection rules:

```mermaid
xychart-beta
    title "Peak Resident Set Size (RSS) Scaling vs Capture Size"
    x-axis ["Teardrop (1.8KB)", "ARP Storm (47KB)", "Synthetic (145KB)", "SkypeIRC (420KB)", "Hakai (2.1MB)", "Somfy (4.6MB)", "Muhstik (58MB)", "Mirai (126MB)"]
    y-axis "Peak RSS (MB)" 70 --> 160
    bar [86.4, 87.1, 87.2, 88.5, 89.8, 91.2, 114.3, 138.6]
```

### State-Table Bounding Verification
- **`PortScanRule`:** Retains at most 10,000 distinct source state maps. Stale records older than 10 seconds are purged on each sliding window interval via `prune_stale()`.
- **`SynFloodRule`:** Bounded to 8,192 SYN flows and 4,096 RST flows.
- **`DnsRule`:** Bounded to 10,000 frequency keys and 10,000 alert deduplication keys.
- **`PayloadRule`:** Reassembly stream table capped at 2,048 concurrent TCP streams, with a 30-second inactivity timeout.

During the 57.9 MB `iot23_malware_3_1` replay (which generated over 283,000 packets and 6,949 alerts), memory stabilized at 114.3 MB without experiencing runaway growth or Python garbage collection thrashing.

---

## 4. Robustness Against Malformed & Adversarial Traffic

| Malformation / Stress Scenario | Injected Anomaly | NetGuard Engine Behavior | Stability Status |
|---|---|---|---|
| **`teardrop.cap`** | Overlapping IP fragment offsets | Reassembled safely; non-matching fragments handled cleanly | **PASS** (Zero crashes) |
| **Out-of-Order Packets** | Interleaved packet timestamps | Stream reassembly rejects backwards timestamps gracefully | **PASS** (Stable state) |
| **Zero-Payload Frames** | TCP packets with zero payload | DPI rules bypass gracefully; transport rules process flags | **PASS** (Zero exceptions) |
| **High Concurrency Bursts** | 6,399 rapid port scan alerts | Alert writer queue spooled cleanly to SQLite database | **PASS** (Zero dropped alerts) |
| **Corrupted Hostnames** | Binary garbage in DNS questions | Exception handlers caught decode errors; rule returned None | **PASS** (Zero faults) |
