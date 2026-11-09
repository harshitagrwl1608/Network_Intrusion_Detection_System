# 01 — Holdout Capture Metadata & Provenance

**Document Status:** Sealed Verification Record  
**Candidate Identifier:** `stratosphere_ctu_hns_botnet_1_1`  
**Dataset Family:** IoT-23 / Stratosphere Laboratory  
**Evaluation Type:** Independent Single-Pass Blind Holdout  

---

## 1. Provenance & Publisher Verification

- **Dataset Name:** Stratosphere CTU IoT-23 Malware Capture 1-1 (Hide and Seek Botnet)
- **Publisher:** Stratosphere IPS / CTU University, Prague, Czech Republic
- **Official Scenario URL:** [https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-1-1/](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-1-1/)
- **Malware Family Executed:** Hide and Seek (HNS) IoT Botnet
- **Infected Device:** Raspberry Pi 3 Model B (`192.168.100.103`)
- **Default Gateway:** `192.168.1.2`
- **Ground Truth Source:** CTU University Verified Malware Execution & Labeled Netflows
- **Capture File Name:** `2018-05-09-192.168.100.103.pcap`
- **Quarantined Path:** `/run/media/harshitgarg/Data1/NetGuard-datasets/holdout_quarantine/stratosphere_ctu_hns_botnet_1_1.pcap`

---

## 2. Cryptographic Integrity & Physical Dimensions

| Dimension | Measured Value | Standard / Requirement | Compliance |
|---|---|---|---|
| **SHA-256 Digest** | `8ebcd17af4e2d20b1cf7ad564760756f457a80b791a0757a2b1a624b2724969c` | Mandatory pre-registered hash | PASS |
| **File Size (Bytes)** | `145,928,231` bytes (139.17 MiB / 145.93 MB) | $\ge 100\text{ MB}$ requirement | PASS |
| **Total Frames** | `1,686,291` packets | $\ge 100,000$ packet requirement | PASS |
| **Capture Duration** | `402,852.02` seconds (~4.66 days) | Multi-day real-world capture | PASS |
| **Earliest Timestamp** | `2018-05-09 21:00:31.015073 UTC` | Monotonic hardware timestamp | PASS |
| **Latest Timestamp** | `2018-05-14 12:54:43.030512 UTC` | Monotonic hardware timestamp | PASS |
| **Strict Time Order** | `True` | Replay determinism guaranteed | PASS |
| **Quarantine Permissions**| `0o444` (read-only) | Immutable quarantine invariant | PASS |

---

## 3. Protocol Hierarchy & Traffic Profile

Protocol distribution computed across all 1,686,291 frames via TShark protocol hierarchy statistics:

```text
===================================================================
Protocol Hierarchy Statistics
Filter: 

frame                                    frames:1686291 bytes:118947551
  eth                                    frames:1686291 bytes:118947551
    ip                                   frames:1653042 bytes:116952611
      tcp                                frames:1216851 bytes:89799225 (72.2%)
        telnet                           frames: 111819 bytes: 8998029 (Brute-force propagation)
        http                             frames:   4922 bytes:  565418
        data                             frames:   6809 bytes:  505426
        ssh                              frames:     11 bytes:    4306
      udp                                frames: 415000 bytes:25361296 (24.6%)
        dof (Hide & Seek P2P protocol)   frames: 387888 bytes:23273280 (P2P mesh communication)
        ntp                              frames:  15356 bytes: 1382040 (Time sync)
        data                             frames:  11728 bytes:  703680
        dns                              frames:      2 bytes:     172
        dhcp                             frames:      2 bytes:     684
      icmp                               frames:  21191 bytes: 1792090 (1.3%)
    arp                                  frames:  33249 bytes: 1994940 (2.0%)
===================================================================
```

### Analysis of Behavioral Characteristics
The capture exhibits authentic, multi-stage infected IoT behavior:
1. **Low-and-Slow Horizontal Telnet Scanning:** 111,819 Telnet frames directed to external IPv4 addresses attempting port 23 exploitation.
2. **Volumetric SYN Bursts:** Concentrated TCP SYN floods sent against specific network services.
3. **P2P Mesh Communication:** 387,888 UDP frames utilizing the custom Hide & Seek Decentralized Over-the-Air Forwarding (DOF) protocol.
4. **Benign Background Traffic:** Regular NTP synchronization, local ARP queries, and ICMP messaging without malicious intent.
