# NetGuard IDS — External Dataset Registry

**Registry Version:** 1.0.0  
**Last Updated:** 2026-11-04  
**Primary Storage Path:** `/run/media/harshitgarg/Data1/NetGuard-datasets`  
**Storage Invariant:** All raw PCAP captures, archives, and external datasets reside strictly outside the Git repository.

---

## 1. Registry Overview

This registry records all external network traffic datasets acquired, verified, and integrated into the NetGuard IDS evaluation pipeline. Each entry documents provenance, cryptographic integrity (SHA-256), capture environment, ground-truth granularity, and target rule coverage across independent publishers.

---

## 2. Acquired & Verified Dataset Catalog

### Entry DS-01: `iot23_malware_34_1` (Mirai Botnet Capture)
- **Official Name:** CTU-IoT-Malware-Capture-34-1
- **Publisher:** Stratosphere Laboratory, AIC Group, Czech Technical University (CTU) in Prague & Avast Software
- **Official Download URL:** `https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/2018-12-21-15-50-14-192.168.1.195.pcap`
- **Dataset Collection:** IoT-23 (Version 1.0.0)
- **Download Date:** 2026-11-04
- **License / Terms:** Creative Commons Attribution 2.0 Generic (CC BY 2.0)
- **File Format:** libpcap (binary capture)
- **Capture File Size:** 126,317,980 bytes (~120.47 MB)
- **SHA-256 Digest:** `92ec7e2f6658ee4b007d0b816986c46cc0338bc5e2bec6ceaaca566c695e4699`
- **Infected Device:** Raspberry Pi 3 Model B (`192.168.1.195`), running Linux armhf
- **Malware Executed:** Mirai botnet variant (MD5: `2f4a47513dcdaeebeea23075d9cfa965`)
- **Attack Behaviors:** Volumetric TCP SYN floods, UDP datagram floods, high-rate egress data floods, Telnet (port 23/2323) scanning and credential brute-force, DNS C2 lookups.
- **Publisher Telemetry Available:**
  - Suricata EVE JSON (`eve.json`, 5,000,194 bytes, 8,950 events)
  - Zeek Connection Log (`conn.log.labeled`, 2,926,718 bytes, 23,145 flows)
- **Label Granularity:** Bidirectional flow-level labels (Zeek: 21,222 Malicious, 1,923 Benign).
- **Target NetGuard Rules:** `SYN_FLOOD`, `DISTRIBUTED_SYN_FLOOD`, `UDP_FLOOD`, `PORT_SCAN`, `BRUTE_FORCE`, `DATA_EXFIL`, `DNS_ANOMALY`.
- **Known Limitations:** Incomplete TCP handshakes on scanning targets (expected for SYN scanning).
- **Citation:** Sebastian Garcia, Agustin Parmisano, & Maria Jose Erquiaga. (2020). *IoT-23: A labeled dataset with malicious and benign IoT network traffic*. Zenodo. DOI: 10.5281/zenodo.4743746.

---

### Entry DS-02: `iot23_malware_3_1` (Muhstik Botnet Capture)
- **Official Name:** CTU-IoT-Malware-Capture-3-1
- **Publisher:** Stratosphere Laboratory, AIC Group, Czech Technical University (CTU) in Prague & Avast Software
- **Official Download URL:** `https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-3-1/2018-05-21_capture.pcap`
- **Dataset Collection:** IoT-23 (Version 1.0.0)
- **Download Date:** 2026-11-04
- **License / Terms:** Creative Commons Attribution 2.0 Generic (CC BY 2.0)
- **File Format:** libpcap (binary capture)
- **Capture File Size:** 57,919,772 bytes (~55.24 MB)
- **SHA-256 Digest:** `c674dc0c8d584fa66e6f00c60df973c5fbacad551c850a76d75ec9952641d00b`
- **Infected Device:** Raspberry Pi 3 Model B (`192.168.100.103`)
- **Malware Executed:** Muhstik Linux botnet
- **Attack Behaviors:** Massive internet-wide horizontal and vertical port scanning, SSH/Telnet credential brute-force, Drupal/PHP web vulnerability exploits (RCE), IRC C2 communication.
- **Label Granularity:** Flow-level and scenario-level labels.
- **Target NetGuard Rules:** `PORT_SCAN`, `SLOW_PORT_SCAN`, `BRUTE_FORCE`, `PAYLOAD_HIT`, `SYN_FLOOD`.
- **Known Limitations:** High packet rate can stress state-table tracking if not bounded.
- **Citation:** Sebastian Garcia et al. (2020). *IoT-23: A labeled dataset with malicious and benign IoT network traffic*. Zenodo.

---

### Entry DS-03: `iot23_malware_8_1` (Hakai Botnet Capture)
- **Official Name:** CTU-IoT-Malware-Capture-8-1
- **Publisher:** Stratosphere Laboratory, AIC Group, Czech Technical University (CTU) in Prague & Avast Software
- **Official Download URL:** `https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-8-1/2018-07-31-15-15-09-192.168.100.113.pcap`
- **Dataset Collection:** IoT-23 (Version 1.0.0)
- **Download Date:** 2026-11-04
- **License / Terms:** Creative Commons Attribution 2.0 Generic (CC BY 2.0)
- **File Format:** libpcap (binary capture)
- **Capture File Size:** 2,098,362 bytes (~2.00 MB)
- **SHA-256 Digest:** `80dcc2602519479ddcde889fa902fee19a76696630811452f8df38888af894f2`
- **Infected Device:** Raspberry Pi 3 Model B (`192.168.100.113`)
- **Malware Executed:** Hakai IoT botnet (Gafgyt/Qbot derivative)
- **Attack Behaviors:** Low-frequency persistent TCP probing to remote ports (specifically port 50), spaced over 22+ hours.
- **Label Granularity:** Flow-level labels.
- **Target NetGuard Rules:** `SLOW_PORT_SCAN`, `PORT_SCAN`.
- **Known Limitations:** Ultra-slow scan rate (1 probe every 40–80 seconds to only 2 unique IP targets) tests boundary behavior and expected True Negative behavior for 10s/120s sliding windows.
- **Citation:** Sebastian Garcia et al. (2020). *IoT-23 Dataset*.

---

### Entry DS-04: `iot23_honeypot_4_1` (Somfy Smart Doorlock — Benign Baseline)
- **Official Name:** CTU-Honeypot-Capture-4-1
- **Publisher:** Stratosphere Laboratory, AIC Group, Czech Technical University (CTU) in Prague & Avast Software
- **Official Download URL:** `https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-4-1/2018-10-25-14-06-32-192.168.1.132.pcap.xz`
- **Dataset Collection:** IoT-23 (Version 1.0.0)
- **Download Date:** 2026-11-04
- **License / Terms:** Creative Commons Attribution 2.0 Generic (CC BY 2.0)
- **Archive Size (XZ):** 376,840 bytes (~0.36 MB)
- **Extracted Size (PCAP):** 4,594,492 bytes (~4.38 MB)
- **SHA-256 Digest (PCAP):** `bc5a57306d9a5f614b09d9c0976f007667fee5b6de3427fbab094fa3084b9b64`
- **Monitored Hardware:** Somfy connected doorlock (physical hardware device, `192.168.1.132`)
- **Traffic Nature:** 100% Genuine Benign IoT Operational Traffic (mDNS, TLS, HTTP, NTP, SSDP).
- **Label Granularity:** Fully benign ground truth.
- **Target NetGuard Rules:** Zero false-positive verification across all 19 rules.
- **Citation:** Sebastian Garcia et al. (2020). *IoT-23 Dataset*.

---

### Entry DS-05: `ws_skype_irc` (Skype & IRC User Traffic — Benign Desktop Baseline)
- **Official Name:** SkypeIRC.cap
- **Publisher:** Wireshark Foundation / Wireshark Sample Captures Archive
- **Official Download URL:** `https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/SkypeIRC.cap`
- **Download Date:** 2026-11-04
- **License / Terms:** Open Wireshark community sample capture repository (Public / Educational)
- **File Format:** libpcap (binary capture)
- **Capture File Size:** 420,869 bytes (~0.40 MB)
- **SHA-256 Digest:** `bac79a9c3413637f871193589d848697af895b7f2700d949022224d59aa6830f`
- **Traffic Nature:** Authentic user desktop session with active IRC chat channels, Skype P2P communication, and high-frequency reverse DNS lookups (`in-addr.arpa`).
- **Target NetGuard Rules:** False-positive verification for `DNS_ANOMALY`, `UDP_FLOOD`, `SLOW_PORT_SCAN`.
- **Key Forensic Finding:** Exposed reverse DNS PTR false positives (`in-addr.arpa` misclassified as data exfiltration) and DNS resolver query flood false positives in `UdpFloodRule`.

---

### Entry DS-06: `ws_arp_storm` (ARP Storm Traffic)
- **Official Name:** arp-storm.pcap
- **Publisher:** Wireshark Foundation
- **Official Download URL:** `https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/arp-storm.pcap`
- **Download Date:** 2026-11-04
- **License / Terms:** Open Wireshark sample capture repository
- **File Format:** libpcap
- **Capture File Size:** 47,296 bytes (~0.05 MB)
- **SHA-256 Digest:** `dc101ea9bfda59f56b54bfb949195c3f169032c045b47f98e6952a86933c1b8d`
- **Traffic Nature:** High-rate broadcast ARP requests (>20 req/s) observed on a cable modem link.
- **Target NetGuard Rules:** `ARP_SPOOF` boundary evaluation.
- **Key Forensic Finding:** Confirmed that `ArpSpoofRule` targets IP-to-MAC mapping conflicts (MitM poisoning) rather than broadcast volumetric ARP request sweeps.

---

### Entry DS-07: `ws_dns_remoteshell` (Remote Shell on DNS Port)
- **Official Name:** dns-remoteshell.pcap
- **Publisher:** Wireshark Foundation (Contributed by Anith Anand)
- **Official Download URL:** `https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns-remoteshell.pcap`
- **Download Date:** 2026-11-04
- **License / Terms:** Open Wireshark sample capture repository
- **File Format:** libpcap
- **Capture File Size:** 25,005 bytes (~0.025 MB)
- **SHA-256 Digest:** `8c89c0d2d5b91695a03d05a451897f583a99d2379afac0822af0d8f390163d95`
- **Traffic Nature:** Interactive command shell executed over UDP port 53 (covert channel evasion).
- **Target NetGuard Rules:** `DNS_ANOMALY`, `PAYLOAD_HIT`.

---

### Entry DS-08: `ws_teardrop` (Teardrop IP Fragmentation Exploit)
- **Official Name:** teardrop.cap
- **Publisher:** Wireshark Foundation
- **Official Download URL:** `https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/teardrop.cap`
- **Download Date:** 2026-11-04
- **License / Terms:** Open Wireshark sample capture repository
- **File Format:** libpcap
- **Capture File Size:** 1,828 bytes (~1.8 KB)
- **SHA-256 Digest:** `e8e4193ae426dabf549cc103c9e93e7d93c6ae049ee9259f1ce2ebdb7315a683`
- **Traffic Nature:** Overlapping IP fragmentation denial-of-service attack packets.
- **Target NetGuard Rules:** Protocol fragmentation handling and engine parser stability.

---

## 3. Storage Allocation and Quota Audit

| Metric | Measured Value | Quota Limit | Status |
|---|---|---|---|
| **Mount Device** | `/dev/sdb1` | `/dev/sdb1` | Valid |
| **Mount Location** | `/run/media/harshitgarg/Data1` | External HDD | Valid |
| **Total Acquired Data** | 191,424,534 bytes (~0.178 GiB) | $\le 5.0$ GiB (initial) | **PASS** (3.6% of initial cap) |
| **Available Disk Space** | 625.3 GiB | $\ge 100$ GiB | **PASS** (625% above minimum) |
| **Total NetGuard Allocation** | $\approx 0.18$ GiB | $\le 450$ GiB | **PASS** |
| **Independent Publishers** | 2 (Stratosphere CTU, Wireshark) | $\ge 2$ | **PASS** |
| **Distinct Scenarios** | 8 | Multi-scenario | **PASS** |
