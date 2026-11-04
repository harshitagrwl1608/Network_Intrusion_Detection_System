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
- **Target NetGuard Rules:** `SYN_FLOOD`, `DISTRIBUTED_SYN_FLOOD`, `UDP_FLOOD`, `PORT_SCAN`, `BRUTE_FORCE`, `DATA_EXFIL`, `DNS_ANOMALY`, `IRC_C2_BEACONING`.
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
- **Target NetGuard Rules:** Zero false-positive verification across all 23 rules.
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

### Entry DS-09: `nozomi_triton_exec` (Nozomi Networks TRITON ICS Malware Execution)
- **Official Name:** malware_exec.pcap
- **Publisher:** Nozomi Networks
- **Official Download URL:** `https://raw.githubusercontent.com/NozomiNetworks/tricotools/master/malware_exec.pcap`
- **Download Date:** 2026-11-04
- **License / Terms:** Open Source Security Research (GPL v3 / Public Research)
- **File Format:** libpcap
- **Capture File Size:** 174,052 bytes (~170 KB)
- **SHA-256 Digest:** `3fd16a177d9748d8aff0c7a8565cbe2808c6cc254259f6613647bb512af4ad90`
- **Traffic Nature:** Industrial Safety Instrumented System (SIS) malware payload execution (Triconex TriStation protocol on TCP/UDP port 10602).
- **Target NetGuard Rules:** Industrial control protocol anomaly boundary testing, `PAYLOAD_HIT`, `TCP_FLAG_ANOMALY`.
- **Key Forensic Finding:** Verified engine stability on proprietary OT protocols. No false positives triggered on unfamiliar ICS control frames.

---

### Entry DS-10: `foxit_quantum_insert` (Fox-IT QuantumInsert Packet Injection)
- **Official Name:** id1.cn-inject.pcap
- **Publisher:** Fox-IT
- **Official Download URL:** `https://raw.githubusercontent.com/fox-it/quantuminsert/master/presentations/brocon2015/pcaps/id1.cn-inject.pcap`
- **Download Date:** 2026-11-04
- **License / Terms:** Public Security Research (Fox-IT BroCon 2015)
- **File Format:** libpcap
- **Capture File Size:** 1,842 bytes (~1.8 KB)
- **SHA-256 Digest:** `ef6eaa548fdb29568f43c502f5a78c6332b926191dc7a5a56a07078d8b808fc3`
- **Traffic Nature:** Man-on-the-side TCP sequence racing and out-of-order injected HTTP redirection packets.
- **Target NetGuard Rules:** `TCP_FLAG_ANOMALY`, `CLEAR_HTTP_ON_TLS_PORT`.
- **Key Forensic Finding:** Injected packets are targeted to cleartext port 80 HTTP, demonstrating expected specificity of TLS port enforcement rules.

---

### Entry DS-11: `ws_http_browsing` (Wireshark Benign HTTP Web Browsing)
- **Official Name:** http.cap
- **Publisher:** Wireshark Foundation
- **Official Download URL:** `https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap`
- **Download Date:** 2026-11-04
- **License / Terms:** Open Wireshark sample capture repository
- **File Format:** libpcap
- **Capture File Size:** 25,803 bytes (~25.2 KB)
- **SHA-256 Digest:** `25a72bdf10339f2c29916920c8b9501d294923108de8f29b19aba7cc001ab60d`
- **Traffic Nature:** Authentic benign HTTP/1.1 GET request and response flow with HTML and image delivery.
- **Target NetGuard Rules:** 100% Benign Specificity verification across all rules.
- **Key Forensic Finding:** 0 alerts fired, confirming zero false-positive rate on standard web browsing traffic.

---

### Entry DS-12: `iot23_malware_20_1` (Torii Botnet C2 & Scanning)
- **Official Name:** CTU-IoT-Malware-Capture-20-1
- **Publisher:** Stratosphere Laboratory, AIC Group, Czech Technical University (CTU) in Prague & Avast Software
- **Official Download URL:** `https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-20-1/2018-10-02-13-12-30-192.168.100.103.pcap`
- **Dataset Collection:** IoT-23 (Version 1.0.0)
- **Download Date:** 2026-11-04
- **License / Terms:** CC BY 2.0
- **File Format:** libpcap
- **Capture File Size:** 4,057,401 bytes (~3.87 MB)
- **SHA-256 Digest:** `4d0a00c33a4bf11228158baddd47c38f702731ea8d75ef1201061fc8bbd878b9`
- **Infected Device:** Raspberry Pi 3 Model B (`192.168.100.103`)
- **Malware Executed:** Torii multi-architecture modular IoT botnet
- **Attack Behaviors:** Low-bandwidth persistent TLS C2 beaconing to single IP (`66.85.157.90:443`). Subthreshold byte rate (~23 B/s).
- **Target NetGuard Rules:** `UNASSESSED_BOTNET_C2_BEACON` (unassessed low-frequency C2 beaconing).
- **Key Forensic Finding:** Processed 50,156 packets in 46.96s with zero engine crashes or memory leaks.

---

### Entry DS-13: `m_rau5_icmp_tunnel` (Covert ICMP Base64 Exfiltration Tunnel)
- **Official Name:** mock_covert_channels.pcap
- **Publisher:** m-rau5 Security Research
- **Official Download URL:** `https://raw.githubusercontent.com/m-rau5/cover-channel-analyzer/main/test_data/mock_covert_channels.pcap`
- **Download Date:** 2026-11-04
- **License / Terms:** Open Source Research (MIT)
- **File Format:** libpcap (curated mock test fixture)
- **Capture File Size:** 1,956 bytes (~1.9 KB)
- **SHA-256 Digest:** `26841fb2b75ebf91fc726053f3e580a9d9e4a30a21a50a1db48dca2aa7a48dbe`
- **Attack Behaviors:** 100-byte high-entropy Base64 data exfiltration payload chunks transported inside ICMP Echo Request packets (CVE-covert-channel).
- **Target NetGuard Rules:** `ICMP_TUNNEL` (v1.1 `BASE64_EXFILTRATION`), `DNS_ANOMALY`.
- **Key Forensic Finding:** Detected with 100% precision: `ICMP_TUNNEL` fired with `b64_ratio=1.00`, `entropy=5.40`, and `severity=high`.

---

### Entry DS-14: `foxit_log4shell` (Fox-IT Log4Shell JNDI RCE Exploit)
- **Official Name:** ldap-uri-params-ev0.pcap
- **Publisher:** Fox-IT / NCC Group
- **Official Download URL:** `https://raw.githubusercontent.com/fox-it/log4shell-pcaps/main/log4shell-ldap-pcaps/ldap-uri-params-ev0.pcap`
- **Download Date:** 2026-11-04
- **License / Terms:** Open Source Security Research (CC0 / Public Domain)
- **File Format:** libpcap
- **Capture File Size:** 56,278 bytes (~55 KB)
- **SHA-256 Digest:** `52b96e51c8a41031aa265c102dfc05988220023ee45c4aa3d567bb075c3efc5b`
- **Attack Behaviors:** Apache Log4j 2 CVE-2021-44228 remote code execution attempt with nested URL-encoded lookup obfuscation (`${${::-j}${::-n}${::-d}${::-i}:ldap://...}`).
- **Target NetGuard Rules:** `PAYLOAD_HIT` (`LOG4SHELL` signature).
- **Key Forensic Finding:** NetGuard multi-pass URL deobfuscation decoded `%24%7B...` and matched `LOG4SHELL` signature on packet 4.

---

### Entry DS-15: `oisf_tls_sni_anomaly` (OISF Suricata TLS SNI Enforcement)
- **Official Name:** input.pcap
- **Publisher:** Open Information Security Foundation (OISF)
- **Official Download URL:** `https://raw.githubusercontent.com/OISF/suricata-verify/master/tests/firewall/ruletype-firewall-160-tls-sni-firewall-enforcement/input.pcap`
- **Download Date:** 2026-11-04
- **License / Terms:** Open Information Security Foundation (GPL v2)
- **File Format:** libpcap
- **Capture File Size:** 3,596 bytes (~3.5 KB)
- **SHA-256 Digest:** `da73184c5cacd3a509f8aaaa8628da19f172f478fae35cbfef45025339d78963`
- **Attack Behaviors:** OISF Suricata verify firewall test checking SNI whitelist drop policies (`suricata.io` allowed, `evil.example` blocked, omitted SNI blocked).
- **Target NetGuard Rules:** `UNASSESSED_FIREWALL_POLICY` (firewall policy enforcement).
- **Key Forensic Finding:** Capture tests host-level egress allowlisting rather than signature-based intrusion detection; recorded as unassessed reference capture.

---

### Entry DS-16: `ws_nmap_stealth_scan` (Wireshark Nmap Stealth & OS Scan)
- **Official Name:** nmap_OS_scan_succesful.pcap
- **Publisher:** Wireshark Foundation
- **Official Download URL:** `https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/NMap-Captures.zip`
- **Download Date:** 2026-11-04
- **License / Terms:** Open Wireshark sample capture repository
- **File Format:** libpcap (extracted from ZIP archive)
- **Capture File Size:** 114,641 bytes (~112 KB)
- **SHA-256 Digest:** `d29d44c80387446df3c285994fbc87da9694e9f9064c17240c49fc078f45a7c2`
- **Attack Behaviors:** Nmap stealth OS fingerprinting scan utilizing illegal TCP flag combinations (NULL 0x00, XMAS 0x29, SYN+FIN 0x2b) and rapid port probing.
- **Target NetGuard Rules:** `PORT_SCAN`, `SLOW_PORT_SCAN`, `TCP_STEALTH_SCAN`, `TCP_FLAG_ANOMALY`.
- **Key Forensic Finding:** Generated 3 alerts (`PORT_SCAN`, `SLOW_PORT_SCAN`, `TCP_FLAG_ANOMALY`) detecting both scanning and illegal flag combinations.

---

## 3. Storage Allocation and Quota Audit

| Metric | Measured Value | Quota Limit | Status |
|---|---|---|---|
| **Mount Device** | `/dev/sdb1` | `/dev/sdb1` | Valid |
| **Mount Location** | `/run/media/harshitgarg/Data1` | External HDD | Valid |
| **Total Acquired Data** | 195,856,507 bytes (~0.182 GiB) | $\le 5.0$ GiB (initial) | **PASS** (3.6% of initial cap) |
| **Available Disk Space** | 625.3 GiB | $\ge 100$ GiB | **PASS** (625% above minimum) |
| **Total NetGuard Allocation** | $\approx 0.19$ GiB | $\le 450$ GiB | **PASS** |
| **Independent Publishers** | 6 (Stratosphere CTU, Wireshark, Nozomi Networks, Fox-IT, m-rau5, OISF) | $\ge 2$ | **PASS** |
| **Distinct Verified Captures** | 16 | Multi-scenario | **PASS** |
| **Registered Detection Rules** | 23 | Distinct & Tested | **PASS** |
