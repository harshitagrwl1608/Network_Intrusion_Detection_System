# NetGuard IDS — Ground-Truth Validation Methodology & Flow Mapping

**Document Version:** 1.0.0  
**Date:** 2026-11-04  
**Auditors:** Dataset Researcher & Independent Security Auditor  
**Scope:** Real-World External Captures (IoT-23, Wireshark Sample Captures)

---

## 1. Ground-Truth Principles & Anti-Pattern Defenses

Evaluating an intrusion detection system against real-world network captures requires strict methodological discipline. Assuming that a capture file is homogeneously "malicious" or "benign" is an invalid anti-pattern that distorts precision and recall.

NetGuard enforces the following ground-truth principles:

1. **Heterogeneous Flow Decomposition:** Attack captures invariably contain background operational traffic (NTP synchronization, DHCP leases, router discovery, DNS lookups, TCP keep-alives). Marking all packets in a malware PCAP as "malicious" manufactures artificial False Positives.
2. **Bidirectional Flow Canonicalization:** Flows are identified by the canonical 5-tuple:
   $$\text{FlowKey} = \big(\min(\text{IP}_1, \text{IP}_2), \max(\text{IP}_1, \text{IP}_2), \min(\text{port}_1, \text{port}_2), \max(\text{port}_1, \text{port}_2), \text{proto}\big)$$
   This ensures that forward requests and reverse replies map to the exact same flow context.
3. **Explicit Multi-Tier Label Granularity:**
   - **Packet-Level:** Flag anomalies, DPI signatures, malformed headers.
   - **Flow-Level:** Connection state, byte/packet volumes, SYN-ACK completions (Zeek `conn.log`).
   - **Time-Windowed Behavioral:** Port scans, DoS floods, brute-force attempts.
   - **Explicit UNKNOWN / UNCERTAIN Tier:** Network traffic lacking definitive cryptographic or protocol proof is categorized as `UNCERTAIN` rather than forcing an arbitrary label.

---

## 2. Dataset-by-Dataset Ground-Truth Analysis

### 2.1 IoT-23 CTU-IoT-Malware-Capture-34-1 (Mirai Botnet)

#### Labelling Methodology & Provenance
- **Origin:** Stratosphere Laboratory, Czech Technical University.
- **Hardware:** Physical Raspberry Pi 3 Model B connected to an open internet testbed via a Linux NAT router (`192.168.1.1`).
- **Infected Host IP:** `192.168.1.195`.
- **Reference Telemetry:** Zeek `conn.log.labeled` (23,145 flows), Suricata `eve.json` (8,950 events).

#### Label Granularity & Flow Decomposition
| Zeek Label | Flow Count | Flow Nature & Verification |
|---|---|---|
| `DDoS` | 14,394 | High-volume SYN and UDP flood flows targeting victim IPs (`1.1.1.1`, `50.50.50.53`, `74.91.117.248`, `71.61.66.148`). |
| `C&C` | 6,706 | Outbound Telnet connections, IRC communication channels, and DNS resolution to botnet controllers. |
| `PartOfAHorizontalPortScan` | 122 | Probes directed at port 63798 across external hosts spaced over 8.3 hours. |
| `Benign` | 1,923 | Legitimate NTP synchronization (`147.231.100.5:123`), local DNS queries, and ARP gateway announcements. |

#### Artifacts & Critical Observations
- **Mixed Traffic Reality:** Out of 23,145 total flows, 1,923 flows (8.3%) are strictly benign background traffic. A simplistic evaluation treating the entire capture as an attack would penalize any alert on NTP or DNS.
- **NAT Mapping:** Outbound connections undergo stateful inspection; external responses arrive at ephemeral source ports allocated by the host stack.
- **Timestamp Synchronization:** Zeek epoch timestamps match packet header timestamps within sub-millisecond precision.

---

### 2.2 IoT-23 CTU-IoT-Malware-Capture-3-1 (Muhstik Botnet)

#### Labelling Methodology & Provenance
- **Infected Host IP:** `192.168.100.103`.
- **Behavioral Nature:** Highly aggressive automated worm. The botnet continuously scans the IPv4 address space for open web servers running vulnerable PHP/Drupal services and attempts brute-force SSH logins.
- **Flow Characteristics:** Over 100,000 distinct SYN packets sent to diverse destination IP addresses on ports 80, 8080, and 22.
- **NetGuard Alignment:** NetGuard generated 6,399 `PORT_SCAN` alerts, 473 `SLOW_PORT_SCAN` alerts, and 77 `BRUTE_FORCE` alerts.
- **Ground-Truth Assessment:** Verified true positive detections of mass scanning and automated credential harvesting.

---

### 2.3 IoT-23 CTU-Honeypot-Capture-4-1 (Somfy Doorlock — Pure Benign)

#### Labelling Methodology & Provenance
- **Monitored Hardware:** Somfy smart doorlock (`192.168.1.132`).
- **Capture Environment:** Stratosphere IoT Honeypot laboratory with unrestrained internet access.
- **Traffic Profile:** Pure benign IoT operation. Device communicates with vendor cloud services over TLS, performs mDNS link-local queries, NTP time checks, and local broadcast announcements.
- **Ground-Truth Label:** 100% Benign.
- **NetGuard Performance:** **0 alerts**. Confirms zero false alarms on legitimate IoT embedded hardware communications.

---

### 2.4 Wireshark Sample Captures: Skype & IRC (Real User Traffic)

#### Labelling Methodology & Provenance
- **Capture Origin:** Real user workstation running Skype P2P client and an IRC chat client.
- **Traffic Profile:** Benign personal computing traffic containing IRC protocol messages, P2P UDP packet exchanges, and reverse DNS address lookups (`in-addr.arpa`).
- **Ground-Truth Label:** Benign operational traffic.
- **False-Positive Root Cause Analysis:**
  - NetGuard generated 8 `DNS_ANOMALY` alerts and 2 `UDP_FLOOD` alerts.
  - **Audit Finding 1 (DNS Reverse Mapping):** NetGuard's `DnsRule._parent_domain` grouped PTR queries (`*.in-addr.arpa`) under `in-addr.arpa`, counting distinct reverse IP lookups as "subdomain data exfiltration".
  - **Audit Finding 2 (DNS Query Rate in UDP Flood):** NetGuard's `UdpFloodRule` exempted `src_port == 53` (DNS server replies), but failed to exempt `dst_port == 53` (client queries to DNS servers). When a workstation sends bursts of DNS queries to resolve Skype peers, `UdpFloodRule` mistook legitimate DNS resolution for a targeted UDP denial-of-service attack.
  - **Action Required:** Fix these two root causes in Phase 4G with regression test verification.

---

## 3. Ground-Truth Flow Alignment Protocol & Label Classification

When matching NetGuard alerts against external reference labels, NetGuard implements a rigorous three-layer matching engine:

1. **Bidirectional Flow Canonicalization (`canonicalize_flow`):**
   Endpoints $(A, \text{port}_A)$ and $(B, \text{port}_B)$ are canonicalized via:
   $$\text{canonical\_ips} = \operatorname{sorted}(\text{norm}(A), \text{norm}(B)), \quad \text{canonical\_ports} = \operatorname{sorted}(\text{port}_A, \text{port}_B)$$
   Both inbound request packets and outbound response packets map deterministically to the identical canonical flow key.

2. **Bijective Flow Matching (Anti-Inflation Guard):**
   In high-rate scenarios (e.g., DoS bursts or rapid port scans), multiple alerts may be triggered for the same flow. NetGuard enforces bijective matching: each ground-truth label instance can be claimed at most once by an alert. Secondary alerts on an already matched attack flow are tracked as co-occurring sub-alerts rather than artificially inflating True Positive counts.

3. **Exhaustive vs. Partial Label Set Handling:**
   - **Exhaustive Ground Truth Mode (`exhaustive=True`):** Applicable to controlled synthetic scenarios or fully labeled benchmark corpuses where every packet is accounted for. Any unmatched alert is classified as a False Positive (`FP`).
   - **Partial / Targeted Ground Truth Mode (`exhaustive=False`):** Applicable to external research PCAPs targeting specific exploit vectors (e.g., Log4Shell, Teardrop, ICMP tunnel). Alerts raised outside the labeled ground-truth set are classified as `UNASSESSED` (or `EXTRA_ALERT`), preventing spurious penalty on secondary real-world anomalies.
   - **Unassessed Reference Captures (`UNASSESSED_REFERENCE_CAPTURE`):** When a capture tests an attack family or protocol domain outside active IDS signature scope (e.g., man-on-the-side TCP racing, firewall whitelisting policies, low-frequency C2 beaconing), it is recorded as unassessed reference data rather than miscategorized as a detection failure.

```mermaid
sequenceDiagram
    autonumber
    participant P as Packet / Flow Stream
    participant NG as NetGuard RuleEngine (22 Rules)
    participant GT as Ground Truth (Zeek/Publisher)
    participant M as Bijective Verification Matcher

    P->>NG: Ingest packet (timestamp T)
    P->>GT: Reference flow classification
    NG->>NG: State evaluation across 22 detection rules
    alt Alert Generated
        NG->>M: Emits Alert (Rule, Src, Dst, Port, T_alert)
        GT->>M: Provides Reference Label (FlowKey, T_start, T_end, Category)
        M->>M: Match (canonical(FlowKey_NG) == canonical(FlowKey_GT)) & (T_start <= T_alert <= T_end + 5s)
        alt Matched Attack Label & Unclaimed
            M->>M: Classify as TRUE POSITIVE (TP) [Claim label bijectively]
        else Matched Benign Label
            M->>M: Classify as FALSE POSITIVE (FP)
        else Unmatched in Partial Mode
            M->>M: Classify as UNASSESSED / CO-OCCURRING
        else Unmatched in Exhaustive Mode
            M->>M: Classify as FALSE POSITIVE (FP)
        end
    else No Alert Generated
        alt Ground Truth was Malicious Attack
            M->>M: Classify as FALSE NEGATIVE (FN)
        else Ground Truth was Benign
            M->>M: Classify as TRUE NEGATIVE (TN)
        end
    end
```

---

## 4. Auditor Sign-Off & Governance Invariant

- **Dataset Researcher Verdict:** `APPROVED`. External dataset provenance, licenses, hashes, and flow labels are verified against official CTU, Wireshark, Nozomi Networks, and Fox-IT repositories across 16 verified captures.
- **Independent Security Auditor Verdict:** `APPROVED`. Detection engine operates with 22 registered, evidence-driven rules under modern rule governance invariants. Port boundaries ($1 \le \text{port} \le 65535$), $O(1)$ LRU state bounding via `prune_stale(now)`, and rich forensic evidence dictionaries are verified across the 587-test suite.
