# 7. Suricata 8.0.7 Comparison Analysis

## Executive Summary
Both NetGuard IDS (v1.1, 23 production rules) and Suricata (v8.0.7, 53,391 ET Open rules) were executed independently against the complete, unsegmented 13,565,553-packet PCAP (`2019-02-28-19-15-13-192.168.1.200.pcap`).

The comparative results demonstrate fundamental architectural differences between stateful behavioral flow analysis and application-layer pattern-matching signatures.

---

## Engine Comparison Matrix

| Evaluation Dimension | NetGuard IDS (v1.1) | Suricata 8.0.7 (ET Open) | Analytical Significance |
| :--- | :--- | :--- | :--- |
| **Ruleset / Architecture** | 23 Canonical Behavioral Rules | 53,391 ET Open Signatures | NetGuard uses stateful flow tracking; Suricata uses multi-pattern string matching |
| **Detection Paradigm** | Stateful Flow & Incident Aggregation | Stateless Payload & Decoder Events | NetGuard condenses 3.39M flows into actionable incidents |
| **Packets Processed** | 13,565,553 (100.0%) | 13,565,553 (100.0%) | Identical baseline capture |
| **Execution Runtime** | 2,711.11 s (~45.18 min) | 85.51 s (~1.43 min) | Suricata is multi-threaded C; NetGuard is single-threaded pure Python |
| **Peak RSS Memory** | 116.44 MB | 1,420 MB | NetGuard maintains strict $O(1)$ LRU bounding (116 MB) |
| **Total Alerts Emitted** | **4,027** | **85** | NetGuard captures the primary attack; Suricata detects payload downloads |
| **Mirai Telnet Scan Detection** | **3,765 Confirmed Alerts** | **0 Direct Scan Alerts** | ET Open lacks default SYN scan heuristics; NetGuard catches full scanning campaign |
| **C&C Malware Download Detection**| 0 Alerts (Payload Out-of-Scope) | **22 Alerts (ELF Download)** | Suricata detects payload signatures via HTTP decoder |

---

## Detailed Suricata Signature Distribution

From the 900 MB `eve.json` generated during the Suricata replay:

| Signature ID | Signature Description | Category | Count | Interpretation |
| :--- | :--- | :--- | :--- | :--- |
| `1:2210045:2` | `SURICATA STREAM Packet with invalid ack` | Generic Protocol Command Decode | 23 | Decoder anomaly from external host replies |
| `1:2210046:3` | `SURICATA STREAM SHUTDOWN RST invalid ack` | Generic Protocol Command Decode | 23 | External hosts rejecting scan probes |
| `1:2019240:16` | `ET INFO Executable and linking format (ELF) file download Over HTTP` | Potential Corporate Privacy Violation | 11 | Direct detection of Mirai binary downloads |
| `1:2032973:3` | `ET HUNTING Possible ELF executable sent when remote host claims text` | Potentially Bad Traffic | 11 | Malicious payload disguise on port 80 |
| `1:2200074:2` | `SURICATA TCPv4 invalid checksum` | Generic Protocol Command Decode | 6 | Checksum offload / bad packet decodes |
| `1:2210054:1` | `SURICATA STREAM excessive retransmissions` | Generic Protocol Command Decode | 3 | Retransmissions during payload retrieval |
| `1:2400036:4883`| `ET DROP Spamhaus DROP Listed Traffic Inbound` | Misc Attack | 3 | Probing IP listed in Spamhaus DROP database |
| `1:2221004:1` | `SURICATA HTTP unable to match response to request` | Generic Protocol Command Decode | 2 | Asymmetric flow decoding |
| `1:2210007:3` | `SURICATA STREAM 3way handshake SYNACK with wrong ack` | Generic Protocol Command Decode | 2 | TCP handshake anomaly from target host |
| `1:2200042:2` | `SURICATA Ethernet packet too small` | Generic Protocol Command Decode | 1 | Final runt packet in PCAP |

---

## Complementary Detection Analysis

1. **Why Suricata Missed the 3.38M Scan Flows**:
   - The default ET Open ruleset relies almost exclusively on pattern matching against established TCP streams and application layer protocols (HTTP, TLS, DNS, SMB).
   - In this capture, the infected Raspberry Pi emitted 3,386,119 TCP SYN packets (`conn_state=S0`) to port 23 across random external IPv4 addresses. Because no TCP handshake completed, no payload was transferred, and ET Open emitted **zero alerts** for the scan itself.
   - Suricata only noticed anomalies when external hosts returned corrupted RST or ACK packets.

2. **Why NetGuard Successfully Detected the Scan Campaign**:
   - NetGuard's `PORT_SCAN` and `SLOW_PORT_SCAN` rules track distinct destination targets per source IP within rolling time windows (10s and 120s).
   - As a result, NetGuard generated **3,473 high-rate scan alerts** and **292 low-and-slow scan alerts**, providing complete temporal coverage of the Mirai worm's propagation.

3. **Why NetGuard Did Not Alert on the 11 ELF Downloads**:
   - The 11 HTTP connections to `167.99.182.238:80` were standard TCP flows where the Mirai dropper downloaded the botnet binary.
   - NetGuard's 23 production rules focus on transport-layer protocol anomalies, port scans, and clear HTTP credential leaks. Without an external file-reputation blocklist or HTTP AV scanner, standard HTTP GET downloads are intentionally out-of-scope for the packet-first engine.

4. **Conclusion**:
   - NetGuard IDS and Suricata operate in distinct, complementary security layers.
   - NetGuard IDS provides superior visibility into horizontal reconnaissance and scanning behavior with bounded memory (116 MB vs 1.4 GB), while Suricata provides file-type identification on completed TCP streams.
