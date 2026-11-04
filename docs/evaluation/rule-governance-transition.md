# NetGuard IDS — Rule Governance Transition & Expansion Report

**Document ID:** `NETGUARD-GOV-2026-001`  
**Date:** November 4, 2026  
**Status:** Approved & Implemented  
**Branch:** `antigravity/overnight-work`  
**Base Commit:** `3b6942e`  

---

## 1. Executive Summary

The historical invariant strictly mandating exactly 19 registered NetGuard detection rules has been formally retired and superseded.

The fixed 19-rule limit originated as an essential early safeguard against uncontrolled rule proliferation and artificial metric inflation during autonomous agent cycles. However, as NetGuard expanded into Phase 4—evaluating against external real-world PCAP datasets (IoT-23 malware traffic, Wireshark security captures, covert tunneling traces)—the numerical ceiling created an artificial barrier to closing demonstrated network security blind spots.

### The New Governing Principle

> **There is NO predetermined maximum or target number of detection rules.**  
> **Governing Invariant:** Every registered detection rule must provide **distinct, justified, tested, and maintainable detection value**.

NetGuard will never increase rule counts merely for statistical metrics or cosmetic complexity, nor will it artificially cap the registry at a new numerical ceiling (e.g., 25, 30, or 50). The rule inventory expands and evolves strictly according to demonstrated coverage requirements backed by empirical packet telemetry.

---

## 2. Workbench & Architecture Modernization

All static constraints, documentation, and hooks enforcing the 19-rule limit were updated across the entire workbench:

1. **Governance & Rule Files:**
   - `.agents/plugins/netguard-workbench/rules/AGENTS.md`: Superseded Section 1 ("Strict Rule Count = 19") with the evidence-driven Rule Governance Invariant.
   - `AGENTS.md`: Superseded Section 2 ("Core Detection Invariant: No New Detection Rules") with "Core Detection Governance: Distinct, Justified & Tested Rules".
2. **Ephemeral Context Injection Hooks:**
   - `.agents/plugins/netguard-workbench/scripts/pre_invocation.py`: Updated to inject the dynamic rule governance invariant.
   - `.agents/plugins/netguard-workbench/scripts/session_start.py`: Updated to enforce distinct and justified rule governance.
3. **Specialist Subagent Definitions:**
   - Updated `detection-rule-engineer.md`, `independent-security-auditor.md`, `performance-auditor.md`, and `regression-qa-reviewer.md` to adopt the new evidence-driven admission requirements.
4. **Skills & Autonomy Documentation:**
   - Updated `.agents/plugins/netguard-workbench/skills/rule-review/SKILL.md`, `.agents/skills/detection-validation/SKILL.md`, `.agents/skills/external-dataset-research/SKILL.md`, and autonomy threat models.
5. **Decoupled Tests and Dashboards:**
   - Decoupled `ids_project/dashboard/app.py` and `ids_project/tests/test_dashboard_api.py` from hardcoded numerical constants, dynamically reading active rule registry length.

---

## 3. Dynamic Rule Invariant Architecture

Hardcoded `assert len(engine.rules) == 19` checks were replaced by a robust, semantic invariant test suite: [`test_rule_governance_invariants.py`](file:///home/harshitgarg/Downloads/Networking_Project/ids_project/tests/test_rule_governance_invariants.py).

This test suite continuously enforces:
1. **Rule Identity Uniqueness (`test_rule_identities_are_unique`)**: Asserts that every registered rule name is globally unique across the engine.
2. **Class Instance Disjointness (`test_no_duplicate_rule_classes`)**: Prevents registering duplicate instances of the same rule class.
3. **Interface Contract Compliance (`test_rule_instances_are_valid`)**: Enforces that all registered rules implement required attributes (`name`, `rule_version`) and methods (`check(record)`, `prune_stale(now)`).
4. **Preservation of Core Baseline (`test_core_baseline_rules_preserved`)**: Guarantees that none of the original 19 baseline rules can be accidentally omitted or removed.
5. **Mandatory Automated Test Coverage (`test_registered_rules_have_associated_test_coverage`)**: Automatically inspects `ids_project/tests/` to guarantee that every single registered rule has dedicated positive/negative automated test suites.
6. **Registry Integrity & Intentionality (`test_dynamic_registry_integrity_and_count_intentionality`)**: Validates that all registered rules are distinct, active objects without unreferenced padding.

---

## 4. Empirical Audit & Gap Identification

An audit of the baseline 19 rules against real-world packet captures identified two severe, unaddressed network telemetry blind spots:

### Gap 1: DNS Port 53 Egress Bypasses & Backdoors
- **Vulnerability**: Attackers frequently bind interactive reverse shells (`cmd.exe`, `/bin/sh`) or forward HTTP/custom C2 over TCP or UDP port 53 to bypass strict perimeter egress filters that permit standard DNS queries.
- **Why Existing Rules Failed**:
  - `DnsRule` (v1.24) only parses structured DNS messages and skips non-DNS records.
  - `PayloadRule` (v1.24) restricts deep packet inspection to designated web/application ports (`_DPI_PORTS = {80, 8080, 8000, 8888, 3000, 5000}`).
  - `CleartextHttpOnTlsPortRule` (v1.11) only inspects port 443.
- **Empirical Evidence**: Wireshark capture [`ws_dns_remoteshell.pcap`](file:///run/media/harshitgarg/Data1/NetGuard-datasets/verified/ws_dns_remoteshell.pcap) contains an interactive Windows XP command prompt (`cmd.exe`) bound to TCP port 53, executing `dir` and `exit` commands. NetGuard generated zero detection alerts for this shell.

### Gap 2: Covert ICMP Data Tunnels & Reverse Shells
- **Vulnerability**: Covert channels (e.g. `icmpsh`, `ptunnel`, `hans`) encapsulate interactive shells, file transfers, and encrypted streams inside ICMP Echo (type 8/128) and Echo Reply (type 0/129) packets.
- **Why Existing Rules Failed**:
  - `IcmpSweepRule` (v1.8) only tracks probes across distinct destinations.
  - `IcmpFloodRule` (v1.8) only tracks high packet volume directed at a single target.
  - A low-rate ICMP tunnel sending 1 packet every few seconds evaded all NetGuard rules because payload contents were never inspected.
- **Empirical Evidence**: Diagnostic pings carry standard small payloads (Windows: 32 bytes; Linux: 56 bytes) or repetitive padding. Malicious ICMP payloads contain executable headers (`MZ`, `\x7fELF`), shell execution tokens (`cmd.exe`, `/bin/sh`), Ptunnel magic (`0xD5200804`), or high-entropy (>4.5) ciphertext.

---

## 5. Evidence-Driven Rule Admissions

Following rigorous admission criteria (demonstrated blind spot, empirical PCAP evidence, bounded $O(1)$ LRU state, zero false positives on benign baselines), two new detection rules were engineered and registered:

### Rule 20: `NonDnsTrafficOnDnsPortRule` (v1.0)
- **Class**: [`NonDnsTrafficOnDnsPortRule`](file:///home/harshitgarg/Downloads/Networking_Project/ids_project/engine/rules.py)
- **Rule Name**: `NON_DNS_TRAFFIC_ON_DNS_PORT`
- **Detection Capabilities**:
  1. `INTERACTIVE_SHELL`: Matches command shell prompts and banners (`Microsoft Windows`, `cmd.exe`, `/bin/sh`, `/bin/bash`, `root@`, `whoami`, `dir\r\n`, `ls -l`).
  2. `CLEARTEXT_HTTP`: Matches HTTP methods (`GET `, `POST `, `HEAD `, `PUT `, `OPTIONS `, `CONNECT `, `HTTP/1.`) targeting port 53.
  3. `NON_DNS_PROTOCOL`: Identifies high-ratio printable ASCII text streams (>0.85) on port 53 that fail standard DNS header structure checks.
- **Benign Protection**:
  - Validates RFC 1035 wire formats: single-packet and streamed TCP DNS queries with 2-byte length prefixes and valid opcodes ($\le 5$) are preserved without false alerts.
  - Exempts DNS over TLS (DoT, RFC 7858) TLS ClientHello handshakes.
  - Ignores empty TCP control packets (SYN/ACK/FIN).
- **State Bounding**: Direction-independent host pair deduplication with 60-second cooldown and 4,096-entry `OrderedDict` LRU bounding.
- **Test Suite**: [`ids_project/tests/test_non_dns_on_dns_port.py`](file:///home/harshitgarg/Downloads/Networking_Project/ids_project/tests/test_non_dns_on_dns_port.py) (14 positive, negative, and state tests passing).

### Rule 21: `IcmpTunnelRule` (v1.0)
- **Class**: [`IcmpTunnelRule`](file:///home/harshitgarg/Downloads/Networking_Project/ids_project/engine/rules.py)
- **Rule Name**: `ICMP_TUNNEL`
- **Detection Capabilities**:
  1. `PTUNNEL_TRAFFIC`: Matches Ptunnel magic token (`0xD5200804`). Severity: `critical`.
  2. `EMBEDDED_EXECUTABLE`: Identifies Windows PE (`MZ`) and Linux ELF (`\x7fELF`) binaries staged over ICMP Echo packets. Severity: `high`.
  3. `ICMP_SHELL_PAYLOAD`: Identifies interactive reverse shell data (`icmpsh`) including `cmd.exe`, `/bin/sh`, `powershell`, and `whoami`. Severity: `high`.
  4. `HIGH_ENTROPY_TUNNEL`: Detects oversized payloads ($\ge 128$ bytes) with Shannon entropy $\ge 4.5$ bits/byte, indicative of compressed or encrypted data channels. Severity: `medium`.
- **Benign Protection**:
  - Excludes standard operating system ping payloads (Windows 32-byte, Linux 56-byte).
  - Inspects only Echo Request (type 8/128) and Echo Reply (type 0/129); ignores ICMP error messages (Destination Unreachable, Time Exceeded) carrying embedded original IP headers.
  - Implements `_is_diagnostic_ping()` to exempt legitimate MTU sweep diagnostics (all zeros, repeating small alphabets, or sequential byte cycles).
- **State Bounding**: Host pair deduplication with 60-second cooldown and 4,096-entry `OrderedDict` LRU bounding.
- **Test Suite**: [`ids_project/tests/test_icmp_tunnel.py`](file:///home/harshitgarg/Downloads/Networking_Project/ids_project/tests/test_icmp_tunnel.py) (14 positive, negative, and state tests passing).

---

## 6. Complete Registered Rule Inventory (21 Rules)

| # | Rule Name | Class | Version | Target Threat / Network Observable |
|---|---|---|---|---|
| 1 | `BLOCKLIST` | `BlocklistRule` | 1.4 | Communication with known-malicious C2/botnet IP addresses |
| 2 | `TCP_FLAG_ANOMALY` | `TcpFlagAnomalyRule` | 1.9 | Illegal TCP flag combinations (SYN+FIN, NULL, XMAS, etc.) |
| 3 | `PORT_SCAN` | `PortScanRule` | 1.13 | High-rate vertical or horizontal TCP SYN port scanning |
| 4 | `UDP_SCAN` | `UdpScanRule` | 1.4 | High-rate vertical or horizontal UDP port probing |
| 5 | `UDP_FLOOD` | `UdpFloodRule` | 1.10 | Targeted high-volume UDP packet floods |
| 6 | `TCP_STEALTH_SCAN` | `TcpStealthScanRule` | 1.8 | Low-profile FIN, NULL, and XMAS reconnaissance probes |
| 7 | `SYN_FLOOD` | `SynFloodRule` | 1.13 | High-volume single-source SYN or RST denial-of-service floods |
| 8 | `DISTRIBUTED_SYN_FLOOD` | `DistributedSynFloodRule` | 1.9 | Multi-source coordinated distributed SYN floods |
| 9 | `ICMP_SWEEP` | `IcmpSweepRule` | 1.8 | Network-wide host discovery sweeps via ICMP Echo |
| 10 | `ICMP_FLOOD` | `IcmpFloodRule` | 1.8 | Targeted ICMP Echo denial-of-service floods |
| 11 | `ARP_SPOOF` | `ArpSpoofRule` | 1.8 | Man-in-the-middle ARP spoofing and IP-MAC mapping changes |
| 12 | `PAYLOAD_HIT` | `PayloadRule` | 1.24 | Deep packet inspection for SQLi, RCE, Log4j, XSS, Webshells |
| 13 | `DNS_ANOMALY` | `DnsRule` | 1.24 | DGA domains, DNS tunneling, frequency anomalies, hex/b64 chunks |
| 14 | `BRUTE_FORCE` | `BruteForceRule` | 1.12 | Repeated connection attempts to authentication ports (SSH, RDP) |
| 15 | `SLOW_PORT_SCAN` | `SlowPortScanRule` | 1.11 | Low-and-slow stealth port reconnaissance over extended windows |
| 16 | `DATA_EXFIL` | `DataExfiltrationRule` | 1.20 | High-volume outbound data exfiltration to external endpoints |
| 17 | `TLS_ANOMALY` | `TlsAnomalyRule` | 1.13 | Literal IP in SNI (RFC 6066) and reverse-proxy tunnel services |
| 18 | `CLEAR_HTTP_ON_TLS_PORT` | `CleartextHttpOnTlsPortRule` | 1.11 | Cleartext HTTP requests transmitted to TLS ports (e.g. 443) |
| 19 | `TCP_ZERO_WINDOW` | `TcpZeroWindowRule` | 1.10 | Sockstress DoS and persistent TCP receiver backpressure |
| 20 | `NON_DNS_TRAFFIC_ON_DNS_PORT` | `NonDnsTrafficOnDnsPortRule` | 1.0 | Interactive shells, HTTP, and non-DNS traffic over DNS port 53 |
| 21 | `ICMP_TUNNEL` | `IcmpTunnelRule` | 1.0 | Covert ICMP tunnels (ptunnel, icmpsh), executables, high entropy |

---

## 7. Verification & Empirical Results

### Unit Test Suite
```bash
pytest ids_project/tests
# ======================== 538 passed in 63.03s ========================
```
- **Total Tests**: 538 tests executed.
- **Pass Rate**: 100% (0 failures, 0 errors, 0 skipped).
- **Dynamic Invariants**: All 6 semantic checks in `test_rule_governance_invariants.py` passed.

### Ground-Truth Evaluation Benchmark
```bash
python3 ids_project/evaluation/run_eval.py
```
- **Labelled Attack Scenarios**: 38
- **True Positives (TP)**: 38 / 38 (100.0%)
- **False Negatives (FN)**: 0
- **False Positives (Attack)**: 0
- **False Positives (Benign)**: 0
- **Precision**: 100.0%
- **Recall**: 100.0%
- **F1 Score**: 100.0%

### Real-World PCAP Verification
1. **Wireshark Remote Shell Capture (`ws_dns_remoteshell.pcap`)**:
   - **Baseline Detection (19 rules)**: 0 alerts on the command shell (missed detection).
   - **Post-Admission Detection (21 rules)**:
     - `[NON_DNS_TRAFFIC_ON_DNS_PORT] (high)`: Detected interactive Windows command prompt (`Microsoft Windows XP [Version 5.1.2600]... C:\>`) on TCP port 53.
     - `[NON_DNS_TRAFFIC_ON_DNS_PORT] (medium)`: Detected non-DNS ASCII command output stream on TCP port 53.
2. **Benign PCAP Baseline (`test_benign.pcap`)**:
   - Replayed 832 benign packets against Rule 20 and Rule 21: **0 false positives**.
3. **IoT-23 Malware Capture (`iot23_malware_8_1.pcap`)**:
   - Replayed 23,623 packets against Rule 20 and Rule 21: **0 false positives**.

---

## 8. Conclusion

NetGuard IDS has successfully evolved from a rigid numerical rule constraint to an evidence-driven, dynamic governance model. The addition of `NonDnsTrafficOnDnsPortRule` and `IcmpTunnelRule` closes critical network evasion blind spots without introducing false positives, while preserving 100% precision and recall across all regression suites and ground-truth benchmarks.

