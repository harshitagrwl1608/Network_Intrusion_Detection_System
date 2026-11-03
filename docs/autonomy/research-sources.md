# NetGuard IDS — Technical & Engineering Research Sources

This document tracks all external technical research, RFC specifications, threat intelligence reports, engine cross-references, and engineering standards utilized during the autonomous continuous improvement campaign.

## 1. Network & Protocol Standards (RFCs)
- **RFC 793 / RFC 9293**: Transmission Control Protocol (TCP) Specification — RST teardown semantics, window advertisement boundaries, sequence number wrapping, zero-window probes.
- **RFC 792**: Internet Control Message Protocol (ICMP) — Echo Request / Reply payload handling, sweep bounds.
- **RFC 1035 / RFC 2181**: Domain Names - Implementation and Specification — DNS label length boundaries (max 63 octets per label, max 255 octets per name), Shannon entropy thresholds for DGA detection.
- **RFC 826**: An Ethernet Address Resolution Protocol (ARP) — Gratuitous ARP, dynamic cache updates, poisoning attack mechanics.
- **RFC 5246 / RFC 8446**: The Transport Layer Security (TLS) Protocol Version 1.2 / 1.3 — ClientHello SNI extensions, cipher suite enumeration.

## 2. Reference Engine Standards & Cross-References
- **Suricata EVE JSON Format Documentation**:
  - `https://docs.suricata.io/en/latest/output/eve/eve-json-format.html`
  - Alert event schema, flow records, DNS event schema, network protocol normalization.
- **Suricata Emerging Threats (ET) Ruleset**:
  - `ET EXPLOIT`, `ET WEB_SERVER`, `ET SCAN`, `ET SQL` rule definitions.
  - Used for parity analysis and signature hardening in `PayloadRule` without creating new detection rules.
- **Sigma Detection Format**:
  - `https://github.com/SigmaHQ/sigma-specification`
  - Logsource specifications, condition syntax, modifier mappings (`contains`, `endswith`, `all of them`).
- **Splunk Search Processing Language (SPL)**:
  - `https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/`
  - `stats`, `bin/bucket`, `transaction`, `streamstats`, search optimization techniques for network flow analysis.

## 3. Threat Intelligence & Security Publications
- **MITRE ATT&CK Matrix for Enterprise**:
  - T1046: Network Service Discovery
  - T1110: Brute Force
  - T1498: Network Denial of Service
  - T1048: Exfiltration Over Alternative Protocol
  - T1071.004: Application Layer Protocol: DNS (DGA)
- **Stratosphere IPS Research (Czech Technical University)**:
  - CTU-13 Dataset analysis and botnet behavior characteristics (Neris, Donbot, Rbot).
