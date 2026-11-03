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

## 4. Empirical Datasets & Packet Telemetry Repositories
- **Canadian Institute for Cybersecurity (CIC)**:
  - *CIC-IDS2017 & CSE-CIC-IDS2018*: Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP 2018.
  - Source: `https://www.unb.ca/cic/datasets/ids-2017.html` and AWS Open Data `s3://cse-cic-ids2018/`.
- **Malware-Traffic-Analysis.net**:
  - Duncan, B. Malware Traffic Analysis exercises, PCAPs, and Suricata EVE threat intelligence feeds (2013–2024).
  - Source: `https://www.malware-traffic-analysis.net/`.
- **Stratosphere Laboratory (Czech Technical University in Prague)**:
  - *Aposemat IoT-23*: Garcia, S., Parmisano, A., & Erquiaga, M. J. "IoT-23: A labeled dataset with malicious and benign IoT network traffic", Zenodo DOI: 10.5281/zenodo.4743746, CC BY 4.0.
  - Source: `https://www.stratosphereips.org/datasets-iot23`.
- **Collegiate Cyber Defense Competition (CCDC) Repositories**:
  - Netresec AB MACCDC PCAP Repository (`https://www.netresec.com/?page=MACCDC`).
  - WRCCDC Multi-Year Traffic Archive (`https://archive.wrccdc.org/pcaps/`).
- **Wireshark Foundation Protocol Sample Captures**:
  - Wireshark GitLab Wiki SampleCaptures (`https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures`) and developer test suite (`test/captures`).
