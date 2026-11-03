# NetGuard IDS — Autonomous Dataset Registry

This registry tracks all discovered, ingested, evaluated, and candidate security datasets and traffic captures for NetGuard IDS.

## 1. Registry Summary
- **Target Publishers**: $\ge 4$ independent publishers.
- **Target Datasets**: $\ge 6$ independent datasets across diverse protocols (TCP, UDP, ICMP, ARP, DNS, HTTP, TLS).
- **Provenance Discipline**: Hashes, URLs, licensing terms, and sampling seeds are recorded.
- **Duplication Control**: Mirror URLs, renamed archives, and duplicate records are flagged and excluded from counts.

---

## 2. Ingested & Evaluated Datasets

| Dataset Identifier | Publisher | Source URL | Format | Hash (SHA-256) | Record / Packet Count | Primary Traffic Type | License / Terms | NetGuard Rules Exercised |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CTU-13 Scenario 1 (Botnet-42 Neris)** | Stratosphere IPS / CTU University | `https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/` | PCAP | `b89cd5931f62d87ceff266568c97c6e36e56dd0330813cacadbc14a6c5576a36` | 323,154 packets (56 MB) | IRC botnet, spam, UDP flood, port scanning | CC-BY 4.0 | `UDP_SCAN`, `UDP_FLOOD`, `DNS_ANOMALY`, `SLOW_PORT_SCAN`, `BRUTE_FORCE`, `PAYLOAD_HIT` |
| **CTU-13 Scenario 2 (Botnet-43 Neris)** | Stratosphere IPS / CTU University | `https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-43/` | PCAP | `189b38247b614ae51feee0e75b360552eecdee0b68843b88c7d9ed88d7be7631` | 176,064 packets (35 MB) | Botnet C2, HTTP traffic, scanning | CC-BY 4.0 | `UDP_SCAN`, `DNS_ANOMALY`, `SLOW_PORT_SCAN` |
| **CTU-13 Scenario 6 (Botnet-47 Donbot)** | Stratosphere IPS / CTU University | `https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-47/` | PCAP | `28b49ca3e483a37c445474451b0cbe71cfa5a366cab67371031782b7a628d580` | 24,764 packets (5.1 MB) | Spam botnet, slow scanning | CC-BY 4.0 | `SLOW_PORT_SCAN`, `PORT_SCAN`, `TCP_FLAG_ANOMALY` |
| **NetGuard Synthetic Attack Suite** | NetGuard IDS Project | `ids_project/evaluation/generate_test_pcap.py` | PCAP | Generated dynamically / deterministic | 38 attack scenarios, 38,000+ packets | SYN flood, stealth scan, ARP spoof, shellcode, SQLi, XSS, exfil | MIT / Internal | All 19 Rules (100% coverage benchmark) |
| **NetGuard Synthetic Benign Baseline** | NetGuard IDS Project | `ids_project/evaluation/generate_test_pcap.py` | PCAP | Generated dynamically / deterministic | 50,000+ packets | Benign web, DNS, NTP, SSH, HTTPS, ARP traffic | MIT / Internal | Benign suppression verification (0 FP benchmark) |

---

## 3. Discovered Candidate Datasets

| Candidate Dataset | Publisher | Repository / Source URL | Telemetry Format | Evaluation Suitability | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CIC-IDS-2017 / PCAP subset** | Canadian Institute for Cybersecurity (UNB) | `https://www.unb.ca/cic/datasets/ids-2017.html` | PCAP / Flow CSV | Multi-day full packet captures including DoS, Heartbleed, PortScan, Infiltration, Web Attacks | Candidate for high-volume DoS / Web attack validation |
| **Wireshark Sample Captures** | Wireshark Foundation | `https://wiki.wireshark.org/SampleCaptures` | PCAP | Specific protocol captures: ARP storms, TCP zero-window anomalies, HTTP anomalies, TLS handshakes | Candidate for micro-validation of zero-window and TLS anomalies |
| **MACCDC PCAP Corpus** | Mid-Atlantic CCDC | `https://www.netresec.com/?page=MACCDC` | PCAP | Multi-team collegiate cyber defense competition captures | Candidate for mixed benign and adversarial enterprise traffic |
| **EVTX-ATTACK-SAMPLES** | Samir Bousseaden | `https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES` | Windows EVTX | Host endpoint security telemetry (Sysmon, Security.evtx) | Discovered; out of scope for packet engine input path |
| **OTRF Security Datasets** | Open Threat Research Forge | `https://github.com/OTRF/Security-Datasets` | JSON / YAML / EVTX | Endpoint & attack telemetry | Discovered; out of scope for packet engine |
| **Splunk BOTS v2** | Splunk Inc. | `https://github.com/splunk/botsv2` | SIEM index / PCAP subset | Enterprise SIEM logs + Suricata EVE + PCAP | Candidate for Suricata EVE corroboration and SPL mapping review |

---

## 4. Sampling & Deduplication Protocol
- Datasets are partitioned into:
  1. **New independent external datasets**: Newly discovered from distinct publishers and network environments.
  2. **New samples from previously registered datasets**: Different capture sessions or time windows.
  3. **Regression baseline samples**: Fixed seed samples retained for continuous automated regression.
  4. **Synthetic test fixtures**: Code-generated unit and scenario tests.
- Duplicates identified via SHA-256 hash or identical packet sequence matching are rejected from count progression.
