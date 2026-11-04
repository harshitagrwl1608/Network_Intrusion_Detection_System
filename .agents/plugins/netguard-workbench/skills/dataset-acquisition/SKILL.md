---
name: dataset-acquisition
description: "Discover, acquire, verify provenance, and catalog external network security and intrusion detection datasets for NetGuard IDS."
---

# External Network Dataset Discovery and Acquisition

This skill guides the identification, provenance validation, and acquisition of external network security captures.

## When to Use
- Expanding publisher diversity across independent research sources.
- Evaluating candidate datasets (CIC-IDS2017/2018, Malware-Traffic-Analysis.net, Wireshark Samples, Aposemat IoT-23).
- Registering a new external capture in `docs/autonomy/dataset-registry.md`.

## Core Procedures

### 1. Publisher Diversity Checklist
Ensure candidate datasets originate from distinct institutions:
- **Stratosphere Laboratory (CTU Prague)**: CTU-13, IoT-23
- **Canadian Institute for Cybersecurity (UNB)**: CIC-IDS2017, CSE-CIC-IDS2018
- **Unit 42 / SANS ISC (Brad Duncan)**: Malware-Traffic-Analysis.net
- **Wireshark Foundation**: Protocol edge-case sample captures
- **Collegiate Cyber Defense Competitions**: MACCDC, WRCCDC

### 2. Provenance & Metadata Verification
Before downloading or staging any dataset:
1. Identify authoritative source URL and original publication reference.
2. Confirm licensing terms (e.g., CC BY 4.0, Open Data Commons, MIT).
3. Compute and record the SHA-256 hash immediately upon download.
4. Record byte size and packet/record count.

### 3. Verification Script Example
Verify dataset integrity and compute checksum:

```bash
sha256sum <downloaded_pcap>
capinfos -c -d -u <downloaded_pcap>
```

### 4. Registry Update
Record entry in `docs/autonomy/dataset-registry.md` with:
- Identifier and Publisher
- Source URL and License
- SHA-256 Hash
- Total packet count and primary traffic type
- Mapped NetGuard detection rules exercised

## Guardrails
- Discard and reject any dataset lacking a verifiable license or clear source attribution.
- Avoid large bulk downloads that exceed available disk quotas.
