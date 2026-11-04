---
name: external-dataset-research
description: Guides discovery, acquisition, verification, and registration of external network security and intrusion detection datasets for NetGuard IDS.
---

# External Dataset Research & Provenance

This skill governs the systematic discovery, cataloging, and ingestion of real-world intrusion and benign traffic datasets.

## Core Directives
1. **Diverse Sourcing**: Discover datasets across multiple distinct providers (e.g., Stratosphere IPS / CTU, Canadian Institute for Cybersecurity / CIC-IDS, Wireshark sample captures, Malware-Traffic-Analysis.net).
2. **Provenance Tracking**:
   - Every candidate dataset must be logged in `docs/autonomy/dataset-registry.md`.
   - Record: Name, Publisher, URL, SHA-256 hash, Capture context, Total records/flows, Attack categories present, and Licensing terms.
3. **Safe Acquisition**:
   - Do NOT execute malicious binaries or scripts.
   - Extract PCAPs or flow logs safely using Python standard libraries or Scapy.
   - Never commit multi-megabyte raw PCAPs to Git. Downsample or slice reproducible micro-fixtures for automated regression suites.
4. **Validation Mapping**:
   - Map captured traffic scenarios directly against NetGuard detection rules.
   - Evaluate true positive detection rates and false positive baseline counts.
