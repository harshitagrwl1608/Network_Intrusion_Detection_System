# 10. Methodology & Reproducibility Guide

## Audit Reproduction Commands
To independently reproduce the entire forensic audit:

```bash
# 1. Verify PCAP and Zeek Hashes
sha256sum /run/media/harshitgarg/Data1/NetGuard-datasets/published_ground_truth_ctu48_1/2019-02-28-19-15-13-192.168.1.200.pcap
sha256sum /run/media/harshitgarg/Data1/NetGuard-datasets/published_ground_truth_ctu48_1/2019-02-28-19-15-13-192.168.1.200-zeek-conn-log.labeled

# 2. Run Standalone Forensic Audit Script
python3 scripts/audits/ctu48_1_ground_truth_audit.py
```

## Forensic Exports Location
- `per_alert_attribution.csv`: `/run/media/harshitgarg/Data1/NetGuard-datasets/published_ground_truth_ctu48_1/audit_v2_exports/per_alert_attribution.csv`
  - SHA-256: `0ee5cdc730c9195d29bad42b22f0ad93723db81b9b64f34c8a18877c4ac32223`
- `per_flow_scan_coverage.csv`: `/run/media/harshitgarg/Data1/NetGuard-datasets/published_ground_truth_ctu48_1/audit_v2_exports/per_flow_scan_coverage.csv`
  - SHA-256: `6918d12ded2364c6e30cc14bb7715001abd505ada3ffe3a14358610e34c3c294`
- `arp_packet_audit.csv`: `/run/media/harshitgarg/Data1/NetGuard-datasets/published_ground_truth_ctu48_1/audit_v2_exports/arp_packet_audit.csv`
  - SHA-256: `459318476b8fba3f6564d5bf6cab19bb486edd39f92549b91e5bfa116654db52`
