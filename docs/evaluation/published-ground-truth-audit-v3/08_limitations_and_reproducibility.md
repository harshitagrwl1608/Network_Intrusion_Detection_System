# 8. Limitations & Reproducibility Guide

## Independent Reproduction Command
```bash
python3 scripts/audits/ctu48_1_ground_truth_audit_v3.py \
  --pcap /run/media/harshitgarg/Data1/NetGuard-datasets/published_ground_truth_ctu48_1/2019-02-28-19-15-13-192.168.1.200.pcap \
  --zeek /run/media/harshitgarg/Data1/NetGuard-datasets/published_ground_truth_ctu48_1/2019-02-28-19-15-13-192.168.1.200-zeek-conn-log.labeled \
  --db /run/media/harshitgarg/Data1/NetGuard-datasets/published_ground_truth_ctu48_1/netguard_eval_48_1.db \
  --suricata-dir /run/media/harshitgarg/Data1/NetGuard-datasets/published_ground_truth_ctu48_1/suricata_output \
  --exports-dir /run/media/harshitgarg/Data1/NetGuard-datasets/published_ground_truth_ctu48_1/audit_v3_exports \
  --docs-dir docs/evaluation/published-ground-truth-audit-v3
```

---

## Forensic Exports Ledger
| File | SHA-256 Digest |
| :--- | :--- |
| `per_alert_attribution.csv` | `649820dff6232a942a9168eca70a2c6e321806fede89085ab43088ae2f1a64f4` |
| `alert_to_zeek_uid.csv` | `631a9620227abc30c7847c31e3713b63ca923682944939d80409fcc690468ac3` |
| `alert_packet_evidence.csv` | `a2f86abf8617f05bf06f9b41071820ed540e2e72204e49651e767677e1c103ef` |
| `per_flow_scan_attribution.csv` | `551d48e24321e60fc00ca2dcd71b085e3eab1afc7c72af98d29812820444cd84` |
| `402_retransmission_case_audit.csv` | `7bd10cd87f88a063c4450c490d513c409615eb4db96ef673a174c06197f64e07` |
| `arp_alert_packet_attribution.csv` | `2e588530ed4ca50960c4d64b25fcd15d41d401cfd20af609bea3610932af8bf0` |
