# 9. Metrics & Complexity Reassessment Audit

## Headline Discrepancy Table

| Metric | Original Headline Claim | Audited Result | Evidence & Analysis | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **Strict True Positive Precision** | 93.49% | **93.49%** (93.4939%) | 3,765 Confirmed Scan Alerts / 4,027 Total Alerts | **SUPPORTED** |
| **Malicious-Associated Alerts** | 257 (6.38%) | **0 (0.00%)** | Reclassified: ARP alerts were false discoveries, not malicious traffic | **CORRECTED** |
| **Alert False Discovery Rate** | 0.12% (5 alerts) | **6.51%** (6.5061%) | All 262 ARP alerts were caused by synthetic `data/arp_table.json` | **CORRECTED** |
| **Transport Scan Precision** | Unstated | **100.00%** | Zero false scan alerts on benign traffic | **SUPPORTED** |
| **Scan Flow Trigger Coverage** | "100% Coverage" | **1.93% (65,243 flows)** | Exact trigger window interval overlap | **CORRECTED** |
| **Scan Campaign Coverage** | "100% Coverage" | **100.00% (3.39M flows)** | Alert cooldown suppression interval overlap | **SUPPORTED** |
| **Suricata Alert Count** | 85 alerts | **85 alerts** | Re-verified from raw `eve.json` | **SUPPORTED** |
| **NetGuard Peak RSS Memory** | 116.44 MB | **116.44 MB** | Measured during initial 13.56M packet replay | **SUPPORTED** |
| **Single-Pass Throughput** | 5,003.7 pps | **5,003.7 pps** | Pure Python struct parser replay (2,711.11s) | **SUPPORTED** |

---

## Complexity & Memory Audit
- `PortScanRule` and `SlowPortScanRule` enforce state bounds via `OrderedDict` with `max_states = 10,000`.
- Per-packet insertion into `OrderedDict` is average $O(1)$.
- Stale eviction (`prune_stale()`) pops oldest entries from the front in $O(K)$ where $K$ is expired entries.
- Peak RSS remained bounded at 116.44 MB over 13.56M packets.
