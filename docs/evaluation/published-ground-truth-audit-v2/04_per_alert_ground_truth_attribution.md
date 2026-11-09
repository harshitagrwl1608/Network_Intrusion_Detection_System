# 4. Per-Alert Ground-Truth Attribution Audit

## The Flawed Previous Matching Condition
The previous runner utilized the condition:
`f.get('src_ip') == sip or f.get('dst_ip') == sip`
Because `192.168.1.200` generated 99.89% of all traffic, this condition erroneously claimed that almost any alert in any window was "malicious associated".

---

## Independent Audit Attribution Criteria
The new audit enforced direction-aware, protocol-specific, port-validated matching:
1. **Source Host**: Strictly `192.168.1.200`.
2. **Transport Protocol**: Strictly `TCP`.
3. **Scanned Port**: Strictly `23` (Telnet).
4. **Time Window**: Evaluated strictly over `[window_start, window_end]`.
5. **Target Count**: Re-verified that distinct destination IPs meet the rule threshold.

---

## Audited Classification Results

| Audit Tier | Category | Alert Count | Percentage | Audited Semantic Interpretation |
| :--- | :--- | :--- | :--- | :--- |
| **Tier A** | `CONFIRMED_TRUE_POSITIVE` | **3,765** | **93.49%** | 3,473 `PORT_SCAN` + 292 `SLOW_PORT_SCAN` alerts confirmed by exact `PartOfAHorizontalPortScan` flows |
| **Tier B** | `MALICIOUS_ASSOCIATED` | **0** | **0.00%** | Reclassified: No scan alerts were ambiguous; ARP alerts were not malicious |
| **Tier C** | `FALSE_POSITIVE` | **262** | **6.51%** | All 262 `ARP_SPOOF` alerts (caused by synthetic `data/arp_table.json` contamination) |
| **Tier D** | `UNASSESSED` | **0** | **0.00%** | None |
| **Tier E** | `UNMATCHED` | **0** | **0.00%** | None |

### Discrepancy Reconciliation
- **Previous Claim**: 3,765 Tier A, 257 Tier B, 5 False Positives.
- **Audited Truth**: **3,765 Tier A, 0 Tier B, 262 False Positives**.
- **Explanation**: The previous runner misclassified 257 `ARP_SPOOF` alerts as Tier B because `192.168.1.200` was active in the window. Examining the actual Layer-2 packet data proves all 262 ARP alerts were false discoveries caused by a pre-loaded test file.
