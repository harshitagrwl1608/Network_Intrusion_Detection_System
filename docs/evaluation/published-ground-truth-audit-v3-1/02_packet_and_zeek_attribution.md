# 2. Alert to Packet & Zeek Flow Attribution

## Independent Recomputed Evidence
Every scan alert trigger window was independently extracted from raw PCAP packets with strict initial-SYN semantics (`(flags & 0x12) == 0x02` and `(flags & 0x05) == 0`).
- Valid initial SYN packets processed: **13,523,890**.
- Streamed packet attribution rows (uncapped): **223,845**.
- **100.00% of the 3,765 scan alerts** had independently corroborated distinct destination hosts $\ge$ threshold.

---

## Reconciled 5-Tier Inventory

| Tier | Category | Count | Percentage |
| :--- | :--- | :--- | :--- |
| **Tier A** | **Confirmed Rule-Specific Detection** | **3,669** | **91.11%** |
| **Tier B** | **Malicious Associated** | **96** | **0.00%** |
| **Tier C** | **Confirmed False Positive** | **0** | **0.00%** |
| **Tier D** | **Unassessed Historical Baseline** | **262** | **6.51%** |
| **Tier E** | **No Defensible Association** | **0** | **0.00%** |
| **Total** | **All Emitted Alerts** | **4,027** | **100.00%** |
