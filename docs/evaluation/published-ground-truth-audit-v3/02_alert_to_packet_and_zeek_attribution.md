# 2. Alert to Packet & Zeek Flow Attribution

## Independent Packet Reconstruction
Audit V3 eliminates all shortcuts of reading alert JSON fields as ground truth. Every one of the 3,765 scan alerts was independently reconstructed from raw PCAP packets:
- Streamed all 13,565,553 packets through sliding alert trigger windows `[window_start, window_end]`.
- Mapped 222,927 TCP SYN scan packets strictly from `192.168.1.200` to port 23 across external IPv4 addresses.
- **100.00% of the 3,765 scan alerts** independently reconstructed distinct destination host counts satisfying the rule threshold (>= 15 for `PORT_SCAN`, >= 30 for `SLOW_PORT_SCAN`).

---

## Five-Tier Classification Breakdown

| Classification Tier | Alert Count | Percentage | Definition & Rule Criteria |
| :--- | :--- | :--- | :--- |
| **Tier A (Confirmed Rule-Specific TP)** | **3,765** | **93.49%** | Reconstructed packets satisfy threshold, direction, port 23, and match Zeek `PartOfAHorizontalPortScan` |
| **Tier B (Malicious Associated)** | **0** | **0.00%** | Malicious traffic association without full rule evidence |
| **Tier C (Confirmed False Positive)** | **262** | **6.51%** | 262 ARP alerts (gateway MAC was stable at 78:8a:20:43:93:d5) |
| **Tier D (Unassessed / Unmatched)** | **0** | **0.00%** | Unmapped alerts |
| **Total Emitted Alerts** | **4,027** | **100.00%** | Complete evaluation inventory |
