# 6. Scan Flow Coverage & Missed Flow Analysis

## Flow-Level Coverage vs. Campaign Coverage
The official publisher ground truth contains **3,386,119** flows labeled `PartOfAHorizontalPortScan`.

---

## Mathematical Coverage Calculations

| Coverage Metric | Scan Flow Count | Percentage | Formula / Methodology |
| :--- | :--- | :--- | :--- |
| **Strict Trigger-Window Coverage** | **65,243** | **1.93%** | Flows falling strictly inside `[window_start, window_end]` of the 3,765 alerts |
| **Campaign Cooldown Window Coverage** | **3,386,119** | **100.0%** | Flows falling inside `[window_start, window_end + cooldown]` |
| **Outside Trigger Windows** | **3,320,876** | **98.07%** | Flows occurring during ongoing alert suppression periods |

---

## Architectural Explanation
NetGuard is designed as an **incident-aggregating IDS**:
1. When a scan begins, NetGuard buffers distinct destination IPs until the threshold is crossed (15 hosts in 10s for `PORT_SCAN`, 30 hosts in 120s for `SLOW_PORT_SCAN`).
2. An alert is emitted covering the trigger interval.
3. NetGuard then enforces a re-fire cooldown (`_alert_cooldown = float(self.window)`) to prevent generating 3.39 million individual alerts.
4. During this cooldown, the scanner continues emitting hundreds of SYN probes per second. These probes belong to the active campaign but are intentionally suppressed by NetGuard.
5. **Audited Conclusion**: The headline claim of *"100% coverage"* was true at the **campaign level** (all 9.77 hours of scanning were covered by alert suppression intervals), but only **1.93%** of flows directly triggered alerts.

---

## Adversarial Finding: Flow Initiation vs. Packet Retransmission Timestamps
Independent cross-referencing by the Independent Security Auditor identified that 402 scan alerts had zero Zeek `PartOfAHorizontalPortScan` flow initiation timestamps strictly within their sub-second `[window_start, window_end]` trigger windows.

Deep packet inspection of the raw PCAP binary resolved this apparent discrepancy:
- Zeek's `ts` timestamp in `conn.log` records the exact instant a connection initiates (first SYN).
- Mirai's port-scanning engine repeatedly retransmits SYNs over multi-second connection durations (average duration: 3.14 seconds).
- NetGuard processes packets in real time. Sub-second alert trigger windows (median 0.08s) capture packets from already active scan flows whose initial SYN occurred 0.1 to 1.5 seconds earlier.
- PCAP tracing verified that in every one of these 402 windows, between 100 and 400 TCP SYN packets from `192.168.1.200` to port 23 on distinct external IPs were actively transmitted across the wire, confirming these alerts as genuine True Positives.
