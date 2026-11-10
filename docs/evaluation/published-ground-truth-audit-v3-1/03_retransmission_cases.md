# 3. Dedicated Retransmission Case Analysis

## Individual Investigation of the 402 Windows
- Total Investigated Cases: **402**
- Fully Resolved via Connection Lifetime `[ts, ts + duration]`: **397 (98.76%)**
- Partially Resolved: **5**
- Unresolved: **0**

In all 402 cases, initial SYN packets arriving in the alert window matched active Zeek flows labeled `PartOfAHorizontalPortScan` whose multi-second lifetimes spanned across the window. All 402 cases qualify strictly for **Tier A**.
