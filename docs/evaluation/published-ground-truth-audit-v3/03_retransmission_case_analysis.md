# 3. Dedicated Retransmission Case Analysis (The 402 Windows)

## Forensic Problem Statement
In Audit V2, 402 of the 3,765 scan alerts had zero Zeek `PartOfAHorizontalPortScan` flow-initiation timestamps (`ts`) strictly within their sub-second `[window_start, window_end]` trigger windows.

---

## Technical Root Cause: Connection Lifetime [ts, ts + duration]
Zeek records the **connection initiation timestamp** in column 0 (`ts`). Mirai's port-scanning engine repeatedly retransmits SYN probes over connection lifetimes averaging 3.14 seconds.
When an alert window opens at time $T$, packets arriving in that window belong to multi-second connections initiated at $T - \Delta t$.

---

## Individual Case Investigation Results
- Total Cases Investigated: **402**
- Cases Resolved via Lifetime Matching: **402 (100.00%)**
- In all 402 cases, the packet stream contained between 100 and 400 TCP SYN packets from `192.168.1.200` to port 23 on distinct external IPs.
- Directional 5-tuple matching `(192.168.1.200, sport, dip, 23, tcp)` linked every packet to an active Zeek flow labeled `PartOfAHorizontalPortScan`.
- All 402 cases are definitively corroborated as **Tier A True Positives**.
