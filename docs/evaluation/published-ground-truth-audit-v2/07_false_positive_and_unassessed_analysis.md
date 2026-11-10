# 7. False Positive & Unassessed Alert Analysis

## Recalculated False Discovery Metrics

| Metric | Previous Report | Audited Ground Truth | Audit Verdict |
| :--- | :--- | :--- | :--- |
| **Confirmed False Positives** | 5 (0.12%) | **262 (6.50%)** | Corrected: All 262 ARP alerts were false discoveries |
| **Unassessed Alerts** | 0 (0.00%) | **0 (0.00%)** | Verified |
| **Unmatched Alerts** | 0 (0.00%) | **0 (0.00%)** | Verified |
| **Transport Scan Rule FP Rate** | 0.00% | **0.00%** | Zero false positives on port scanning |

---

## Metric Clarification: False Positive Rate vs. False Discovery Rate
- The ratio `FP / Total_Alerts` is an **Alert False Discovery Fraction** (`6.50%`).
- In conventional statistics, `FPR = FP / (FP + TN)`. Because there are 3,734 benign connection records in Zeek and zero benign connections triggered a port scan, the flow-level FPR is **0.00%**.
- However, at the alert level, 262 out of 4,027 alerts were spurious due to the pre-seeded ARP table.
