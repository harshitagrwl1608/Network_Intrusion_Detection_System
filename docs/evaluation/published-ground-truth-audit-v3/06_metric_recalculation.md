# 6. Metric Recalculation & Discrepancy Reconciliation

## Final Audited Metrics Summary

$$\text{Strict Alert Precision} = \frac37654027 = \mathbf{93.49\%}$$

$$\text{Alert False Discovery Rate} = \frac2624027 = \mathbf{6.51\%}$$

$$\text{Transport Scanning Rule Precision} = \frac37653765 = \mathbf{100.00\%}$$

---

## Discrepancy Matrix

| Metric | Original Claim | Audit V2 Result | Audit V3 Final Result | Final Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **Confirmed Precision** | 93.49% | 93.50% | **93.49%** | **SUPPORTED** |
| **Malicious Associated** | 257 (6.38%) | 0 (0.00%) | **0 (0.00%)** | **CORRECTED** |
| **False Discovery Rate** | 0.12% | 6.50% | **6.51%** | **CORRECTED** |
| **Scan Rule Precision** | Unstated | 100.00% | **100.00%** | **SUPPORTED** |
| **Scan Flow Coverage** | "100% Recall" | 1.93% / 100% | **3.29% Trigger / 100% Campaign** | **CORRECTED** |
