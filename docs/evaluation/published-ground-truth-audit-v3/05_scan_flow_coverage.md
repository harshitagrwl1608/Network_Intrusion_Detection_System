# 5. Scan Flow Coverage Analysis

## Denominators & Distinction

| Metric | Flow Count | Fraction of 3.39M Scan Flows | Interpretation |
| :--- | :--- | :--- | :--- |
| **Publisher Scan Flows** | **3,386,119** | **100.00%** | Total `PartOfAHorizontalPortScan` flows in Zeek log |
| **Trigger-Window Evidence Flows** | **111,817** | **3.30%** | Unique scan flows with packets inside alert trigger windows |
| **Campaign Cooldown Overlap** | **3,386,119** | **100.00%** | Flows occurring during active alert suppression intervals |
| **Unobserved / Outside Suppression** | **0** | **0.00%** | Flows outside all alert coverage |

---

## Measurability of Recall
Conventional flow-level recall is **NOT MEASURABLE** for NetGuard because NetGuard is an **incident-aggregating detector**. Once an alert fires, NetGuard intentionally suppresses further alerts for 10s or 120s to prevent alert flooding. Calling cooldown overlap "recall" is a category error.
