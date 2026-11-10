# 4. Event-Level Ground-Truth Corroboration

## Five-Tier Semantic Evaluation
Every NetGuard alert is corroborated against the official publisher-provided expert labels:

| Tier | Classification | Alert Count | Percentage |
| :--- | :--- | :--- | :--- |
| **Tier A** | `CONFIRMED_TRUE_POSITIVE` | `3,765` | `93.49%` |
| **Tier B** | `MALICIOUS_TRAFFIC_ASSOCIATED` | `257` | `6.38%` |
| **Tier C** | `FALSE_POSITIVE` | `5` | `0.12%` |
| **Tier D** | `UNASSESSED` | `0` | `0.00%` |
| **Tier E** | `UNMATCHED` | `0` | `0.00%` |

## Precision Metrics
- **Strict True Positive Precision (Tier A only)**: `93.49%`
- **Total Malicious Traffic Precision (Tier A + B)**: `99.88%`
- **Empirical False Positive Rate**: `0.12%`
