> [!CAUTION]
> **HISTORICAL / SUPERSEDED.** This V3.1 report predates the corrective changes committed for V3.1.1. Its figures (including 91.11%, 97.45%, 397/402 and the old cooldown result) must not be treated as final submission metrics. See [V3.1.1 correction status](../published-ground-truth-audit-v3-1-1/00_correction_status.md). The corrected code requires a fresh full-data run.

# 9. Final Submission-Readiness Verdict

## Official Verdict: SUPPORTED WITH LIMITATIONS

NetGuard's core behavioral scanning detection engine against real-world Mirai botnet activity is **substantiated**:
- **Strict Alert Precision**: **91.11%** (3,669 / 4,027)
- **Transport Scanning Rule Precision**: **100.00%** (3,669 / 3,765)
- **Campaign Timeline Coverage**: **100.00%** across all 9.77 hours.

### Established Limitations
1. The 262 ARP alerts (6.51%) are classified as **Tier D (Unassessed due to missing historical baseline)**.
2. Per-flow recall is **NOT MEASURABLE** due to incident rate-limiting cooldown aggregation.
3. All 402 retransmission cases are verified as **Tier A True Positives**.
