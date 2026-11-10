# NetGuard IDS — Evaluation & Reporting Standard

**Document ID:** `NETGUARD-STD-EVAL-2026`  
**Status:** Permanent Standard  
**Applies to:** All future evaluations, holdout audits, and benchmark reports across NetGuard IDS.

---

## 1. Purpose & Motivation

During the forensic audit of CTU-IoT-Malware-Capture-48-1 (Mirai), multiple structural and evidentiary flaws were identified in historical evaluation runs:
1. **Conflation of Metric Units:** Alert-level confirmation fractions were described as conventional precision ($TP / (TP + FP)$), obscuring the fact that uncorroborated alerts were not confirmed false alarms.
2. **Ungrounded Flow Recall:** Temporal overlap between alert cooldown intervals and Zeek connection records was presented as proof of detection or suppression, creating ungrounded recall claims across 3.39M flows.
3. **Loose Attribute Association:** Retransmission cases were classified using global capture timestamps rather than per-alert 5-tuple and packet evidence.
4. **Hardcoded Fallbacks & Fabricated Defaults:** Parser components defaulted to hardcoded IP/port pairs (e.g. `192.168.1.200:23`) instead of failing closed when alert metadata was absent.
5. **Schema Drift in Telemetry Exports:** CSV telemetry rows had column counts mismatched with headers, resulting in shifted columns and lost fields.
6. **Superficial Reconciliation Gates:** Verdicts were certified solely because high-level counts reconciled, ignoring parser truncations, malformed records, or unassessed baselines.

This standard establishes mandatory contracts, single-source-of-truth architectures, and automated programmatic gates to prevent these errors from recurring.

---

## 2. Mandatory Evidence & Metric Contract

Every quantitative metric reported by NetGuard must carry an explicit evidence specification:

### 2.1 Units of Analysis
Every measurement must explicitly declare its unit of analysis:
- **`packet`**: Individual Layer-2/3/4 packet frame in PCAP.
- **`flow`**: Bidirectional or unidirectional transport connection identified by directional 5-tuple and connection lifetime $[ts, ts + duration]$.
- **`event`**: Ground-truth intrusion event or simulated attack instance documented in a publisher log.
- **`alert`**: Detection event emitted by a NetGuard rule engine instance.
- **`campaign`**: Aggregate macroscopic activity span across multiple flows or hosts.

Cross-unit ratios (e.g. dividing alert count by total network flows) are mathematically invalid and strictly prohibited from being labeled as "Precision" or "Recall".

### 2.2 Evidence Status Taxonomy
Every reported figure must be assigned one of five evidentiary statuses:
- **`MEASURED`**: Directly observed and counted from raw packet frames or database records without inference.
- **`DERIVED`**: Mathematically computed from strictly measured components where numerator and denominator are proven in the same unit.
- **`INFERRED`**: Modeled via analytical boundaries (e.g. post-alert cooldown overlap); must be explicitly marked as analytical.
- **`NOT_MEASURED`**: Metric cannot be established from available telemetry (e.g. per-flow recall on windowed aggregation rules).
- **`UNVERIFIED`**: Third-party reference data whose runtime environment receipt is missing (e.g. Suricata input PCAP byte identity).

### 2.3 Strict Prohibitions
1. **No Conflation of Confirmation Fraction with Precision**: The Tier-A fraction of alerts ($\text{Tier A} / \text{Total Alerts}$) must be called **Tier-A Confirmation Share**, never "Precision". Precision requires establishing that non-Tier-A alerts are confirmed false positives.
2. **No Fabricated Recall**: Recall ($TP / (TP + FN)$) requires an independent, complete ground-truth denominator in the same unit. If NetGuard aggregates 1,000 packets into 1 alert, dividing 1 alert by 1,000 flows is mathematically barred. Recall must be marked `NOT_MEASURABLE`.
3. **No Temporal Cooldown Suppression Claims**: Demonstrating that a flow start time falls into $[window\_end, window\_end + cooldown]$ is temporal interval overlap only. It does not prove that the detector observed or suppressed that packet.
4. **No Timestamp-Only Attribution**: Attribution requires matching full directional 5-tuple `(src_ip, src_port, dst_ip, dst_port, protocol)` within exact flow lifetime $[start, end]$. Timestamp proximity alone is invalid.
5. **No Missing-as-Benign Assumption**: Unmatched flows or missing labels must be classified as `UNMATCHED` or `UNASSESSED`, never assumed to be benign.
6. **No Fallback Fabrication**: If alert metadata is missing (e.g. invalid threshold, missing port), the parser must fail closed and report an error, never substitute a convenient default.

---

## 3. Single Source of Truth Architecture

To prevent discrepancies between Markdown reports, JSON summaries, and CSV exports:
1. **Canonical In-Memory Evaluation Result**: All figures, tier distributions, packet counts, and validation checks must be calculated once and stored in an immutable canonical result structure (`EvaluationResult`).
2. **Derivative Artifacts**:
   - `summary.json`: Direct JSON serialization of the canonical result.
   - `report.md`: Rendered strictly from the canonical result fields; no template may compute or hardcode independent statistics.
   - `*.csv`: Emitted row-by-row with strict schema enforcement; row counts must match canonical result tallies.
3. **Export Hash Gating**: SHA-256 hashes of generated CSV exports and reports are calculated **only after** files are completely flushed, closed, and verified on disk.

---

## 4. Automatic Consistency and Quality Validation Gates

Before any evaluation report is declared valid, the automated `EvaluationValidator` must execute 11 mandatory checks:

1. **Tier Count Reconciliation**: $\sum \text{Tiers} == \text{Total Emitted Alerts}$.
2. **Confusion Matrix Reconciliation**: $TP + FP + FN + TN == \text{Total Evaluated Units}$.
3. **Mathematical Reproducibility**: Derived metrics (e.g. Confirmation Share, F1) recalculate exactly from stored numerators and denominators.
4. **Export Schema Parity**: Every row in every exported CSV has the exact number and order of columns specified by its header.
5. **Export Row Count Integrity**: Number of rows in each CSV matches the canonical record counter.
6. **Cross-Format Agreement**: Values displayed in Markdown tables agree exactly with values in `summary.json`.
7. **No Hardcoded Historical Figures**: Generated outputs contain no static historical constants (e.g. hardcoded sizes or historical 397/5 ratios).
8. **Evidence Completeness**: Ambiguous, unmatched, and malformed records are explicitly tallied and accounted for.
9. **Provenance & Configuration Fingerprints**: Input file SHA-256 digests, Git commit hash, working-tree status, and engine rule fingerprints are populated.
10. **Evidence Source Mapping**: Every headline claim links directly to a measurable evidence collection in the result object.
11. **Fail-Closed Execution**: If any required validation check fails, report generation aborts or emits an `INCONCLUSIVE` verdict; it cannot claim success.

---

## 5. Evidence-Based Verdict System

Evaluations must separate technical execution integrity from academic submission claims:

| Verdict | Definition | Criteria |
| :--- | :--- | :--- |
| **`SUPPORTED (FULL)`** | All claims academically substantiated | Technical validation passes, ground truth is complete, units align, all baselines authenticated. |
| **`SUPPORTED WITH LIMITATIONS`** | Substantiated within explicit, documented bounds | Technical validation passes, but ground truth has scope limits (e.g. unpreserved ARP baseline, temporal-only cooldowns). |
| **`INCONCLUSIVE`** | Evaluation cannot establish conclusion | A required reconciliation gate failed, inputs truncated, or reference data missing. |
| **`REJECTED`** | Evidence contradicts claims | Significant false-positive rate observed, or detection rules failed to corroborate ground truth. |

---

## 6. Implementation Reference

The Python implementation of this standard is located under:
- [`ids_project/evaluation/reporting/contract.py`](file:///home/harshitgarg/Downloads/Networking_Project/ids_project/evaluation/reporting/contract.py) — Core data structures, taxonomy, and metric contracts.
- [`ids_project/evaluation/reporting/validator.py`](file:///home/harshitgarg/Downloads/Networking_Project/ids_project/evaluation/reporting/validator.py) — Automated 11-gate validation engine.
- [`ids_project/evaluation/reporting/builder.py`](file:///home/harshitgarg/Downloads/Networking_Project/ids_project/evaluation/reporting/builder.py) — Canonical report, JSON, and CSV generator.

