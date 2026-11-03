---
name: detection-validation
description: Methodology for validating NetGuard IDS rules against synthetic scenarios and real-world network captures.
---

# Detection Validation & Benchmarking

This skill governs the systematic validation of NetGuard IDS rules without inflating rule counts or creating new detection rules.

## Core Directives
1. **Rule Set Invariance**:
   - Exactly 19 rule instances are registered in `RuleEngine.rules`.
   - Never add new rules to pass a validation test; optimize and harden existing rules.
2. **Dual-Evaluation Methodology**:
   - **Ground-Truth Benchmarking**: Use `ids_project/evaluation/run_eval.py` for labeled evaluation (calculating Precision, Recall, F1, Latency, Memory).
   - **Engine Comparison**: Use `ids_project/evaluation/compare.py` for comparative agreement analysis against reference engines (e.g. Suricata EVE JSON).
3. **Evidence-Based Reporting**:
   - Document any false positives or false negatives discovered during validation.
   - Trace any discrepancies down to packet-level characteristics (e.g., TCP flag combinations, payload chunking, malformed headers, DNS query structures).
