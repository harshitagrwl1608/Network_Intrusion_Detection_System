---
name: reproducible-evaluation
description: "Run ground-truth evaluation, verify deterministic seeds, calculate precision/recall metrics, and inspect test scenarios."
---

# Reproducible Regression and Ground-Truth Evaluation

This skill provides procedures for running and verifying reproducible ground-truth evaluation scenarios and regression test suites.

## When to Use
- Running full ground-truth evaluation across all 38 attack scenarios.
- Verifying benign traffic suppression (0 false positives).
- Validating automated test execution across diverse seeds.

## Evaluation Execution

### 1. Ground-Truth Attack & Benign Benchmark
Run the automated evaluation runner:

```bash
python3 ids_project/evaluation/run_eval.py
```

Expected benchmarks:
- **Scenarios Evaluated**: 38/38 detected
- **Detection Rate (Recall)**: 100%
- **Precision**: 100%
- **False Positives**: 0

### 2. Comprehensive Test Suite
Execute the complete pytest suite:

```bash
pytest ids_project/tests
```

All 482+ tests across unit, integration, memory, and performance suites must pass cleanly.

### 3. Verification Invariants
- Tests must use deterministic seeds for PRNG fixtures.
- Temporary SQLite databases must be unlinked/cleaned after execution.
- System time mocking must be used where timing intervals are validated.

## Guardrails
- Never disable or comment out failing tests.
- Every metric reported must be grounded in an actual script execution output.

