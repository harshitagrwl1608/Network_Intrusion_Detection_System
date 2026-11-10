---
name: regression-testing
description: Guidelines and execution patterns for running, extending, and maintaining the NetGuard IDS regression test suite.
---

# Regression Testing & Quality Assurance

This skill defines the testing protocols required before any commit is authored to `antigravity/overnight-work`.

## Core Directives
1. **Mandatory Execution Gates**:
   - `pytest ids_project/tests`: Full unit, integration, and rule test suite must achieve 100% pass rate.
   - `python3 ids_project/evaluation/run_eval.py`: All evaluation scenarios must complete with 100% scenario detection (or zero unintended regressions).
2. **Defensive Edge Case Testing**:
   - Unit tests must explicitly test boundary conditions:
     - Out-of-bounds ports (0, 65536, negative, non-integer).
     - Empty, malformed, or unicode IP addresses.
     - Out-of-order, clock-skewed, or future timestamps.
     - Connection resets (RST packets) terminating state immediately.
     - Memory bounding and pruning (`prune_stale`).
3. **Never Suppress Failures**:
   - Do NOT delete or weaken assertions in existing tests to mask regressions.
   - Fix the underlying engine implementation or harden rule logic to satisfy correct behavior.
