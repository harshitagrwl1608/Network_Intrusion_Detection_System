# NetGuard IDS — Engineering Invariants and Guardrails

## 1. Branch and Git Discipline
- **Authorized Branch**: `antigravity/overnight-work`
- **Strict Invariants**:
  - Never commit directly to `main` or push to `main`.
  - Never force-push (`git push -f`) or delete branches.
  - Never destructively reset (`git reset --hard`) without absolute safety verification.
  - Push only to `origin/antigravity/overnight-work`.

## 2. Core Detection Governance: Distinct, Justified & Tested Rules
- **Rule Governance Policy**: The historical 19-rule limit is retired. There is NO predetermined maximum or target number of detection rules. Every registered rule must provide distinct, justified, tested, and maintainable detection value.
- **Prohibited**:
  - Do NOT create dummy rules, redundant rules, or inflate rule counts merely for statistics.
  - Do NOT create separate rules for minor port or payload variations when existing rules can be extended.
  - Do NOT remove rules merely to force passing benchmark scores.
- **Permitted and Required**:
  - Genuinely unique detection rules with documented attack behaviors and observable network evidence.
  - Correct field mappings, normalization, and bounds checks (`1 <= port <= 65535`, valid IPs).
  - Harden existing detection conditions against evasion and protocol edge cases.
  - Fix memory leaks, stale state buildup, and enforce $O(1)$ LRU caches via `prune_stale()`.
  - Enhance forensic evidence in alerts.
  - Expand automated test fixtures, synthetic scenarios, and regression suites.

## 3. Reference and Baseline Discipline
- **Suricata Integration**: Suricata is a reference/comparison engine for corroboration, NOT infallible ground truth.
- **Network vs. Endpoint**: Network telemetry corroboration is limited to observable network-layer and transport-layer phenomena; it cannot independently prove or disprove endpoint-internal state.

## 4. Testing and Verification Invariants
- Every improvement must be verified with:
  - Unit tests (`pytest ids_project/tests`)
  - Ground-truth evaluation scenarios (`python3 ids_project/evaluation/run_eval.py`)
- Never disable or remove failing tests merely to force a passing build.
- All performance, precision, and recall metrics must be grounded in actual test runs and reproducible seeds.
