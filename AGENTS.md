# NetGuard IDS — Engineering Invariants and Guardrails

## 1. Branch and Git Discipline
- **Authorized Branch**: `antigravity/overnight-work`
- **Strict Invariants**:
  - Never commit directly to `main` or push to `main`.
  - Never force-push (`git push -f`) or delete branches.
  - Never destructively reset (`git reset --hard`) without absolute safety verification.
  - Push only to `origin/antigravity/overnight-work`.

## 2. Core Detection Invariant: No New Detection Rules
- **Rule Count Restriction**: The system strictly maintains exactly **19 rule instances** registered in `RuleEngine.rules`.
- **Prohibited**:
  - Do NOT create new detection rules, dummy rules, or inflate rule counts.
  - Do NOT create new Sigma detections, Splunk detections, or Suricata signatures.
- **Permitted and Required**:
  - Correct field mappings, normalization, and bounds checks.
  - Harden existing detection conditions against evasion and protocol edge cases.
  - Fix memory leaks, stale state buildup, and unpruned caches.
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
