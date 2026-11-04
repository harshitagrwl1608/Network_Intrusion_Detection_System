# NetGuard Engineering Rules & Guardrails

## 1. Rule Governance Invariant (Evidence-Driven Admission & Distinct Value)
- **Governing Principle**: The historical 19-rule limit is retired. There is NO predetermined maximum or target number of detection rules. Every registered detection rule must provide distinct, justified, tested, and maintainable detection value.
- **Rule Admission Requirements**:
  - Unique detection purpose not reasonably addressed by improving an existing rule.
  - Documented observable packet or flow evidence and protocol prerequisites.
  - Defined thresholds and deterministic $O(1)$ LRU state bounding via `OrderedDict` and `prune_stale(now)`.
  - Comprehensive unit test coverage: positive detection, benign negative suppression, and evasion edge cases.
  - Relevant PCAP or independently reproducible test evidence with false-positive analysis.
  - Strictly enforce port boundaries: `1 <= port <= 65535`, validate IP addresses, and guard against future clock drift (`timestamp > now`).
  - Rich forensic `evidence` dictionary populated in generated alerts.
- **Prohibited**:
  - Do NOT create dummy rules, redundant rules, or inflate rule counts merely for metrics.
  - Do NOT create separate rules for minor port or payload variations when existing logic can be generalized.
  - Do NOT remove or modify rules merely to force passing benchmarks without technical justification.

## 2. Telemetry and Reference Engine Boundaries
- **Packet-First Telemetry**: NetGuard operates on packet captures (PCAP) and live network streams. Host-based endpoint event logs (such as Windows EVTX) are out of scope for the packet inspection engine.
- **Suricata Integration**: Suricata is a reference/comparison engine for corroboration, NOT infallible ground truth.
- **Zeek Integration**: Zeek structured event logs (`conn.log`, `dns.log`, `ssl.log`) provide complementary flow and session telemetry for corroboration without signature dependency.

## 3. Git Discipline & Safety Invariants
- **Authorized Branch**: `antigravity/overnight-work`.
- **Strict Guardrails**:
  - Never commit directly to `main` or push to `main`.
  - Never force-push (`git push -f`) or delete branches.
  - Never execute destructive resets (`git reset --hard`) without absolute safety verification.
  - Push strictly to `origin/antigravity/overnight-work`.

## 4. Verification and Testing Discipline
- Every change must be verified against:
  - Unit tests: `pytest ids_project/tests`
  - Ground-truth evaluation scenarios: `python3 ids_project/evaluation/run_eval.py`
- Never disable, skip, or remove failing tests merely to force a passing build.
- All evaluation metrics must be grounded in actual test runs and reproducible seeds.

