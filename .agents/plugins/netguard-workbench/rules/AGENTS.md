# NetGuard Engineering Rules & Guardrails

## 1. Rule Inventory Invariant (Strict Rule Count = 19)
- **Invariant**: The system strictly maintains exactly **19 rule instances** registered in `RuleEngine.rules`.
- **Prohibited**:
  - Do NOT create new detection rules, dummy rules, or inflate rule counts.
  - Do NOT create new Sigma detections, Splunk detections, or Suricata signatures.
  - Do NOT modify engine detection code to add ad-hoc rules during customization tasks.
- **Permitted and Required**:
  - Correct field mappings, protocol normalizations, and input bounds checks.
  - Strictly enforce port boundaries: `1 <= port <= 65535`.
  - Validate IP addresses: guard against empty strings, invalid formatting, or `None`.
  - Guard timestamps against future clock drift (`timestamp > now`).
  - Implement deterministic $O(1)$ LRU state bounding via `OrderedDict` and `prune_stale(now=None)`.
  - Populate rich forensic `evidence` dictionaries in generated alerts.

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
