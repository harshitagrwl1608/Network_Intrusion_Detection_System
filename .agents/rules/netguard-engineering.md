# NetGuard Engineering Rules & Guardrails

## Detection Engineering Guardrails
1. **Rule Inventory Invariant**:
   - `RuleEngine.rules` must contain exactly 19 rule instances.
   - Any modification must preserve or harden existing rules without altering the total count.
2. **Defensive Boundaries**:
   - Validate port numbers strictly: `1 <= port <= 65535`.
   - Validate IP addresses: guard against empty strings, invalid characters, or None.
   - Guard timestamps against clock drift and future jumps (`timestamp > now`).
   - Implement `prune_stale(now)` on all stateful rules with bounded memory footprint.
3. **Forensic Integrity**:
   - Alerts must populate rich forensic `evidence` dictionaries (e.g., target ports, packet counts, triggered thresholds, sample payloads).
   - Ensure sanitized serialization of byte sequences and non-ASCII characters.

## Data & Telemetry Guardrails
1. **Dataset Provenance**:
   - Every external dataset must be logged in `docs/autonomy/dataset-registry.md` with source URL, publisher, license, hash, and record counts.
   - Never commit raw bulk datasets (>1MB) to Git; store local test fixtures as lightweight synthetic PCAPs or curated JSON records.
2. **Evaluation vs. Comparison**:
   - Ground truth evaluation must be executed via `run_eval.py`.
   - Suricata comparison is executed via `compare.py` and reported as comparative agreement, not accuracy.

## Git & Execution Guardrails
1. **Branch Strictness**:
   - All commits must reside on `antigravity/overnight-work`.
   - Before any commit: verify `pytest ids_project/tests` passes 100%.
2. **Commit Messages**:
   - Must be descriptive and prefix with the Cycle number (e.g., `Cycle N: Harden ...`).
