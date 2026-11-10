# NetGuard IDS — Development and Engineering Workflow

---

## 1. Git Discipline & Safety Invariants

> [!CAUTION]
> **Strict Repository Guardrails**:
> - **Authorized Development Branch:** `antigravity/overnight-work`
> - **Never commit directly to `main` or push to `main`.**
> - **Never force-push (`git push -f`) or delete existing branches.**
> - **Never execute destructive resets (`git reset --hard`) or wholesale directory purges (`git clean -fd`)** without absolute safety verification.
> - **Always push strictly to `origin/antigravity/overnight-work`.**

### Commit Message Conventions

NetGuard adheres to conventional commit formatting:
`<type>(<scope>): <concise present-tense description>`

**Common types:**
- `feat`: New capability or detection rule
- `fix`: Bug fix, false-positive remediation, or regex correction
- `test`: Extending unit tests, regression suites, or evaluation harnesses
- `docs`: Documentation updates, architecture guides, or evaluation reports
- `refactor`: Code restructuring without modifying detection behavior
- `perf`: Replay throughput or memory optimization

**Examples:**
- `fix(dpi): harden PAYLOAD_HIT with application-aware HTTP parsing and credential redaction`
- `test(eval): add regression test for RFC 2046 multipart comment delimiters`
- `docs(arch): update architecture guide with HttpParser pipeline`

---

## 2. Rule Governance Invariant (Evidence-Driven Admission)

NetGuard operates under strict evidence-driven rule governance:

> [!IMPORTANT]
> **Rule Governance Principles**:
> - **No Arbitrary Limits:** The historical 19-rule limit is retired. There is NO predetermined maximum or target number of detection rules.
> - **Distinct Value:** Every registered rule must provide distinct, justified, tested, and maintainable detection value.
> - **Prohibited Practices:**
>   - Do NOT create dummy rules, redundant rules, or inflate rule counts merely for vanity metrics.
>   - Do NOT create separate rules for minor port or payload variations when existing rules can be generalized.
>   - Do NOT remove or disable rules merely to force passing benchmark scores.
>   - Do NOT alter detection behavior or thresholds without empirical verification against test suites.

### Mandatory Admission Requirements for New Rules

1. **Unique Purpose:** Solves a distinct detection need not reasonably addressed by improving an existing rule.
2. **Observable Network Evidence:** Grounded in observable transport-layer or application-layer packet evidence.
3. **Deterministic State Bounding:** All sliding-window and tracking state must use `OrderedDict` with explicit $O(1)$ LRU bounding and `prune_stale(now)` expiration logic.
4. **Port & Address Validation:** Strictly enforce `1 <= port <= 65535`, valid IPv4/IPv6 addresses, and guard against future clock drift (`timestamp > now`).
5. **Comprehensive Unit Testing:** Every rule must have unit tests covering:
   - Positive detection (attack pattern triggers alert)
   - Benign negative suppression (normal protocol traffic does not trigger alert)
   - Evasion and boundary edge cases (malformed packets, boundary values, empty payloads)
6. **Rich Forensic Evidence:** Generated alerts must populate a structured `evidence_json` dictionary detailing triggering parameters, matched bytes/patterns, and sliding-window statistics.

---

## 3. Step-by-Step Guide: Implementing a New Detection Rule

### Step 1: Design & Threshold Definition
1. Identify the target attack behavior and observable wire evidence.
2. If the rule requires configurable thresholds, define them in [`ids_project/config.py`](../ids_project/config.py) using the `_detection_int` or `_detection_float` helper functions to guarantee safe startup fallbacks:
   ```python
   NEW_RULE_THRESHOLD = _detection_int("NEW_RULE_THRESHOLD", 25)
   NEW_RULE_WINDOW    = _detection_int("NEW_RULE_WINDOW", 10)
   ```

### Step 2: Implement the Rule Class
In [`ids_project/engine/rules.py`](../ids_project/engine/rules.py):
1. Define the rule class:
   ```python
   class NewAttackRule:
       name = "NEW_ATTACK_RULE"
       version = "1.0"

       def __init__(self, threshold: int, window: int):
           self.threshold = threshold
           self.window = window
           self._state = OrderedDict()  # LRU state cache
           self._max_entries = 2048

       def prune_stale(self, now: float) -> None:
           cutoff = now - self.window
           while self._state:
               key, (first_seen, _) = next(iter(self._state.items()))
               if first_seen < cutoff:
                   self._state.popitem(last=False)
               else:
                   break

       def check(self, record: dict) -> list[dict]:
           # 1. Safe timestamp extraction
           now = _finite_record_timestamp(record)
           if now is None:
               return []

           # 2. Protocol prerequisite check
           if record.get("protocol") != "TCP":
               return []

           # 3. Port & address normalization
           dst_port = _normalize_port(record.get("dst_port"))
           if dst_port is None:
               return []

           # 4. State maintenance & threshold evaluation
           self.prune_stale(now)
           # ... detection logic ...

           # 5. Return structured alert if threshold exceeded
           return [{
               "rule_name": self.name,
               "rule_version": self.version,
               "timestamp": now,
               "src_ip": record.get("src_ip"),
               "dst_ip": record.get("dst_ip"),
               "src_port": record.get("src_port"),
               "dst_port": dst_port,
               "protocol": "TCP",
               "detail": f"Observed suspicious activity on port {dst_port}",
               "severity": "high",
               "confidence": "high",
               "evidence_json": {
                   "observed_count": count,
                   "threshold": self.threshold,
                   "window_seconds": self.window,
               },
               "window_start": now - self.window,
               "window_end": now,
               "idempotency_key": hashlib.sha256(...).hexdigest(),
           }]
   ```

### Step 3: Register the Rule in `RuleEngine`
In `RuleEngine.__init__()` in [`ids_project/engine/rules.py`](../ids_project/engine/rules.py):
1. Instantiate the rule with configuration parameters:
   ```python
   self.rules = [
       # ... existing rules ...
       NewAttackRule(
           threshold=getattr(cfg, "NEW_RULE_THRESHOLD", 25),
           window=getattr(cfg, "NEW_RULE_WINDOW", 10),
       ),
   ]
   ```
2. Add the rule class to the protocol routing tables (`self._tcp_rules`, `self._udp_rules`, etc.) to optimize packet dispatch.

### Step 4: Write Unit Tests
Create a dedicated test file in `ids_project/tests/` (e.g. `test_new_attack_rule.py`):
```python
import pytest
from engine.rules import NewAttackRule

def test_new_attack_rule_positive_detection():
    rule = NewAttackRule(threshold=5, window=10)
    # Replay 6 triggering packets
    for i in range(6):
        record = {
            "protocol": "TCP",
            "src_ip": "192.168.1.50",
            "dst_ip": "192.168.1.1",
            "dst_port": 80,
            "event_timestamp": 1000.0 + i,
        }
        alerts = rule.check(record)
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "NEW_ATTACK_RULE"

def test_new_attack_rule_benign_suppression():
    rule = NewAttackRule(threshold=5, window=10)
    # Replay packets below threshold
    for i in range(3):
        record = {
            "protocol": "TCP",
            "src_ip": "192.168.1.50",
            "dst_ip": "192.168.1.1",
            "dst_port": 80,
            "event_timestamp": 1000.0 + i,
        }
        alerts = rule.check(record)
    assert len(alerts) == 0

def test_new_attack_rule_invalid_inputs():
    rule = NewAttackRule(threshold=5, window=10)
    # Missing timestamp, invalid port, non-TCP
    assert rule.check({"protocol": "UDP"}) == []
    assert rule.check({"protocol": "TCP", "dst_port": 99999}) == []
```

### Step 5: Update Documentation & Governance Tests
1. Update [`ids_project/tests/test_rule_governance_invariants.py`](../ids_project/tests/test_rule_governance_invariants.py) to include the new rule in the authoritative rule registry test.
2. Add the rule description to [`docs/DETECTION_ENGINE.md`](DETECTION_ENGINE.md).
3. Document any new configuration parameters in [`docs/CONFIGURATION.md`](CONFIGURATION.md).

---

## 4. Verification & Quality Gates

Before committing any change to `antigravity/overnight-work`, verify all quality gates:

```bash
# 1. Run the full unit and regression test suite
python3 -m pytest ids_project/tests -q
# Gate: 100% pass (baseline: 854+ passed, 0 failures)

# 2. Run the synthetic evaluation harness
python3 ids_project/evaluation/run_eval.py
# Gate: 42 attack alerts, 0 false positives on benign traffic

# 3. Check code formatting and static invariants
git diff --check
git status
```

---

## 5. Working with External Benchmark Datasets

When executing multi-PCAP ground-truth benchmarks:
- Mount the external dataset drive at `/run/media/harshitgarg/Data1/NetGuard-datasets/verified/`.
- Ensure converted `.pcap` files reside in `data/ciciot2023_eval/` or `data/external_benchmarks/converted_pcaps/`.
- Use the provided benchmark runner script:
  ```bash
  bash scripts/evaluation/run_ground_truth_benchmark.sh
  ```
- **Do NOT commit raw `.pcap` or `.pcapng` capture files or generated SQLite database artifacts (`.db`) to the git repository.**

