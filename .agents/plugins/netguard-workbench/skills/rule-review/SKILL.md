---
name: rule-review
description: "Audit NetGuard detection rules for boundary conditions, port bounds, IP validation, timestamp drift, and adherence to rule governance invariants."
---

# Detection Rule Review and Verification

This skill provides a structured methodology for auditing, hardening, and reviewing NetGuard detection rules.

## When to Use
- Reviewing rules in `ids_project/engine/rules.py`.
- Auditing input boundary checks, defensive assertions, and normalization logic.
- Verifying rule governance invariants: every rule is distinct, justified, tested, and maintainable.

## Rule Audit Checklist

### 1. Rule Governance Invariant
Assert that all registered rules satisfy the governance requirements:
- Unique rule identity (`rule.name`) with no duplicate registrations.
- Genuinely distinct detection purpose not addressed by an existing rule.
- Associated positive, negative, and evasion tests in `ids_project/tests/`.
- Preserves all core baseline rules:
  `BlocklistRule`, `PortScanRule`, `UdpScanRule`, `UdpFloodRule`, `TcpStealthScanRule`,
  `TcpFlagAnomalyRule`, `SynFloodRule`, `DistributedSynFloodRule`, `IcmpSweepRule`,
  `IcmpFloodRule`, `ArpSpoofRule`, `PayloadRule`, `DnsRule`, `BruteForceRule`,
  `SlowPortScanRule`, `DataExfiltrationRule`, `CleartextHttpOnTlsPortRule`,
  `TlsAnomalyRule`, `TcpZeroWindowRule`.

### 2. Defensive Boundaries Checklist
- **Port Boundaries**: Strictly assert `1 <= port <= 65535` for all transport layer ports.
- **IP Normalization**: Check for non-empty string, valid characters, and canonical formatting (`ipaddress.ip_address`).
- **Clock Drift**: Evict or reject timestamps where `timestamp > now` to prevent zombie state from replay jumps.
- **OrderedDict LRU Bounding**: Ensure internal tracking dictionaries are bounded with `popitem(last=False)` and `move_to_end(key)`.
- **GC Defaults**: Ensure `prune_stale(self, now: float = None)` defaults to `now = time.time()` when `now is None`.
- **Forensic Evidence**: Ensure alerts populate granular data in the `evidence` dictionary (e.g. target port, sample payload snippet, triggered counts).

## Verification Command
Run unit tests across all rules:

```bash
pytest ids_project/tests/test_finite_rule_timestamps.py
pytest ids_project/tests
```

