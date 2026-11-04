---
name: rule-review
description: "Audit NetGuard detection rules for boundary conditions, port bounds, IP validation, timestamp drift, and adherence to the 19-rule invariant."
---

# Detection Rule Review and Verification

This skill provides a structured methodology for auditing, hardening, and reviewing NetGuard detection rules.

## When to Use
- Reviewing rules in `ids_project/engine/rules.py`.
- Auditing input boundary checks, defensive assertions, and normalization logic.
- Verifying the 19-rule inventory invariant.

## Rule Audit Checklist

### 1. The 19-Rule Invariant
Assert that `RuleEngine.rules` contains exactly the 19 registered rules:
1. `BlocklistRule`
2. `PortScanRule`
3. `UdpScanRule`
4. `UdpFloodRule`
5. `TcpStealthScanRule`
6. `TcpFlagAnomalyRule`
7. `SynFloodRule`
8. `DistributedSynFloodRule`
9. `IcmpSweepRule`
10. `IcmpFloodRule`
11. `ArpSpoofRule`
12. `PayloadRule`
13. `DnsRule`
14. `BruteForceRule`
15. `SlowPortScanRule`
16. `DataExfiltrationRule`
17. `CleartextHttpOnTlsPortRule`
18. `TlsAnomalyRule`
19. `TcpZeroWindowRule`

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

