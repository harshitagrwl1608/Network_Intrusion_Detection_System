---
name: suricata-validation
description: "Differential validation and corroboration between NetGuard IDS alerts and Suricata EVE JSON event outputs."
---

# Suricata Differential Validation

This skill governs the execution and interpretation of multi-engine cross-validation comparing NetGuard alerts with Suricata telemetry.

## When to Use
- Evaluating NetGuard detection coverage against Suricata baseline signatures.
- Parsing and corroborating `eve.json` alerts using `ids_project/evaluation/compare.py`.
- Refining semantic family mappings for shared network phenomena (SQLi, command injection, SYN flood).

## Operational Workflow

### 1. Ingest Suricata EVE JSON
Load events with resilient parsing and timestamp normalization:

```python
from ids_project.evaluation.compare import load_suricata_alerts

# Resilient ingestion handling ISO-8601, epoch floats, and null alert blocks
suricata_events = load_suricata_alerts("eve.json")
print(f"Loaded {len(suricata_events)} Suricata alerts")
```

### 2. Semantic Family Cross-Engine Mapping
NetGuard corroborates alerts by observable network behavior rather than signature names:

| Semantic Attack Family | NetGuard Rule / Alert | Suricata Signature Patterns |
| :--- | :--- | :--- |
| `sql_injection` | `PAYLOAD_HIT` (SQL_INJECTION) | `ET EXPLOIT SQL`, `GPL SQL` |
| `command_injection`| `PAYLOAD_HIT` (CMD_INJECTION) | `ET EXPLOIT CMD`, `ET WEB_SPECIFIC_APPS` |
| `log4shell` | `PAYLOAD_HIT` (LOG4SHELL) | `ET EXPLOIT Apache log4j`, `CVE-2021-44228` |
| `syn_flood` | `SYN_FLOOD`, `DISTRIBUTED_SYN_FLOOD`| `ET DOS Possible Syn Flood` |
| `dns_tunnel` | `DNS_ANOMALY` (DNS_TUNNEL) | `ET INFO DNS Query to *.top`, `DNS Tunneling` |
| `tcp_zero_window` | `TCP_ZERO_WINDOW` | `SURICATA TCP Window Zero` |

### 3. Run Comparative Evaluation
Execute comparison between NetGuard database alerts and Suricata outputs:

```python
from ids_project.evaluation.compare import run_ground_truth

metrics = run_ground_truth(netguard_alerts, suricata_events, window_sec=5.0)
print(f"Concordance: {metrics['agreement_rate']:.2%}")
```

## Guardrails
- Suricata is a comparison baseline, not ground truth. Detections by NetGuard without a Suricata match are not automatically false positives.
- Network telemetry corroboration is limited to observable network-layer and transport-layer phenomena; it cannot independently prove or disprove endpoint-internal state.

