---
name: zeek-analysis
description: "Parse, analyze, and correlate Zeek network security monitoring logs (conn.log, dns.log, ssl.log) with NetGuard telemetry."
---

# Zeek Network Analysis

This skill guides the analysis of Zeek (Bro) structured event logs to corroborate connection lifecycle, protocol metadata, and network anomalies.

## When to Use
- Auditing connection state transitions (`history` string in `conn.log`).
- Cross-referencing NetGuard DNS alerts with Zeek `dns.log` records.
- Investigating SSL/TLS certificate chains, cipher suites, and SNI headers in `ssl.log`.
- Verifying volumetric flow metrics (bytes in, bytes out, duration).

## Zeek Log Analysis Patterns

### 1. Parsing `conn.log` Connection States
Zeek records connection state flags in the `history` field:
- `S`: SYN seen.
- `h`: SYN-ACK seen in responder direction.
- `A`: ACK seen.
- `D`: Data payload transferred.
- `F`: FIN exchange.
- `R`: RST packet sent.

Common anomaly patterns:
- `S`: Incomplete connection attempt (Port Scan or SYN Flood).
- `ShR`: Server rejected connection with RST (Closed Port Probe).
- `ShADadFf`: Clean established TCP connection.

### 2. Python Parser for Zeek TSV / JSON Logs

```python
import json

def parse_zeek_json_log(log_path):
    records = []
    with open(log_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                records.append(json.loads(line))
    return records
```

### 3. Correlating with NetGuard Alerts
- Compare Zeek `conn.log` duration and byte counts with `DataExfiltrationRule` threshold triggers.
- Match domain queries from Zeek `dns.log` against `DnsRule` high-entropy or long-label detections.

## Guardrails
- Maintain distinction between Zeek event logs (protocol parsing) and NetGuard detection alerts (threat detection).
- Do not introduce Zeek runtime dependencies into NetGuard core rule execution.
