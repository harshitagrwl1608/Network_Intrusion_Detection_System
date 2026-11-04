---
name: forensic-reporting
description: "Inspect alert evidence dictionaries, generate structured forensic reports, and validate alert schemas in NetGuard SQLite databases."
---

# Evidence-Based Forensic Reporting

This skill governs the inspection, extraction, and documentation of forensic evidence from NetGuard alerts.

## When to Use
- Extracting alert metadata from the NetGuard SQLite alerts database (`ids_project/storage/alerts.db`).
- Validating the JSON serialization of `evidence_json` dictionaries in generated alerts.
- Writing structured incident reports or campaign logs.

## Forensic Extraction Workflow

### 1. Querying Alert Telemetry from SQLite
Query alerts directly using SQLite in read-only mode:

```bash
sqlite3 -readonly ids_project/storage/alerts.db "SELECT id, timestamp, rule_name, src_ip, dst_ip, severity, evidence_json FROM alerts ORDER BY timestamp DESC LIMIT 10;"
```

### 2. Python Forensic Validator
Verify that the `evidence_json` field parses cleanly as JSON and contains required keys:

```python
import json
import sqlite3

def audit_alert_evidence(db_path="ids_project/storage/alerts.db"):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cursor = conn.cursor()
    cursor.execute("SELECT id, rule_name, evidence_json FROM alerts")
    
    anomalies = []
    for alert_id, rule_name, evidence_str in cursor.fetchall():
        try:
            evidence = json.loads(evidence_str) if evidence_str else {}
            if not isinstance(evidence, dict):
                anomalies.append((alert_id, "Evidence is not a dict"))
        except Exception as e:
            anomalies.append((alert_id, f"JSON parse error: {e}"))
            
    conn.close()
    return anomalies
```

### 3. Report Generation Standards
All forensic reports must include:
- Executive summary with total packet volume and unique IPs.
- Chronological attack timeline with UTC timestamps.
- Granular evidence breakdown (ports targeted, packet counts, triggering signatures).
- Actionable containment and firewall remediation recommendations.

## Guardrails
- Sanitize payload snippets: redact sensitive tokens, passwords, or binary data.
- Ensure all byte sequences are hex-encoded or UTF-8 sanitized with replacement characters.

