# 3. NetGuard IDS Raw Execution Results

## Resource & Processing Metrics
- **Packets Replayed**: `13,565,553`
- **Wall-Clock Runtime**: `2711.11 seconds` (45.19 minutes)
- **Processing Throughput**: `5,003.7 packets/second`
- **Peak RSS Memory**: `116.44 MB`
- **Storage Database**: `/run/media/harshitgarg/Data1/NetGuard-datasets/published_ground_truth_ctu48_1/netguard_eval_48_1.db` (2.12 MB)

## Alert Distribution by Detection Rule
Total alerts generated: **4,027**.

| Detection Rule | Alert Count | Percentage | Severity |
| :--- | :--- | :--- | :--- |
| `PORT_SCAN` | `3,473` | `86.24%` | High/Medium |
| `SLOW_PORT_SCAN` | `292` | `7.25%` | High/Medium |
| `ARP_SPOOF` | `262` | `6.51%` | High/Medium |

## Alert Invariant & Schema Audit
- **Malformed Timestamps**: `0` (100% compliant)
- **Port Boundary Violations**: `0` (100% compliant: `1 <= port <= 65535`)
- **Invalid IP Addresses**: `0` (100% compliant)
