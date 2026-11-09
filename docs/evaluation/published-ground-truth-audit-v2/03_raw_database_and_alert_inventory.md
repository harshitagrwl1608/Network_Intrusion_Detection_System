# 3. Raw Database & Alert Inventory Audit

## Database Integrity & Verification
- **SQLite Database Path**: `/run/media/harshitgarg/Data1/NetGuard-datasets/published_ground_truth_ctu48_1/netguard_eval_48_1.db`
- **SHA-256 Checksum**: `6bb5376835c5b25ba721e80fa2547c6cbadb56f38710a8d28650dc8ec6cff042`
- **SQLite Integrity Check**: `ok` (OK)
- **Total Alerts Persisted**: `4,027`
- **Alert ID Sequence**: Strictly monotonic from `1` to `4027` without gaps.

---

## Alert Breakdown by Detection Rule
| Rule Name | Alert Count | Percentage | Severity | Window Boundary Persistence |
| :--- | :--- | :--- | :--- | :--- |
| `PORT_SCAN` | `3,473` | `86.24%` | High / Medium | `window_start` and `window_end` 100% Persisted |
| `SLOW_PORT_SCAN` | `292` | `7.25%` | Medium | `window_start` and `window_end` 100% Persisted |
| `ARP_SPOOF` | `262` | `6.51%` | Medium | None (Event-driven point alerts) |

---

## Database Reuse Defect Audit
Inspection of `ids_project/evaluation/run_ctu48_1_validation.py` revealed:
```python
if existing_alerts > 0:
    replay_seconds = 2711.11
    avg_pps = 5003.7
    peak_rss_mb = 116.44
```
**Forensic Audit Finding**:  
1. The single-pass replay of 13,565,553 packets was genuinely executed once and recorded in `netguard_eval_48_1.log` (lines 1 to 4080).
2. During the subsequent evaluation script invocation, the runner detected existing rows and bypassed re-running the 45-minute replay, assigning the previously logged execution numbers.
3. **Verdict**: The performance metrics are **REPORTED FROM PRIOR RUN BUT REUSED IN FINAL PASS**.
