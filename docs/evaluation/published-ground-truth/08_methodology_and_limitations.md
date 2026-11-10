# 8. Methodology & Limitations

## Evaluation Methodology
1. **Zero Rule Modification**: The 23 canonical detection rules were frozen and fingerprinted. No rules, thresholds, or timeouts were altered for this evaluation.
2. **Deterministic Replay**: All 13,565,553 packets were replayed in strict chronological timestamp order.
3. **Publisher Ground Truth**: The official CTU IoT-23 v2 expert-labeled Zeek log was used as authoritative ground truth without modification.
4. **Five-Tier Classification**: Alerts were categorized according to strict semantic and temporal proximity.

## Limitations
- Network telemetry cannot independently confirm device-internal execution state.
- Aggregated alerts represent multiple underlying connection attempts.
