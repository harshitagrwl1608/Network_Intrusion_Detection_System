# 11. Final Independent Audit Verdict — Corrected

## Verdict: PARTIALLY SUPPORTED — ACCURACY CLAIMS UNVERIFIED

The CTU IoT-23 v2 Capture 48-1 dataset and publisher-labelled Zeek log are genuine evaluation inputs according to the recorded provenance. The repository's raw database inventory reports 4,027 NetGuard alert rows: 3,473 `PORT_SCAN`, 292 `SLOW_PORT_SCAN`, and 262 `ARP_SPOOF`.

The capture's publisher labels document a large Mirai horizontal-scanning campaign. The 3,765 scan-rule alert records are consistent with the known infected source and TCP/23 behaviour. This supports the conclusion that NetGuard reacted to the capture's scan pattern.

However, Audit V2 does not independently substantiate every scan alert as a true positive. Its Tier A assignment is based on fields and evidence already stored in the NetGuard alert row; it does not join each alert to contributing Zeek UIDs and packet-level evidence. Therefore the earlier 93.49% overall precision and 100% transport-scan precision claims are withdrawn pending a valid per-alert attribution audit.

## Findings that can currently be stated

1. **Dataset:** The official CTU IoT-23 v2 Capture 48-1 dataset and labelled Zeek log are the intended evaluation sources. The supplied Audit V2 documents report the expected publisher flow counts. The PCAP SHA-256 has conflicting values across supplied report text and the committed summary; rehash the local artifact before treating the PCAP digest as settled.
2. **Raw alert inventory:** Audit V2 reports 4,027 rows: 3,473 `PORT_SCAN`, 292 `SLOW_PORT_SCAN`, 262 `ARP_SPOOF`. These are inventory counts, not automatically validated detection counts.
3. **Scan alert interpretation:** 3,765 scan-rule alerts have metadata consistent with source `192.168.1.200`, TCP destination port 23, and recorded window/target evidence. This is a consistency check, not yet independent publisher-label corroboration.
4. **ARP observations:** The report states that 6,252 ARP frames showed stable observed MAC mappings and no conflicting gateway MAC. This strongly indicates the 262 ARP alerts are unsupported false alarms on this capture. The exact historical runtime `arp_table.json` contents/hash at replay start were not preserved, so synthetic initial-state contamination is the leading explanation, not a fully proven historical cause.
5. **Temporal overlap:** 65,243 publisher scan flow-start timestamps (1.93%) reportedly fall inside strict alert trigger windows. The 100% result refers only to timestamps overlapping the union of trigger windows extended by alert cooldowns. It is not scan-flow recall, detection coverage, or evidence that all flows independently triggered detection.
6. **Suricata:** 85 alert rows were counted from the available EVE JSON. The audit runner does not enforce EVE input-PCAP identity, EVE SHA-256, full execution manifest or all Suricata settings; a fully reproducible comparative run is not established.
7. **Performance:** 2,711.11 seconds and 116.44 MB are reported as measurements from an initial replay and reused in a later database-reuse path. Audit V2 did not independently reproduce them.
8. **Engine provenance:** The cited Git trees support that core committed detection files were unchanged between the cited engine and evaluation commits. Historical local working-tree cleanliness and all effective environment overrides at execution time remain unverified.

## Metrics status

| Metric | Corrected status |
|---|---|
| 93.49% strict alert precision | **UNVERIFIED — do not advertise as established** |
| 100% scan-rule precision | **UNVERIFIED — per-alert ground-truth joins missing** |
| 99.88% malicious precision | **WITHDRAWN** |
| 6.51% alert false-discovery fraction | **PROVISIONAL** — 262 ARP alerts unsupported by observed capture evidence; historical initial state not preserved |
| Conventional false-positive rate | **NOT CALCULATED** — valid TN denominator unavailable |
| 1.93% strict trigger-window flow-start overlap | Descriptive interval statistic, not recall |
| 100% cooldown-extended temporal overlap | Descriptive interval statistic, not recall or campaign detection coverage |
| 85 Suricata EVE alert rows | Recounted, full run provenance not established |
| NetGuard runtime and peak RSS | Reported historical measurements, not independently reproduced in Audit V2 |

## Required next steps

1. Reconstruct actual contributing packets and Zeek UIDs for every scan alert, including the 402 retransmission cases.
2. Independently verify source/destination, protocol, ports, target sets, timestamp semantics, retransmissions and publisher detailed labels.
3. Preserve ambiguous cases as unassessed; do not force every alert into TP or FP.
4. Treat ARP alerts as unsupported on this capture unless per-alert packet attribution establishes otherwise; retain uncertainty about historical runtime state.
5. Recompute alert-level precision, false-discovery fraction and any justified coverage metrics from auditable classifications.
6. Verify exact PCAP, Zeek, database and EVE hashes against local artifacts and reconcile conflicting PCAP hash reports.
7. Reconstruct effective runtime configuration and historical Git provenance where original evidence exists; mark missing history unverifiable.
8. Add audit-specific automated tests, run the current full test suite and record actual CI/test evidence.
9. Update README claims and test counts only after the evidence and tests are reconciled.

**Submission wording:** NetGuard generated scan alerts on an official publisher-labelled Mirai horizontal-scanning capture. The current Audit V2 supports the presence of a genuine scan campaign and identifies likely ARP false alarms, but it does not yet establish event-level precision or recall. Do not present the earlier 93.49% precision or 100% recall/coverage claims as verified academic results.

See [13_correction_and_submission_readiness.md](13_correction_and_submission_readiness.md) for the correction register.