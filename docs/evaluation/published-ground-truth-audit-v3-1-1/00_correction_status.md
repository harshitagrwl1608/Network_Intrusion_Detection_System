# Audit V3.1.1 — Correction Status and Evidence Boundary

**Code status:** Corrective changes committed to `antigravity/overnight-work`.  
**Full-data status:** NOT RERUN after these corrections.  
**Submission status:** NOT YET READY AS A DEFINITIVE INDEPENDENT ACCURACY AUDIT.

## Why the V3.1 results are provisional

The V3.1 execution reported 3,669 Tier A, 96 Tier B and 262 Tier D alerts. Those values were calculated before the additional corrections below. They must be treated as historical run results, not as verified output from the corrected code.

The Tier-A shares (91.11% of all alert rows and 97.45% of scan-rule alert rows) are confirmation fractions. They are **not conventional precision estimates**, because Tier B is malicious-associated but incompletely corroborated and Tier D is unassessed, not a proven false positive.

## Corrective code changes

1. **Full directional five-tuple matching:** packet candidates are checked against origin IP/port, responder IP/port and protocol, as well as exact Zeek connection lifetime.
2. **Ambiguous matches:** the audit no longer silently selects the first candidate. Multiple candidate UIDs are recorded as ambiguous and do not count as uniquely corroborated targets.
3. **Unknown Zeek duration:** a `-` duration remains unknown. It is not converted into a fabricated zero-duration connection and cannot prove lifetime overlap.
4. **Tier classification:** Tier A depends on the threshold number of uniquely corroborated distinct targets. Mixed benign and unmatched evidence is not called a confirmed false positive.
5. **Retransmission reporting:** Tier A, partial Tier B and unresolved retransmission cases are reported separately; reports no longer upgrade all 402 cases to Tier A.
6. **Cooldown intervals:** flow-start overlap is calculated against post-alert intervals using documented default durations. It is explicitly temporal overlap, not proof of suppression or detection. Runtime cooldown overrides remain unverified.
7. **PCAP record accounting:** runt frames are counted in packet-record totals, while incomplete packet headers/data fail closed instead of silently ending the stream.
8. **ARP findings:** nearest-frame data is labelled contextual only, not a demonstrated per-alert packet match. Missing historical runtime ARP state remains Tier D.
9. **Suricata:** EVE and log hashes are recorded, but the existing EVE file is not treated as proof of same-PCAP input identity or zero horizontal-scan detection.
10. **Metric/report language:** Tier-A shares are not called conventional precision, and reports are generated from the reconciled summary.

## What remains unverified

- The corrected script has not been rerun on the original PCAP, Zeek log, database and EVE files.
- The prior 3,669 / 96 / 262 classification counts may change after ambiguous-flow and unknown-duration cases are handled conservatively.
- Corrected export hashes and row counts do not yet exist.
- Full project and audit-specific tests have not been rerun after the latest changes.
- No GitHub CI workflow/status result is available for the V3.1 commit.
- Suricata input-PCAP identity and runtime rule/configuration provenance remain unavailable.
- Historical runtime ARP baseline and effective environment overrides were not preserved.

## Submission decision

**Do not submit the V3.1 headline percentages as final results.**

The code corrections are intended to remove the remaining attribution/reporting shortcuts. A single complete execution of the corrected V3.1.1 script on the original local inputs is still necessary to generate the new result set. The final decision should be made from that run's actual summary and exports, not from the previous report.

Until then, the defensible claim is limited to this: NetGuard emitted scan alerts in a capture whose publisher-labelled Zeek data records a Mirai horizontal-scanning campaign. The corrected event-level confirmation fractions and overall performance remain pending.
