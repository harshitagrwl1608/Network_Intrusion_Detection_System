# Audit V2 Correction & Submission Readiness Errata

**Status:** This document supersedes conflicting accuracy and readiness statements in Audit V2 reports 04, 06, 07, 09, 11 and `audit_summary.json` until the audit implementation is corrected and rerun. The original files remain preserved as historical outputs.

## Final assessment

**PARTIALLY SUPPORTED — the Mirai scan behaviour is demonstrated, but the published precision and recall claims are not established.**

The official CTU capture and its labelled Zeek dataset are real, and the repository contains the reported audit artifacts. The audit's numerical classification of individual alerts is not yet a valid independent event-level ground-truth evaluation.

## Corrected interpretation of current results

| Item | Observed result | Defensible interpretation |
|---|---:|---|
| NetGuard alert rows | 4,027 | Raw database inventory reported by Audit V2 |
| Scan-rule alerts | 3,765 | 3,473 PORT_SCAN + 292 SLOW_PORT_SCAN; alert metadata is consistent with the known Mirai TCP/23 scan pattern |
| ARP_SPOOF alerts | 262 | No conflicting gateway/device IP-to-MAC claim was found in the 6,252 ARP frames reported as inspected; these alerts are unsupported by this capture and should be treated as false alarms for this dataset |
| Scan-alert precision | Not established | The audit script assigns Tier A from fields already stored on each alert; it does not join the alert to contributing publisher-labelled Zeek UIDs or independently reconstruct the packet evidence |
| Strict flow-start timestamp overlap | 65,243 / 3,386,119 (1.93%) | Zeek flow-start timestamps inside the alert trigger intervals; this is not flow recall and does not account for packets/retransmissions within longer-lived flows |
| Trigger-plus-cooldown timestamp overlap | 3,386,119 / 3,386,119 (100%) | Temporal overlap with the union of alert intervals extended by configured cooldowns; this is not detection coverage, recall, or proof that every flow was detected |
| Suricata EVE alerts | 85 | Recounted from the available EVE file; exact run provenance and same-input identity are not independently enforced by the audit script |
| NetGuard runtime / RSS | 2,711.11 s / 116.44 MB reported | Values attributed to the initial replay log and reused on a subsequent database-reuse path; not independently reproduced by Audit V2 |
| Engine freeze | Core files identical in the two cited committed trees | Historical local working-tree cleanliness and effective environment overrides at execution time remain unverified |

## 1. Why 93.49% is not a verified precision result

The arithmetic (3,765 / 4,027 = 93.49\%) is correct. The numerator is not independently substantiated.

The Tier A condition in `scripts/audits/ctu48_1_ground_truth_audit.py` checks the alert's own source address, destination port, protocol, non-null window fields and stored `distinct_hosts` evidence. It does not retrieve and validate the contributing Zeek flow UIDs, destination set, flow labels, or packet-level SYN evidence for each alert.

This is a rule-consistency check against the alert record, not an independent alert-to-ground-truth join. Therefore:
- Keep 3,765 as **scan-rule alerts consistent with the configured/recorded trigger metadata**.
- Do not call all 3,765 confirmed true positives yet.
- Do not publish 93.49% as verified precision.
- Do not publish 100% transport-scan precision until benign and malicious event attribution is independently reconstructed.

The 402 alerts whose trigger windows contain no Zeek flow-start timestamps require packet-to-flow reconstruction. The report's retransmission explanation is plausible, but the committed audit script does not perform or export the claimed per-alert packet trace for all 402 cases.

## 2. ARP findings and historical cause

The reported PCAP inspection found one observed MAC per relevant IP across 6,252 ARP frames and no conflicting gateway MAC claim. That is strong evidence that the 262 ARP alerts do not represent ARP spoofing in this capture.

The tracked `ids_project/data/arp_table.example.json` contains the synthetic gateway MAC `00:11:22:33:44:01`. However, the actual runtime `arp_table.json` is ignored/untracked and its historical contents/hash at replay start were not preserved. The example file is evidence of a plausible fixture source, not proof that it was the exact runtime state used.

Correct wording: **262 ARP alerts are unsupported false alarms on the observed Capture 48-1 traffic; synthetic initial-state contamination is the leading explanation, but the exact historical runtime-state provenance is unverified.**

## 3. Coverage terminology

The 100% result is an interval-overlap calculation using `[window_start, window_end + cooldown]`. A continuous union of cooldown-extended intervals means the publisher flow-start timestamps fall within these intervals. It does not mean every flow was inspected as a distinct detection, that every flow independently triggered a rule, or that flow-level recall was 100%.

Use these terms only:
- **Trigger-window flow-start overlap:** 1.93%.
- **Cooldown-extended temporal overlap:** 100% (as calculated by the current script).

Do not call the second value campaign detection coverage or recall.

## 4. Historical execution and engine provenance

The Git comparison supports that the committed core detection files were unchanged between the cited engine and evaluation commits, while evaluation comparator code changed. This does not prove that the original local working tree was clean when the replay ran: the original runner allowed dirty-tree verification, and the audit script hardcodes historical commit identifiers rather than reconstructing the historical working tree from Git objects.

Likewise, values read from `config.py` are defaults, not proof of runtime environment overrides. Mark historical runtime cleanliness and effective environment configuration **UNVERIFIABLE** unless original manifests/logs establish them.

The reported NetGuard runtime and RSS were recorded during an initial replay according to the audit narrative, then reused on a later database-reuse path. They are **historically reported measurements**, not independently reproduced by Audit V2.

## 5. Suricata comparison

The current audit script counts `event_type == "alert"` records in the existing EVE file. It does not enforce EVE SHA-256 validation, prove the EVE file was generated from the exact PCAP bytes, or independently reproduce the run configuration, ruleset checksum, worker count and runtime.

Therefore, 85 is a **recounted EVE alert count**, not a fully reproducible comparative experiment. Keep Suricata's result separate from publisher ground truth; Suricata is not the label oracle.

## 6. Provenance discrepancies to resolve

The supplied Audit V2 report text and the committed summary do not agree on the PCAP SHA-256. The supplied report text contains `ac2e41f022a8435d8e7c10b7f8e363628e9d9e4a317e08922e9e68c92a926ba6`, while the committed summary and dataset report contain `ac2e41f0d5b2479ce5e1779fbaa6d6b73a6151050d86f04f80a872759034865c`. Rehash the actual local PCAP and resolve this before describing its cryptographic provenance as settled.

Earlier evaluation material also reported a different database digest from Audit V2. Treat database identity as artifact-specific and reconcile the exact file/path/version; do not silently substitute hashes.

## 7. Metric terminology and arithmetic

The exact arithmetic is:
- (3,765 / 4,027 = 93.4939\ldots\%\), rounded to **93.49%**.
- (262 / 4,027 = 6.5061\ldots\%\), rounded to **6.51%**.

The second ratio is an **alert false-discovery fraction**, not the conventional false-positive rate (FPR). Conventional FPR requires a defensible negative-instance denominator (FP/(FP+TN)). No conventional FPR, recall or F1 is established by the current audit.

## 8. Independent review and test status

The adversarial-review memo is present in the same audit commit. Its presence does not by itself establish that a separate person or independent process performed the review. No reviewer identity, separate execution record or independently signed artifact is provided in the repository.

The audit commit has no GitHub CI status checks or workflow runs recorded. The README's 747-test count is stale relative to later reported 756-test runs; neither count is independently verified by the Audit V2 commit. Run the current full test suite and dedicated audit tests before submission.

## Required next actions

1. Replace the Tier A shortcut with reproducible per-alert packet-to-Zeek UID attribution, including all 402 retransmission cases.
2. Export the exact contributing packet records, Zeek UIDs, destination targets, labels and rationale for every scan alert.
3. Keep ARP findings at the evidence-supported wording above unless the historical runtime ARP-state file is recovered.
4. Rename cooldown overlap to a temporal metric and remove all recall/campaign-detection wording.
5. Validate the exact PCAP, Zeek, database and EVE hashes from the local files; record the actual run manifest and effective environment configuration.
6. Reconstruct historical Git-tree hashes and distinguish committed-tree equality from unavailable local working-tree state.
7. Add audit-specific tests for joins, label semantics, flow reuse, retransmissions, ARP mapping changes, metric denominators and deterministic report/JSON agreement.
8. Update generated reports, README and JSON from one tested source of truth.

**Until these actions pass, the academically safe claim is that NetGuard emitted scan alerts during a publisher-documented Mirai horizontal-scanning capture, while event-level precision and recall remain unverified.**