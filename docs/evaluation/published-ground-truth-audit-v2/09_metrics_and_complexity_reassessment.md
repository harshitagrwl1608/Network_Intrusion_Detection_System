# 9. Metrics & Complexity Reassessment — Corrected

**Status: accuracy metrics pending valid per-alert ground-truth attribution.**  
This correction supersedes unsupported precision, recall and campaign-coverage claims in the earlier Audit V2 version. See [13_correction_and_submission_readiness.md](13_correction_and_submission_readiness.md). Historical outputs are retained for audit traceability.

## Reconciled inventory

| Item | Count | Status |
|---|---:|---|
| Raw alert rows in audited DB | 4,027 | Reported and database-integrity-checked |
| `PORT_SCAN` alerts | 3,473 | Raw alert inventory |
| `SLOW_PORT_SCAN` alerts | 292 | Raw alert inventory |
| `ARP_SPOOF` alerts | 262 | Raw alert inventory; unsupported by captured ARP observations |
| Scan-rule alerts combined | 3,765 | Consistent with infected-host TCP/23 alert metadata; not yet independently ground-truth joined |

## Metrics that must not currently be advertised as verified

| Metric | Earlier Audit V2 claim | Corrected status |
|---|---:|---|
| Overall alert precision | 93.49% | **UNVERIFIED** — Tier A is assigned from alert fields/evidence, without per-alert Zeek UID and packet attribution |
| Transport-scan precision | 100.00% | **UNVERIFIED** — no complete alert-to-labelled-flow attribution |
| Alert false-discovery fraction | 6.51% | **PROVISIONAL** — 262 ARP alerts are unsupported by the capture's reported Layer-2 observations; exact historical initial-state provenance is not preserved |
| Conventional false-positive rate | 0.00% | **NOT CALCULATED** — no valid alert-level TN denominator |
| Scan flow recall | 100.00% | **NOT ESTABLISHED** |
| Trigger-window flow-start overlap | 1.93% (65,243 / 3,386,119) | Descriptive temporal overlap only |
| Cooldown-extended temporal overlap | 100.00% (3,386,119 / 3,386,119) | Descriptive interval overlap only; not detection coverage or recall |
| Suricata EVE alert rows | 85 | Recounted from available EVE; input/run provenance not fully enforced |
| NetGuard runtime / peak RSS | 2,711.11 s / 116.44 MB | Reported from an initial replay log, reused on a later database-reuse path; not independently reproduced by Audit V2 |

## Arithmetic (for inventory only)

`3,765 / 4,027 = 93.4939...%` and `262 / 4,027 = 6.5061...%`.

These ratios are mathematically correct but **must not be presented as precision or false-discovery rates until the classifications are independently substantiated**. The ratio `FP / total alerts`, when valid labels exist, is an alert false-discovery fraction, not conventional FPR.

## Complexity and memory

The source uses bounded `OrderedDict` state in scan rules. Average dictionary lookup/insertion is O(1), while stale pruning and history maintenance have separate costs. The reported 116.44 MB peak RSS is an empirical value attributed to the initial replay; it is not a formal proof that all engine memory is O(1) or bounded independently of every configuration and workload.

## Required before reinstating accuracy claims

1. Export per-alert packet evidence and all contributing Zeek UIDs.
2. Match direction, endpoints, protocol, ports, packet timestamps/retransmissions and publisher labels.
3. Prove each alert's rule threshold from independently reconstructed contributing packets.
4. Retain ambiguous/mixed cases as unassessed.
5. Calculate denominators from the resulting auditable classifications.
6. Reproduce input hashes, run manifests and benchmark measurements.
