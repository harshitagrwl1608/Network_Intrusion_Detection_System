# NetGuard IDS Engine Handoff

This file is a working handoff for the next engineer or AI agent. It summarizes the current engine, completed work, reproducible checks, comparison limits, and a disciplined next-cycle plan. Treat all detections as heuristic leads unless validated against labelled ground truth.

## Current project state

- Repository: `/home/harshitgarg/Downloads/Networking_Project`
- Engine package: `ids_project/`
- At handoff creation, the checkout was clean on `main`, at `3630ce54e46b2e5f3520043e7dd557d09dcce95e` (`update`), tracking `origin/main`.
- The current engine registers **19 rule instances** in `RuleEngine.rules` (including `UdpScanRule`, which subclasses `PortScanRule`). This is different from the number of individual DPI signatures inside `PayloadRule` and DNS sub-detections.
- Dashboard/UI work is out of scope for the current improvement effort.
- Never test with live capture. Use saved PCAPs and isolated output paths. Do not execute malware found in captures.

## What has been added or tuned

The earlier cycles are documented in the repository-level [`OVERNIGHT_STATUS.md`](../OVERNIGHT_STATUS.md). That report covers the initial engine reliability work and cycles through TCP zero-window detection. The latest changes in commit `3630ce5` add/refine the following:

- **Offline PCAP replay and parsing:** stream binary PCAP records instead of loading the entire capture at once; retain useful TCP/DNS metadata in normalized packet records; parse DNS qtype and TCP window data; avoid malformed or truncated input crashes.
- **State and performance controls:** bound long-lived state, use sliding windows and cooldowns, deduplicate repeated RST segments and repeated payload findings, and avoid repeatedly counting the same observations as fresh evidence.
- **Rule tuning from real traffic review:** raise UDP flood threshold for web/QUIC ports to reduce burst-related noise while retaining the lower threshold on other UDP services; exempt DNS SRV queries from length-only tunneling suspicion; scope DNS entropy allowlist handling narrowly; deduplicate payload alerts by source/destination service and signature.
- **New `CLEAR_HTTP_ON_TLS_PORT` rule:** identifies repeated plaintext HTTP request lines on TCP 443/8443. It requires repeated requests and is rate-limited. It detected recurring cleartext C2 traffic in the ClickFix capture; it is a heuristic and can also indicate unusual but benign service configuration.
- **Suricata agreement comparator:** improved matching for recognized TCP scan families, and tests/documentation clarify that Suricata is a comparison baseline, not ground truth.
- **Regression coverage:** added/updated tests for the above rules, DNS/ARP behavior, PCAP parsing, TCP zero-window, UDP flood and agreement matching.

### Current rule inventory (19 registered)

`BLOCKLIST`, `TCP_FLAG_ANOMALY`, `PORT_SCAN`, `UDP_SCAN`, `UDP_FLOOD`, `TCP_STEALTH_SCAN`, `SYN_FLOOD`, `DISTRIBUTED_SYN_FLOOD`, `ICMP_SWEEP`, `ICMP_FLOOD`, `ARP_SPOOF`, `PAYLOAD_HIT`, `DNS_ANOMALY`, `BRUTE_FORCE`, `SLOW_PORT_SCAN`, `DATA_EXFIL`, `TLS_ANOMALY`, `CLEAR_HTTP_ON_TLS_PORT`, and `TCP_ZERO_WINDOW`.

Read the constructors/config defaults in `ids_project/engine/rules.py` and `ids_project/config.py` before changing thresholds. Do not assume a rule name corresponds to one detection signature: `PAYLOAD_HIT` contains multiple signatures, and `DNS_ANOMALY` covers several DNS heuristics.

## Latest verification

Results verified during the current continuation on 2026-10-22:

- Full test suite: **248 passed** (`python -m pytest -q -p no:cacheprovider`). The `no:cacheprovider` option avoids pytest trying to write cache files into the repository.
- Synthetic evaluation: **37/37 labelled scenarios detected; 0 missed scenarios; 0 unmatched attack alerts; 0 alerts on the benign fixture.** These are fixture results only and do **not** imply 100% real-world accuracy.
- All 1,159 synthetic attack packets and 806 benign packets were replayed; alert persistence checks reported no dropped/spooled alerts or shutdown timeout.
- `git diff --check` was clean at inspection.
- The sandbox denied Scapy's local interface enumeration during import. Re-running the offline tests/evaluation with an approved elevated process succeeded; Scapy did not perform live capture. If this happens in another environment, preserve offline-only operation and use the platform's approved test permissions.

## External sample captures and Suricata comparison

Previously downloaded public malware-traffic-analysis.net captures and associated artifacts were in `/tmp` (verify they still exist before use):

- `/tmp/netguard-samples-20251229/2025-12-29-ClickFix-page-sends-NetSupportRAT.pcap` (~41 MB, 52,602 packets)
- `/tmp/netguard-samples-20251230/2025-12-30-Lumma-Stealer-infection-with-other-malware.pcap` (~19 MB, 17,013 packets)
- Suricata 8.0.7 was unpacked locally under `/tmp/netguard-suricata`; it was not installed system-wide. Existing outputs were `/tmp/netguard-suricata/clickfix/eve.json` and `/tmp/netguard-suricata/lumma/eve.json`.

Prior completed comparison notes (re-check against artifacts if relying on them):

- ClickFix: Suricata emitted 707 alerts, mostly built-in HTTP app-layer/parser warnings plus one local broad-SYN alert. NetGuard, after tuning, emitted 10 alerts: 9 `CLEAR_HTTP_ON_TLS_PORT` and one long-domain DNS heuristic.
- Lumma: Suricata emitted one local broad-SYN alert. NetGuard emitted 3 alerts after deduplication/tuning (`DATA_EXFIL`, `PAYLOAD_HIT`, `TCP_ZERO_WINDOW`).
- The strict comparator had no exact matches in that run. There was endpoint-level overlap for the repeated cleartext HTTP/C2 endpoint on ClickFix, but strict timestamps/event semantics did not align. This is **not** proof either engine is correct or incorrect.
- These local Suricata runs used built-in event rules and a local broad-SYN rule, not Emerging Threats or another threat-feed ruleset. Do not describe them as a full ET comparison.

Public sample sources referenced in the earlier review:

- ClickFix / NetSupport RAT analysis: <https://www.malware-traffic-analysis.net/2025/12/29/index.html>
- Lumma Stealer analysis: <https://www.malware-traffic-analysis.net/2025/12/30/index.html>

Captured traffic can include malware payloads and personal/environment identifiers. Keep it isolated, do not execute payloads, and report only the minimum relevant packet/flow metadata.

## Reproducing checks

Run from `ids_project/`:

```bash
python -m pytest -q -p no:cacheprovider
python evaluation/run_eval.py --no-generate
git diff --check
```

The evaluator creates isolated temporary databases and replays the checked-in synthetic fixtures. Verify the fixture and label versions are aligned before relying on scenario counts.

For an offline comparison against an existing Suricata EVE file, use a fresh temporary directory and the saved PCAP. For example:

```bash
tmpdir=$(mktemp -d /tmp/netguard-review.XXXXXX)
python evaluation/replay.py \
  --pcap /tmp/netguard-samples-20251229/2025-12-29-ClickFix-page-sends-NetSupportRAT.pcap \
  --blocklist data/test_blocklist.txt \
  --db "$tmpdir/netguard.db" \
  --arp-table "$tmpdir/arp.json"
python evaluation/compare.py --mode agreement \
  --eve /tmp/netguard-suricata/clickfix/eve.json \
  --db "$tmpdir/netguard.db"
```

Repeat with the Lumma PCAP and its EVE file. Check first that the artifacts exist and that the EVE output was produced from the exact same PCAP. Use the explicit `--db` path; never let an evaluation touch the normal application database or ARP table. Comparison reports agreement/disagreement only. For accuracy claims, use independent labels and document their provenance.

## Where work left off

The latest DNS length alert in ClickFix is the 52-character label `n-4sunmu52cohwy5upiytnab27jzxtriwpjwcvdey-0lu-script.googleusercontent.com`. The local `.env` sets `DNS_QUERY_MAX_LEN=50` (the code default is 60; preserve the user's override). Offline `tshark` inspection found HTTPS/SVCB (qtype 65) and A (qtype 1) queries within 2 microseconds; the A response arrived about 46 ms later with `142.250.138.132`. This is consistent with a Google-hosted script/asset and suggests a length-only false positive, but does not prove the broader campaign benign. Do not blanket-allow the suffix: assess narrow, evidence-backed tuning using labeled benign long-label examples and DNS-tunnel positives. Repeated cleartext HTTP on TCP/443 also reaches the reported C2 endpoint.

A later ClickFix replay was interrupted and its partial database was discarded; the fresh completed latest-code replay is documented in the 2026-10-22 continuation section below.

## Next work: repeatable test → evaluate → review → implement cycles

For every cycle, keep the change small and evidence-backed:

1. **Orient:** inspect `git status`, recent commits, `OVERNIGHT_STATUS.md`, this handoff, current tests, and current PCAP/label versions. Preserve pre-existing local edits and configuration.
2. **Establish baseline:** run targeted tests, the complete suite, and the synthetic evaluator. Save command output and record the commit, sample hashes, packet counts, and config overrides in a dated cycle note.
3. **Select a concrete discrepancy:** choose a reproducible false positive, missed labelled behavior, parsing defect, state leak, resource issue, or useful coverage gap. Use PCAP metadata and packet-level inspection to form a hypothesis; treat Suricata disagreement as an investigation lead only.
4. **Review evidence:** check timestamps, endpoints, direction, protocol, retransmissions, session semantics, sample provenance, and whether labels actually support the claim. Look for benign counterexamples before lowering thresholds or adding broad signatures.
5. **Add a regression first:** create a focused positive test, a benign/near-miss negative test, and a boundary/state/cooldown test where relevant. Keep raw malware samples out of the repository unless there is a clear, safe reason; small synthetic fixtures are preferred.
6. **Make one targeted change:** prefer parser correctness, protocol-specific guards, bounded state, explicit configuration, deduplication, or precise rule conditions. Document thresholds and their expected trade-offs. Avoid broad allowlists and rules that only memorize one sample.
7. **Re-run and compare:** targeted tests, full test suite, synthetic labeled eval (including benign capture), then the same public/sample PCAP offline in both engines when available. Check replay completeness, persistence, output counts and comparator semantics.
8. **Inspect regressions:** compare per-rule alert deltas and inspect both new alerts and suppressed alerts. Revert or revise a change if the improvement is only a metric artifact or it creates unreviewed blind spots.
9. **Record and hand off:** update a dated cycle note with rationale, files, exact commands, before/after metrics, limitations, next questions, and current repo state. Keep synthetic metrics separate from real-world accuracy claims.

### Suggested investigation priorities

1. Expand the benign fixture with receiver-side zero-window/backpressure cases and add labeled Sockstress-like positives across single and multiple connections.
2. Investigate the long `googleusercontent.com` DNS name with additional labeled benign and tunnel examples. Its current sample queries/responses are documented above; do not blanket-allow the suffix or change the user's `DNS_QUERY_MAX_LEN=50` override without evidence.
3. Exercise the endpoint-family comparator on additional same-PCAP pairs and verify it never changes exact agreement results.
4. Assess state limits and runtime on diverse benign and attack captures. Include IPv6, fragmentation/truncation, retransmission, DNS-over-TCP, long-lived flows, QUIC, and mixed traffic, with labeled expected outcomes where possible.
5. Improve the corpus and labels: expand benign diversity and independent labeled attack samples. Do not optimize rules solely against the small 37-scenario synthetic fixture.

## Evidence cycle: 2026-10-22 continuation

This ongoing cycle started from commit `3973244` and preserved the two untracked `PRESENTATION_GUIDE.md` files. It changed `ids_project/engine/rules.py`, `ids_project/config.py`, `ids_project/.env.example`, `ids_project/evaluation/run_eval.py`, `ids_project/evaluation/generate_test_pcap.py`, the comparator/tests, the benign PCAP fixture, and this handoff. `TCP_ZERO_WINDOW` is now version `1.3`.

### Findings and implementation

- Replayed the 17,013-packet Lumma PCAP through NetGuard and compared it with the existing Suricata 8.0.7 EVE output generated from that same PCAP. NetGuard raised three signals (`PAYLOAD_HIT` for `CREDENTIAL_LEAK`, `TCP_ZERO_WINDOW`, and `DATA_EXFIL`); Suricata raised one local broad-SYN signal on another endpoint. Exact agreement was 0/4 alerts. This is a rule-coverage disagreement, not a correctness verdict.
- Inspected the zero-window packets with `tshark`: they were repeated ACKs with `win=0` from remote `13.201.207.191:443` toward the client. The initial SYN came from the client, so the advertiser was the TCP responder. This can indicate server-side TCP backpressure and is not alone proof of Sockstress. Kept the detection threshold and trigger behavior, but calibrated the alert to medium/heuristic. The rule now tracks bounded initial-SYN state and adds `advertiser_role` (`initiator`, `responder`, or `unknown`) to alert evidence; it ignores SYN packets as zero-window samples, records without TCP flags, and RST packets. Tests cover role classification, SYN/RST exclusion and confidence. The latest Lumma replay processed 17,013/17,013 packets, raised the same three alerts, persisted all three, and identified `advertiser_role=responder`.
- ClickFix comparison: a fresh full NetGuard replay on the role-aware latest code at `/tmp/netguard-clickfix-role.7ZLIwU/clickfix.db` processed 52,602/52,602 packets, persisted 10 alerts with no drops/timeouts, and compared against the matching Suricata EVE file containing 707 alerts. Strict timestamp/event agreement remains 0. The separate endpoint/family metric records `CLEAR_HTTP_ON_TLS_PORT` and Suricata HTTP parser warnings on `10.12.29.101 → 185.39.19.96:443` (9 NetGuard events, 694 Suricata parser events). Their timestamps/aggregation differ substantially, so this is explicitly not counted as an exact match. The earlier interrupted replay's partial DB is not used.
- The long DNS label `n-4sunmu52cohwy5upiytnab27jzxtriwpjwcvdey-0lu-script.googleusercontent.com` resolved through `googlehosted.l.googleusercontent.com` to a Google IP and produced one length heuristic. This can be an Apps Script-style host; the suspicious campaign context means a broad suffix allowlist is not justified. No DNS rule change was made.
- Review of S37 showed the generated positive distributed its 25 zero-window packets across five TCP source ports. The old rule aggregated all packets by IP pair and advertiser role, so it could also combine a burst from only two unrelated flows. The refined rule preserves persistent single-flow detection (at least 20 packets on one flow), but requires at least `TCP_ZERO_WINDOW_MIN_FLOWS` distinct 4-tuples (default 3) before aggregating a multi-flow burst. Alerts now report `single_flow` or `multi_flow`, total distinct flows, and maximum packets on one flow. The new configuration is included in `.env.example` and evaluation metadata. Tests cover a positive single flow, a positive three-flow burst, and a negative two-flow aggregate. Added a deterministic benign PCAP scenario with two established connections and 20 responder-side zero-window ACKs; regenerated benign capture grew from 806 to 832 packets. The attack PCAP remains byte-identical (1,159 packets) and labels remain 37 scenarios.
- Latest Lumma replay with this change: 17,013/17,013 packets, 3 NetGuard alerts versus 1 Suricata alert; the zero-window alert remains and reports 20 packets on one flow (`single_flow`, `responder`, medium/heuristic). Exact Suricata agreement remains 0/4, with no mapped endpoint-family overlap.
- Latest ClickFix replay with this change: 52,602/52,602 packets, 10 NetGuard alerts versus 707 Suricata alerts; strict agreement remains zero, with the same separate HTTP endpoint-family overlap of 9 NetGuard events and 694 Suricata parser events.
- Synthetic evaluation after the changes: 37/37 labelled scenarios, 0 unmatched attack alerts and 0 benign alerts, including the new two-flow backpressure traffic. Full test suite after all changes: 259 passed. These fixture metrics are not real-world accuracy estimates.

### Threshold sensitivity check: two-flow backpressure

A controlled sensitivity run over the same 37-scenario attack PCAP and expanded benign PCAP set `TCP_ZERO_WINDOW_MIN_FLOWS=2` only in the process environment (no saved configuration changed). Attack detection stayed at 37/37 with zero unmatched attack alerts, but the benign fixture raised one `TCP_ZERO_WINDOW` false positive: 20 responder-side zero-window ACKs split across two established flows. The benign replay processed all 832 packets; alert persistence reported no drops. This directly exercises the reason the default is 3: at two, ordinary receiver backpressure can satisfy the aggregate threshold. Keep the default at 3 unless independently labelled traffic demonstrates a better trade-off. The run is a synthetic boundary test, not a real-world precision estimate.

### Comparator behavior change

`evaluation/compare.py` now prints `endpoint_correlations` separately from strict event matches. It recognizes the cleartext-HTTP-on-TLS-port rule against Suricata HTTP parser alerts on ports 443/8443, and the existing recognized TCP scan families. It requires the same source, destination, destination port, protocol, and mapped family, but deliberately ignores timestamps. These rows are review cues only and do not affect the agreement percentage or `both`/`only` lists. Two regression tests cover distant timestamps and a mismatched service port. For the ClickFix endpoint above, this reveals overlap that the strict event metric could not communicate without weakening exact match criteria.

Commands/results for this cycle:

```bash
python -m pytest -q -p no:cacheprovider
# 259 passed
python evaluation/run_eval.py --no-generate
# synthetic: 37/37 TP; 0 FN; 0 unmatched attack alerts; 0 benign alerts
python evaluation/replay.py --pcap /tmp/netguard-samples-20251230/2025-12-30-Lumma-Stealer-infection-with-other-malware.pcap --blocklist data/test_blocklist.txt --db /tmp/<fresh-dir>/lumma.db --arp-table /tmp/<fresh-dir>/lumma-arp.json
python evaluation/compare.py --mode agreement --eve /tmp/netguard-suricata/lumma/eve.json --db /tmp/<fresh-dir>/lumma.db
python evaluation/compare.py --mode agreement --eve /tmp/netguard-suricata/clickfix/eve.json --db /tmp/netguard-clickfix-role.7ZLIwU/clickfix.db
```

The temp paths are examples; use a new directory for each run. The test/evaluation commands required approved local interface enumeration by Scapy in the restricted environment; they replayed stored files and did not perform live capture.

### Next cycle leads

1. Expand the benign fixture with receiver-side zero-window/backpressure cases and multi-flow Sockstress-like positives, then evaluate precision/recall trade-offs with labels.
2. Evaluate whether initiator/responder context improves precision on independently labelled samples; do not increase severity unless evidence establishes malicious context.
3. Add more diverse, independently labelled traffic and repeat same-PCAP Suricata comparisons. Investigate parser coverage gaps instead of treating rule disagreement as false positives/negatives.
4. Preserve the new separation between strict event agreement and time-agnostic endpoint-family review; never call endpoint overlap an exact detection match.

## Evidence cycle: 2026-10-22 DATA_EXFIL byte accounting

This cycle followed the existing-rule-only constraint: no detection rule was added. It started from the working tree after the zero-window two-flow sensitivity check.

### Finding and implementation

- Review of `DataExfiltrationRule` found its volume estimate used `max(len(payload), ip_len - 40)`. A fixed subtraction could count TCP options as data and overcount IPv6 headers; it could also mask the packet parser's `PAYLOAD_MAX_BYTES` cap by treating packet length as application bytes.
- `capture/sniffer.py` now records `payload_len`, the full captured transport-payload length before the DPI sample cap. TCP, UDP, and ICMP records expose it; the bounded `payload` field remains available for DPI. `DATA_EXFIL` version 1.3 uses this field, falling back to the actual supplied payload length for legacy records, and no longer estimates application bytes from IP length. Alert evidence records `byte_count_basis=captured_packet_payload`.
- Regression tests cover header-only IPv4/TCP option packets and IPv6/TCP headers, full payload length when the DPI sample is capped, TCP/UDP parser extraction, and existing positive volume/archive-signature behavior.

### Verification

- Focused parser and rule tests: **28 passed**.
- Full suite: **263 passed** in 59.41s.
- Synthetic evaluation (`python evaluation/run_eval.py --no-generate`): **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**. These are fixture-only results.
- ClickFix latest-code replay: **52,602/52,602 packets**, 10 NetGuard alerts, no alert drops or shutdown timeout. Compared to the same-capture Suricata 8.0.7 EVE with 707 alerts: 0 strict event matches; separate time-agnostic endpoint/family correlation is 9 NetGuard `CLEAR_HTTP_ON_TLS_PORT` alerts to 694 Suricata HTTP parser events on `10.12.29.101 → 185.39.19.96:443`. Suricata's events are primarily HTTP parsing anomalies, not 694 distinct independent malicious actions.
- Lumma latest-code replay: **17,013/17,013 packets**, 3 NetGuard alerts, no alert drops or shutdown timeout. Compared to the same-capture Suricata EVE with one local broad-SYN alert: 0 strict matches and no shared mapped endpoint family. NetGuard's `DATA_EXFIL` alert on `10.12.30.101 → 13.201.207.191:443` reports **1,000,296 bytes in 30s**. An independent `tshark` sum of TCP payload lengths over the same alert window and endpoint also reports exactly **1,000,296 bytes**; sequence overlap was 4 bytes across the entire capture for this endpoint. The event is only 296 bytes above the configured 1,000,000-byte web threshold, so review independent benign examples before changing that threshold.
- Sample PCAP SHA-256: ClickFix `7b18868c20aff09e15c6bc68806a304b45af6f33d4776834238388a0666c660f`; Lumma `312282fe0e3cbd877066d024de61ec1ffc3fac57d7a9ed2dbd254a99b1060ba7`. Suricata EVE files were already verified as complete for these PCAPs (52,602 and 17,013 packets). It used bundled app-layer event rules and a local broad-SYN signature, not an ET threat-feed ruleset.

### Current artifacts and next review

- Current fresh public-sample databases: `/tmp/netguard-cycle-v14.EHtKG3/clickfix.db` and `/tmp/netguard-cycle-v14.EHtKG3/lumma.db`. The synthetic fragmentation comparison is under `/tmp/netguard-fragment-eval.6YUraw/`.
- Keep auditing TCP retransmission and multi-connection aggregation behavior, especially for thresholds crossed by small margins. Suricata disagreement remains a coverage lead, not a ground-truth verdict.

## Evidence cycle: 2026-10-22 fragmented payload accounting

This cycle continued the existing `DATA_EXFIL` rule only; no new detection rules were added.

### Finding and implementation

- Packet inspection showed that non-initial IPv4/IPv6 fragments have no transport ports for Scapy to dissect. The previous payload-length fix therefore counted the initial fragment but missed continuation-fragment bytes, and IPv6 non-initial fragments were labelled with the fragment-extension protocol number rather than TCP/UDP.
- `capture/sniffer.py` now preserves fragment ID, byte offset, more-fragments state, and full captured payload length for non-initial fragments. IPv6 Fragment headers are resolved to their underlying transport protocol.
- `DATA_EXFIL` version 1.4 maps fragment IDs back to the service port learned from the initial fragment. It buffers out-of-order continuation fragments until the initial fragment arrives, then merges their byte counts into the service window. Fragment mapping and orphan queues expire with the rule window and are bounded to prevent state exhaustion. IPv4, IPv6, ICMPv6 echo payloads, and full payload lengths beyond the DPI sample cap are covered by parser tests.

### Verification

- Focused parser/rule tests: **35 passed**.
- Full suite: **270 passed** in 59.37s.
- Synthetic evaluation: **37/37 labeled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**. These metrics describe only the checked-in fixtures.
- A separate synthetic PCAP containing 28 fragmented packets across IPv4 and IPv6 (four 250-byte transport payloads per address family) was replayed through both engines. With a temporary `DATA_EXFIL_BYTE_THRESHOLD=1000`, NetGuard processed 28/28 packets and raised one exact 1,000-byte alert per destination service. Suricata processed the same file and emitted zero alerts under the bundled app-layer event rules and local broad-SYN signature. This is expected rule-coverage disagreement; the local Suricata rules do not include a volumetric exfiltration signature. Artifacts are isolated under `/tmp/netguard-fragment-eval.6YUraw/`.
- `tshark` confirmed neither public sample contains IP fragments or outbound IPv6 echo payloads. Fresh complete replay on current version 1.4 processed ClickFix **52,602/52,602 packets** and Lumma **17,013/17,013 packets**, with no alert drops or shutdown timeouts. Same-PCAP comparisons remained ClickFix 10 NetGuard vs 707 Suricata alerts, with the separate 9-to-694 HTTP endpoint-family correlation, and Lumma 3 vs 1 with no overlap. Strict exact matches remain zero. The Lumma 30-second payload sum was independently verified at 1,000,296 bytes.

### Next review

- Add benign, labeled fragmented-transfer examples before tuning thresholds further.
- Review repeated TCP-sequence and overlapping-fragment accounting in `DATA_EXFIL`; the Lumma volume signal sits just above threshold, though `tshark` matched its current captured-byte sum and found only 4 bytes of sequence overlap across that endpoint for the full sample.
- Keep Suricata comparisons on identical PCAPs and state its rule-set scope. Do not interpret engine disagreement as ground truth.

## Evidence cycle: 2026-10-22 exact retransmission accounting

This cycle tuned existing `DATA_EXFIL`; it did not add a rule.

### Finding and implementation

- `tshark` identified TCP retransmission events in both public captures: ClickFix had 717 total (9 client-to-server and 708 server-to-client), while Lumma had one client-to-server retransmission to `172.67.152.119:443`. The Lumma `DATA_EXFIL` target is `13.201.207.191:443`, so its volume event is not explained by that retransmission.
- Packet normalization now emits a 128-bit BLAKE2s fingerprint of each complete TCP payload and of fragment data. `DATA_EXFIL` version 1.5 uses sequence number, direction, payload length and fingerprint to suppress exact TCP-segment repeats. Exact duplicate fragments are also suppressed using fragment ID, offset, length and fingerprint. A same-sequence segment with different bytes is still counted. The fingerprint cache is bounded to 50,000 observations and expires by the existing rule window.
- Partial sequence overlaps and differently fragmented retransmissions are not deduplicated yet. This is explicit in alert evidence; do not interpret the reported count as TCP stream reassembled unique bytes. Exact suppression is limited to repeats that can be proven from the normalized metadata.

### Verification

- Focused parser and rule tests: **38 passed**.
- Full suite after the final code and evidence-string/version edits: **273 passed** in 59.96s.
- Synthetic evaluation after retransmission logic and the final code edits: **37/37 labeled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**. These are fixture-only results.
- Fresh current-code (`DATA_EXFIL` v1.5) public sample replays: ClickFix **52,602/52,602**, 10 alerts, no drops/timeouts; Lumma **17,013/17,013**, 3 alerts, no drops/timeouts. Same-PCAP Suricata comparisons: ClickFix 707 alerts with 0 strict matches and a separate 9-to-694 HTTP endpoint-family correlation; Lumma 1 alert with 0 strict matches/no endpoint-family overlap. Fresh databases are `/tmp/netguard-cycle-v15.uLHKH9/clickfix.db` and `/tmp/netguard-cycle-v15.uLHKH9/lumma.db`.
- The current Lumma DB confirms the `DATA_EXFIL` alert is version **1.5**, still reports 1,000,296 bytes (the independent `tshark` payload-length sum for that endpoint/window), with evidence identifying exact TCP-segment/IP-fragment duplicate suppression and explicitly noting partial overlaps remain counted. The only observed client-origin retransmission in the Lumma capture was to a different endpoint, not the exfil destination.

### Next review

- Decide whether partial TCP overlap should be removed from byte totals. First build tests for contained/partial overlap, wraparound, out-of-order delivery, connection reuse and bounded state; compare runtime on the 52,602-packet capture before using a more complex interval tracker.
- Add independent labeled benign uploads before retuning the 1,000,000-byte web threshold. Do not add a detection rule.

## Evidence cycle: 2026-10-22 DNS length heuristic tuning

This cycle tuned the existing `DNS_ANOMALY` rule only; the rule inventory remains 19 instances.

### Finding and implementation

- The length signal measured the entire dotted QNAME. That treats separator dots and ordinary registered-domain labels as if they were tunnel data, so a hostname can cross the threshold without any individually long label.
- `DNS_ANOMALY` version 1.8 now measures the longest individual DNS label and reports that label and its length as evidence. Existing entropy, hex-chunk, frequency, subdomain-volume checks and CDN entropy exemptions are unchanged. The `DNS_QUERY_MAX_LEN` comments now describe the per-label behavior.
- Added regression cases for a 62-character FQDN composed of labels no longer than 23 characters (no length alert at a threshold of 60) and a 61-character single label (alert with label-level evidence). No rule was added.

### Verification

- Focused DNS/ARP suite: **20 passed**.
- Full suite after this tuning, including structured label evidence: **275 passed** in 56.16s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 missed, 0 unmatched attack alerts, 0 benign alerts**. These are checked-in fixture results only.
- Fresh public-sample replay with the current local configuration: ClickFix **52,602/52,602**, 10 alerts; Lumma **17,013/17,013**, 3 alerts; no drops or shutdown timeouts. A final ClickFix replay after adding structured evidence confirms the DNS alert remains present under the configured 50-character threshold and identifies the exact 52-character label; the other nine alerts are cleartext HTTP events.
- Same-PCAP Suricata comparisons: ClickFix NetGuard 10 vs Suricata 707 alerts, 0 strict matches, and 9-to-694 HTTP endpoint-family correlation; Lumma NetGuard 3 vs Suricata 1, 0 strict matches/endpoint-family overlap. Suricata outputs use bundled app-layer events plus a local broad-SYN rule, not a threat-feed ruleset; disagreement is not ground truth.
- Databases and logs: final ClickFix replay `/tmp/netguard-cycle-dns18-final.Fxi80x/`; earlier same-code Lumma replay `/tmp/netguard-cycle-dns18.k3JltS/` (the final follow-up only added structured DNS evidence fields and does not alter Lumma detection behavior).

### Remaining limitation

- A long QNAME made of several short labels will no longer trigger the length heuristic by itself. Entropy, hex-chunk, repeated-query and distinct-subdomain signals remain active. Validate this tradeoff with independently labelled benign and tunnel captures before changing the threshold further.

## Evidence cycle: 2026-10-22 TCP zero-window handshake filtering

This cycle tuned the existing `TCP_ZERO_WINDOW` rule only; no detection rule was added.

### Finding and implementation

- The rule already ignored initial SYN packets but its ACK/window check could still count a zero-window SYN-ACK. A window advertised during the handshake is negotiation state, not evidence of sustained established-flow backpressure.
- `TCP_ZERO_WINDOW` version 1.4 now excludes every SYN-bearing packet from zero-window counts while retaining initial SYN direction learning. Added a regression that sends 30 zero-window SYN-ACKs and verifies neither history nor alerts are created.

### Verification

- Focused TCP zero-window tests: **17 passed**.
- Full suite after the change: **276 passed** in 55.96s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**.
- `tshark` found **0 zero-window SYN-ACK packets** in both public samples, so this filter should not alter their existing alerts. Fresh current-code replays confirmed ClickFix **52,602/52,602**, 10 alerts, and Lumma **17,013/17,013**, 3 alerts, with no drops/timeouts.
- Same-PCAP Suricata comparisons remained ClickFix 10 vs 707 alerts (0 strict matches; 9-to-694 HTTP endpoint-family correlation) and Lumma 3 vs 1 (0 strict matches/endpoint-family overlap). Suricata remains a comparison baseline, not ground truth.
- Fresh databases and replay/comparison logs: `/tmp/netguard-cycle-tcp14.Bsvw5F/`.

### Next review

- Continue review of partial TCP overlap in existing `DATA_EXFIL`. Prior Lumma inspection found only four overlapping sequence bytes across the full capture, so design the state tracker against synthetic partial/contained-overlap, wraparound, out-of-order, and connection-reuse cases before changing production accounting. Compare runtime and memory on both public captures. Do not add a rule.

## Evidence cycle: 2026-10-22 DATA_EXFIL tuple-reuse deduplication

This cycle continued tuning existing `DATA_EXFIL`; it did not add a rule.

### Finding and implementation

- A regression test reproduced an undercount: when the same TCP 4-tuple was reused inside the 30-second window and a new connection repeated the same sequence, length and bytes, the exact-segment cache treated the new transfer as a retransmission.
- `DATA_EXFIL` version 1.6 tracks a bounded generation per canonical TCP endpoint pair. An initial SYN with a new sequence advances the generation; a repeated SYN with the same sequence keeps it. Exact-segment fingerprints now include that generation. Late SYNs cannot roll active state backward. The generation map is bounded to 5,000 entries and pruned with the rule window.
- Added tests for tuple reuse, repeated SYN retransmission, late old SYNs, malformed TCP flags, and the generation-state bound. Existing partial overlaps are still counted; this change only distinguishes exact retransmissions across connection incarnations.

### Verification

- Focused `DATA_EXFIL` tests: **26 passed**.
- Full suite after generation-state optimization and malformed-metadata guard: **279 passed** in 59.47s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**.
- Fresh v1.6 replay before the final malformed-flag fallback: ClickFix **52,602/52,602**, 10 alerts; Lumma **17,013/17,013**, 3 alerts; no drops/timeouts. The final fallback only handles invalid synthetic flag metadata; parsed PCAP flags are integers. The Lumma `DATA_EXFIL` alert remains **1,000,296 bytes** and reports version 1.6, so tuple-generation tracking did not alter the observed sample result.
- Same-PCAP Suricata comparisons: ClickFix NetGuard 10 vs Suricata 707 alerts, 0 strict matches and 9-to-694 HTTP endpoint-family correlation; Lumma NetGuard 3 vs Suricata 1, 0 strict matches/endpoint-family overlap. Suricata outputs use bundled app-layer events plus a local broad-SYN rule, not a threat-feed ruleset.
- Fresh final-code databases and comparison logs: `/tmp/netguard-cycle-data16-final.tarzRD/`.

### Remaining limitation

- TCP partial overlaps and differently segmented retransmissions remain in the byte total. Before changing this, test bounded range accounting for partial/contained overlaps, 32-bit wraparound, out-of-order segments, tuple reuse and state eviction; compare time and memory against the current exact-fingerprint approach on both PCAPs.
- The parser currently emits a full-segment digest, not per-byte overlap proof. Blindly subtracting every intersecting TCP sequence byte could undercount different payload content sent at reused sequence positions. Preserve the current conservative count until the design either verifies overlapping bytes or explicitly defines the metric as unique sequence-space bytes.

## Evidence cycle: 2026-10-22 DATA_EXFIL byte-count evidence precision

This cycle clarified the evidence emitted by the existing rule; no detection rule was added and the 19-rule inventory is unchanged.

### Finding and implementation

- The rule suppresses exact TCP-segment/IP-fragment retransmissions, but labeled its alert basis simply `captured_payload_bytes`. That could be read as the raw sum of every captured payload despite exact duplicate suppression.
- `DATA_EXFIL` version 1.7 now reports `captured_payload_bytes_after_exact_duplicate_suppression` and a separate `partial_tcp_overlaps_counted` evidence flag. No threshold or alert decision changed.
- A byte-level review of the Lumma `DATA_EXFIL` 30-second window compared captured TCP payload bytes against per-source-port TCP sequence ranges: **1,000,296 captured bytes**, **1,000,295 unique sequence bytes**, one overlapping byte, identical content, zero conflicting bytes. Even subtracting that byte leaves the event 295 bytes above the 1,000,000-byte threshold. This is sample-specific evidence, not enough to justify blind overlap subtraction for arbitrary payloads.

### Verification

- Focused `DATA_EXFIL` tests: **26 passed**.
- Full suite: **279 passed** in 58.87s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**.
- Final v1.7 public-sample replay: ClickFix **52,602/52,602**, 10 alerts; Lumma **17,013/17,013**, 3 alerts; no drops/timeouts. The Lumma database confirms version 1.7, 1,000,296 bytes, the corrected basis string and `partial_tcp_overlaps_counted=true`.
- Same-PCAP Suricata comparison: ClickFix 10 vs 707 alerts, 0 strict matches and 9-to-694 HTTP endpoint-family correlation; Lumma 3 vs 1, 0 strict matches/endpoint-family overlap. Suricata remains a comparison baseline, not ground truth.
- Databases and comparison logs: `/tmp/netguard-cycle-data17.H366ZS/`.

### Next review

- Keep overlap accounting conservative until a bounded design can verify partial byte content, handle 32-bit wraparound, out-of-order data, connection reuse and state eviction, and stay within acceptable replay cost. Do not add a rule or retune the web threshold from this one alert.

## Evidence cycle: 2026-10-22 nested DNS subdomain coverage

This cycle improved the existing `DNS_ANOMALY` subdomain-exfiltration signal; no rule was added and the engine remains at 19 registered rules.

### Finding and implementation

- The `DNS_EXFIL` distinct-subdomain counter used only `labels[0]`. Queries shaped like `host.<changing-chunk>.evil.com` therefore all appeared to have the same subdomain (`host`) and escaped the distinct-subdomain threshold.
- `DNS_ANOMALY` version 1.9 now tracks the full prefix before the rule's registrable-domain boundary, such as `host.chunk0004` under `evil.com`. The alert evidence's `subdomain` field now reports this full prefix. Parent grouping, windows, thresholds and other anomaly checks are unchanged.
- Added a regression with five changing nested chunks under a fixed `host` label and a stable parent; it now reaches `DNS_EXFIL`. Existing one-label and entropy cases were adjusted to assert the expanded evidence semantics.

### Verification

- Focused DNS/ARP and DNS subdomain tests: **27 passed**.
- Full suite: **280 passed** in 59.10s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**.
- Fresh v1.9 replay: ClickFix **52,602/52,602**, 10 alerts; Lumma **17,013/17,013**, 3 alerts; no drops/timeouts. ClickFix still has one `DNS_ANOMALY` alert (same long-label event); no new nested-subdomain event appeared in either sample.
- Same-PCAP Suricata comparisons unchanged: ClickFix 10 vs 707 alerts, 0 strict matches and 9-to-694 HTTP endpoint-family correlation; Lumma 3 vs 1, 0 strict matches/endpoint-family overlap. Suricata output is a comparison baseline, not ground truth.
- Fresh databases and comparison logs: `/tmp/netguard-cycle-dns19.AaHObw/`.

### Remaining limitation

- The existing public captures do not contain enough distinct nested DNS subdomains to validate a real exfiltration case. The added positive is synthetic; obtain independently labeled DNS tunnel and benign nested-hostname samples before tuning this threshold.

## Safety and reporting constraints

- Offline replay only; no live packet capture.
- Do not fetch threat-feed data or execute contents from malware PCAPs.
- Keep temporary databases, ARP tables, EVE output and downloaded samples isolated under `/tmp`.
- Preserve `.env`, local blocklists, ARP tables, databases and user configuration. Prefer test-specific blocklists.
- Suricata is a useful comparative IDS baseline, not ground truth. Synthetic benchmark percentages are not deployment accuracy estimates.
- The scheduled NetGuard improvement heartbeat was stopped at the user's request. Continue only when the user or an explicitly authorized follow-up asks for work.

## Evidence cycle: 2026-10-22 BRUTE_FORCE SYN retransmission suppression

This cycle tuned the existing `BRUTE_FORCE` rule only. No rule was added; the inventory remains 19 registered rules.

### Finding and implementation

- A focused regression reproduced that a retransmitted initial SYN could be counted as another authentication attempt when packet records included TCP sequence metadata.
- `BRUTE_FORCE` version 1.2 now suppresses a repeated SYN only when source/destination addresses, both ports, and the 32-bit TCP sequence number match within the configured detection window. A different sequence on the same 4-tuple remains a distinct attempt. If sequence/port metadata is missing or malformed, the record follows the prior counting behavior rather than being silently discarded.
- The retransmission identity cache is protected by the rule lock, pruned with the detection window, and independently bounded (up to 50,000 identities, scaled from `max_states`). Added a bound regression alongside the retransmission/new-attempt test.

### Verification

- Focused `BRUTE_FORCE` tests: **12 passed**.
- Full suite: **282 passed** in 47.91s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts and 0 benign alerts**. Both attack (1,159 packets) and benign (832 packets) replays completed with no dropped alerts or shutdown timeout. These synthetic fixture values are not real-world accuracy estimates.
- Fresh ClickFix replay: **52,602/52,602 packets**, 10 alerts, no drops/timeouts. Compared with its matching Suricata 8.0.7 EVE: 707 alerts, 0 strict event matches, and separate time-agnostic HTTP endpoint-family correlation of 9 NetGuard events to 694 Suricata parser events at `10.12.29.101 → 185.39.19.96:443`.
- Fresh Lumma replay: **17,013/17,013 packets**, 3 alerts, no drops/timeouts. Compared with its matching Suricata EVE: 1 alert, 0 strict matches and no mapped endpoint-family overlap. The NetGuard output remains `PAYLOAD_HIT`, `TCP_ZERO_WINDOW`, and `DATA_EXFIL`.
- The public samples contain no `BRUTE_FORCE` event, so this tuning did not change their per-rule output. Suricata is a comparison baseline, not ground truth; its EVE outputs here contain built-in app-layer events and the local broad-SYN signature, not a threat-feed ruleset.
- Temporary replay databases and logs: `/tmp/netguard-cycle-bruteforce12.NneAeW/`.
- `git diff --check` is clean. Existing user changes and both untracked `PRESENTATION_GUIDE.md` files were preserved.

### Remaining limitation / next cycle

- Retransmission suppression requires sequence metadata. When it is absent, the rule retains the previous conservative count behavior. Add malformed/wraparound sequence cases if parser behavior changes, and retain coverage for out-of-order timestamps, cache expiry and bound eviction.
- Next, inspect a different existing rule for a reproducible state or threshold defect. Do not add rules. Keep offline replay and Suricata comparison on the same captures, with agreement differences treated as review leads rather than ground truth.

## Evidence cycle: 2026-10-22 DNS query retry accounting

This cycle tuned the existing `DNS_ANOMALY` frequency heuristic only. No rule was added; the engine still registers 19 rules.

### Finding and implementation

- The packet parser retained DNS question name and type but discarded the 16-bit transaction ID. As a result, an unanswered query retransmitted with the same ID and question was counted as a second lookup and could satisfy `DNS_FREQ` prematurely.
- The parser now preserves `dns_id` for UDP and TCP DNS questions. `DNS_ANOMALY` version 1.10 uses it with source/destination endpoints, ports, qtype, and normalized qname to suppress only exact transaction retries inside a 2-second retry interval. New IDs count as new queries. Records lacking complete transaction metadata keep the prior behavior.
- The retry cache is lock-protected, bounded from the frequency-state limit (up to 50,000 entries), and stale entries are pruned. Other DNS checks (entropy, label length, hex chunks, and distinct subdomains) are unchanged.
- Added regression coverage for same-ID retry, a new-ID query, retry-window expiry, bounded cache state, and parser extraction over TCP.

### Verification

- Full suite: **285 passed** in 48.40s.
- Synthetic evaluation: **37/37 labelled scenarios detected; 0 FN, 0 unmatched attack alerts, 0 benign alerts**. Attack (1,159 packets) and benign (832 packets) PCAP replays completed without alert drops or shutdown timeout. Fixture results are not real-world accuracy estimates.
- Fresh ClickFix replay: **52,602/52,602 packets**, 10 alerts, no drops/timeouts. Same-PCAP Suricata comparison: 707 alerts, 0 strict matches, and the separate HTTP endpoint-family correlation remains 9 NetGuard to 694 Suricata parser events on `10.12.29.101 → 185.39.19.96:443`.
- Fresh Lumma replay: **17,013/17,013 packets**, 3 alerts, no drops/timeouts. Same-PCAP Suricata comparison: one alert, 0 strict matches and no mapped endpoint-family overlap.
- Both public captures retained their previous NetGuard alert sets; neither exposed a DNS-frequency alert whose status changed under retry deduplication. This means these samples verify no observed regression, but do not validate the retry behavior against labeled DNS retry traffic.
- Fresh DBs and comparison logs: `/tmp/netguard-cycle-dns110.ceQS1V/`.
- `git diff --check` was clean at verification. User-local configuration and the untracked presentation files were preserved.

### Remaining limitation / next cycle

- The 2-second retry interval is a bounded heuristic; DNS retry timing varies by resolver. The rule intentionally does not suppress same-ID repeats beyond that short interval or without complete metadata. Add independently labeled benign resolver retries and DNS tunnel traffic before adjusting the interval. Continue existing-rule tuning only; do not add rules.

### State-ordering follow-up

- A later review found that a reordered DNS observation could be added to `_seen_queries` before the frequency history rejected it. That could poison the retry cache and suppress the subsequent in-order query.
- Moved retry-cache mutation after the frequency history's out-of-order guard. Added a regression that first failed by observing the late transaction in the cache, then verified it is rejected without state mutation and that its later in-order arrival is counted.
- Focused DNS tests: **31 passed**. Final full suite: **286 passed** in 48.01s. Final synthetic evaluation remains **37/37**, 0 unmatched attack alerts and 0 benign alerts.
- Final-code ClickFix replay: **52,602/52,602 packets**, 10 alerts; comparison remains 0 strict matches against 707 Suricata events and the separate 9-to-694 HTTP endpoint-family correlation. Final-code Lumma replay: **17,013/17,013 packets**, 3 alerts; comparison remains 0 strict matches against one Suricata event, with no mapped endpoint-family overlap.
- Final replay DBs/logs: `/tmp/netguard-cycle-dns-ordering.kdiL0k/`. `git diff --check` is clean; rule inventory remains 19.

## Evidence cycle: 2026-10-22 PAYLOAD_HIT TCP tuple reuse

This cycle tuned the existing `PAYLOAD_HIT` stream inspector; no rule was added and the engine remains at 19 registered rules.

### Finding and implementation

- Stream reassembly was keyed by directional 4-tuple and sequence numbers but did not retain the initial SYN sequence. If a new TCP connection reused a tuple, its bytes could be compared against the previous connection's sequence space: a small new sequence gap could miss a signature split across the new flow, while a sequence value adjacent to old buffered bytes could join data from separate connections.
- `PAYLOAD_HIT` version 1.9 now records the initial sequence number in bounded stream state. An initial SYN with a different sequence resets buffered/reordered bytes before reassembly. A repeated SYN with the same sequence preserves the active stream. The rule now observes initial SYN metadata even when the SYN has no payload; other empty TCP packets still do not allocate stream state. Sequence-only records can identify SYNs when the normalized `initial_syn` field is absent.
- Added regressions for detecting a signature split after tuple reuse, not joining bytes across two connections with adjacent sequence spaces, and preserving the current stream on an identical SYN retransmission.

### Verification

- Focused payload tests: **31 passed**.
- Final full suite after the flags-only compatibility adjustment and cross-connection negative case: **289 passed** in 47.08s.
- Final synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**. Fixture results are not real-world accuracy estimates.
- Final public-sample replays: ClickFix **52,602/52,602 packets**, 10 alerts; Lumma **17,013/17,013 packets**, 3 alerts. Same-PCAP Suricata comparison remained ClickFix 0 strict matches of 707 (separate 9-to-694 HTTP endpoint-family correlation), Lumma 0 strict matches of one Suricata alert with no mapped endpoint-family overlap. No live capture was used.
- Final replay DBs: `/tmp/netguard-cycle-payload19-final.viiOuV/`.
- The rule inventory remains **19**; `git diff --check` is clean.

### Remaining limitation / next cycle

- A SYN sequence collision on a reused 4-tuple is indistinguishable from a retransmission from the fields currently retained, though an identical initial sequence is rare for a new connection. Midstream captures without an observed SYN cannot reliably identify tuple reuse. Keep DPI state bounded and avoid claiming inspection of TLS-encrypted content.
- Complete final verification for the compatibility adjustment, then continue reviewing an existing rule for a reproducible behavior defect. Do not add rules.

## Evidence cycle: 2026-10-22 DISTRIBUTED_SYN_FLOOD alert rate limiting

This cycle tuned the existing distributed SYN flood rule only; no new rule was added, and the registered rule count remains 19.

### Finding and implementation

- The rule cleared all target evidence immediately after alerting and had no cooldown. A continuing flood therefore rebuilt the threshold state and could emit repeated alerts on each subsequent threshold-sized packet group.
- `DISTRIBUTED_SYN_FLOOD` version 1.2 now keeps its threshold-capped evidence window and applies a per-target 60-second alert cooldown. During cooldown, packet and source evidence continues to roll forward, but repeated alerts are suppressed. Once the cooldown and event window have elapsed, a later qualifying burst can alert again.
- Cooldown state is bounded with active target state and removed when its target is evicted; stale cooldowns are pruned. Regression tests cover alert-storm suppression, later-burst recovery and cooldown-state bounds.

### Verification

- Focused port-scan/distributed-flood tests: **17 passed**.
- Full suite: **291 passed** in 47.15s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**. Results apply only to the synthetic fixtures.
- Fresh ClickFix replay: **52,602/52,602 packets**, 10 NetGuard alerts; compared with the same-PCAP Suricata EVE: 707 alerts, 0 strict matches, with the separate 9-to-694 HTTP endpoint-family correlation.
- Fresh Lumma replay: **17,013/17,013 packets**, 3 NetGuard alerts; compared with its same-PCAP Suricata EVE: one alert, 0 strict matches and no mapped endpoint-family overlap.
- The public samples did not trigger `DISTRIBUTED_SYN_FLOOD`; their alert sets are unchanged. Suricata remains a comparison baseline rather than ground truth.
- Replay DBs: `/tmp/netguard-cycle-distributed12.0Dr3Mr/`. `git diff --check` is clean. Rule inventory remains 19.

### Remaining limitation / next cycle

- The 60-second cooldown is fixed (not a configuration knob). Synthetic tests validate repeated-alert suppression and recovery, but the available public captures do not contain a distributed SYN flood. Continue reviewing existing rules only; do not add rules.

## Evidence cycle: 2026-10-22 SYN_FLOOD alert rate limiting

This cycle tuned the existing `SYN_FLOOD` rule's SYN and RST flood subchecks. No new rule was added; the engine remains at 19 rules.

### Finding and implementation

- Both flood paths cleared their rolling history after alerting and had no cooldown. A sustained single-source SYN or RST burst could therefore emit an alert every time another threshold-sized group arrived.
- `SYN_FLOOD` version 1.5 now retains only the most recent threshold-sized event window and rate-limits repeat alerts per SYN target or RST source/destination for 60 seconds. It continues updating evidence while suppressing alerts, then can alert again when the cooldown expires and the recent window still qualifies.
- Cooldown state is bounded by the corresponding flow-state limit, removed alongside target eviction, and pruned when stale. This also caps post-alert history instead of allowing flood-rate growth in per-flow timestamp lists.
- Regressions cover SYN and RST alert-storm suppression, later-burst recovery, cooldown-state bounds, and stale cooldown pruning.

### Verification

- Focused SYN/RST flood and scan tests: **27 passed**.
- Full suite: **293 passed** in 48.73s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**. These metrics describe only the checked-in fixtures.
- Fresh ClickFix replay: **52,602/52,602 packets**, 10 NetGuard alerts; matching Suricata EVE had 707 alerts, 0 strict matches and the same separate 9-to-694 HTTP endpoint-family correlation.
- Fresh Lumma replay: **17,013/17,013 packets**, 3 NetGuard alerts; matching Suricata EVE had one alert, 0 strict matches and no mapped endpoint-family overlap.
- The saved public captures do not produce a NetGuard SYN/RST flood alert, so they show no regression but do not validate a true flood. Suricata remains a comparison baseline, not ground truth.
- Replay DBs: `/tmp/netguard-cycle-syn15.wUAbAR/`. `git diff --check` is clean; registered rule count remains 19.

### Remaining limitation / next cycle

- The 60-second cooldown is a fixed default, not a configurable setting. Review the alert-volume trade-off against labeled sustained-flood traffic before changing it. Continue existing-rule tuning only; do not add rules.

## Evidence cycle: 2026-10-22 ICMP_FLOOD echo-code validation

This cycle tuned the existing `ICMP_FLOOD` rule only. No rule was added; the 19-rule inventory is unchanged.

### Finding and implementation

- `ICMP_SWEEP` counts only code-zero ICMP echo requests, but `ICMP_FLOOD` checked the echo type and ignored the code. Malformed IPv4 type-8 or IPv6 type-128 messages with nonzero codes could therefore contribute toward a flood threshold.
- `ICMP_FLOOD` version 1.1 now requires echo code zero, matching the sweep rule's protocol semantics. Missing code metadata remains compatible with legacy records by treating it as zero.
- Added IPv4 and IPv6 tests proving malformed-code packets neither alert nor allocate history, while valid echo requests still reach threshold.

### Verification

- Focused ICMP flood/sweep tests: **15 passed** plus two parameterized protocol cases.
- Full suite: **294 passed**, with the two parameterized protocol cases passing, in 48.92s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**. These are fixture-only results.
- Fresh ClickFix replay: **52,602/52,602 packets**, 10 NetGuard alerts; compared with 707 matching Suricata EVE alerts, 0 strict matches, and the separate 9-to-694 HTTP endpoint-family correlation.
- Fresh Lumma replay: **17,013/17,013 packets**, 3 NetGuard alerts; compared with one matching Suricata EVE alert, 0 strict matches and no mapped endpoint-family overlap.
- Neither public capture exercises malformed ICMP echo codes, so those replays confirm no observed regression but do not validate that edge against a real sample. Suricata remains a comparator, not ground truth.
- Replay DBs: `/tmp/netguard-cycle-icmp11.aWWi2Y/`. `git diff --check` is clean; rule inventory remains 19.

### Remaining limitation / next cycle

- The public captures may not contain malformed ICMP echo messages, so this condition is validated synthetically. Continue tuning existing rules only; do not add rules.

## Evidence cycle: 2026-10-22 TCP_STEALTH_SCAN malformed metadata handling

This cycle hardened the existing `TCP_STEALTH_SCAN` rule only. No rule was added; the inventory remains 19.

### Finding and implementation

- Unlike the other TCP flag paths, `TCP_STEALTH_SCAN` converted `tcp_flags` and `dst_port` without guarding malformed record values. A bad string, infinity, or invalid port could raise during rule evaluation and prevent later checks for that record.
- `TCP_STEALTH_SCAN` version 1.1 now ignores unconvertible flags/ports and ports outside the valid 0–65535 range before updating probe state. Valid zero-flag probes remain supported; no thresholds or normal packet matching changed.
- Added regression coverage proving malformed metadata is ignored without allocating probe state.

### Verification

- Focused stealth-scan and PCAP parser tests: **21 passed**.
- Full suite: **295 passed, 2 subtests passed** in 48.71s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**. These numbers describe only checked-in synthetic fixtures.
- Fresh ClickFix offline replay: **52,602/52,602 packets**, 10 NetGuard alerts; matching Suricata EVE contained 707 alerts. Exact event matches: 0. The separate endpoint-family correlation remains 9 NetGuard cleartext-HTTP alerts to 694 Suricata HTTP parser events on `10.12.29.101 → 185.39.19.96:443`.
- Fresh Lumma offline replay: **17,013/17,013 packets**, 3 NetGuard alerts; matching Suricata EVE contained one alert. Exact event matches and mapped endpoint-family overlaps: 0. NetGuard's `DATA_EXFIL` measurement remained 1,000,296 bytes on `10.12.30.101 → 13.201.207.191:443`.
- These captures do not exercise malformed TCP metadata, so their purpose is checking for regressions, not validating the edge case. Suricata remains a baseline, not ground truth. Artifacts: `/tmp/netguard-stealth-cycle.oGsbSi/`.
- `git diff --check` was clean before the final metadata-only version bump; rerun final checks after the bump.

### Remaining limitation / next cycle

- Parser-produced records contain numeric ports and flags, so this defensive path primarily protects replay/API integrations and malformed direct records. Continue existing-rule tuning only; do not add rules.

## Evidence cycle: 2026-10-22 TCP_ZERO_WINDOW bounded state

This cycle improved the existing `TCP_ZERO_WINDOW` rule only. No rule was added; the registered inventory remains 19.

### Finding and implementation

- `TCP_ZERO_WINDOW` bounded the number of tracked history keys, but its per-key event deque could grow for every packet received inside the active window. Its cooldown map also retained keys after their corresponding histories were evicted. A sustained advertisement stream or many short-lived alerting sources could therefore consume unbounded memory despite `max_tracked`.
- Version 1.5 retains only the most recent `threshold` observations per key, enough to evaluate the single-flow threshold and multi-flow corroboration. When keys are evicted, their cooldown entries are removed too; cooldown state is also capped by `max_tracked`.
- Alert evidence now says the reported zero-window count is a lower bound, since the stored window is intentionally capped. The threshold, 10-second time window, flow diversity requirement, and cooldown behavior are unchanged.
- Regression tests reproduced the two issues before the fix: 1,000 events were retained for one key and 125 cooldown keys remained with a 100-key history limit. Both bounded-state tests pass after the change.

### Verification

- Focused `TCP_ZERO_WINDOW` tests: **19 passed**.
- Full suite: **297 passed, 2 subtests passed** in 49.09s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**; these fixture-only metrics are not real-world accuracy estimates.
- Fresh ClickFix replay: **52,602/52,602 packets**, 10 NetGuard alerts vs. 707 same-PCAP Suricata alerts; 0 strict event matches. The separate HTTP endpoint-family correlation remains 9 NetGuard alerts to 694 Suricata HTTP parser events.
- Fresh Lumma replay: **17,013/17,013 packets**, 3 NetGuard alerts vs. one same-PCAP Suricata alert; 0 strict matches and 0 mapped endpoint-family overlap. NetGuard still emits the responder-side zero-window signal, now described as “at least 20” observations.
- The two public captures do not create a high-cardinality flood, so the memory/state improvement is validated by synthetic stress tests. Suricata remains a comparison baseline, not ground truth. Fresh replay artifacts: `/tmp/netguard-zero-window-cycle.paYH3U/`.

### Remaining limitation / next cycle

- The threshold-sized evidence window intentionally provides a lower bound, not an exact packet total for sustained bursts. The saved benign PCAP includes two flows with 10 such packets each (no alert); the labeled attack fixture includes 25 across five flows and still alerts. Continue existing-rule tuning only; do not add rules.

## Evidence cycle: 2026-10-22 DATA_EXFIL rolling-window accounting

This cycle improved the existing `DATA_EXFIL` rule only. No rule was added; the registered inventory remains 19.

### Finding and implementation

- Volumetric evaluation recomputed `sum(bytes)` across the full per-flow packet deque on every record. Cost grew with the number of packets in the window. The deque also assumed arrival timestamps were ordered: a late packet appended behind newer events could remain after expiry and inflate later totals.
- `DATA_EXFIL` version 1.8 maintains a cached per-flow byte total, adding new and pending-fragment bytes and subtracting bytes as events expire. Flow eviction and stale pruning also remove the cached total.
- Records older than the newest event for that service are ignored for volumetric accounting, keeping deque order valid. Direct archive/database signatures are still evaluated on late records and can alert independently; such a record does not roll back the flow cooldown or volume history.
- Regression tests reproduced the false alert from a delayed 500-byte event after 600+200 bytes had already been recorded, and verify expiry, fragments, flow eviction, and pruning against cached totals.

### Verification

- Focused `DATA_EXFIL` tests: **30 passed**.
- Full suite: **301 passed, 2 subtests passed** in 48.96s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**; fixture-only results.
- Final fresh ClickFix replay: **52,602/52,602 packets**, 10 NetGuard alerts vs. 707 same-PCAP Suricata alerts; 0 strict event matches. The separate HTTP endpoint-family correlation remains 9 NetGuard alerts to 694 Suricata HTTP parser events.
- Final fresh Lumma replay: **17,013/17,013 packets**, 3 NetGuard alerts vs. one same-PCAP Suricata alert; 0 strict matches and 0 mapped endpoint-family overlap. `DATA_EXFIL` still reports 1,000,296 bytes for the same endpoint/window, and the existing responder-side `TCP_ZERO_WINDOW` signal remains unchanged.
- Suricata is a comparator, not ground truth. Final artifacts: `/tmp/netguard-data-exfil-v18-final.gpeBTu/`.

### Remaining limitation / next cycle

- Cached totals reduce CPU work but packet-event deques still retain one entry per payload observed in the time window. Bound or compress those histories only with an evaluation strategy that preserves sliding-window threshold behavior and makes any approximation explicit. Continue tuning existing rules only; do not add rules.

## Evidence cycle: 2026-10-22 DNS_ANOMALY subdomain-state cap

This cycle improved the existing `DNS_ANOMALY` rule only. No rule was added; the registered inventory remains 19.

### Finding and implementation

- DNS query-frequency history was already capped at its threshold, but distinct-subdomain history stored every new label for the full window. A DNS tunnel or high-rate randomized-name stream could therefore grow one source/parent history without bound after the alert threshold was reached.
- `DNS_ANOMALY` version 1.11 retains only the newest threshold-sized set of distinct subdomains. Newer observations replace older evidence, so the threshold decision remains true while at least that many distinct subdomains are still in the window. Alert evidence adds `distinct_subdomains_saturated` to show that the displayed count is a threshold-sized lower bound.
- Added a stress regression that sends 1,000 distinct labels for one source and parent, verifies state stays at three entries with a threshold of three, and checks that the threshold alert reports saturated evidence.

### Verification

- Focused DNS and related scenario tests: **32 passed, 47 deselected**.
- Full suite: **302 passed, 2 subtests passed** in 47.51s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**; fixture-only result.
- Fresh ClickFix replay: **52,602/52,602 packets**, 10 NetGuard alerts vs. 707 same-PCAP Suricata alerts; 0 strict matches. Separate endpoint-family correlation remains 9 NetGuard cleartext-HTTP alerts to 694 Suricata HTTP parser events.
- Fresh Lumma replay: **17,013/17,013 packets**, 3 NetGuard alerts vs. one same-PCAP Suricata alert; 0 strict matches and 0 mapped endpoint-family overlap. NetGuard still reports the same 1,000,296-byte `DATA_EXFIL` event.
- These samples did not exercise a large distinct-subdomain stream, so the state cap is validated with the synthetic stress test. Suricata remains a comparison baseline, not ground truth. Artifacts: `/tmp/netguard-dns-subdomain-cycle.KzPv6G/`.

### Remaining limitation / next cycle

- The DNS label-history cap now bounds each source/parent key, but overall state is still bounded by the configured frequency-key limit rather than a global byte budget. Continue auditing existing rule state and threshold behavior; do not add rules.

## Evidence cycle: 2026-10-22 DATA_EXFIL threshold-sized byte history

This cycle improved the existing `DATA_EXFIL` rule only. No rule was added; the registered inventory remains 19.

### Finding and implementation

- Version 1.8 cached volume totals to remove repeated deque scans, but retained one event tuple for every payload in the window. Tiny payloads could still grow a per-flow history in proportion to packet rate.
- Version 1.9 retains only the newest `effective_threshold` bytes per flow. Since payload lengths are positive integers, the event deque is bounded by that many entries per flow. The retained suffix preserves the threshold predicate: if the active window contains at least the threshold bytes, the newest threshold bytes are also still in the window.
- First threshold-crossing alerts retain the exact observed byte total (including the packet that crosses it). Once older bytes have been trimmed, later volume evidence reports the threshold as a lower bound and sets `byte_count_is_lower_bound=true`. Saturation clears when the retained suffix expires below threshold. Signature-based archive/database detection remains independent and reports the exact matching packet payload size.
- Regressions exercise 2,000 one-byte packets against a 1,000-byte threshold, exact first-crossing totals, lower-bound saturation, and recovery to exact counts after expiration.

### Verification

- Focused `DATA_EXFIL` plus PCAP parsing tests: **47 passed** before the final two saturation tests; final `DATA_EXFIL`-only run: **32 passed**.
- Full suite: **304 passed, 2 subtests passed** in 49.21s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**; fixture-only result.
- Final fresh ClickFix replay: **52,602/52,602 packets**, 10 NetGuard alerts vs. 707 same-PCAP Suricata alerts; 0 strict matches. Separate endpoint-family correlation remains 9 NetGuard cleartext-HTTP alerts to 694 Suricata HTTP parser events.
- Final fresh Lumma replay: **17,013/17,013 packets**, 3 NetGuard alerts vs. one same-PCAP Suricata alert; 0 strict matches and 0 mapped endpoint-family overlap. The `DATA_EXFIL` alert still reports the exact first-crossing measurement of **1,000,296 bytes**.
- Suricata is a comparison baseline, not ground truth. Artifacts: `/tmp/netguard-data-exfil-v19.YAcbyN/`.

### Remaining limitation / next cycle

- Per-flow history is now bounded by its configured byte threshold, but the aggregate worst-case still scales with the 5,000-flow limit and the web threshold. Review a global memory budget that degrades predictably under many simultaneous tiny-payload flows without silently changing threshold semantics. Continue existing-rule tuning only; do not add rules.

## Evidence cycle: 2026-10-22 DATA_EXFIL global state budget

This cycle improved the existing `DATA_EXFIL` rule only. No rule was added; the registered inventory remains 19.

### Finding and implementation

- Version 1.9 bounded each flow by threshold bytes, but thousands of concurrent flows could still multiply that state. Cooldown keys could also outlive histories removed by stale pruning.
- Version 1.10 adds a global event budget of 1,000,000 entries, raised when either configured byte threshold is larger so one flow can still reach its threshold using one-byte records. Per-flow histories are LRU ordered; when the aggregate budget is exceeded, the least recently used other flow is evicted together with its cached total, saturation marker, and cooldown. Existing flow-count eviction also uses the same cleanup path.
- Cooldown keys are kept in insertion/LRU order and capped at `MAX_TRACKED_FLOWS`; cooldown evidence may therefore also be evicted under high churn. Event accounting is updated for appends, fragment merges, window expiry, byte trimming, pruning, and flow eviction.
- Regression tests reproduce 1,200 entries across two subthreshold flows against a 1,000-entry test budget, prove the older flow is evicted while the active flow can still reach its byte threshold, and show cooldown state stays capped after stale-history pruning.

### Verification

- Focused `DATA_EXFIL` tests: **34 passed**.
- Full suite: **306 passed, 2 subtests passed** in 47.84s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**; fixture-only results.
- Fresh ClickFix replay: **52,602/52,602 packets**, 10 NetGuard alerts vs. 707 same-PCAP Suricata alerts; 0 strict event matches. Separate endpoint-family correlation remains 9 NetGuard cleartext-HTTP alerts to 694 Suricata HTTP parser events.
- Fresh Lumma replay: **17,013/17,013 packets**, 3 NetGuard alerts vs. one same-PCAP Suricata alert; 0 strict matches and 0 mapped endpoint-family overlap. `DATA_EXFIL` still reports the exact first-crossing measurement of **1,000,296 bytes**.
- Suricata is a comparison baseline, not ground truth. Artifacts: `/tmp/netguard-data-exfil-v110.MOuxG8/`.

### Remaining limitation / next cycle

- LRU flow eviction is the explicit overload behavior: a flow removed under global pressure loses its rolling evidence and cooldown until observed again. Stress tests cover eviction and retained-flow threshold behavior, but the public samples do not reach the global cap. Continue evaluating existing-rule state policies and thresholds; do not add rules.

## Evidence cycle: 2026-10-22 BRUTE_FORCE bounded cooldown history

This cycle refined the existing `BRUTE_FORCE` rule only. No rule was added; the engine still registers 19 rules.

### Finding and implementation

- During its 60-second alert cooldown, the rule kept appending attempts to a key's history even though further alerts were suppressed. A sustained attack could therefore grow per-key history without bound. Separately, histories could expire while their cooldown entries remained, allowing cooldown state to grow during high key churn.
- `BRUTE_FORCE` version 1.3 caps per-key retained timestamps at the configured alert threshold, preserving the rolling-window threshold decision while marking the count as a lower bound after additional attempts. This saturation marker is cleared when the active count falls below threshold and on alert/reset/eviction.
- Cooldown state now uses insertion order and is capped at `max_states`; history, saturation and cooldown are removed together on state-key eviction. Existing SYN retransmission deduplication remains unchanged.
- Added regressions for 1,000 attempts during cooldown, a renewed alert after cooldown, and cooldown-map bounds under stale-history pruning/high key churn.

### Verification

- Focused `BRUTE_FORCE` tests: **15 passed**.
- Full suite: **308 passed, 2 subtests passed** in 50.21s.
- Synthetic evaluation: **37/37 labelled scenarios detected; 0 missed scenarios, 0 unmatched attack alerts, 0 benign alerts**. All 1,159 attack and 832 benign fixture packets replayed; no alert drops/spooling/shutdown timeout. These synthetic fixtures are not real-world accuracy estimates.
- Fresh ClickFix replay: **52,602/52,602 packets**, 10 NetGuard alerts vs. 707 same-PCAP Suricata events, 0 strict matches. Time-agnostic cleartext HTTP endpoint-family correlation: 10 NetGuard alerts vs. 694 Suricata parser events for `10.12.29.101 → 185.39.19.96:443`.
- Fresh Lumma replay: **17,013/17,013 packets**, 3 NetGuard alerts vs. 1 same-PCAP Suricata alert, 0 strict matches and no mapped endpoint-family overlap. NetGuard's existing alerts remained `DATA_EXFIL`, `TCP_ZERO_WINDOW`, and `PAYLOAD_HIT`.
- Neither public sample contains a brute-force event, so they verify no observed output regression but do not validate the adjusted rule against labeled brute-force traffic. Suricata is a comparison baseline, not ground truth; those EVE files contain built-in app-layer events and a local broad-SYN signature, not an external threat-feed ruleset.
- Isolated artifacts: `/tmp/netguard-bruteforce-v13.aKzpSe/`.

### Remaining limitation / next cycle

- Attempt evidence is intentionally a threshold-sized lower bound during a sustained cooldown; it no longer exposes the exact total attempts. Validate this bounded evidence behavior on labeled authentication retry/brute-force captures when available. Continue reviewing existing rule logic and thresholds only; do not add rules.

## Evidence cycle: 2026-10-22 PORT_SCAN evidence and cooldown bounds

This cycle tuned the existing `PORT_SCAN`/inherited `UDP_SCAN` implementation. No rules were added; the engine remains at 19 registered rule instances.

### Finding and implementation

- `PortScanRule` limited the number of scan keys but each horizontal scan key could retain every distinct destination host observed during the window. Under a sustained scan this nested evidence could scale with packet volume. Per-key fired/cooldown dictionaries also had no explicit cardinality cap when many keys crossed thresholds before pruning.
- Version 1.5 caps each vertical/horizontal distinct-target history at `2 * threshold`. This preserves the existing threshold alert and medium-to-high severity boundary. If additional unique targets overflow the cap, the retained count is a lower bound and evidence includes a saturation flag; alert detail is explicit. Expired target history clears saturation when the retained evidence drops below cap.
- Vertical and horizontal fired-state maps now use ordered eviction at `max_states`; evicting a scan history key also removes its associated saturation and fired state. Existing per-target window/cooldown behavior remains.
- Added tests for 500 unique horizontal targets with a threshold of three, and scan-key churn against a five-key state budget.

### Verification

- Focused port-scan tests: **19 passed**.
- Full suite: **310 passed, 2 subtests passed** in 49.16s.
- Synthetic evaluation: **37/37 labelled scenarios detected; 0 FN, 0 unmatched attack alerts, 0 benign alerts**. All 1,159 attack and 832 benign fixture packets replayed with no alert drops or shutdown timeout. Synthetic fixture metrics are not real-world accuracy estimates.
- Fresh post-change offline same-PCAP comparisons: ClickFix **52,602/52,602 packets**, 10 NetGuard vs. 707 Suricata events (0 strict matches; endpoint-family correlation 9 NetGuard cleartext HTTP events vs. 694 Suricata parser events); Lumma **17,013/17,013 packets**, 3 NetGuard vs. 1 Suricata event (0 strict matches, 0 mapped endpoint-family overlap). Replay shutdown had no alert drops/spooling/timeouts. The three Lumma alerts remain `DATA_EXFIL`, `TCP_ZERO_WINDOW`, and `PAYLOAD_HIT`. Suricata comparison remains non-ground-truth and its outputs are not a threat-feed ruleset. Artifacts: `/tmp/netguard-portscan-v15.1qsj3t/`.

### Remaining limitation / next cycle

- The cap retains enough observations to preserve alert and severity thresholds, but the exact scan breadth beyond `2 * threshold` is intentionally unavailable; saturated values are lower bounds. Public samples do not exercise the stress cap. Continue validating existing rule state behavior and threshold boundaries; do not add rules.

## Evidence cycle: 2026-10-22 CLEAR_HTTP_ON_TLS_PORT bounded evidence and cooldown LRU

This cycle refined the existing `CLEAR_HTTP_ON_TLS_PORT` rule only. No rule was added; registered rule count remains 19.

### Finding and implementation

- The per-service sliding window retained every matching HTTP request timestamp, including throughout its 600-second alert cooldown. High-rate traffic to one TLS endpoint could therefore grow a single history without bound.
- Version 1.2 caps each service history at `min_requests`. Extra requests preserve the threshold decision and set `request_count_saturated=true`; the evidence count is explicitly a lower bound. Stale pruning and state eviction also clear saturation metadata.
- Cooldown entries are refreshed in LRU order when matching requests arrive during cooldown, preventing a hot endpoint's active cooldown from being evicted ahead of colder keys under state pressure. The map remains capped at `max_states`.
- Regressions cover 1,000 requests during cooldown, recovery after cooldown, preserving the most recently active service history, and preserving an active cooldown through key churn.

### Verification

- Focused cleartext HTTP tests after LRU coverage: **6 passed**.
- Full suite after the change: **313 passed, 2 subtests passed** in 48.97s.
- Synthetic evaluation after the change: **37/37 labelled scenarios detected; 0 FN, 0 unmatched attack alerts, 0 benign alerts**. All 1,159 attack and 832 benign fixture packets replayed without alert drops or shutdown timeout. These are fixture metrics, not real-world accuracy estimates.
- Fresh same-PCAP Suricata comparisons after the change: ClickFix **52,602/52,602 packets**, 10 NetGuard vs. 707 Suricata events, 0 strict matches, and time-agnostic HTTP endpoint-family correlation of 9 vs. 694 parser events (`10.12.29.101 → 185.39.19.96:443`); Lumma **17,013/17,013 packets**, 3 NetGuard vs. 1 Suricata event, 0 strict matches and no mapped endpoint-family overlap. The endpoint totals did not change. Suricata EVE is a comparison baseline, not ground truth (built-in app-layer events plus local broad-SYN signature). Artifacts: `/tmp/netguard-clearhttp-v12.6eaUOc/`.

### Remaining limitation / next cycle

- The cap deliberately sacrifices the exact number of repeated plaintext requests beyond `min_requests`; it retains the detection predicate and reports saturation. Public captures are not labeled ground truth for benign cleartext-on-TLS service configurations. Continue testing existing rule boundaries/state only; do not add rules.

## Evidence cycle: 2026-10-22 PORT_SCAN active-key LRU retention

This cycle further refined the existing `PORT_SCAN`/inherited `UDP_SCAN` behavior only. No rules were added; the registered inventory remains 19.

### Finding and implementation

- The nested per-target evidence and cooldown dictionaries were bounded, but the outer vertical/horizontal scan-key dictionaries evicted keys in insertion order. A frequently active scan key could therefore lose its still-valid window when newer one-off scan keys arrived, causing a later threshold miss.
- Version 1.6 makes both outer key maps LRU ordered. Each packet refreshes the active vertical and horizontal key; new keys evict the least recently active history, and the existing cleanup also drops its saturation/fired metadata. Per-key evidence remains capped at twice the threshold from v1.5, so alert/severity thresholds are preserved.
- Added separate regressions proving that an active vertical scan still crosses threshold after unrelated key churn and that an active horizontal scan does likewise.

### Verification

- Focused port-scan tests: **21 passed**.
- Full suite: **315 passed, 2 subtests passed** in 48.35s.
- Synthetic evaluation: **37/37 labelled scenarios detected; 0 FN, 0 unmatched attack alerts, 0 benign alerts**. All 1,159 attack and 832 benign packets replayed without dropped alerts or shutdown timeout; fixture metrics are not real-world accuracy estimates.
- Fresh same-PCAP comparisons: ClickFix **52,602/52,602 packets**, 10 NetGuard alerts vs. 707 Suricata events, 0 strict matches; HTTP endpoint-family correlation is 9 NetGuard vs. 694 Suricata parser events on `10.12.29.101 → 185.39.19.96:443`. Lumma **17,013/17,013 packets**, 3 NetGuard vs. 1 Suricata event, 0 strict matches and no mapped endpoint-family overlap. These public captures did not exercise max-state LRU pressure, so they confirm unchanged sample behavior, not the new eviction behavior. Suricata remains a comparator, not ground truth. Artifacts: `/tmp/netguard-portscan-v16.JYarLy/`.

### Remaining limitation / next cycle

- LRU eviction protects actively refreshed keys but an evicted cold key loses its in-window evidence and cooldown. Public samples do not reach the configured scan-key cap. Continue existing-rule state and threshold evaluation only; do not add rules.

## Evidence cycle: 2026-10-22 PAYLOAD_HIT cooldown ordering and LRU

This cycle refined the existing `PAYLOAD_HIT` rule only. No rules were added; registered inventory remains 19.

### Finding and implementation

- `PAYLOAD_HIT` purged alert cooldown entries whose timestamps were later than the current event timestamp. A reordered/late packet could therefore erase a newer alert's cooldown and allow a duplicate alert. In addition, the bounded alert-state map evicted in insertion order, so a frequently repeated signature could lose cooldown protection under key churn.
- Version 1.10 retains newer cooldown timestamps when processing an older event. A late event is suppressed while its matching cooldown timestamp is still newer than the event, rather than deleting it. Cooldown entries use ordered LRU eviction and matching suppressed signatures refresh their recency; the map retains its existing configured cap.
- Regressions reproduce out-of-order event timestamps and cooldown-key churn with a small state cap. Existing DPI signatures and stream inspection are unchanged.

### Verification

- Focused payload detection tests: **33 passed**.
- Full suite: **317 passed, 2 subtests passed** in 48.13s.
- Synthetic evaluation: **37/37 labelled scenarios detected; 0 FN, 0 unmatched attack alerts, 0 benign alerts**. All 1,159 attack and 832 benign packets replayed with no dropped alerts or shutdown timeout. These fixture metrics are not real-world accuracy estimates.
- Fresh same-PCAP Suricata comparison: ClickFix **52,602/52,602 packets**, 10 NetGuard alerts vs. 707 Suricata events, 0 strict matches; separate HTTP endpoint-family correlation 9 vs. 694 parser events on `10.12.29.101 → 185.39.19.96:443`. Lumma **17,013/17,013 packets**, 3 NetGuard vs. 1 Suricata event, 0 strict matches and no endpoint-family overlap. Counts are unchanged; Suricata is a comparator, not ground truth. Artifacts: `/tmp/netguard-payload-v110.AfE21q/`.

### Remaining limitation / next cycle

- Under maximum alert-state pressure, the least recently active cooldown can still be evicted, so that signature may alert again before its normal cooldown expires. Continue tuning existing rule state and event ordering; do not add rules.

## Evidence cycle: 2026-10-22 PAYLOAD_HIT transport-scoped cooldown

This cycle refined only the existing `PAYLOAD_HIT` cooldown key. No rule was added; the registered inventory remains 19.

### Finding and implementation

- The cooldown grouped signature matches by `(source, destination, destination port)` and omitted transport. Identical payload evidence over TCP and UDP to the same host/port could suppress one another even though they are independent transports.
- Version 1.11 includes transport protocol in the cooldown key. The existing host/service aggregation still collapses client source-port churn within one transport and preserves independent signatures.
- A regression proves the same signature on TCP and UDP to the same endpoint can alert independently; existing same-transport cooldown tests still verify suppression.

### Verification

- Focused payload detection tests: **34 passed**.
- Full suite: **318 passed, 2 subtests passed** in 47.78s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**; all 1,159 attack and 832 benign fixture packets replayed with no alert drops or shutdown timeout. These are fixture-only results.
- Fresh same-PCAP comparisons: ClickFix **52,602/52,602 packets**, 10 NetGuard alerts vs. 707 Suricata events, 0 strict matches and separate HTTP endpoint-family correlation 9 vs. 694 parser events (`10.12.29.101 → 185.39.19.96:443`). Lumma **17,013/17,013 packets**, 3 NetGuard vs. 1 Suricata event, 0 strict matches and no mapped endpoint-family overlap. Both samples' alert counts are unchanged; they do not contain a same-host/port TCP+UDP signature pair, so they do not exercise the new protocol split. Suricata is a baseline, not ground truth. Artifacts: `/tmp/netguard-payload-v111.TVKJtd/`.

### Remaining limitation / next cycle

- The cooldown intentionally ignores client source ports, so repeated host/service signature alerts remain collapsed within the cooldown period. Continue reviewing signature grouping and event ordering for existing rules only; do not add rules.

## Evidence cycle: 2026-10-22 DNS_ANOMALY cooldown LRU retention

This cycle refined only the existing DNS anomaly alert-dedup state. No rules were added; registered inventory remains 19.

### Finding and implementation

- The DNS anomaly cooldown map was bounded at `max_seen_keys`, but a suppressed repeat did not refresh key recency. Under alert-key churn, an actively repeated key could be evicted as if cold, allowing a duplicate alert before cooldown expiry. `_prune_seen` also replaced the map with a plain dictionary, losing any ordered-eviction behavior.
- Version 1.12 stores cooldown keys in an `OrderedDict`, refreshes recency on suppression and alert, and prunes stale entries in place. The existing `max_seen_keys` cap and 60-second cooldown are unchanged.
- Added a regression with a two-key cap: alert A, alert B, touch A during cooldown, insert C, and verify B is evicted while A remains suppressed.

### Verification

- Focused DNS and cycle-8 tests: **82 passed**.
- Full suite: **319 passed, 2 subtests passed** in 47.98s.
- Synthetic evaluation: **37/37 labelled scenarios detected; 0 FN, 0 unmatched attack alerts, 0 benign alerts**. All 1,159 attack and 832 benign packets replayed without alert drops or shutdown timeout. Fixture-only metrics are not real-world accuracy estimates.
- Fresh same-PCAP comparisons: ClickFix **52,602/52,602 packets**, 10 NetGuard vs. 707 Suricata events, 0 strict matches, with separate HTTP endpoint-family correlation 9 vs. 694 parser events (`10.12.29.101 → 185.39.19.96:443`). Lumma **17,013/17,013 packets**, 3 NetGuard vs. 1 Suricata event, 0 strict matches and no mapped endpoint-family overlap. Counts are unchanged; neither public sample stresses the DNS cooldown key cap. Suricata is a comparison baseline, not ground truth. Artifacts: `/tmp/netguard-dns-v112.iVrPUv/`.

### Remaining limitation / next cycle

- Under saturation, the least recently active cooldown is still evicted and can re-alert before expiry. The cap bounds memory and that overload tradeoff is explicit. Continue reviewing existing rule threshold/state behavior only; do not add rules.

## Evidence cycle: 2026-10-22 ICMP_FLOOD cooldown state cap

This cycle tuned only the existing `ICMP_FLOOD` state handling. No rule was added; the inventory remains 19.

### Finding and implementation

- The per-flow request history had a `max_flows` bound, but the separate cooldown map had no cardinality limit. Unique source/target pairs that crossed the threshold could grow cooldown state until periodic expiration.
- Version 1.2 stores cooldown keys in insertion/LRU order and caps them at `max_flows`. Requests suppressed by an active cooldown refresh recency, so key churn discards the coldest cooldown first and preserves active protections where possible.
- Added a regression with `max_flows=2`: alert A, alert B, touch A, alert C; assert the map remains bounded, B is evicted, and A remains suppressed.

### Verification

- Focused ICMP flood tests: **9 passed, 2 subtests passed**.
- Full suite: **320 passed, 2 subtests passed** in 48.53s.
- Synthetic evaluation: **37/37 labelled scenarios detected, 0 FN, 0 unmatched attack alerts, 0 benign alerts**. All 1,159 attack and 832 benign packets replayed without alert drops or shutdown timeout; these are fixture-only metrics.
- Fresh same-PCAP comparisons: ClickFix **52,602/52,602 packets**, 10 NetGuard vs. 707 Suricata events, 0 strict matches; HTTP endpoint-family correlation 9 vs. 694 parser events (`10.12.29.101 → 185.39.19.96:443`). Lumma **17,013/17,013 packets**, 3 NetGuard vs. 1 Suricata event, 0 strict matches and no mapped endpoint-family overlap. The samples do not contain ICMP flood traffic, so they verify no observed unrelated regression, not cooldown state pressure. Suricata is a comparison baseline, not ground truth. Artifacts: `/tmp/netguard-icmp-v12.aDmgCa/`.

### Remaining limitation / next cycle

- Under sustained unique-key churn, the least recently active cooldown can be evicted before its timer expires, allowing that flow to alert again after meeting the threshold. Continue improving existing rule state and threshold handling only; do not add rules.

## Evidence cycle: 2026-10-22 UDP_FLOOD flow and cooldown LRU bounds

This cycle tuned only the existing `UDP_FLOOD` state management. No rules were added; registered inventory remains 19.

### Finding and implementation

- Both flow history and cooldown maps were unbounded by a shared flow limit: `max_flows` evicted only histories, while cooldown keys accumulated until time-based pruning. The flow history map also evicted by insertion age, so an active subthreshold source/target could lose evidence under key churn.
- Version 1.1 makes both maps ordered and caps each at `max_flows`. Packet arrivals refresh active history recency; suppressed traffic refreshes cooldown recency. New keys evict the least recently active item. Cooldown duration is clamped non-negative.
- Added regressions for a two-flow cooldown cap with active-key retention and for an active subthreshold flow reaching threshold after unrelated key churn. Both tests failed against the prior implementation before the fix.

### Verification

- Focused UDP flood tests: **10 passed**.
- Full suite: **322 passed, 2 subtests passed** in 49.01s.
- Synthetic evaluation: **37/37 labelled scenarios detected; 0 FN, 0 unmatched attack alerts, 0 benign alerts**. Attack and benign replays processed 1,159 and 832 packets without alert drops or shutdown timeout. Results are fixture-only.
- Fresh same-PCAP comparisons: ClickFix **52,602/52,602 packets**, 10 NetGuard alerts vs. 707 Suricata events, 0 strict matches; separate HTTP endpoint-family correlation is 9 NetGuard vs. 694 Suricata parser events (`10.12.29.101 → 185.39.19.96:443`). Lumma **17,013/17,013 packets**, 3 NetGuard alerts vs. 1 Suricata event, 0 strict matches and no mapped endpoint-family overlap. Neither public capture contains UDP flood state pressure, so these results confirm unchanged sample behavior but do not test the LRU change directly. Suricata is a comparator, not ground truth. Artifacts: `/tmp/netguard-udp-v11.Drvuyp/`.

### Remaining limitation / next cycle

- At capacity, the least recently active history or cooldown is evicted and loses some window/cooldown evidence; this overload behavior is now bounded and recency-based. Continue tuning existing rules only; do not add rules.

## Evidence cycle: 2026-10-22 SLOW_PORT_SCAN cooldown LRU retention

This cycle tuned only the cooldown state for the existing `SLOW_PORT_SCAN` rule. No rules were added; registered inventory remains 19.

### Finding and implementation

- The per-source/direction cooldown table was cardinality-bounded, but used insertion-order eviction. A source repeatedly suppressed during its cooldown did not refresh recency, so key churn could evict that active cooldown early and allow duplicate alerts.
- Version 1.2 changes the cooldown table to ordered LRU state. Suppressed hits refresh recency; newly allowed alerts refresh/append; overflow evicts the least recently active key. The cap and configured cooldown duration remain unchanged.
- Added a churn regression reproducing the prior premature eviction with a two-entry cap; it failed before the fix and passes after.

### Verification

- Focused slow-port-scan tests: **10 passed**.
- Full suite: **323 passed, 2 subtests passed** in 48.26s.
- Synthetic evaluation: **37/37 labelled scenarios detected; 0 FN, 0 unmatched attack alerts, 0 benign alerts**. The attack and benign fixture captures ran without alert drops or shutdown timeout. Fixture results are not real-world accuracy estimates.
- Fresh same-PCAP comparison: ClickFix **52,602/52,602 packets**, 10 NetGuard alerts vs. 707 Suricata events, 0 strict matches; separate HTTP endpoint-family correlation is 9 vs. 694 parser events (`10.12.29.101 → 185.39.19.96:443`). Lumma **17,013/17,013 packets**, 3 NetGuard alerts vs. 1 Suricata event, 0 strict matches and no mapped endpoint-family overlap. Neither sample stresses slow-scan cooldown key churn. Suricata is a comparator, not ground truth. Artifacts: `/tmp/netguard-slow-v12.Q8HkZP/`.

### Remaining limitation / next cycle

- Under sustained unique-source churn, the least recently active cooldown can still be evicted at the configured cap, allowing that source/direction to alert again before expiry. Continue tuning existing-rule state, thresholds, and parsing only; do not add rules.

## Evidence cycle: 2026-11-02 batch audit and payload false-positive reduction

This cycle followed the existing-rule-only constraint. No rules were added; the registered inventory remains 19: `ARP_SPOOF`, `BLOCKLIST`, `BRUTE_FORCE`, `CLEAR_HTTP_ON_TLS_PORT`, `DATA_EXFIL`, `DISTRIBUTED_SYN_FLOOD`, `DNS_ANOMALY`, `ICMP_FLOOD`, `ICMP_SWEEP`, `PAYLOAD_HIT`, `PORT_SCAN`, `SLOW_PORT_SCAN`, `SYN_FLOOD`, `TCP_FLAG_ANOMALY`, `TCP_STEALTH_SCAN`, `TCP_ZERO_WINDOW`, `TLS_ANOMALY`, `UDP_FLOOD`, and `UDP_SCAN`.

### Batch findings and implementation

- The first-pass audit covered the current implementation, version, test coverage, state/cooldown handling, and early protocol guards for all 19 registered rules. The actionable defects were in existing `TCP_FLAG_ANOMALY` and `PAYLOAD_HIT` behavior.
- `TCP_FLAG_ANOMALY` version 1.1 now uses a bounded `OrderedDict` cooldown with LRU refresh on suppressed packets. Previously, a repeatedly suppressed source/anomaly pair could be evicted by unrelated key churn and alert again before its cooldown expired. The constructor also clamps cooldown and state-cap inputs to safe non-negative/minimum values. A two-key churn regression reproduces the former eviction.
- `PAYLOAD_HIT` version 1.13 now avoids two observed false-positive paths. The `HEADER_INJECTION` raw-CRLF branch requires the CRLF to occur inside an HTTP request-target parameter before the request-line version; ordinary `Content-Type`, `Location`, and `Set-Cookie` headers no longer match. `HTTP_METHOD_TAMPERING` excludes ordinary REST user endpoints and enforces path-segment boundaries for retained management paths, preventing `/administrator` and `/api/v1/administer` from matching `/admin`.
- The retained payload coverage includes raw request-target CRLF injection, percent-encoded CRLF injection, stream-split raw injection, WebDAV/TRACE probes, and DELETE/PATCH on `/admin`, `/api/vN/admin`, `/api/vN/config`, `/config`, `/actuator`, and `/manage`.

### Competing-output comparison and Terra review

- A direct old-versus-new pattern comparison showed both false-positive reductions while retaining the intended attacks: normal `Content-Type` requests changed **match → no match**; query requests followed by a valid `Content-Type` header changed **match → no match**; raw request-target and percent-encoded CRLF injection stayed **match → match**; `DELETE /api/v1/user/10` changed **match → no match**; `DELETE /api/v1/admin/users/10` stayed **match → match**; and `/administrator` changed **match → no match**.
- Only the disputed `PAYLOAD_HIT` refinements were sent to Terra. Terra confirmed the direction, identified that the initial raw-CRLF expression still allowed a request-line version before the CRLF, and required path-segment boundaries for management endpoints. Both corrections were implemented and covered by regressions.

### Verification

- Focused payload, cycle-8, and TCP-flag tests: **104 passed**.
- Broader non-Scapy suite: **305 passed, 8 deselected, 2 subtests passed** in 35.28s. The deselected replay-clock/evaluation integration tests and the separately ignored PCAP parser module require Scapy interface enumeration, which the current restricted sandbox denies. The same suite had passed when local interface enumeration was available in the prior cycle; do not treat this restricted-environment result as a replacement for a full replay run.
- `git diff --check` is clean.

### Verification rerun: 2026-11-02

- Full regression suite, including Scapy replay/parser tests: **328 passed, 2 subtests passed** in 48.41s. Scapy interface enumeration required an unrestricted local test process; no live packet capture was started.
- Synthetic evaluation (`evaluation/run_eval.py`): **37/37 labelled attack scenarios detected, 0 unmatched attack alerts, 0 benign alerts**. The replay processed all **1,159 attack packets** and **832 benign packets**, with zero dropped alerts and no shutdown timeout. Results are fixture-only and do not estimate real-world accuracy. Artifacts: `/tmp/networking_project_rule_eval.json` and `/tmp/networking_project_rule_eval.csv`.
- The earlier request to complete end-to-end replay when interface enumeration is available is satisfied. The independent ClickFix and Lumma Suricata comparisons remain pending; they are not required to interpret these synthetic metrics.

### Sigma and SPL validation status

- The repository contains no Sigma rule files, SPL files, Sigma CLI/module, Splunk executable, or Splunk SDK. Automated Sigma validation and SPL regression cannot be meaningfully run against absent artifacts; no pass result is claimed. Add versioned Sigma/SPL assets and their expected outputs before introducing a validation gate. This is tooling/content absence, not a detection-rule failure.

### Next cycle

- Compare the saved ClickFix and Lumma PCAPs against their existing local Suricata EVE files. Keep exact agreement separate from endpoint-family correlation; Suricata agreement is a comparator, not ground truth.
- If Sigma/SPL coverage is required, define the source corpus and expected normalized outputs without creating additional detection rules; then add validation around those supplied artifacts.

## Follow-up: 2026-11-02 malformed TCP flags in TCP_ZERO_WINDOW

- The existing `TCP_ZERO_WINDOW` rule converted `tcp_flags` directly with `int()`. A malformed normalized record raised from the rule and was caught by the engine's outer guard, which logged an error and skipped this rule for that record.
- Version 1.6 treats non-integer TCP flag values as unavailable telemetry and returns no alert. Valid packet behavior and the zero-window predicate are unchanged; no rule was added.
- Regression comparison: the new malformed-input test would raise `ValueError` at the old direct conversion and now returns `None` with no history mutation.
- Verification: focused TCP zero-window tests **20 passed**; full suite **329 passed, 2 subtests passed** in 48.73s. `git diff --check` passed after the code, test, and documentation edits.

## Follow-up: 2026-11-02 nonpositive scan and flood settings

- `PORT_SCAN` and `SYN_FLOOD` stored constructor threshold/window values without validation. A zero threshold made a single SYN satisfy the trigger; negative values could do the same, and non-integer direct constructor arguments could fail during packet checks.
- Both existing rules now use their documented defaults when a supplied threshold or window cannot be parsed as a positive integer, and emit a warning. Their rule versions are `PORT_SCAN` 1.7 and `SYN_FLOOD` 1.6. Valid settings preserve the existing detection predicates and coverage.
- Regressions compare zero, negative, and nonnumeric constructor values: all fall back to defaults and an isolated SYN does not alert. On the previous code, zero alerted on the first SYN and nonnumeric values failed at threshold comparison.
- Verification: focused scan/flood tests **80 passed, 6 subtests passed**; full suite **331 passed, 8 subtests passed** in 48.67s. Synthetic replay processed 1,159 attack and 832 benign packets: **37/37 labelled attack scenarios detected, 0 unmatched attack alerts, 0 benign alerts, 0 dropped alerts, and no shutdown timeout**. These are synthetic-fixture results only.

## Follow-up: 2026-11-02 replay coverage for CLEAR_HTTP_ON_TLS_PORT

- The 37-scenario synthetic manifest did not include the existing `CLEAR_HTTP_ON_TLS_PORT` rule, and the evaluator's known-rule and version-metadata lists also omitted it. Unit tests covered the rule, but the batch replay could not validate it.
- Added S38 to the existing fixture generator: two ordinary plaintext HTTP GET requests to the same TCP/443 service, enough to exercise the rule's repeated-request condition. Updated the evaluator to accept the existing rule and include its version and non-secret thresholds in run metadata. This adds test coverage only; the rule inventory remains 19.
- Before the evaluator change, the expanded manifest failed setup with “unknown rule `CLEAR_HTTP_ON_TLS_PORT`.” Afterward, the positive replay matched the expected rule and the existing benign replay stayed alert-free.
- Verification: evaluation-artifact and cleartext-rule tests **10 passed**; full suite **333 passed, 8 subtests passed** in 49.01s. Synthetic replay processed **1,161 attack and 832 benign packets**, detected **38/38 labelled scenarios**, covered **all 19 existing rule families**, and produced zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. Fixture-only metrics; not a real-world precision or recall estimate.

## Follow-up: 2026-11-02 segmented request lines in CLEAR_HTTP_ON_TLS_PORT

- The existing rule matched an HTTP request line only at the beginning of one captured TCP payload. A request line split across segments could therefore evade `CLEAR_HTTP_ON_TLS_PORT` even though the traffic was plaintext HTTP on TCP/443 or TCP/8443.
- Version 1.3 keeps bounded directional prefix state (at most 2,064 bytes per prefix, 30-second expiry, and `max_states` keys). It joins only sequence-adjacent TCP payloads, suppresses an exact retransmission of an incomplete segment, drops mismatched continuations, and ignores late segments without replacing newer state. It preserves the existing method, port, repeat-count, and cooldown conditions.
- S38 splits its first request line across TCP segments and sends a second request on another client port. The follow-up below expands this to include out-of-order delivery.
- Verification: focused cleartext tests **10 passed**; full suite **337 passed, 8 subtests passed** in 51.77s. Synthetic replay: **38/38 scenarios**, all 19 rule families covered, zero unmatched attack alerts, zero benign alerts, zero dropped alerts, no shutdown timeout; 1,162 attack and 832 benign packets processed. These remain fixture-only results.

## Follow-up: 2026-11-02 out-of-order request segments in CLEAR_HTTP_ON_TLS_PORT

- The initial segmented-request fix joined adjacent segments in capture order but discarded a continuation that arrived ahead of a missing segment. This could still miss plaintext HTTP if packet capture observed TCP reordering.
- Version 1.4 buffers at most four future segments per already identified request prefix, within a 2,064-byte aggregate bound and the existing state cap and 30-second expiry. It joins buffered segments only when the missing sequence range arrives, then applies the unchanged request-line pattern and request threshold. Unrelated payloads and large gaps remain excluded.
- Added a unit regression that sends the last segment before the middle segment and verifies the request is counted exactly once. Existing S38 now exercises the same three-segment reordering in the replay PCAP.
- Verification: focused cleartext tests **11 passed**; full suite **342 tests passed** in 46.02s. Synthetic replay processed **1,163 attack and 832 benign packets**, detected **38/38 scenarios** across all 19 rule families, and produced zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. These remain fixture-only results.

## Follow-up: 2026-11-02 malformed flag metadata in TCP_FLAG_ANOMALY

- `TCP_FLAG_ANOMALY` converted `tcp_flags` directly to `int`, so a malformed normalized record raised before the rule could return safely. Negative or wider-than-nine-bit values could also satisfy masked flag predicates despite not representing a TCP flags field.
- Version 1.2 ignores non-integer values and values outside `0..0x1FF` without changing cooldown state. All existing anomaly conditions and valid nine-bit TCP flag combinations remain unchanged.
- Added regression cases for nonnumeric, infinite, negative, and oversized values. Existing positive and benign flag-combination cases remain covered.
- Verification: focused TCP flag tests **11 passed**; full suite **343 tests passed** in 49.38s. Synthetic replay processed **1,163 attack and 832 benign packets**, detected **38/38 scenarios**, with zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. Fixture-only results.

## Follow-up: 2026-11-02 TCP_ZERO_WINDOW setting validation

- The existing constructor coerced a zero detection threshold to `1`, allowing a single zero-window advertisement to satisfy the burst trigger. It also accepted negative windows and cooldowns and raised on malformed caps or thresholds.
- Version 1.7 now uses documented defaults for invalid/nonpositive thresholds, windows, caps, and flow corroboration settings. Cooldown must be finite and non-negative; `0` remains a valid way to disable cooldown. Minimum configured state cap and two-flow corroboration behavior remain in place.
- Added regressions proving invalid values select safe defaults, one zero-window packet does not trigger the default burst threshold, and zero cooldown remains valid.
- Verification: focused zero-window tests **22 passed**; full suite **345 tests passed** in 48.16s. Synthetic replay processed **1,163 attack and 832 benign packets**, detected **38/38 scenarios** across all 19 rule families, with zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. Fixture-only results.

## Follow-up: 2026-11-02 UDP_FLOOD and ICMP_FLOOD setting validation

- Both flood-rule constructors coerced a zero threshold to `1`, so a single packet could satisfy a flood rule. Invalid windows/state caps could raise, and `ICMP_FLOOD` accepted negative or non-finite cooldowns that bypassed expected suppression behavior.
- `UDP_FLOOD` version 1.2 and `ICMP_FLOOD` version 1.3 now fall back to existing documented threshold/window/state defaults and require a finite non-negative cooldown. Valid low test thresholds, including `1`, and `cooldown=0` remain supported. UDP's higher web threshold remains at least its general threshold.
- Added regressions for invalid values and one-packet no-alert behavior while asserting valid threshold-one behavior.
- Verification: focused UDP/ICMP flood tests **23 passed**; full suite **349 tests passed** in 46.32s. Synthetic replay processed **1,163 attack and 832 benign packets**, detected **38/38 scenarios** across all 19 rule families, with zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. Fixture-only results.

## Follow-up: 2026-11-02 scan threshold and state-cap validation

- `TCP_STEALTH_SCAN`, `ICMP_SWEEP`, and `DISTRIBUTED_SYN_FLOOD` each coerced a zero threshold to `1`; this could report one probe or one target as a scan/flood. Their window, cardinality, or distributed-source settings also accepted invalid values via clamping or raised during construction.
- Versions `TCP_STEALTH_SCAN` 1.2, `ICMP_SWEEP` 1.2, and `DISTRIBUTED_SYN_FLOOD` 1.4 now use each rule's existing documented threshold, window, and state-cap defaults when settings are invalid. Positive values including intentional threshold-one configurations remain unchanged.
- Added regressions for invalid thresholds, windows, and state caps, including the one-packet/one-target false-alert case. Existing positive threshold-one distributed and stealth/flood unit cases remain passing.
- Verification: focused scan tests **39 passed**; full suite **352 tests passed** in 45.49s. Synthetic replay processed **1,163 attack and 832 benign packets**, detected **38/38 scenarios** across all 19 rule families, with zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. Fixture-only results.

## Follow-up: 2026-11-02 CLEAR_HTTP_ON_TLS_PORT setting validation

- `CLEAR_HTTP_ON_TLS_PORT` coerced `min_requests=0` to `1`, allowing one ordinary plaintext request to trigger a detector whose intent is repeated requests. Invalid window/state settings could also raise, while a non-finite cooldown could produce unreliable suppression.
- Version 1.5 now falls back to the existing defaults for invalid minimum-request, window, and state-cap settings. Cooldown must be finite and non-negative; `0` remains supported. Valid fractional windows and positive custom thresholds are preserved.
- Added a regression for zero minimum requests and malformed companion settings. One request remains below the default repeat threshold.
- Verification: focused cleartext tests **12 passed**; full suite **353 tests passed** in 45.66s. Synthetic replay processed **1,163 attack and 832 benign packets**, detected **38/38 scenarios**, with zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. Fixture-only results.

## Follow-up: 2026-11-02 BRUTE_FORCE, SLOW_PORT_SCAN, and DATA_EXFIL setting validation

- `BRUTE_FORCE` and `SLOW_PORT_SCAN` forced thresholds to their minimums even when configured with zero, which could lower defaults from 20 to 2 and 30 to 2. `DATA_EXFIL` similarly clamped a zero byte threshold to 1,000 instead of its 50,000-byte default. Invalid windows/state caps could also fail construction.
- Versions `BRUTE_FORCE` 1.4, `SLOW_PORT_SCAN` 1.3, and `DATA_EXFIL` 1.12 now parse settings through safe positive-integer defaults while preserving valid intentional thresholds and the existing minimums. Invalid custom brute-force ports are skipped; valid configured ports remain enabled.
- Added regressions proving invalid settings use defaults and do not lower detection thresholds; existing custom-threshold tests remain unchanged and pass.
- Verification: focused rule tests **118 passed**; full suite **356 tests passed** in 45.91s. Synthetic replay processed **1,163 attack and 832 benign packets**, detected **38/38 scenarios** across all 19 rule families, with zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. Fixture-only results.

## Follow-up: 2026-11-02 malformed TCP sequence metadata in PAYLOAD_HIT

- `PayloadRule._update_stream` converted `tcp_payload_seq` without handling malformed input. Reproduction with a valid SQL injection payload and `tcp_payload_seq="malformed"` raised `ValueError` before packet-level matching, losing that detection.
- Version 1.14 now skips TCP stream reconstruction when the payload sequence number is invalid. The independent packet sample continues through the existing signature inspection, preserving detection for the current packet while leaving stream state untouched.
- Added a regression test that verifies the SQL injection signature alerts despite malformed sequence metadata and that no stream state is created.
- Verification: focused payload tests **38 passed**; full suite **338 tests passed** in 46.60s. Synthetic replay: **38/38 scenarios**, all 19 rule families covered, zero unmatched attack alerts, zero benign alerts, zero dropped alerts, no shutdown timeout; 1,162 attack and 832 benign packets processed. These are fixture-only results.

## Follow-up: 2026-11-02 DNS anomaly setting validation

- `DNS_ANOMALY` accepted `freq_threshold` without parsing it, causing malformed values to raise during packet checks. A zero frequency window silently restricted counts to queries with identical timestamps. Malformed subdomain windows and tracking caps could also raise during construction.
- Version 1.15 now parses frequency and subdomain windows and tracking caps as positive integers, falling back to documented defaults when invalid. Frequency and subdomain thresholds are non-negative: `0` remains the explicit opt-out, while negative or malformed values fall back to the default threshold. This preserves valid settings and prevents invalid input from accidentally disabling detection or breaking checks.
- Added regressions for malformed/negative thresholds, zero opt-outs, invalid tracking caps, zero frequency windows, and malformed subdomain windows. Positive thresholds still trigger the existing query-frequency and distinct-subdomain conditions over their fallback windows.
- Verification: focused DNS and cycle-8 tests **87 passed**; full suite **341 tests passed** in 46.83s. Synthetic replay: **38/38 scenarios**, all 19 rule families covered, zero unmatched attack alerts, zero benign alerts, zero dropped alerts, no shutdown timeout; 1,162 attack and 832 benign packets processed. Fixture-only results.

## Follow-up: 2026-11-02 bounded TLS ClientHello inspection and reassembly

- `TLS_ANOMALY` inspected only the generic DPI payload sample, capped at 512 bytes. A reproducible ClientHello with a 600-byte padding extension before SNI placed the hostname beyond that cap: parsing the full record found the suspicious SNI, while parsing its first 512 bytes did not.
- The existing capture path now provides a separate `tls_payload` sample, capped at the maximum TLS record size, for the rule's existing TLS service ports. `TLS_ANOMALY` first parses this sample and also reassembles bounded sequence-adjacent ClientHello prefixes, buffering up to four out-of-order segments per tracked flow with a 30-second expiry and existing 4,096-flow state limit. Generic DPI payload size and other rule inputs remain unchanged. Detection predicates, port coverage, and alert cooldown remain unchanged; no detection was added.
- Regressions cover SNI beyond the generic payload cap, out-of-order segmentation, and capture extraction of the dedicated sample.
- Verification: focused TLS tests **11 passed**; parser tests **16 passed**; full suite **359 tests passed** in 47.02s. Synthetic replay processed **1,163 attack and 832 benign packets**, detected **38/38 labelled scenarios** across all 19 existing rules, and produced zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. Fixture-only results; they are not estimates of real-world accuracy.

## Follow-up: 2026-11-02 DNS grouping for short gTLD registrations

- `DNS_ANOMALY._parent_domain` treated any alphabetic final label up to three characters and any short preceding label as a likely multi-label suffix. That classified `a.bad.com`, `b.bad.com`, and `c.bad.com` as three separate parents, so the existing distinct-subdomain exfiltration signal could not aggregate them. A direct reproduction with a three-query threshold produced no alert and three different parent keys.
- The heuristic now applies its three-label grouping only when the final TLD has exactly two alphabetic characters, retaining the existing common country-code suffix behavior (for example, `example.co.uk`) while grouping ordinary `.com` registrations such as `bad.com` correctly. Detection thresholds and other DNS anomaly predicates are unchanged. The DNS rule is version 1.16; no rule was added.
- Regressions cover detection under short-label `.com` registrations and retained `co.uk` grouping.
- Verification: focused DNS tests **39 passed**; full suite **361 tests passed** in 45.15s. Synthetic replay processed **1,163 attack and 832 benign packets**, detected **38/38 labelled scenarios**, and produced zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. Fixture-only results.

## Follow-up: 2026-11-02 TLS ClientHello record-boundary validation

- `_extract_tls_sni` previously ignored TLS record and handshake lengths. A reproducible record declaring a four-byte payload but carrying 78 trailing bytes containing a suspicious SNI still returned that hostname, allowing malformed data to trigger an alert as though it were a valid ClientHello.
- `TLS_ANOMALY` version 1.4 now requires a complete, length-consistent record and handshake, bounds extension and server-name parsing to their declared containers, checks the cipher-suite vector, and accepts only ASCII host names as required by TLS SNI. Existing detection predicates and port coverage are unchanged.
- Regression cases cover a record length shorter than its appended data, a handshake length beyond the record, and a truncated record. Existing valid literal-IP, tunnel-SNI, long ClientHello, and reordered segment cases continue to pass.
- Verification: TLS tests **12 passed**; full suite **362 tests passed** in 48.63s. Synthetic replay processed **1,163 attack and 832 benign packets**, detected **38/38 labelled scenarios**, and produced zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. Fixture-only results.

## Follow-up: 2026-11-02 complete HTTP retransmission handling

- `CLEAR_HTTP_ON_TLS_PORT` counted a fully captured request line on every matching packet. A single complete request retransmitted at the same TCP sequence therefore counted twice and fired the existing two-request threshold; a direct reproduction alerted on the second identical segment.
- Version 1.6 tracks bounded exact TCP segment identities for complete requests, using direction, sequence number, and the capture payload digest (or a local digest for legacy records). Duplicate segments within the request window are suppressed before history updates. Distinct requests on a keep-alive connection remain countable because their sequence numbers advance. Late events are rejected before they can populate the retransmission cache.
- Regressions prove exact retransmission suppression, detection of a new same-line request at a later sequence, and that a late event does not poison the cache.
- Verification: focused cleartext tests **14 passed**; full suite **364 tests passed** in 48.95s. Synthetic replay processed **1,163 attack and 832 benign packets**, detected **38/38 labelled scenarios**, and produced zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. Fixture-only results.

## Follow-up: 2026-11-02 full IP multicast exclusion in DATA_EXFIL

- `DATA_EXFIL` documented multicast and broadcast destination exemptions but used string checks that excluded only IPv4 `224.*`, missing the rest of IPv4 multicast space, including `239.0.0.0/8`. A 1,000-byte UDP record from a private source to `239.1.2.3` reproduced a false volumetric exfiltration alert.
- Version 1.13 parses the destination IP and excludes any multicast address plus the limited IPv4 broadcast address. Invalid destination address strings are ignored as unclassifiable. Private-to-public outbound flow thresholds and signature checks remain unchanged.
- Regressions cover IPv4 multicast groups in both 224/8 and 239/8, IPv6 multicast, and limited broadcast; existing public-destination volume and signature cases remain covered.
- Verification: focused DataExfil tests **36 passed**; full suite **365 tests passed** in 48.80s. Synthetic replay processed **1,163 attack and 832 benign packets**, detected **38/38 labelled scenarios**, and produced zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. Fixture-only results.

## Follow-up: 2026-11-02 SYN_FLOOD RST setting validation

- `SYN_FLOOD` used `max(1, int(rst_threshold))`, so a zero RST threshold became 1 and one RST could trigger a flood alert. Several RST windows and state-cap arguments also raised on malformed values or silently clamped invalid values to 1.
- Version 1.7 now applies the existing documented defaults to invalid/nonpositive capacities, thresholds, and windows. The response grace period must be finite and non-negative; zero remains an intentional opt-out. Positive threshold 1 remains valid for explicit single-RST configurations.
- Regressions cover invalid settings and no alert from one RST under fallback defaults, plus valid threshold-one and zero-grace behavior.
- Verification: focused RST tests **12 passed**; full suite **367 tests passed** in 48.42s. Synthetic replay processed **1,163 attack and 832 benign packets**, detected **38/38 labelled scenarios**, and produced zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. Fixture-only results.

## Follow-up: 2026-11-02 TLS cooldown setting validation

- `TLS_ANOMALY` directly converted its cooldown to `float`. With `NaN`, the cooldown comparison is always false, so repeated identical alerts fired without suppression; negative cooldowns similarly bypassed suppression, while malformed strings could break construction.
- Version 1.5 uses the documented 60-second default for malformed, negative, or non-finite cooldowns. `0` remains a valid explicit opt-out; valid positive cooldowns are unchanged.
- Regressions cover NaN, infinity, negative, and malformed values, verify repeated alerts are suppressed after fallback, and confirm zero still allows immediate repeats.
- Verification: TLS tests **13 passed**; full suite **368 tests passed** in 46.83s. Synthetic replay processed **1,163 attack and 832 benign packets**, detected **38/38 labelled scenarios**, and produced zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. Fixture-only results.

## Follow-up: 2026-11-02 detection environment parsing and PAYLOAD_HIT safeguards

- Many detection thresholds and cooldowns were parsed with raw `int()`/`float()` calls during `config.py` import. A malformed environment value could abort IDS startup before rule-level safe defaults were reached. The `PAYLOAD_MAX_BYTES=0` setting also became a one-byte inspection cap, silently losing multi-byte payload signatures; `PayloadRule` directly converted malformed limits and accepted non-finite cooldowns.
- Detection settings now use safe environment readers that fall back on malformed and non-finite values while preserving valid zero opt-outs and leaving range validation to each rule constructor. `PAYLOAD_HIT` version 1.15 validates its payload cap, stream timeout, stream count, and finite non-negative cooldown against existing defaults.
- A subprocess regression sets malformed port-scan, TLS, and exfiltration settings and confirms configuration import succeeds with defaults while DNS frequency zero remains preserved. Payload regressions confirm invalid buffer/cooldown values use safe defaults and signatures still trigger.
- Verification: focused environment and payload tests **40 passed**; full suite **370 tests passed** in 46.70s. Synthetic replay processed **1,163 attack and 832 benign packets**, detected **38/38 labelled scenarios**, and produced zero unmatched attack alerts, zero benign alerts, zero dropped alerts, and no shutdown timeout. Fixture-only results.
