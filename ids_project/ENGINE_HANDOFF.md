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
- One subsequent ClickFix replay/comparison started but was interrupted before completion; its partial DB `/tmp/netguard-current-clickfix.db` is incomplete and must not be used as a result.

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

The most recent test and synthetic evaluation are green. The current notable real-sample lead is that a long `googleusercontent.com` DNS name still trips the DNS length heuristic in ClickFix, while repeated cleartext HTTP on TCP/443 reaches the reported C2 endpoint. The long DNS name may be a legitimate Google-hosted asset or a suspicious name; the available capture and heuristic alone do not establish which. Review its query context and independent labels before adding an allowlist or changing thresholds.

The last attempted ClickFix replay against the existing Suricata EVE output was interrupted; no new comparison result was obtained in that attempt. Do not report it as completed. Earlier comparison results are summarized above.

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

1. Finish the interrupted ClickFix Suricata comparison in a fresh temporary workspace and independently reproduce the earlier ClickFix/Lumma counts.
2. Investigate the long `googleusercontent.com` DNS name with DNS response/context and benign counterexamples. Do not blanket-allow the suffix: preserve length/frequency/subdomain checks unless evidence supports a narrower exception.
3. Review cleartext HTTP-on-TLS-port behavior for proxy/tunnel and protocol-mismatch edge cases, and compare alert aggregation to Suricata's HTTP parser events with a separately documented semantic metric; keep exact event matching unchanged unless justified.
4. Assess state limits and runtime on additional diverse benign and attack captures. Include IPv6, fragmentation/truncation, retransmission, DNS-over-TCP, long-lived flows, QUIC, and mixed traffic, with labeled expected outcomes where possible.
5. Improve the corpus and labels: expand benign diversity and independent labeled attack samples. Do not optimize rules solely against the small 37-scenario synthetic fixture.

## Safety and reporting constraints

- Offline replay only; no live packet capture.
- Do not fetch threat-feed data or execute contents from malware PCAPs.
- Keep temporary databases, ARP tables, EVE output and downloaded samples isolated under `/tmp`.
- Preserve `.env`, local blocklists, ARP tables, databases and user configuration. Prefer test-specific blocklists.
- Suricata is a useful comparative IDS baseline, not ground truth. Synthetic benchmark percentages are not deployment accuracy estimates.
- The scheduled NetGuard improvement heartbeat was stopped at the user's request. Continue only when the user or an explicitly authorized follow-up asks for work.
