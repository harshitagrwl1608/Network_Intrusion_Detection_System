# NetGuard IDS — Deep Review & Next-Changes Plan

**Repository:** https://github.com/harshitagrwl1608/Network_Intrusion_Detection_System  
**Branch reviewed:** `main`  
**Reviewed HEAD:** `5d22fbacd0f2485f7f71b906bd5c03af75439370`  
**Previous reviewed HEAD:** `edce746b71c1dd4572e47fd981cdb0a525a719ee`  
**Review date:** 19 October 2026

## Scope and confidence

This is a source-level review of the current repository tree and the latest commit. I inspected the detection engine, capture/replay, test-PCAP generator, labels, database writer, configuration, dashboard endpoints/UI, and README. I did **not** change the GitHub repository. I could not clone the latest checkout or run the application in this environment because GitHub hostname resolution failed, and the repository has no visible automated test suite or CI workflow in the tracked tree. Therefore, the findings below are code-path findings and risks, not claims from a successful runtime test.

## 1. Overall verdict

NetGuard has a useful end-to-end shape: Scapy capture/normalization → six detection rules → asynchronous DB persistence → Flask/SSE dashboard → replay and evaluation scripts. The latest change is a real improvement over the previous revision: blocklist IPs are normalized, both scan histories are updated before a scan decision, DNS frequency settings are passed into the rule, labels include more endpoint attributes, and the evaluation CLI supports an explicit SQLite database path.

**The next milestone should be reliability and trustworthy evaluation, not more detection rules.** There are still situations where the engine can lose alerts, misclassify benign traffic, or produce metrics that are not a fair measure of precision/recall.

## 2. Highest-priority findings

### P0 — Alerts can be dropped when the DB queue fills

**Where:** `ids_project/engine/rules.py` — `RuleEngine.check()`, `_enqueue()`, `_db_writer_loop()`, and `flush()`.

Every packet with a source MAC and source IP enqueues a `device` write. Alerts use the same bounded queue (`maxsize=2000`). Each device update is persisted separately, and DB writes commit individually. If the queue fills, `_enqueue()` logs and drops whichever item is being enqueued—including an alert. Device churn or a burst of packets can therefore crowd alerts out of the queue. Logging the dropped item does not recover it.

`flush()` also waits at most five seconds and does not wait on `Queue.join()`. On a high backlog, it can return before the writer has finished. This can make a replay look complete while some alerts remain unwritten.

**Required change:**

1. Do not enqueue a device upsert for every packet. Deduplicate by `(MAC, IP)` and coalesce last-seen updates.
2. Give alerts guaranteed delivery semantics separate from device updates. At minimum, reserve alert capacity and apply backpressure or durable spooling when that capacity is exhausted; never silently drop an alert.
3. Expose counters for queue depth, alert write failures, dropped/coalesced device writes, and shutdown timeouts.
4. Implement a reliable drain-and-stop protocol that waits for pending alert writes and closes the writer connection; add overload and shutdown tests.

This is the most important issue to fix because it affects the core security promise of the application.

### P1 — Port scan rule counts UDP packets as scan probes

**Where:** `ids_project/engine/rules.py` — `PortScanRule.check()`.

The guard is `if protocol == "TCP" and not syn_flag: return None`. A TCP packet without the SYN bit is skipped, but a UDP packet with a destination port bypasses the guard and is added to vertical/horizontal scan state. The rule comments and README describe SYN-based scanning, so the implementation and stated behavior disagree.

**Required change:** explicitly restrict the rule to TCP and initial connection attempts. Extract a clear `initial_syn` flag that requires SYN set and ACK clear. Do not count UDP records in this rule unless a separate UDP-scan detector is deliberately implemented and separately named.

### P1 — `DNS_FREQ_THRESHOLD=0` does not disable the frequency rule

**Where:** `ids_project/.env.example`, `ids_project/config.py`, and `DnsRule.check()` in `ids_project/engine/rules.py`.

The example environment says to set `DNS_FREQ_THRESHOLD=0` to disable frequency detection. The code currently checks `query_count >= self._freq_threshold`, so a threshold of zero makes every DNS query satisfy the frequency condition. This can create an alert on the first query per domain.

**Required change:** define frequency detection as enabled only when `freq_threshold > 0`, then check `query_count >= freq_threshold`. Add tests for values `0`, `1`, and the default threshold.

### P1 — DNS allowlisting bypasses all DNS anomaly checks

**Where:** `DnsRule.check()` in `ids_project/engine/rules.py`.

The code returns immediately when a queried domain ends with a whitelisted suffix. That skips not just the high-entropy test, but also long-domain and query-frequency checks. Consequently, a very long or repeatedly queried domain under one of the broad whitelisted suffixes can never trigger this rule. A whitelist intended to suppress known benign entropy can unintentionally suppress the other detection signals too.

**Required change:** apply the allowlist narrowly to the entropy signal (or to explicitly documented checks) instead of returning before all checks. Keep length/frequency checks active unless a separate, explicit exception is justified. Scope trust exceptions to domains the operator owns where possible.

### P1 — SYN flag means “SYN bit present,” not “initial SYN”

**Where:** `ids_project/capture/sniffer.py` — `_extract()`; consumed by both `PortScanRule` and `SynFloodRule`.

The extracted flag is based on the SYN bit alone. SYN-ACK packets also have this bit set. The detector therefore does not distinguish connection-start attempts from SYN-ACK responses. Common service source-port filtering reduces some scan false positives but is not a complete substitute, especially for non-standard service ports.

**Required change:** store the TCP flags or derive `initial_syn = SYN && !ACK` and use it for scan/flood counting. Update explanations and docs so they do not imply handshake outcomes are verified; the current flood rule counts packets and does not track completed handshakes.

### P1 — IPv6 is accepted by the blocklist but not captured/detected

**Where:** `ids_project/capture/sniffer.py` and the `start_sniff()` BPF filter.

The extractor checks Scapy's IPv4 `IP` layer and the default BPF filter is `ip or arp`. It does not normalize IPv6 packets. The blocklist parser accepts IPv6 addresses, but traffic to/from those addresses will not flow through the current IPv4 rule path.

**Required change:** either clearly scope and document the current engine as IPv4-only, or add IPv6 capture/extraction and tests across relevant rules. Avoid implying that IPv6 blocklist entries currently provide protection if IPv6 traffic is not inspected.

### P1 — Documented tcpdump text replay format does not match the parser

**Where:** `README.md` text-capture command and `ids_project/capture/sniffer.py` — `_replay_text_log()`.

The README recommends `tcpdump -nn -tttt ...`, whose records begin with a full date and time (for example, `YYYY-MM-DD HH:MM:SS...`). The parser's main regex expects only `HH:MM:SS...` at the start of a line. With the documented command, records can fail to match and be skipped. The parser also reconstructs a date using today's date, and timestamps without fractional seconds fall back to `time.time()`, undermining replay determinism.

**Required change:** parse the documented full-date format as well as explicitly supported alternatives; report the number of skipped/unparsed lines and fail with a clear message if zero records were processed. Add fixtures for `tcpdump -tttt`, `-tt`, and records without fractional seconds.

### P1 — Evaluation is not yet a complete quantitative benign/attack benchmark

**Where:** `ids_project/evaluation/generate_test_pcap.py`, `evaluation/replay.py`, `evaluation/compare.py`, and `evaluation/scenarios/test_labels.csv`.

The update materially improves ground-truth matching: labels now include source/destination/protocol details, and the evaluator can use an isolated DB. However:

- The ground-truth evaluation command replays the **attack** PCAP and computes metrics against attack scenarios. The generator separately instructs replaying the benign PCAP into another DB with a fresh ARP table, but does not aggregate that result into precision/recall/F1. “Expect zero alerts” is a manual check, not a measured false-positive metric.
- The label CSV describes attack scenarios, not labelled benign examples. There is no machine-readable assertion that benign scenarios produce zero detections, or a combined report that compares attack detections with benign false alarms.
- `compare.py` reads all rows from the selected DB. If the default DB is used and contains old traffic/replays, stale alerts become extra/unmatched events. More subtly, the generator's copy-paste commands reuse the fixed path `/tmp/netguard-eval.db` and do not clear it before replay. Re-running those commands appends duplicate alerts, which the one-to-one matcher can then count as potential false positives. An isolated filename is not enough unless its contents are fresh.
- The test ARP table path is also reused. It is good that attack and benign samples use separate ARP paths, but a runner should create fresh state for each run automatically rather than depend on the user remembering to delete files.
- Matching is scenario-level and greedy. It is suitable for this small synthetic sample only if each scenario is intended to produce one alert; it should not be presented as a broad accuracy benchmark.

**Required change:** create one evaluation runner that automatically creates fresh DB and ARP state for each capture, replays attack and benign sets separately, validates labels, and emits one combined report. Preserve separate state for the benign ARP test to avoid contamination from the attack capture's gateway MAC. Report attack TP/FN, benign FP counts (overall and per rule), and per-scenario outcomes. Save output JSON/CSV plus config/version metadata. Keep Suricata agreement and labelled evaluation explicitly separate; neither engine should be assumed to be ground truth.

## 3. Other important issues

### P2 — ARP spoofing can repeatedly alert on the same conflicting mapping

**Where:** `ArpSpoofRule.check()` in `ids_project/engine/rules.py`.

When an IP appears with a different MAC, the rule returns an alert but leaves the stored mapping unchanged. Every subsequent packet asserting that new MAC can fire the rule again. That can create an alert storm and worsen queue saturation. Preserve the previous trusted mapping for comparison, but add a per-IP cooldown/incident state and a clear re-baselining procedure for legitimate router/device replacement.

### P2 — Offline replay uses PCAP event time but GC uses wall-clock time

**Where:** `replay_pcap()` in `ids_project/capture/sniffer.py` and `RuleEngine._gc_loop()` in `ids_project/engine/rules.py`.

Stateful rules evaluate windows using packet timestamps from the PCAP, but the GC thread calls `prune_stale(time.time())`. Synthetic fixtures use a fixed timestamp in 2023. If a replay takes long enough for the 10-second GC loop to run, the wall-clock cleanup can purge histories that are perfectly current in PCAP event time. This makes replay results dependent on processing speed and conflicts with the claim that results are deterministic.

**Required change:** disable wall-clock GC during offline replay or make the replay driver advance/prune state using the event-time clock. Add a slow-replay regression test.

### P2 — Persisted evidence is not presented in the investigation UI

**Where:** `ids_project/storage/db.py`, `/api/alerts/<id>` in `ids_project/dashboard/app.py`, and `openInvestigation()` in `ids_project/dashboard/static/dashboard.js`.

The rule engine serializes `evidence` to `evidence_json`, and the schema persists confidence, rule version and detection-window fields. The investigation modal displays generic explanation and detail text but does not render the stored structured evidence. This leaves one of the best improvements from the last commit hidden from analysts.

**Required change:** parse the evidence JSON defensively in the API or frontend, render it as an escaped structured evidence section, and include confidence, rule version, and window timing. Fix the generic `SYN_FLOOD` explanation so it says the engine counts SYN packets and does not verify handshake completion. Add a DNS-frequency explanation too.

### P2 — Dashboard exposes telemetry and feedback without authentication by default

**Where:** `ids_project/config.py`, `ids_project/.env.example`, and `ids_project/dashboard/app.py`.

The dashboard defaults to binding `0.0.0.0`, and the routes shown in the source have no authentication/authorization layer. A reachable client can read alert/device history and submit analyst feedback. This may be acceptable for a tightly isolated lab, but is not a safe default for a monitoring tool intended to run on a LAN.

**Required change:** default to `127.0.0.1`; require explicit opt-in to expose the service beyond localhost; add authentication/authorization and TLS or deployment behind a properly configured reverse proxy before network exposure. Restrict feedback writes tocd authorized users.

### P2 — README and rule descriptions are out of sync with implementation

The README still describes the DNS length default as `>50` characters while configuration now defaults to 60. It presents the Suricata comparison as ground-truth benchmarking even though `compare.py` correctly says Suricata is a comparison baseline, not ground truth. It also describes scan thresholds with `>` while the implementation fires at `>= threshold`. Correct the README and UI explanations after behavior is agreed and tested.

### P2 — Some rules remain packet-level heuristics rather than protocol-aware detection

Payload inspection only scans the payload available in an individual packet; it does not reassemble TCP streams, normalize URL encoding, or inspect TLS-encrypted application data. DNS entropy currently examines the first label rather than searching all relevant labels. These are acceptable documented prototype limits, but should be reflected accurately in scope/claims. For the next increment, add bounded TCP stream reassembly and stronger DNS features only after the current tests are stable.

### P3 — Path handling edge cases remain

`storage/db.py:get_connection()` and `engine/blocklist.py:download_blocklist()` call `os.makedirs(os.path.dirname(path), exist_ok=True)` without handling an empty directory name. A valid bare filename such as `alerts.db` or `blocklist.txt` can fail in some of these paths. The ARP table save path already handles this case; apply the same pattern consistently.

## 4. What changed in the latest commit

| Area | Current status |
|---|---|
| IP blocklist matching | Plain IP entries are canonicalized in both loader and observed-IP matcher, improving equivalent IPv6 textual matching (capture still needs IPv6 support). |
| Port-scan state | Vertical and horizontal histories are updated before the threshold decision; this fixes one early-return state issue. UDP filtering remains wrong because the code only skips non-SYN packets when protocol is TCP. |
| DNS frequency | Config values are now passed through the rule engine, and parent-domain grouping has a heuristic for common two-label public suffixes. The zero-threshold and over-broad-whitelist behaviors remain. |
| Payload DPI | Direction handling was refined and multiple signatures/evidence can be included. Packet-level-only limitations remain. |
| Ground truth | The CSV now includes more endpoint/protocol fields and the CLI accepts `--db`. Benign results still are not included in a combined metric. |
| Test fixtures | Attack and benign PCAPs are separate, and test blocklist/ARP paths can be isolated. The scripts still need an integrated automated evaluation/reporting harness. |
| Documentation | The new post-update review is present, but docs should be updated to reflect actual current behavior and benchmark limitations. |

## 5. Recommended work order

### Milestone 1 — Make alert delivery dependable

1. Deduplicate and batch device writes.
2. Separate device traffic from alert delivery; implement no-silent-loss behavior for alerts.
3. Implement reliable `flush()`/shutdown and add overload tests.
4. Add counters that make queue saturation visible in the dashboard/logs.

**Exit criterion:** a stress test can saturate the queue and still prove that every generated alert is persisted or the system raises a clear, measurable failure instead of silently losing it.

### Milestone 2 — Correct the existing rule semantics

1. Use an initial-SYN flag (SYN set, ACK clear) for scan/flood logic.
2. Restrict `PORT_SCAN` to TCP SYNs; test TCP ACK/PSH and UDP packets as negatives.
3. Fix DNS threshold-zero disabling semantics.
4. Keep DNS length/frequency checks active when entropy allowlisting applies.
5. Add ARP alert cooldown/re-baselining semantics.

**Exit criterion:** each rule has table-driven positive, negative, threshold-boundary, and duplicate-alert tests.

### Milestone 3 — Make replay reproducible

1. Fix the tcpdump text parser to support the exact formats documented in the README.
2. Ensure offline replay state cleanup uses event time, not unrelated wall time.
3. Add deterministic tests for packet timestamp preservation and boundary windows.
4. Validate zero-packet/zero-parsed-record cases as errors.

**Exit criterion:** replaying the same PCAP quickly or with an intentionally slow loop yields the same alert set and event timestamps.

### Milestone 4 — Build defensible evaluation

1. Add automated tests and label schema validation.
2. Build a runner that creates brand-new temporary databases and ARP state automatically for each run; never reuse the fixed `/tmp/netguard-eval.db` without resetting it.
3. Compute per-rule true detections/misses and benign false alarms; show the denominator and matching policy.
4. Make DB isolation mandatory for benchmark mode by using a temporary path automatically and validating that the DB starts empty.
5. Keep Suricata agreement as a separate comparison report.
6. Add a GitHub Actions workflow to run tests on every push.

**Exit criterion:** a clean command produces a repeatable report with all scenarios accounted for and no stale production DB rows included.

### Milestone 5 — Improve analyst trust and deployment safety

1. Show persisted structured evidence in the investigation modal.
2. Add auth and secure deployment defaults for dashboard access.
3. Align README, `.env.example`, alert explanations and claims with tested behavior.
4. Decide explicitly whether this release is IPv4-only or implement tested IPv6 capture.

Only after these milestones should you prioritize additional detection types (ICMP anomaly detection, lateral movement, TCP stream DPI, NXDOMAIN/unique-subdomain DNS analytics).

## 6. Minimal regression test plan

- `PortScanRule`: 15 distinct TCP SYN destination ports alert at the configured threshold; TCP ACK-only and UDP probes do not alert; vertical and horizontal scans are distinct.
- `SynFloodRule`: initial SYNs count; SYN-ACKs do not; threshold N-1 does not alert and N does.
- `DnsRule`: threshold zero disables frequency; threshold N fires at N; whitelist exempts only intended signal(s); long/entropy/frequency outcomes are independently tested.
- `ArpSpoofRule`: first mapping does not alert; conflicting mapping alerts once during cooldown; legitimate re-baselining behaves explicitly.
- `RuleEngine`: a full queue does not silently discard alerts; writer failure/shutdown is visible and recoverable.
- `replay_pcap`: event times are preserved; results do not change with processing delay; supported tcpdump text fixtures parse all intended rows.
- `compare.py`: stale/production DB cannot enter benchmark results; every attack label gets exactly one outcome; benign false alarms are counted in the aggregate result.
- `Dashboard`: evidence is escaped and rendered, and unauthenticated access is rejected when network exposure is configured.

## 7. Bottom line

The latest update improves the project materially, especially the rule state, blocklist matching and label specificity. The remaining issue is not a lack of features; it is whether the engine can preserve alerts under load and whether test results mean what they claim to mean.

**Fix queue/alert reliability first, then rule correctness, then deterministic replay, then a combined attack+benign evaluation harness.** Once those are in place, the project will be much easier to defend in a demo, portfolio review, or technical interview because you will be able to explain not only what it detects, but also how you tested the claims and what its known limits are.
