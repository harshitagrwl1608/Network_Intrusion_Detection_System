# NetGuard IDS — Post-Update Code Review

**Repository:** https://github.com/harshitagrwl1608/Network_Intrusion_Detection_System  
**Reviewed branch:** `main`  
**Current reviewed HEAD:** `edce746b71c1dd4572e47fd981cdb0a525a719ee`  
**Previous reviewed revision:** `9c38a36aa48361e391cd53d507d38b1f8ec4f9dc`  
**Review basis:** Static review of commit `edce746` and changed files. No code was changed in the repository, and this review did not execute the application or run a test suite.

---

## 1. Executive summary

This is a substantial and directionally good update. Compared with the previous revision, the latest commit changes the capture/normalization layer, rules, configuration, blocklist parser, replay and evaluation tools, test-PCAP generator, and alert schema. It also adds a labelled-scenario CSV and this project's improvement roadmap.

Several earlier recommendations are now partly or substantially addressed:

- PCAP replay now passes the captured packet timestamp into `_extract()` and separates event time from processing time.
- Port-scan tracking now distinguishes vertical and horizontal dimensions and uses a lock around the main scan state.
- Payload DPI collects multiple matching signatures and adds structured evidence and confidence metadata.
- DNS query-frequency tracking has been introduced.
- Blocklist loading now distinguishes exact IP addresses from CIDR networks and downloads via a temporary file followed by `os.replace()`.
- Alert storage now has fields for rule version, source port, protocol, confidence, evidence JSON, and detection-window boundaries, with migrations for existing databases.
- Replay can accept alternate blocklist, SQLite database, and ARP-table paths.
- The Suricata comparison distinguishes engine agreement from the separate ground-truth mode.
- The PCAP generator now creates attack and benign captures and writes a test-only blocklist rather than appending the test indicator to the default feed.

**The next priority is to make the evaluation workflow trustworthy and the new configuration actually effective, then close a few implementation gaps.** The current change is a meaningful step forward, but code and documentation that advertise a ground-truth metric do not yet make the scenario matching specific enough to justify that claim.

## 2. What improved in this commit

| Area | Change in the latest commit | Assessment |
|---|---|---|
| Packet timestamps | `_extract()` now supports `capture_ts`, uses `pkt.time` when available, and retains `event_timestamp`, `processing_timestamp`, and the legacy `timestamp` alias. | Good correction for deterministic PCAP replay. Still needs automated tests for both binary PCAP and text-log replay. |
| Port scans | `PortScanRule` uses separate vertical `(src_ip, dst_ip)` and horizontal `(src_ip, dst_port)` histories, evidence fields, rule versions, and an `RLock`. | Correct direction; one control-flow issue remains where a vertical hit returns before horizontal history is updated for that packet. |
| DPI | Payload matching now gathers all matching signatures and records inspected-byte evidence, signature confidence, and packet-level limitations. | Better evidence. The intended server-response direction skip is described in comments but is not implemented by the actual conditional. |
| DNS | Entropy, length, and repeated-query frequency can contribute to an anomaly alert; state and cooldown logic are present. | Useful expansion, but the configured frequency threshold/window are not wired into the rule constructor, and parent-domain grouping needs correction. |
| Blocklist | `BlocklistData` separates exact IPs from parsed CIDR networks; invalid entries are skipped with a warning; refresh uses a temp file and atomic replacement. | Substantial improvement. Exact IP strings are not canonicalized and CIDR lookup is a linear scan over stored networks. |
| Alert schema | DB schema and write function now persist rule version, source port, protocol, confidence, JSON evidence and window fields. | Good. The frontend does not yet appear to render `evidence_json` in its JavaScript investigation UI. |
| Evaluation | `compare.py` now has `agreement` and `ground-truth` modes; the Suricata matcher checks more fields and one Suricata event can match at most one NetGuard alert. | Agreement reporting is clearer. The ground-truth CSV/matcher integration still needs work before precision/recall/F1 should be trusted. |
| Test fixtures | Generator now creates attack and benign PCAPs and an isolated test blocklist. | Better separation from production data. The current CSV does not identify scenario endpoints or benign expectations, and generated usage instructions contain a broken replay command. |
| Queue lifecycle | The writer queue is bounded and there is a stop event. | Avoids unbounded growth, but the queue drops entries when full and shutdown can return after a five-second join while writes may still be pending. |

The commit changes the existing six rule classes; it does **not** yet implement the additional ICMP anomaly, lateral-movement, dedicated authentication brute-force, data-exfiltration, beaconing, or Slowloris rules discussed in the earlier proposal. The sniffer now extracts some ICMP fields, which is useful preparation for future rules.

## 3. Highest-priority follow-up changes

### P0 — Repair the ground-truth evaluation contract

**Files:** `ids_project/evaluation/scenarios/test_labels.csv`, `ids_project/evaluation/compare.py`, `ids_project/evaluation/generate_test_pcap.py`, `ids_project/evaluation/replay.py`.

The new `test_labels.csv` currently has only `scenario_id`, `expected_rule`, and `description`. `run_ground_truth()` is written to optionally match `src_ip`, `dst_ip`, and `dst_port`, but those fields are absent from this CSV. In practice, the matcher can therefore count an alert with the expected rule name as a match for a scenario even when it came from a different test event. The CSV's `description` field is also not the `notes` field referenced in the evaluator's reporting code.

There is a second workflow mismatch: `replay.py` supports `--db`, but `compare.py` has no corresponding database option and reads `config.SQLITE_PATH`. Therefore, a replay that writes to an isolated database will not automatically be evaluated against that same database by the documented command.

**Recommended fix:**

1. Extend the scenario manifest with stable fields such as `scenario_id`, `pcap`, `expected_rule`, `src_ip`, `dst_ip`, `dst_port`, `protocol`, expected detection outcome, and description. Where one scenario can produce more than one valid rule, represent expected detections explicitly rather than assuming one alert per scenario.
2. Add `--db` to `compare.py` and use the same isolated database for replay and evaluation. Add an isolated ARP-table path to evaluation instructions too. Do not let test runs accidentally analyse the normal working database.
3. Label benign scenarios explicitly and report attack-scenario detection separately from benign false alerts. Do not mark every unmatched alert from an attack capture as a false positive if it may be a valid secondary detection.
4. Use an event identity or scenario-specific matching fields, not rule name alone. Enforce one-to-one matching and document how duplicate alerts and multi-hit rules are counted.
5. Add assertions that fail when required label columns are missing, the database has no test run, or a scenario maps ambiguously.

Until these changes land, treat the new ground-truth mode as a useful prototype, not a validated measurement of operational precision, recall, or F1.

### P0 — Fix the replay command printed by the PCAP generator

The generator currently prints a command shaped like:

```bash
python evaluation/replay.py data/test_attacks.pcap --blocklist data/test_blocklist.txt
```

But the replay parser requires the PCAP to be passed as `--pcap`. The instruction should instead follow the parser's accepted arguments, for example:

```bash
python evaluation/replay.py \
  --pcap data/test_attacks.pcap \
  --blocklist data/test_blocklist.txt \
  --db /tmp/netguard-eval.db \
  --arp-table /tmp/netguard-eval-arp.json
```

Then provide the same database path to the evaluation command after adding `compare.py --db`. A separate clean database should be used for each repeatable benchmark run.

Also harden `replay.py` for a missing explicit `--blocklist` path. It logs a warning when the path is missing, but then calls `load_blocklist()` with no URL; `load_blocklist()` subsequently attempts to open the nonexistent file. Either fail immediately with a clear error or return an empty, explicitly disabled blocklist without crashing.

### P1 — Wire DNS frequency configuration through the complete path

**Files:** `ids_project/config.py`, `ids_project/engine/rules.py`, `ids_project/.env.example`.

`config.py` now defines `DNS_FREQ_THRESHOLD` and `DNS_FREQ_WINDOW`, but `DnsRule` uses class constants `FREQ_THRESHOLD = 20` and `FREQ_WINDOW = 60`, and the `RuleEngine` constructor does not pass those config values to `DnsRule`. Changing these environment variables therefore has no effect on the frequency detector. The `.env.example` file also does not document the new settings.

**Recommended fix:** accept `freq_threshold` and `freq_window` in `DnsRule.__init__`, assign instance fields, use them consistently in `check()` and `prune_stale()`, pass them from `RuleEngine`, and document them in `.env.example`. Add tests proving that changing each value changes the firing boundary.

### P1 — Correct parent-domain grouping in DNS frequency detection

`DnsRule._parent_domain()` uses the last two DNS labels as the parent domain. That does not always produce the registrable domain: for example, unrelated names such as `one.example.co.uk` and `two.other.co.uk` can both collapse to `co.uk`. This can aggregate unrelated query activity and trigger false frequency alerts.

**Recommended fix:** use a maintained Public Suffix List-aware library or a deliberately limited, documented suffix strategy. Add tests for multi-label public suffixes (such as `co.uk` and `com.au`) and for domains with changing subdomains. For frequency-only alerts, use a cooldown key scoped to `(source, parent domain, detection subtype)`; a cooldown on the full query name can still emit many alerts for changing subdomains under the same parent.

### P1 — Implement the DPI response-direction filter, not just its comment

`PayloadRule.check()` comments that server-direction response traffic should be skipped when `src_port` is a DPI service port. The condition actually present only returns when **neither** `dst_port` nor `src_port` is in `_DPI_PORTS`; when the source port is a known service port, the packet continues to payload matching. Thus server responses are still inspected despite the comment.

**Recommended fix:** implement and test an explicit direction decision. As a minimal heuristic, do not treat a packet whose source is a configured service port and whose destination is not a configured service port as a client-originated request. For a more defensible approach, track connection direction or parse supported application protocols rather than inferring direction exclusively from port numbers. Keep the limitation documented: per-packet DPI does not reconstruct TCP streams.

### P1 — Avoid skipping entire shared-hosting suffixes in DNS

The DNS allowlist includes broad hosting/CDN suffixes such as `github.io`, `cloudfront.net`, and `s3.amazonaws.com`. These services can host both legitimate and abusive infrastructure. A global suffix exemption can suppress suspicious subdomains simply because they are hosted by a large provider.

**Recommended fix:** make allowlists configurable and narrowly scoped (prefer exact domains or explicit organisation-owned names), include the allowlist reason in diagnostic telemetry, and test suspicious subdomains under shared hosting domains. A known hosting provider should be context, not an automatic guarantee of benign activity.

### P1 — Avoid losing security alerts when the writer queue is full

The queue is now bounded, but `_enqueue()` uses `put_nowait()` and logs a warning when full. It drops both device records and alert records. During a burst, this can lose the very alerts the detector is intended to preserve. `flush()` also joins the writer for a fixed five seconds and can return without proving all pending writes finished.

**Recommended fix:** make overload behavior explicit and observable. Consider different policies for low-priority device refreshes versus security alerts; use backpressure, alert-priority capacity, or a durable spool for alerts. Add counters for queue depth, rejected records, write failures and shutdown timeout. Make shutdown wait for queue completion or report unambiguously that some work could not be flushed. Add a stress test that verifies alert persistence under load.

### P2 — Update the dashboard to show the new alert evidence

The database and alert detail API now expose extended alert columns, but `dashboard/static/dashboard.js` does not reference `evidence_json`, `rule_version`, `confidence`, or the window fields in the reviewed version. The extra data is persisted but is not yet surfaced in the analyst workflow.

**Recommended fix:** render the rule version, confidence, observed time window and structured evidence in the investigation modal. Parse `evidence_json` defensively and display content as text (not unsafe HTML). Preserve bounded evidence and avoid storing unnecessary credentials or complete sensitive payloads.

### P2 — Keep exact IP entries canonical

The blocklist loader validates exact addresses but stores their original strings. The matcher checks exact strings before parsing the address for CIDR membership. Equivalent IPv6 spellings can therefore fail an exact match. Normalize exact IPs on ingestion with `str(ipaddress.ip_address(token))`, and normalize the observed endpoint the same way before exact matching. Add IPv4, IPv6, CIDR, invalid-line, and mixed-feed tests. For very large network lists, profile the per-packet linear CIDR scan and consider an indexed range lookup only if measurements justify it.

### P2 — Complete the documentation updates

The README and `.env.example` files did not change in the latest commit. They do not describe the new benign PCAP, test blocklist, label schema, new rule configuration, or distinction between engine-agreement and ground-truth modes. The README still describes the former narrower synthetic capture and refers to precision/recall/F1 from the Suricata comparison without the new qualification.

**Recommended fix:** refresh both READMEs and `.env.example` after the evaluation workflow is corrected. Provide one copy-pasteable clean test sequence and state explicitly which metrics are ground-truth metrics versus agreement statistics.

## 4. Smaller correctness and maintainability points

- `PortScanRule.check()` returns immediately when the vertical-scan threshold fires, before the current packet is added to horizontal-scan history. Keep both state updates independent so a packet contributes to both dimensions; emit multiple alerts if both dimensions cross a threshold and the alert schema supports it.
- `BlocklistRule._in_blocklist()` scans the CIDR list linearly. It is acceptable for a small list, but its cost should be measured as network entries grow.
- In the generator, label registration is kept in a module-level list. Clear or rebuild the scenario manifest on each generation invocation if the generator may be called repeatedly from tests in the same Python process.
- The rule cleanup thread uses a timed sleep, and the ARP persistence thread runs in an indefinite loop. Add consistent stop events and joins where deterministic shutdown is important.
- The database connection factory should handle a SQLite path with no directory component safely (`os.path.dirname(path) or "."`).
- The `severity` and `confidence` vocabularies need documentation: a heuristic may be high impact but uncertain; a strong signature match is not proof that exploitation succeeded. Keep severity, confidence and investigation status distinct.

## 5. Recommended next sequence

1. **Correct evaluator and CLI wiring**: update the label schema, add `compare.py --db`, fix the generator's replay command, and make missing blocklist handling explicit.
2. **Add test automation**: test `_extract()` event timestamps; verify vertical/horizontal scan boundaries; test exact/CIDR blocklists; test DPI request/response direction; test DNS frequency configuration and public-suffix grouping; test schema migrations against an existing DB; and test repeatable isolated replay.
3. **Fix DNS configuration and parent-domain logic**; narrow broad allowlists.
4. **Fix DPI direction and port-scan state update ordering.**
5. **Harden the writer queue and shutdown** with drop/timeout telemetry and an alert-preserving overload policy.
6. **Expose the structured evidence in the dashboard** and refresh documentation.
7. Only then consider new rules such as ICMP anomalies, lateral movement, beaconing, or exfiltration analytics.

## 6. Acceptance checklist

- [ ] Replaying the same PCAP twice into clean isolated state yields the same rule results and uses packet capture timestamps.
- [ ] Ground-truth scenarios match by concrete event/scenario attributes, not rule name alone.
- [ ] The evaluator uses the same specified database as replay and can test both attack and benign captures.
- [ ] Changing `DNS_FREQ_THRESHOLD` and `DNS_FREQ_WINDOW` through environment configuration changes detector behavior.
- [ ] DNS frequency state behaves correctly for domains with multi-label public suffixes.
- [ ] A known service-port response is handled according to the documented DPI direction policy.
- [ ] Vertical and horizontal histories both receive packets even when one detector dimension fires.
- [ ] Alert queue overload and shutdown cannot silently discard alerts without a visible counter/error report.
- [ ] The dashboard shows structured evidence and rule/confidence/window fields from saved alerts.
- [ ] README instructions match the actual CLI and distinguish ground-truth metrics from engine agreement.
- [ ] Automated tests and CI pass on a fresh checkout.

## 7. Scope note

This is a static review of the latest pushed code at commit `edce746b71c1dd4572e47fd981cdb0a525a719ee`. I verified repository contents and reviewed changed implementations, but did not run the Python app, replay the PCAP files, benchmark performance, or execute a test suite. The recommendations above identify code-path gaps visible in source; measured accuracy and runtime behavior remain to be established by tests.
