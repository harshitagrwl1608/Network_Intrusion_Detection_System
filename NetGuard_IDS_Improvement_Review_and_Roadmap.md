# NetGuard IDS — Code Review, Improvement Recommendations & Implementation Roadmap

**Repository:** [harshitagrwl1608/Network_Intrusion_Detection_System](https://github.com/harshitagrwl1608/Network_Intrusion_Detection_System)  
**Review date:** 19 October 2026  
**Reviewed branch:** `main`  
**Reviewed tree revision:** `9c38a36aa48361e391cd53d507d38b1f8ec4f9dc`  
**Basis:** Static review of the repository files retrieved during this review, plus the supplied `engine_finetuning_plan.md`.

> **Scope and confidence:** This is a source-code review and improvement plan. The application was not executed and no live-traffic benchmark or complete test-suite run was performed. Findings below describe behavior visible in the reviewed source; throughput, accuracy, and runtime impact remain to be measured. Suggestions are recommendations, not claims about currently implemented behavior.

---

## 1. Executive Summary

NetGuard is a promising, modular network intrusion detection project. The repository includes packet capture and normalization, six independent detection rules, asynchronous alert persistence, a Flask SOC dashboard, analyst TP/FP feedback, PCAP replay, and a Suricata comparison script.

The next major improvement should be **reliability and defensible evaluation before adding a large number of new rules**. The current project has useful building blocks, but several implementation and evaluation details could lead to misleading results:

1. PCAP replay does not preserve packet timestamps in `_extract()`; timestamps are initialized using the current wall-clock time.
2. Port scan tracking combines destinations under a source IP, making vertical and horizontal scan classification impossible with the current state key.
3. Payload DPI returns on the first signature match, examines individual packet payloads, and does not reassemble full application streams.
4. DNS detection uses query length and leftmost-label entropy, but lacks query-rate, NXDOMAIN-rate, and interval analytics.
5. The alert table does not persist each rule's structured `evidence` dictionary.
6. The Suricata comparison matches primarily on source IP, destination IP, and timestamp; it does not establish independent ground truth and does not include destination port or rule semantics in the match key.
7. Stateful detection objects are checked by the capture thread while a separate cleanup thread calls `prune_stale()`; those shared state structures do not show per-rule synchronization.
8. Every observed source device packet can enqueue a device upsert, and the writer commits each write individually. This deserves load measurement and may become avoidable storage work.

### Recommended priority

**First:** correct timestamps and build automated tests.  
**Second:** improve the reliability and evidence quality of the six existing rules.  
**Third:** implement a labelled evaluation pipeline with defensible metrics.  
**Fourth:** add new detection capabilities selectively, beginning with lateral-movement and ICMP anomaly detection after the normalized event schema is expanded.

The project's strongest differentiator is not the number of signatures it has. It is the combination of a self-built engine, understandable explanations, persistent evidence, analyst feedback, and a transparent comparison against an established engine.

---

## 2. Current Project Snapshot

The following components were present in the reviewed repository tree:

| Component | Repository path | Reviewed status |
|---|---|---|
| Packet capture and normalization | `ids_project/capture/sniffer.py` | Present; uses Scapy and extracts IP/ARP, TCP/UDP ports, SYN indicator, selected payload bytes, and DNS query name |
| Detection rules and orchestrator | `ids_project/engine/rules.py` | Present; six rules run for each normalized record |
| Threat-feed loading | `ids_project/engine/blocklist.py` | Present; local feed with age-based refresh attempt |
| Configuration | `ids_project/config.py`, `ids_project/.env.example` | Present; thresholds and selected features configurable |
| Alert persistence | `ids_project/storage/db.py` | Present; SQLite/PostgreSQL abstraction, alerts, observations, devices and analyst feedback |
| Analysis layer | `ids_project/analysis/aggregator.py` | Present; derives observations and a basic threat level from recent alerts |
| Web dashboard | `ids_project/dashboard/` | Present; Flask endpoints, frontend assets, dashboard data and SSE endpoint |
| Replay | `ids_project/evaluation/replay.py`, `ids_project/capture/sniffer.py` | Present; binary PCAP and text-log replay paths |
| Synthetic fixture generator | `ids_project/evaluation/generate_test_pcap.py` | Present; crafts representative synthetic packets for a small subset of patterns |
| Suricata comparator | `ids_project/evaluation/compare.py` | Present; compares alert lists using a simple heuristic match |

### Existing six rules

1. `BlocklistRule` — exact IP-string match against a loaded set.
2. `PortScanRule` — tracks distinct destination ports per source within a sliding window.
3. `SynFloodRule` — counts SYN packets for a `(source IP, destination IP, destination port)` key within a sliding window.
4. `ArpSpoofRule` — persists an observed IP-to-MAC mapping and alerts when a known IP is observed with a different MAC.
5. `PayloadRule` — checks selected ports and a capped per-packet payload sample against four regular-expression signatures.
6. `DnsRule` — flags a DNS query when the leftmost label's entropy or the complete query length exceeds configured limits, with a 60-second duplicate-alert cooldown for the same source/domain pair.

The implementation should not be described as having the additional rules in the supplied plan until they are implemented and tested.

---

## 3. Verified Code Findings and Proposed Fixes

### 3.1 PCAP timestamps are not preserved

**Files:** `ids_project/capture/sniffer.py`, especially `_extract()` and `replay_pcap()`.

`_extract()` creates each record with `{"timestamp": time.time()}`. The replay path passes packets to `_extract()` but does not replace that value with the captured packet's timestamp. Synthetic PCAP packets have their own `pkt.time` values, but the rule engine is not using those captured timestamps through this extractor.

**Why it matters:** sliding-window outcomes during replay may depend on how quickly replay runs rather than on the original traffic timing. That undermines reproducibility and can make timing-based comparisons unreliable.

**Recommended fix:** use the packet's capture timestamp when available, with a safe fallback for live packets or packet types without a timestamp. Keep event time distinct from processing time if both are useful. Test replay using packets with known timestamps and assert deterministic results.

### 3.2 Port-scan detection does not separate targets

**File:** `ids_project/engine/rules.py`, `PortScanRule`.

The state uses `source IP -> [(timestamp, destination port)]`. It does not retain destination IP in the scan-history key. Activity by one source against multiple hosts can therefore contribute to one pool of distinct ports. The rule also emits a generic scan alert rather than a clear scan type.

**Recommended fix:** maintain separate detection dimensions:

- **Vertical scan:** `(src_ip, dst_ip)` with distinct destination ports.
- **Horizontal scan:** `(src_ip, dst_port)` with distinct destination IPs.
- **Slow scan:** longer-lived summaries across multiple short windows, with bounded memory and explicit time-based expiration.

Return the measured values, observation window, threshold, target count and scan type in structured evidence. Preserve multi-rule alerting; do not add an early exit.

### 3.3 SYN-flood rule measures connection attempts, not confirmed flooding

**File:** `ids_project/engine/rules.py`, `SynFloodRule`.

The rule counts SYN packets for each source/destination/service tuple. It does not track handshake outcomes, SYN-ACK observations, ACK completion, overall destination load, or distributed multi-source rate.

**Recommended fix:** keep this as a threshold-based **SYN burst / possible SYN flood** detector unless additional flow-state evidence is implemented. If handshake correlation is added, collect sufficient TCP flags and track connection state with appropriate expiration. Make thresholds configurable and evaluate a threshold sweep against benign and attack cases; do not assume that a lower threshold is automatically better.

The plan's suggested SYN-ACK ratio cannot be implemented reliably from the current record schema alone; additional TCP-flag and flow-correlation state is required.

### 3.4 Payload DPI is packet-scoped and returns only the first match

**File:** `ids_project/engine/rules.py`, `PayloadRule`; `ids_project/capture/sniffer.py`.

The rule checks at most the configured payload size, returns when the first regex matches, and examines packet-level TCP raw payload rather than a reassembled application stream. The configured ports are only heuristics for deciding whether the payload may be plaintext.

**Limitations:** split requests, percent-encoded content, application-layer framing, and patterns after the inspected byte cap can be missed. A signature match is evidence of a suspicious pattern, not proof that an application was successfully exploited. Port number alone cannot prove the protocol is plaintext.

**Recommended fix:**

- Return all signatures that match the same inspected sample.
- Preserve the signature identifier, bounded match evidence, direction, protocol assumptions, and inspection limit.
- Add test cases for case variants, whitespace, encodings, benign strings that resemble signatures, and matches beyond the size cap.
- Add HTTP normalization or TCP stream reassembly as a separate, scoped feature with its own tests; do not silently treat the current packet-level DPI as complete application inspection.
- Avoid persisting unnecessary credentials or full sensitive payloads. Store bounded evidence and apply clear retention controls.

### 3.5 DNS anomaly detection needs domain-level temporal features

**File:** `ids_project/engine/rules.py`, `DnsRule`.

The current rule evaluates leftmost-label Shannon entropy and total query length. It deduplicates the same `(source IP, domain)` alert within 60 seconds but does not count repeated queries or calculate inter-query timing. The sniffer currently extracts DNS query names from UDP DNS query packets.

**Recommended fix:** keep entropy and length as separate evidence signals, then add bounded state for:

- Query frequency by source and normalized parent domain.
- Number of distinct queried subdomains under a parent domain.
- NXDOMAIN response rate, requiring response-code extraction and query/response correlation.
- Inter-arrival time regularity for candidate beaconing, using preserved capture timestamps.

A DNS alert cooldown must limit repeated notifications without erasing the underlying counters. Use configurable allowlists with an explicit scope; do not assume a cloud or CDN suffix is always benign.

### 3.6 CIDR blocklist entries are not evaluated as networks

**File:** `ids_project/engine/blocklist.py`, together with `BlocklistRule` in `engine/rules.py`.

The loader reads feed entries into strings, and `BlocklistRule` checks whether the exact source or destination string belongs to that set. A CIDR entry such as `203.0.113.0/24` will not match an address such as `203.0.113.7` through exact set membership.

**Recommended fix:** parse exact IPv4/IPv6 addresses separately from network entries. Normalize valid entries and match IPs against networks using `ipaddress`. Add tests for exact IPv4, IPv6, IPv4 CIDR, invalid entries and empty feeds. Keep domain matching as a separate capability; a DNS-domain query is not the same thing as an IP blocklist entry.

Also validate downloaded content and update the feed atomically so a failed or malformed refresh does not replace a previously usable file. Surface feed freshness and refresh failures to logs/dashboard.

### 3.7 Structured evidence is lost at persistence time

**Files:** `ids_project/engine/rules.py`, `ids_project/storage/db.py`.

Some rules include an `evidence` dictionary in their alert result, but the visible alert schema and insertion function do not persist that dictionary. The final stored alert therefore loses structured fields such as `distinct_ports`, `window_s`, `threshold`, DNS entropy, subdomain and signature evidence.

**Recommended fix:** add an `evidence_json` column through a safe migration and serialize bounded, JSON-compatible evidence. Add a stable rule version/detection ID. Ensure the dashboard details endpoint can render the evidence safely and that the evaluation code can export it.

### 3.8 Stateful rule tracking and background cleanup share mutable state

**File:** `ids_project/engine/rules.py`, `RuleEngine` and stateful rules.

The sniffer path invokes each rule's `check()` while `_gc_loop()` calls rules' `prune_stale()` methods from another thread. The reviewed stateful dictionaries do not show per-rule synchronization between those two paths.

**Recommended fix:** either give each stateful rule a lock around updates and pruning, or move pruning into the same processing path with bounded work. Add concurrent stress tests. Ensure state has maximum size, predictable expiry and observable cleanup behavior.

### 3.9 Database work may become a bottleneck

**File:** `ids_project/engine/rules.py`, `RuleEngine.check()` and `_db_writer_loop()`.

Every source packet with a MAC and IP can enqueue a device-upsert operation. The writer processes queue items one at a time, and the database functions commit writes individually. The queue is not bounded in the visible setup.

**Recommended fix:**

- Deduplicate device updates or update device last-seen values on a controlled interval.
- Batch compatible database writes and commit them together.
- Use a bounded queue with explicit backpressure and counters for queue depth, write errors and rejected/dropped work.
- Add graceful stop signaling, worker joins and shutdown flushing.
- Measure before considering multiprocessing; move to separate processes only if profiling shows a real limitation.

### 3.10 Suricata comparison is not independent ground-truth evaluation

**File:** `ids_project/evaluation/compare.py`.

The matcher considers source IP, destination IP and a five-second timestamp tolerance; it does not require the destination port or detection rule/category to match. Suricata events are treated as the reference for TP/FP/FN counts.

**Why it matters:** different events between the same endpoints can be paired, and a valid detection made only by one engine is not necessarily a false positive or false negative. Suricata is a valuable comparative baseline, but its alerts are not automatically ground truth.

**Recommended fix:** implement two explicitly named evaluation modes:

1. **Ground-truth evaluation:** compare expected labelled scenarios/events with NetGuard output.
2. **Engine agreement:** compare NetGuard and Suricata outputs using a documented match key and tolerance, reporting agreement/disagreement without mislabelling it as ground truth.

Where applicable, include destination port, protocol, time window, scenario ID and detection category in event matching. Ensure that one reference event cannot match multiple candidate alerts. Isolate the database and reset rule state between evaluation runs.

### 3.11 Synthetic test coverage is narrow

**File:** `ids_project/evaluation/generate_test_pcap.py`.

The fixture generator creates normal-looking packets and patterns for a blocklist hit, port scan, SYN burst and ARP mapping change. The checked-in generator does not establish complete tests for all current rules, benign edge cases, and proposed new rules.

**Recommended fix:** make each scenario reproducible and label its expected outcome. Include positive, negative and boundary cases for every rule. Avoid having the generator silently contaminate the production/default blocklist with a test indicator; prefer a dedicated test-feed fixture and isolated temporary paths.

### 3.12 Dashboard claims and event-stream implementation should be described precisely

**File:** `ids_project/dashboard/app.py` and README files.

The `/api/stream` route emits Server-Sent Events, but it polls the database every two seconds to discover new alerts. The dashboard should not be described as sending events directly from a rule at the instant the rule fires.

**Recommended fix:** retain SSE and consider a shared event queue/pub-sub mechanism if lower-latency streaming is required. Design reconnection/catch-up behavior, bounded buffers and handling for multiple clients. Document the actual polling/streaming behavior and measured latency.

### 3.13 Deployment security needs a release checklist

The dashboard configuration allows host binding through environment settings and includes investigation and feedback endpoints. Before exposing it to other machines, review authentication and authorization, debug mode, CSRF/input handling where applicable, secret management, database permissions, and the risk of storing network payload or internal-address data. Prefer loopback binding by default for development unless LAN exposure is deliberately configured.

---

## 4. Review of the Supplied Finetuning Plan

The supplied `engine_finetuning_plan.md` proposes improvements to the current six rules and six additional rules. The direction is useful, but some recommendations need adjustment before implementation.

| Proposal | Recommendation | Reason / prerequisite |
|---|---|---|
| Horizontal and slow scans | Implement early | Fixes missing destination dimension; use separate vertical/horizontal state keys and bounded longer-term tracking. |
| Collect all DPI matches | Implement early | Improves evidence breadth with limited architectural change; add false-positive tests and keep payload limits. |
| CIDR IP feeds | Implement early | Current blocklist is exact-string matching; network parsing is required. |
| Domain blocklist | Add as separate module | Domain indicators are not interchangeable with IP indicators; normalize and match DNS names separately. |
| Lower SYN flood threshold to 50 | Do not hard-code this as the final threshold | Run a labelled threshold sweep; high SYN rate alone does not establish incomplete handshakes or impact. |
| SYN-ACK ratio | Later, after TCP state extraction | Requires packet-flag detail and reliable handshake correlation that the current record schema lacks. |
| Brute-force rule using SYNs | Rename/re-scope initially as connection-attempt burst | A repeated connection to SSH/RDP/FTP does not prove failed authentication. Login failure evidence needs protocol/application visibility. |
| ICMP anomaly rule | Good early new rule | Extend normalized records to include ICMP type/code, payload size and relevant direction. Treat large payloads as a heuristic, not proof of tunnelling. |
| Lateral movement | Good early new rule | Add configurable internal CIDRs, internal/external classification and target-host tracking. Exemptions should be explicit and audited. |
| Data exfiltration | Redesign first | Count bytes using flow/IP length accounting and direction; payload sample length is not total transferred volume. Cloud destination allowlists alone are insufficient. |
| DNS beaconing | Add after timestamps and DNS state are reliable | Requires event time preservation, bounded interval history and sample-count policy. Periodicity is a signal, not proof of C2. |
| Slowloris | Defer | Requires TCP connection and HTTP-header/request timing state; encrypted HTTP traffic limits visibility without additional decryption or endpoint telemetry. |
| Alert cooldown for all rules | Implement centrally and carefully | Suppress duplicate notifications without discarding counters or underlying event history. |
| Severity tiers | Implement with evidence and documentation | Separate severity (impact), confidence (strength of evidence), and workflow status (analyst handling). Do not arbitrarily label marginal evidence as high. |
| Active IPS blocking | Defer | Requires an explicit authorization boundary, safe mode, expiry, rollback and protection from false-positive lockouts. |
| Machine learning | Defer until a reliable dataset exists | First establish baseline metrics, robust features, labelled examples and a reproducible test split. |

### Suggested added rules after the foundational work

1. `LateralMovementRule` — track one internal source contacting many internal hosts over a configured window.
2. `ICMPAnomalyRule` — track ICMP rates and selected message/payload features, with the limits clearly documented.
3. `ConnectionAttemptBurstRule` — track repeated attempts against a single service, without claiming authentication failure unless the application protocol supplies evidence.

Add one rule at a time and evaluate it against both attack and benign scenarios.

---

## 5. Target Architecture

The existing modular layout can be retained. The recommended change is stronger contracts between its existing parts.

### 5.1 Normalize packet events consistently

Every packet record should have a documented schema. Fields may include:

- Capture/event timestamp and, separately, processing timestamp where needed.
- Source/destination IP and MAC addresses when available.
- Protocol, TCP flags, source/destination ports, packet/IP length.
- Parsed DNS query/response metadata when available.
- A bounded payload sample only when inspection is enabled and permitted.

Fields should be optional where the protocol does not provide them. Rules should fail safely when required fields are missing.

### 5.2 Standardize alert schema

Proposed target fields:

- `alert_id` / stable detection ID
- `rule_id`, `rule_version`
- `event_timestamp`, `created_timestamp`
- `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`
- `severity`, `confidence`, `status`
- `summary`, `detail`
- `evidence_json`
- `window_start`, `window_end` when applicable
- `suppression_count` or correlation/incident ID where useful

Illustrative example (not an actual alert from the repository):

```json
{
  "rule_id": "PORT_SCAN",
  "rule_version": "1.1",
  "event_timestamp": 1792375200.5,
  "src_ip": "192.168.1.105",
  "dst_ip": "192.168.1.1",
  "severity": "medium",
  "confidence": "heuristic",
  "evidence": {
    "distinct_ports": 20,
    "window_seconds": 10,
    "threshold": 20,
    "scan_type": "vertical"
  }
}
```

### 5.3 Separate detection, alert management and persistence

- **Detection rule:** maintains the minimum state needed and emits structured candidate alerts.
- **Alert manager:** applies cooldowns, deduplication, correlation, severity policy and routing while preserving event counts.
- **Persistence layer:** stores structured, versioned evidence and supports migrations/batching.
- **Analysis/dashboard:** renders saved incidents and system health rather than reconstructing facts from display strings.
- **Evaluation harness:** runs the same event records through a known configuration and compares results with scenario labels.

### 5.4 Keep multiple detections from one event

No early exit is recommended. A packet may legitimately trigger multiple independent rules. Add correlation at incident level so related alerts can be grouped without discarding rule-level evidence.

---

## 6. Evaluation Plan

### 6.1 Build a labelled corpus

Start with deterministic synthetic scenarios, then add carefully selected sanitized PCAPs or established datasets where the data format and intended task fit the packet-level engine. Do not mix flow-level dataset metrics with packet-level detection claims without documenting the mapping.

Minimum scenario groups:

- **Existing rule positives:** blocklist hit, vertical scan, SYN burst, ARP identity change, each DPI signature family, suspicious DNS entropy/length.
- **Benign negatives:** browser/service traffic, normal DNS, legitimate long/random-looking DNS labels, ordinary bursts, authorized scanning and approved network changes.
- **New rule cases:** horizontal scanning, slow scanning, internal host sweeps, ICMP bursts, repeated service connection attempts and periodic callbacks.
- **Robustness cases:** missing fields, malformed packets, duplicates, out-of-order timestamps, state expiry, repeated replay and abrupt worker shutdown.

Each scenario should record an ID, input PCAP, expected rule(s), expected suppression/negative outcomes, configuration, and notes about what the capture actually makes observable.

### 6.2 Measure more than a single F1 score

Report per rule and overall where appropriate:

- True positives, false positives, false negatives against labelled outcomes.
- Precision, recall and F1, with clear definitions and denominators.
- False alerts per hour on a documented benign corpus.
- Detection delay from the relevant scenario start/event.
- Packet/event processing throughput and processing latency under controlled load.
- Queue depth, dropped/failed work, memory growth and state cleanup behavior.
- Results by scenario and threshold/configuration.

Do not report precision or recall when the matching labels do not support a valid ground-truth interpretation. Do not treat every alert generated by one attack as an independent successful attack detection.

### 6.3 Run the same experiments consistently

For every evaluation run:

1. Use an isolated database or clearly reset evaluation storage.
2. Reset stateful rule memory and ARP baseline to known conditions.
3. Use the same input capture and documented configuration.
4. Preserve packet timestamps and verify ordering assumptions.
5. Save the exact code revision, configuration, scenario labels and output report.
6. Repeat runs where concurrency or performance matters.
7. Use Suricata as a comparison engine separately from ground-truth evaluation.

---

## 7. Phased Implementation Roadmap

### Phase 1 — Correctness and repeatability (first milestone)

- [ ] Preserve capture timestamps through `_extract()` and PCAP replay.
- [ ] Add unit tests for all six current rules and boundary conditions.
- [ ] Add a stable normalized-record and alert schema.
- [ ] Persist structured evidence and add schema migration.
- [ ] Fix exact-IP/CIDR matching and validate threat-feed updates.
- [ ] Separate/reset replay state and use a dedicated test blocklist.
- [ ] Add state synchronization or remove cross-thread mutation of rule state.
- [ ] Make worker shutdown and queue flushing explicit.

**Exit criteria:** deterministic replay, test coverage for current rules, no unexplained mismatches in known synthetic scenarios, and evidence preserved from rule result to database/dashboard.

### Phase 2 — Improve six existing detections

- [ ] Split vertical/horizontal port-scan tracking.
- [ ] Add bounded slow-scan tracking.
- [ ] Return all matching DPI signatures.
- [ ] Add benign and adversarial payload tests.
- [ ] Add DNS query frequency and normalized parent-domain tracking.
- [ ] Centralize alert deduplication/cooldowns without losing counters.
- [ ] Distinguish severity, confidence and analyst status.

**Exit criteria:** per-rule positives and negatives documented, threshold choices explained by test results, and a recorded false-alert profile on benign traffic.

### Phase 3 — Evaluation and reliability

- [ ] Replace source/destination/time-only comparator with documented event matching.
- [ ] Add ground-truth scenario evaluation separate from Suricata agreement.
- [ ] Add per-rule metrics and threshold sweeps.
- [ ] Add packet/processing/queue/database health counters.
- [ ] Measure throughput, latency, queue growth and memory on reproducible workloads.
- [ ] Document supported capture conditions and encrypted-traffic limitations.

**Exit criteria:** reproducible report from a clean setup; no accuracy claims based solely on Suricata agreement; system health visible during capture.

### Phase 4 — Carefully scoped expansion

- [ ] Add internal CIDR configuration and `LateralMovementRule`.
- [ ] Extend record schema and add `ICMPAnomalyRule`.
- [ ] Add `ConnectionAttemptBurstRule` with clear non-authentication semantics.
- [ ] Add DNS beaconing once timestamp and temporal tests pass.
- [ ] Prototype flow-based volume anomalies with reliable byte accounting.
- [ ] Consider TCP stream/HTTP state for Slowloris only as a separate scope.
- [ ] Consider machine learning only after a reproducible, labelled feature baseline exists.

**Exit criteria:** each new feature has measurable incremental value, rule-specific false-positive tests and documented visibility requirements.

---

## 8. Acceptance Checklist for a Strong Academic Demonstration

A reviewer should be able to:

- [ ] Install the project using documented instructions.
- [ ] Run tests without live network privileges.
- [ ] Generate a deterministic synthetic PCAP and inspect its scenario labels.
- [ ] Replay the PCAP into a clean evaluation store and reproduce expected alerts.
- [ ] Inspect each alert's rule, timestamps, endpoint context, configuration and structured evidence.
- [ ] See the difference between attack detection, engine agreement and analyst feedback.
- [ ] View false positives and false negatives per rule, not just a project-wide score.
- [ ] See whether packet capture and alert persistence are healthy.
- [ ] Understand limits around encrypted traffic, packet-only inspection, capture placement and unobserved handshakes.
- [ ] Distinguish implemented features from planned or experimentally unverified work in the README and report.

---

## 9. Changes to Defer

### Machine learning

Do not add Isolation Forest simply to claim zero-day detection. First establish which traffic features are available, how labels are assigned, how normal baselines are selected, and whether the model improves a defined metric over the rule baseline. An anomaly score is not a verdict that traffic is malicious.

### Automated blocking / IPS

Keep this a detection-first IDS until false-positive behavior and operational safety are measured. Any future blocking feature should have explicit opt-in, dry-run mode, rule/target scope, expiry, audit records, allowlist protections, and a tested rollback path.

### Multiprocessing

Do not redesign capture around the GIL without measurements. First profile capture, parsing, rule evaluation, queue handling and database time. Use process separation only if evidence identifies a bottleneck and the state-sharing model is designed deliberately.

### Excessive rule count

Do not implement all proposed rules simultaneously. Each additional stateful detector increases memory use, tuning effort, overlap and alert noise. Ship small independently tested changes and retain regression results.

---

## 10. Final Recommendation

**The next release should be a reliability-and-evaluation release, not a rule-count release.** Fix event-time preservation, test the existing six rules, preserve structured evidence, correct the Suricata comparison semantics, and make runtime health visible. Then implement the most useful additional detections one by one.

This path makes NetGuard easier to explain, demonstrate, maintain and defend academically. It also gives future improvements a measurable baseline rather than relying on feature claims alone.

### Repository files reviewed

- [Top-level README](https://github.com/harshitagrwl1608/Network_Intrusion_Detection_System/blob/main/README.md)
- [Detection rules and RuleEngine](https://github.com/harshitagrwl1608/Network_Intrusion_Detection_System/blob/main/ids_project/engine/rules.py)
- [Packet capture and replay](https://github.com/harshitagrwl1608/Network_Intrusion_Detection_System/blob/main/ids_project/capture/sniffer.py)
- [Configuration](https://github.com/harshitagrwl1608/Network_Intrusion_Detection_System/blob/main/ids_project/config.py)
- [Blocklist loader](https://github.com/harshitagrwl1608/Network_Intrusion_Detection_System/blob/main/ids_project/engine/blocklist.py)
- [Storage/database layer](https://github.com/harshitagrwl1608/Network_Intrusion_Detection_System/blob/main/ids_project/storage/db.py)
- [Synthetic PCAP generator](https://github.com/harshitagrwl1608/Network_Intrusion_Detection_System/blob/main/ids_project/evaluation/generate_test_pcap.py)
- [PCAP replay entry point](https://github.com/harshitagrwl1608/Network_Intrusion_Detection_System/blob/main/ids_project/evaluation/replay.py)
- [Suricata comparison script](https://github.com/harshitagrwl1608/Network_Intrusion_Detection_System/blob/main/ids_project/evaluation/compare.py)
- [Dashboard application](https://github.com/harshitagrwl1608/Network_Intrusion_Detection_System/blob/main/ids_project/dashboard/app.py)
- Supplied plan: `engine_finetuning_plan.md` (reviewed from the uploaded attachment).
