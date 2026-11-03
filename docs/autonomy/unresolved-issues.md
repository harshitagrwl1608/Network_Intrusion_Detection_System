# NetGuard IDS — Autonomous Campaign Issues & Architecture State

This document tracks known limitations, performance bottlenecks, edge-case risks, and future engineering opportunities identified and addressed during the overnight engineering campaign.

---

## 1. Resolved Issues in Campaign (Cycles 1 – 15)

1. **PortScanRule & UdpScanRule Future Clock-Drift & Orphaned Saturated Keys (Resolved in Cycle 5)**:
   - Added future clock-drift eviction (`timestamp > now`) to prevent zombie entries when replay timestamps jump or re-anchor.
   - Added `intersection_update` to `_vert_saturated` and `_horiz_saturated` to ensure evicted hosts are never permanently marked saturated.
2. **SlowPortScanRule & BruteForceRule LRU Capacity & Port Normalization (Resolved in Cycle 6)**:
   - Migrated `SlowPortScanRule._vert` and `_horiz` to `OrderedDict` with deterministic $O(1)$ LRU eviction and `move_to_end` recency tracking.
   - Enforced port boundary validation on `src_port` and added `_saturated_history.intersection_update(self._history)` in `BruteForceRule`.
3. **Automated Evaluation Runner Forensic Metadata Extraction (Resolved in Cycle 7)**:
   - Fortified `ids_project/evaluation/run_eval.py` to select `rule_version` and parse `evidence_json` from the alerts database.
   - Updated report summaries to output active rule versions for all detected scenarios.
4. **Suricata EVE JSON Ingestion & Semantic Corroboration Engine (Resolved in Cycle 8)**:
   - Hardened `ids_project/evaluation/compare.py` to canonicalize IPv6 addresses and strip whitespace immediately on ingestion.
   - Expanded `_semantic_family` to support cross-engine corroboration for web attacks (`xss`, `ssrf`), authentication attacks (`brute_force`), and TCP anomalies (`tcp_zero_window`).
5. **DataExfiltrationRule & CleartextHttpOnTlsPortRule State Bounding (Resolved in Cycle 9)**:
   - Expanded `DataExfiltrationRule` with cleartext private key export signatures (OpenSSH, RSA, EC, PKCS#8).
   - Rebuilt `DataExfiltrationRule.prune_stale` to filter valid active windows, prune future-drifted cooldown timestamps, and clean up orphaned saturated entries.
   - Hardened `CleartextHttpOnTlsPortRule` with default `now=None` in `prune_stale`, alternative TLS ports (4443, 9443), and support for HTTP/2 client preface (`PRI * HTTP/2.0`) and WebDAV verbs.
6. **DnsRule & PayloadRule Entropy Stability and Garbage Collection (Resolved in Cycle 10)**:
   - Hardened `_shannon_entropy` against non-string input, zero-length and single-char strings, and normalized IDN punycode prefixes (`xn--`).
   - Hardened `DnsRule.prune_stale` and `PayloadRule.prune_stale` with optional `now: float = None` (defaulting to `time.time()`) and unconditional pruning of stale deduplication state.
7. **BlocklistRule Subnet Partitioning & LRU Memoization (Resolved in Cycle 11)**:
   - Added bounded $O(1)$ LRU memoization cache (4096 entries) and segregated IPv4 and IPv6 subnets, eliminating linear cross-protocol parsing overhead.
8. **TlsAnomalyRule RFC 6066 SNI & Clock-Drift Eviction (Resolved in Cycle 11)**:
   - Added strict IP parsing with square bracket stripping for IPv6 literal SNI and clock-drift eviction in `prune_stale`.
9. **TcpStealthScanRule & TcpFlagAnomalyRule State Bounding (Resolved in Cycle 12)**:
   - Converted probe tracking to `OrderedDict` with deterministic $O(1)$ LRU eviction and standardized optional `now=None` GC defaults across TCP stealth and flag anomaly rules.
10. **IcmpSweepRule & IcmpFloodRule LRU State Management (Resolved in Cycle 13)**:
    - Converted target history and fired tracking to `OrderedDict` with deterministic $O(1)$ LRU eviction and standardized optional `now=None` GC defaults.
11. **DistributedSynFloodRule Target & Source LRU Eviction (Resolved in Cycle 14)**:
    - Converted target tracking and inner source tracking to `OrderedDict` with deterministic $O(1)$ LRU eviction and future clock-drift pruning.
12. **Complete 19-Rule Invariant & Full Regression Verification (Resolved in Cycle 15)**:
    - Empirically verified exactly 19 rule instances in `RuleEngine.rules`, 38/38 ground-truth scenario detections (100% precision, 100% recall), and 482/482 passing unit tests.

---

## 2. Structural & Architectural Notes for Future Work

1. **Sigma & Splunk SIEM Reference Mapping**:
   - The NetGuard engine implements its 19 detection rules directly in Python. SIEM integrations mapping each of the 19 detection families to Sigma yaml and Splunk SPL reference definitions can be maintained as external documentation artifacts without modifying engine detection code.
2. **Live Interface Sniffing Permissions**:
   - Raw packet sniffing (`ids_project/capture/sniffer.py`) requires root/`CAP_NET_RAW` privileges in live deployment. Offline PCAP replay (`ids_project/evaluation/replay.py`) requires no privileges and serves as the primary evaluation path.
3. **Public Suffix List Integration**:
   - `DnsRule` currently uses a maintained list of common two-level country-code suffixes (`_COMMON_MULTI_LABEL_CC_SUFFIXES`). A local, offline Mozilla Public Suffix List parser could be integrated for exact multi-label TLD parsing if zero external network dependencies can be guaranteed.
