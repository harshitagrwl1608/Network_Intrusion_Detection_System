# REA Phase C — Prioritized Performance Engineering Implementation Plan

**Document Status:** Sealed Verification Record  
**Author:** Reverse Engineering Agent (REA)  
**Target Release:** NetGuard IDS v1.2 Performance Engine  
**Authorized Branch:** `antigravity/overnight-work`  
**Delivery Path:** `docs/performance/rea-implementation-plan.md`  

---

## 1. Plan Overview & Engineering Philosophy

Following Suricata 8.0.7 reverse engineering and empirical bottleneck profiling of NetGuard, this plan prioritizes performance improvements strictly by **throughput ROI vs. detection integrity risk**. 

In strict adherence to rule governance invariants:
- **No detection rules, thresholds, cooldowns, or time windows will be modified.**
- **No early-exit logic after an alert will be introduced** (multiple alerts on one packet remain fully supported).
- **All optimizations must maintain 100% alert equivalence** against the sealed baseline.

---

## 2. Ranked Implementation Proposals

### Proposal 1: Protocol-Aware Candidate Rule Dispatch & Fast-Path IP Matching
- **Target Subsystem:** `ids_project/engine/rules.py` (`RuleEngine.check()`, `_is_trusted()`)
- **Mechanisms:**
  1. **Candidate Rule Dispatch:** Build protocol dispatch table at engine initialization:
     - `arp_rules`: `[BlocklistRule, ArpSpoofRule]`
     - `tcp_rules`: `[BlocklistRule, TcpFlagAnomalyRule, PortScanRule, SlowPortScanRule, TcpStealthScanRule, SynFloodRule, DistributedSynFloodRule, BruteForceRule, CleartextHttpOnTlsPortRule, TcpZeroWindowRule, TlsAnomalyRule, IrcC2BeaconingRule, PayloadRule, DataExfiltrationRule, IpFragmentAnomalyRule]`
     - `udp_rules`: `[BlocklistRule, UdpScanRule, UdpFloodRule, DnsRule, PayloadRule, DataExfiltrationRule, IpFragmentAnomalyRule]`
     - `icmp_rules`: `[BlocklistRule, IcmpSweepRule, IcmpFloodRule, IcmpTunnelRule, IpFragmentAnomalyRule]`
     - `all_rules`: Complete list of 23 canonical rules for unclassified/unknown protocols.
  2. **Fast-Path `_is_trusted`:** Pre-normalize trusted IP strings in `TRUSTED_HOSTS_STR` for $O(1)$ set lookup, eliminating 10,000+ redundant `ipaddress.ip_address()` object allocations per minute.
- **Measured Expected Benefit:** **+35% to +50% speedup in rule evaluation**.
- **Implementation Complexity:** Low (clean modular dispatch).
- **Detection Integrity Risk:** **Zero**. Every rule's protocol requirements are statically verified. Unclassified packets fall back to evaluating all 23 rules.
- **Rollback Strategy:** Fall back to unconditional `for rule in self.rules`.

---

### Proposal 2: Stateful History Optimization in `SlowPortScanRule`
- **Target Subsystem:** `ids_project/engine/rules.py` (`SlowPortScanRule.check()`, `prune_stale()`)
- **Mechanisms:**
  1. Eliminate full list reallocation `[(t, p) for t, p in history if ...]` and `.sort()` on every incoming SYN.
  2. Implement an in-place sliding-window representation using `collections.deque` or indexed monotonic timestamps where expired entries are popped from the left in $O(1)$ time.
  3. Maintain a set of currently tracked destination hosts/ports for $O(1)$ duplicate checking.
- **Measured Expected Benefit:** **+20% to +35% speedup in TCP SYN evaluation**.
- **Implementation Complexity:** Medium.
- **Detection Integrity Risk:** Low. Invariants strictly preserved: window cutoff `now - window`, threshold count, cooldown checks, and evidence dictionaries remain identical.
- **Rollback Strategy:** Restore original list comprehension history logic.

---

### Proposal 3: High-Speed Binary Packet Parser (`FastPcapReader` & `_fast_extract`)
- **Target Subsystem:** `ids_project/capture/sniffer.py` (`_extract()`, `replay_pcap()`)
- **Mechanisms:**
  1. **Binary PCAP Streamer:** Read raw 16-byte PCAP packet headers (`ts_sec`, `ts_usec`, `incl_len`, `orig_len`) using Python `struct.unpack_from()`.
  2. **In-Place Struct Decoding:** Decode Ethernet (14 bytes), IPv4 (20 bytes), IPv6 (40 bytes), TCP (20 bytes), UDP (8 bytes), ICMP (8 bytes) directly from raw byte buffers in <1 microsecond.
  3. **Strict Field Parity:** Produce the exact normalized record dictionary expected by all 23 rules, including TCP flags, sequence numbers, window size, IP length, fragment digests, and TLS payloads.
  4. **Scapy Fallback:** Automatic fallback to Scapy if a frame cannot be parsed by the binary fast parser (e.g. uncommon link types or corrupt frame).
- **Measured Expected Benefit:** **+200% to +400% speedup in packet acquisition and decoding**.
- **Implementation Complexity:** Medium-High.
- **Detection Integrity Risk:** Medium. Requires rigorous differential testing across all 755 unit tests and ground-truth captures to prove zero missing fields.
- **Rollback Strategy:** Configurable flag `USE_FAST_PARSER = False` defaulting to Scapy.

---

### Proposal 4: Batched Alert Persistence & Replay Logging Modes
- **Target Subsystem:** `ids_project/engine/rules.py` (`_alert_writer_loop()`), `ids_project/evaluation/replay.py`
- **Mechanisms:**
  1. **Queue Batch Draining:** When writing to SQLite, drain up to 50 pending alerts from `_alert_queue` and commit in a single database transaction using `executemany()` or batch commit.
  2. **Configurable Log Modes:** Provide `--log-mode summary|quiet|all`. `summary` aggregates alerts by rule and prints periodic throughput updates every 5 seconds, eliminating stdout lock contention during high-volume replays.
- **Measured Expected Benefit:** **+10% to +20% overall throughput**.
- **Implementation Complexity:** Low.
- **Detection Integrity Risk:** Zero. All alerts are persisted to DB; disk spooling and flush guarantees remain identical.
- **Rollback Strategy:** One-line revert to per-alert single commit.

---

## 3. Execution Schedule & Milestones

1. **Step 1:** Implement Proposal 1 (Protocol-aware rule dispatch & `_is_trusted` fast-path). Run unit tests.
2. **Step 2:** Implement Proposal 2 (`SlowPortScanRule` sliding window optimization). Verify sliding-window invariants.
3. **Step 3:** Implement Proposal 3 (Fast binary packet parser with Scapy fallback). Verify field parity.
4. **Step 4:** Implement Proposal 4 (Batched alert persistence & summary logging).
5. **Step 5:** Benchmark on development captures (`iot23_malware_8_1.pcap` and previously observed benchmark capture).
6. **Step 6:** Run full validation suite (`pytest ids_project/tests` and `ids_project/evaluation/run_eval.py`).

*Plan Sealed by Reverse Engineering Agent (REA).*
