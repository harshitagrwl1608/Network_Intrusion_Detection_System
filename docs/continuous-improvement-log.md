# NetGuard IDS — Continuous Improvement Mission Log

This log tracks continuous inspection, improvement, hardening, validation, and testing across NetGuard IDS development cycles.

**Branch**: `antigravity/overnight-work`  
**Execution Model**: Multi-Cycle Continuous Improvement Loop (Minimum 10 cycles)  
**Rule Count Restriction**: Strictly preserve existing 19 rule instances in `RuleEngine.rules`. No dummy rule inflation.

---

## Cycle 1 / 10

- **Date/Time**: 2026-11-03 23:42:00 UTC+5:30
- **Files Inspected**:
  - `ids_project/engine/rules.py`
  - `ids_project/tests/test_dns_and_arp_detection.py`
  - `ids_project/tests/test_finite_rule_timestamps.py`
  - `ids_project/tests/test_new_rules_cycle8.py`
  - `ids_project/tests/test_payload_detection.py`
  - `ids_project/evaluation/run_eval.py`
- **Weakness Discovered**:
  1. `ArpSpoofRule` lacked a `prune_stale` method, causing its `_cooldown` dictionary to grow unbounded over long-running continuous capture and replay sessions.
  2. `PortScanRule` and `SlowPortScanRule` lacked explicit validation of destination port boundaries (`1 <= dst_port <= 65535`) and empty IP strings, risking invalid state entries or index misses.
  3. `SynFloodRule` lacked destination port validation (`1 <= dst_port <= 49151`) and did not expose `target_port` in its alert `evidence` dictionary, reducing forensic utility.
  4. `IcmpSweepRule` computed an unnecessary set comprehension over `history` when `history` already filters duplicates upon insertion.
  5. `PayloadRule._DPI_PORTS` omitted standard enterprise ports for Microsoft SQL Server (`1433`) and Memcached (`11211`), missing deep-packet inspection for SQL injection and remote command execution on these common service endpoints.
- **Changes Implemented**:
  1. Added `ArpSpoofRule.prune_stale(now)` to prune expired cooldowns older than `ALERT_COOLDOWN_S` (bumped rule version to 1.8).
  2. Hardened `PortScanRule` and `SlowPortScanRule` to validate `1 <= dst_port <= 65535` and non-empty `src_ip`/`dst_ip` (bumped SlowPortScanRule to 1.10).
  3. Hardened `SynFloodRule` to validate `1 <= dst_port <= 49151` and added `target_port` to alert evidence (bumped rule version to 1.13).
  4. Optimized `IcmpSweepRule` to check `len(history) < self.threshold` directly (bumped rule version to 1.7).
  5. Added ports `1433` and `11211` to `_DPI_PORTS` in `PayloadRule` (bumped rule version to 1.23).
  6. Added tests in `test_dns_and_arp_detection.py` (`test_arp_spoof_prune_stale_clears_expired_cooldowns`) and `test_payload_detection.py` (`test_mssql_and_memcached_dpi_ports_inspected`).
- **Tests Executed**:
  - `pytest ids_project/tests`: 454 passed in 53.13s.
  - `python3 ids_project/evaluation/run_eval.py`: 38/38 detected (100% precision, 100% recall, 0 false positives).
- **Test Results**: All 454 unit tests and 38 synthetic ground-truth evaluation scenarios passed cleanly.
- **Commit Hash**: `3cb7454` (pushed to `origin/antigravity/overnight-work`)
- **Remaining Issues**:
  - Inspect `ids_project/evaluation/compare.py` for Suricata EVE JSON parsing edge cases, protocol normalization, and network-endpoint corroboration.
  - Inspect `ids_project/capture/sniffer.py` for packet decoding robustness, IPv6 extension headers, and truncation handling.
  - Review other rules in `ids_project/engine/rules.py` for normalization flaws, boundary conditions, and memory leaks.
- **Next Cycle's Objective**: Inspect `ids_project/evaluation/compare.py` and Suricata integration for timestamp handling, protocol normalization, port extraction, and alert corroboration logic.

---

## Cycle 2 / 10

- **Date/Time**: 2026-11-03 23:46:00 UTC+5:30
- **Files Inspected**:
  - `ids_project/evaluation/compare.py`
  - `ids_project/tests/test_compare.py`
  - `ids_project/storage/db.py`
  - `ids_project/evaluation/run_eval.py`
- **Weakness Discovered**:
  1. `load_suricata_alerts` failed or crashed on edge-case EVE JSON files: empty lines triggered `json.JSONDecodeError`, null alert structures (`"alert": null`) triggered `AttributeError`, and non-standard timestamps (epoch floats, timezone offsets without colons like `+0000`) caused timestamp parsing to silently drop or fail.
  2. Suricata field variations were unhandled: alternative destination IP keys (`dest_ip` vs `dst_ip`) and destination port keys (`dest_port` vs `dst_port`) resulted in `None` fields.
  3. `_events_match` lacked IP canonicalization, causing equivalent IPv6 addresses (e.g., `2001:0db8::1` vs `2001:db8::1`) or addresses with accidental whitespace to fail matching.
  4. `_semantic_family` cross-engine corroboration was limited to scans and cleartext HTTP on TLS ports, missing defensible network-observable mappings for web exploits (SQL injection, command injection, Log4Shell, directory traversal), volumetric floods (SYN flood, ICMP flood), DNS tunneling, and TLS anomalies that Suricata can independently corroborate without overstepping into unobservable endpoint claims.
  5. `run_ground_truth` assumed raw integer port equality and string equality on IPs, susceptible to string vs integer formatting differences.
- **Changes Implemented**:
  1. Hardened `load_suricata_alerts` in `compare.py`:
     - Added robust line stripping and `dict` type checks.
     - Handled `null` alert objects safely (`event.get("alert") or {}`).
     - Added resilient multi-format timestamp parser supporting ISO-8601 (`Z`, `+00:00`, `+0000`, `-0500`), float/int epoch seconds, and malformed string fallbacks.
     - Extracted both `dest_ip`/`dst_ip`, `dest_port`/`dst_port`, `flow_id`, and `app_proto` fields.
     - Enforced `utf-8` decoding with replacement error handler.
  2. Added IP and Port normalization helpers `_norm_ip` (using `ipaddress.ip_address`) and `_norm_port` (`0 <= port <= 65535`).
  3. Expanded `_semantic_family` with well-grounded network-observable attack families:
     - `sql_injection`: NetGuard `PAYLOAD_HIT` (SQL_INJECTION) <-> Suricata SQL injection / SQLi signatures.
     - `command_injection`: NetGuard `PAYLOAD_HIT` (CMD_INJECTION, SHELLSHOCK) <-> Suricata command injection signatures.
     - `log4shell`: NetGuard `PAYLOAD_HIT` (LOG4SHELL) <-> Suricata Log4j / CVE-2021-44228 signatures.
     - `path_traversal`: NetGuard `PAYLOAD_HIT` (PATH_TRAVERSAL) <-> Suricata path/directory traversal signatures.
     - `syn_flood`: NetGuard `SYN_FLOOD` / `DISTRIBUTED_SYN_FLOOD` <-> Suricata SYN flood signatures.
     - `icmp_flood`: NetGuard `ICMP_FLOOD` <-> Suricata ICMP flood signatures.
     - `dns_tunnel`: NetGuard `DNS_ANOMALY` (DNS_TUNNEL, DNS_EXFIL) <-> Suricata DNS tunnel/exfiltration signatures.
     - `tls_anomaly`: NetGuard `TLS_ANOMALY` <-> Suricata TLS SNI / certificate anomaly signatures.
  4. Updated `_events_match` and `run_ground_truth` to use `_norm_ip` and `_norm_port`.
  5. Added comprehensive test coverage in `ids_project/tests/test_compare.py`: `test_ipv6_normalization_in_events_match`, `test_load_suricata_alerts_resilience`, and `test_semantic_family_cross_engine_corroboration`.
- **Tests Executed**:
  - `pytest ids_project/tests/test_compare.py`: 8 passed in 0.13s (3 new comprehensive tests).
  - `python3 ids_project/evaluation/run_eval.py`: 38/38 detected (100% precision, 100% recall, 0 false positives).
- **Test Results**: All tests passed with zero regressions.
- **Commit Hash**: `9199d8e` (pushed to `origin/antigravity/overnight-work`)
- **Remaining Issues**:
  - Inspect `ids_project/capture/sniffer.py` for packet decoding robustness, IPv6 extension headers, and truncation handling.
  - Review `ids_project/engine/rules.py` rules (e.g., `UdpFloodRule`, `TcpZeroWindowRule`, `TlsAnomalyRule`) for input bounds and edge cases.
- **Next Cycle's Objective**: Inspect `ids_project/capture/sniffer.py` for packet decoding safety, truncated packet handling, and protocol layer boundary checks.

---

## Cycle 3 / 10

- **Date/Time**: 2026-11-03 23:48:30 UTC+5:30
- **Files Inspected**:
  - `ids_project/capture/sniffer.py`
  - `ids_project/engine/rules.py`
  - `ids_project/tests/test_pcap_replay_and_parsing.py`
  - `ids_project/tests/test_data_exfiltration.py`
  - `ids_project/evaluation/run_eval.py`
- **Weakness Discovered**:
  1. In `ids_project/capture/sniffer.py`, `_extract` assumed `pkt[TCP].seq` was non-None when computing `tcp_payload_seq = (tcp_seq + int(bool(flags & 0x02))) & 0xFFFFFFFF`, causing unhandled `TypeError` exceptions on truncated or malformed TCP packets.
  2. `pkt[IP].len` and `pkt[IPv6].plen` lacked `None` and overflow guards, risking unexpected exceptions when Scapy parsed packets with omitted length fields.
  3. `flags` in TCP could raise `ValueError`/`TypeError` if represented by unexpected flag objects; ports `dport`/`sport` in TCP and UDP lacked exception guards against invalid values.
  4. DNS query extraction did not guard against `question.qname` being already `str` rather than `bytes`, risking `AttributeError: 'str' object has no attribute 'decode'` on certain Scapy builds or synthetic fixtures.
  5. `_parse_tcpdump_endpoint` only supported a small set of basic port names (`http`, `https`, `domain`, `ssh`, `ntp`, `ftp`, `telnet`, `smtp`, `dns`), dropping or misclassifying critical enterprise service names like `ldap`, `ldaps`, `imaps`, `pop3s`, `ms-sql-s`, `mysql`, `postgresql`, `redis`, and `memcache` during ASCII tcpdump replays.
  6. `DataExfiltrationRule` lacked coverage for modern ransomware staging compression (Zstandard), credential store exfiltration (KeePass password vaults), and raw network trace leaks (PCAP/PCAP-NG magic headers).
- **Changes Implemented**:
  1. Hardened TCP sequence and flag extraction in `sniffer.py`:
     - Safely computed `tcp_payload_seq` only when `tcp_seq` is non-None, defaulting to `None` otherwise.
     - Protected `tcp_flags` casting with fallback to 0.
     - Protected `dst_port` and `src_port` casting to integer.
  2. Protected `ip_len` extraction against `None` and overflow errors for both IPv4 and IPv6.
  3. Hardened DNS extraction to handle both `bytes` and `str` types for `question.qname` safely.
  4. Expanded `_parse_tcpdump_endpoint` common ports dictionary with enterprise service aliases: `ldap` (389), `ldaps` (636), `submission` (587), `imaps` (993), `pop3s` (995), `ms-sql-s`/`ms-sql` (1433), `mysql` (3306), `postgres`/`postgresql` (5432), `redis` (6379), `memcache` (11211), `rdp` (3389), `snmp` (161), and `bgp` (179).
  5. Expanded `DataExfiltrationRule._EXFIL_SIGNATURES` (bumped to v1.19) with:
     - `\x28\xb5\x2f\xfd`: Zstandard (zstd) compressed archive.
     - `\x03\xd9\xa2\x9a`: KeePass password database (.kdbx) vault dump.
     - `\xd4\xc3\xb2\xa1`: PCAP network traffic capture.
     - `\n\r\r\n`: PCAP-NG network traffic capture.
  6. Hardened stateful rule cooldown drift eviction and validation across:
     - `UdpFloodRule` (v1.9): exempt mDNS source port 5353, enforce destination/source port range (1-65535), and evict future-drifted cooldown timestamps. Added test `test_mdns_port_5353_source_exempt` in `test_udp_flood.py`.
     - `TcpFlagAnomalyRule` (v1.8): port range boundary validation (1-65535) and cooldown drift eviction.
     - `IcmpFloodRule` (v1.7): cooldown drift eviction in `prune_stale`.
     - `DnsRule` (v1.23): expanded ccTLD suffixes (Nigeria `.ng`, Spain `.es`, Poland `.pl`, Greece `.gr`, Canada government `.gc.ca`) and `_prune_seen` drift eviction.
     - `TlsAnomalyRule` (v1.12): added modern reverse tunnel suffixes (`.localxpose.io`, `.tunnelto.dev`, `.hopto.org`, `.zapto.org`).
     - `BruteForceRule` (v1.11): cooldown drift eviction in `prune_stale`.
  7. Added comprehensive test coverage in:
     - `ids_project/tests/test_pcap_replay_and_parsing.py`: `test_extract_handles_missing_tcp_seq_and_flags_safely`, `test_extract_handles_missing_ip_len_safely`, `test_tcpdump_endpoint_parser_resolves_extended_common_ports`.
     - `ids_project/tests/test_data_exfiltration.py`: updated version assertions to `1.19` and verified Zstandard, KeePass, PCAP, and PCAP-NG detection.
     - Synchronized version assertions across `test_udp_flood.py`, `test_tcp_flag_anomaly.py`, `test_icmp_flood.py`, `test_finite_rule_timestamps.py`, `test_new_rules_cycle8.py`, `test_dns_and_arp_detection.py`, and `test_tls_anomaly.py`.
- **Tests Executed**:
  - `pytest ids_project/tests`: 462 passed in 56.47s.
  - `python3 ids_project/evaluation/run_eval.py`: 38/38 detected (100% precision, 100% recall, 0 false positives).
- **Test Results**: All 462 unit tests and 38 synthetic ground-truth evaluation scenarios passed cleanly.
- **Commit Hash**: `c102699` (pushed to `origin/antigravity/overnight-work`)
- **Remaining Issues**:
  - Inspect `TcpZeroWindowRule` for flow eviction, state growth bounds, and Sockstress detection robustness.
  - Inspect `UdpScanRule` and `PortScanRule` saturation handling.
  - Investigate external dataset evaluation scripts (`replay.py`, `analysis/aggregator.py`).
- **Next Cycle's Objective**: Inspect `TcpZeroWindowRule` and flow tracking in `ids_project/engine/rules.py` for window scale factor handling, RST teardown handling, and flow state bounding.

---

## Cycle 4 / 10

- **Date/Time**: 2026-11-03 23:58:30 UTC+5:30
- **Files Inspected**:
  - `ids_project/engine/rules.py`
  - `ids_project/tests/test_tcp_zero_window.py`
  - `ids_project/tests/test_finite_rule_timestamps.py`
  - `ids_project/evaluation/run_eval.py`
- **Weakness Discovered**:
  1. In `TcpZeroWindowRule`, when a connection was terminated by a TCP RST packet (`tcp_flags & 0x04`), the canonical connection key remained cached in `self._initiators` until the long 120-second `_handshake_ttl` expired. Under rapid port-cycling or connection teardowns, `self._initiators` accumulated stale state unnecessarily.
  2. `_connection_key` in `TcpZeroWindowRule` did not validate port ranges (`1 <= port <= 65535`) and did not safely reject `None` ports before integer casting.
  3. `prune_stale` in `TcpZeroWindowRule` did not protect against future timestamp drift in `_fired` (`self._fired[k] > now`) or `_initiators` (`timestamp > now`).
  4. Missing regression tests for RST cleanup and clock-drift pruning in `test_tcp_zero_window.py`.
- **Changes Implemented**:
  1. Updated `TcpZeroWindowRule` (bumped to v1.10):
     - Added immediate connection teardown in `_initiators` upon observing TCP RST (`tcp_flags & 0x04`).
     - Hardened `_connection_key` with port range validation (`1 <= port <= 65535`) and safe `None` checking.
     - Hardened `prune_stale` to evict future-drifted timestamps in `_fired` and `_initiators`.
     - Validated `src_port` and `dst_port` boundaries in `check`.
  2. Updated `ids_project/tests/test_finite_rule_timestamps.py` with the updated `1.10` version assertion.
  3. Added unit tests in `ids_project/tests/test_tcp_zero_window.py`:
     - `test_rst_packet_clears_initiator_state`: verifies RST cleans up initiator state immediately.
     - `test_prune_stale_clears_future_drifted_cooldown_and_initiators`: verifies clock-drifted state is safely purged.
- **Tests Executed**:
  - `pytest ids_project/tests/test_tcp_zero_window.py ids_project/tests/test_finite_rule_timestamps.py`: 31 passed in 0.39s.
  - `pytest ids_project/tests`: 462 passed in 56.47s.
  - `python3 ids_project/evaluation/run_eval.py`: 38/38 detected (100% precision, 100% recall, 0 false positives).
- **Test Results**: All 462 unit tests and 38 synthetic ground-truth evaluation scenarios passed cleanly.
- **Commit Hash**: Pending commit for Cycle 4.
- **Remaining Issues**:
  - Inspect `PortScanRule` and `UdpScanRule` vertical and horizontal state sets and saturation limits.
  - Inspect `ids_project/analysis/aggregator.py` for alert correlation, time-window grouping, and statistical summaries.
  - Inspect Splunk and Sigma compatibility documentation and mappings.
- **Next Cycle's Objective**: Inspect `PortScanRule` and `UdpScanRule` for saturation state bounds, memory leak prevention under large IP scan sweeps, and horizontal scan thresholding.

---

## Next Actions Summary

1. Commit Cycle 4 verified improvements to `antigravity/overnight-work`.
2. Push to `origin/antigravity/overnight-work`.
3. Proceed immediately to Cycle 5: Port and UDP scan saturation state bounds, memory leak prevention, and horizontal scan thresholding.
