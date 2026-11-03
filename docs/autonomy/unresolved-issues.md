# NetGuard IDS — Unresolved Issues & Backlog

This document tracks known limitations, performance bottlenecks, edge-case risks, and future engineering opportunities identified during the autonomous campaign.

## 1. High-Priority Engineering Backlog
1. **Vertical vs. Horizontal Port Scan Saturation**:
   - `PortScanRule` tracks destination ports per destination IP, but under high-volume randomized IP scans (horizontal sweeps across Class B/C networks), the dictionary of tracked targets can grow large before TTL expiration. Needs bounded state limits (`deque` or max tracked IPs).
2. **UDP Scan / Flood Memory Bounding**:
   - `UdpScanRule` and `UdpFloodRule` track per-IP destination histories. Under massive distributed UDP bursts (e.g. amplification attacks), IP tracking maps should enforce strict LRU/FIFO caps.
3. **Suricata EVE JSON Timestamp Parsing Robustness**:
   - Suricata outputs ISO 8601 timestamps with microsecond precision and varying timezone offsets (`+0000`, `Z`, `+02:00`). `compare.py` handles most formats, but edge cases with non-standard leap seconds or fractional digits should be fortified.
4. **Data Exfiltration Byte Accumulation**:
   - `DataExfiltrationRule` calculates egress byte volume over rolling windows. Need to verify connection reuse and symmetric flow accounting to prevent false positives on large authorized file transfers.

## 2. Structural & Architectural Notes
1. **Sigma & SPL Artifact Tooling**:
   - While NetGuard is a pure Python network packet IDS, enterprise SIEM interoperability benefits from standardized Sigma rule definitions and equivalent Splunk searches mapping each of the 19 detection rules. Currently, no standalone `.yml` Sigma files or `.spl` files exist in the tree. Developing reference mapping documents for the existing 19 rules enhances forensic integration.
2. **Live Interface Sniffing Permissions**:
   - Raw packet sniffing (`ids_project/capture/sniffer.py`) requires root/`CAP_NET_RAW` privileges in live deployment. Offline PCAP replay (`ids_project/evaluation/replay.py`) does not require privileges and serves as the primary evaluation path.
