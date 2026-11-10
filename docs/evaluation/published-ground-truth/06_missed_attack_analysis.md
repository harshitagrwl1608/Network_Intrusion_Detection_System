# 6. Missed Attack Flow Analysis

## In-Scope vs. Out-of-Scope Malicious Flows

The official publisher ground truth labels **3,390,604** flows as `Malicious`.

### 1. In-Scope Malicious Traffic: Mirai Telnet Scanning & Attack Bursts
- **Flow Count**: 3,390,593 flows (99.9997% of all malicious traffic).
- **Target Port**: Destination port **23** (Telnet).
- **Detailed Ground-Truth Labels**:
  - `PartOfAHorizontalPortScan`: 3,386,119 flows
  - `Attack`: 2,752 flows
  - `C&C-PartOfAHorizontalPortScan`: 888 flows
  - `C&C-HeartBeat-Attack`: 834 flows
- **Connection Characteristics**: Rapid TCP SYN packets (`conn_state=S0`) dispatched from `192.168.1.200` to pseudo-random public IPv4 addresses across the Internet.
- **NetGuard Coverage**: 
  - NetGuard detected this entire campaign via **3,473 `PORT_SCAN`** alerts and **292 `SLOW_PORT_SCAN`** alerts.
  - Rather than flooding the alert log with 3.39 million redundant individual packet alerts (which would overwhelm SIEM systems and storage), NetGuard's stateful behavioral aggregation coalesces rapid scan attempts into structured incident alerts every 10–120 seconds.
  - NetGuard provided 100% temporal and endpoint coverage of the scanning activity across the entire 9.77-hour duration.

### 2. Out-of-Scope Malicious Traffic: HTTP C&C Dropper Downloads
- **Flow Count**: 11 flows (0.0003% of malicious traffic).
- **Target Port**: Destination port **80** (HTTP) on C&C host `167.99.182.238`.
- **Detailed Ground-Truth Label**: `C&C-HeartBeat-FileDownload`.
- **Connection Characteristics**: Completed standard TCP connections (`conn_state=SF`) executing standard HTTP GET requests to download Mirai ELF binary droppers.
- **Engine Boundary & Absence of Alert**:
  - NetGuard operates as a transport-layer stateful network intrusion detection system with rules targeting port scans, floods, ARP spoofing, cleartext credential leaks, and protocol anomalies.
  - Standard HTTP file retrieval without known-bad domain reputations or endpoint antivirus analysis is out-of-scope for transport-layer network IDS rules.
  - In contrast, Suricata 8.0.7 detected these 11 downloads using its HTTP stream reassembler and ELF header signature (`ET INFO Executable and linking format (ELF) file download Over HTTP`).
  - This transparently illustrates the boundary between NetGuard's network-behavioral scope and Suricata's application-payload signature scope.
