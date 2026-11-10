# NetGuard IDS — Detection Engine Reference

NetGuard IDS implements **23 independent detection rules**. For each packet, the `RuleEngine` selects candidate rules via protocol-aware routing (`_rules_by_proto`) and executes them sequentially. Candidate rules evaluate without early exit — a single packet may legitimately trigger multiple rules. Unclassified protocols evaluate across all 23 rules.

All rules are implemented in [`ids_project/engine/rules.py`](../ids_project/engine/rules.py).

> [!IMPORTANT]
> The rule names in this document exactly match the `rule_name` field emitted in alerts
> (e.g. `PORT_SCAN`, `PAYLOAD_HIT`, `DNS_ANOMALY`). Do not confuse internal Python class names
> (e.g. `PortScanRule`) with the alert rule_name identifiers.

---

## Overview Table

| # | Rule Name | Class | Protocol | Category |
|---|---|---|---|---|
| 1 | `BLOCKLIST` | `BlocklistRule` | Any | Reputation |
| 2 | `TCP_FLAG_ANOMALY` | `TcpFlagAnomalyRule` | TCP | Protocol Abuse |
| 3 | `PORT_SCAN` | `PortScanRule` | TCP | Reconnaissance |
| 4 | `UDP_SCAN` | `UdpScanRule` | UDP | Reconnaissance |
| 5 | `UDP_FLOOD` | `UdpFloodRule` | UDP | Denial of Service |
| 6 | `TCP_STEALTH_SCAN` | `TcpStealthScanRule` | TCP | Reconnaissance |
| 7 | `SYN_FLOOD` | `SynFloodRule` | TCP | Denial of Service |
| 8 | `DISTRIBUTED_SYN_FLOOD` | `DistributedSynFloodRule` | TCP | Denial of Service |
| 9 | `ICMP_SWEEP` | `IcmpSweepRule` | ICMP | Reconnaissance |
| 10 | `ICMP_FLOOD` | `IcmpFloodRule` | ICMP | Denial of Service |
| 11 | `ARP_SPOOF` | `ArpSpoofRule` | ARP | Layer 2 Attack |
| 12 | `PAYLOAD_HIT` | `PayloadRule` | TCP/HTTP | Deep Packet Inspection |
| 13 | `DNS_ANOMALY` | `DnsRule` | DNS/UDP | Covert Channel / C2 |
| 14 | `BRUTE_FORCE` | `BruteForceRule` | TCP | Credential Attack |
| 15 | `SLOW_PORT_SCAN` | `SlowPortScanRule` | TCP/UDP | Evasion / Reconnaissance |
| 16 | `DATA_EXFIL` | `DataExfiltrationRule` | TCP/UDP | Data Exfiltration |
| 17 | `TLS_ANOMALY` | `TlsAnomalyRule` | TCP/TLS | Protocol Anomaly |
| 18 | `CLEAR_HTTP_ON_TLS_PORT` | `CleartextHttpOnTlsPortRule` | TCP | Protocol Anomaly |
| 19 | `TCP_ZERO_WINDOW` | `TcpZeroWindowRule` | TCP | Denial of Service / Evasion |
| 20 | `NON_DNS_TRAFFIC_ON_DNS_PORT` | `NonDnsTrafficOnDnsPortRule` | TCP/UDP | Covert Channel |
| 21 | `ICMP_TUNNEL` | `IcmpTunnelRule` | ICMP | Covert Channel |
| 22 | `IP_FRAGMENT_ANOMALY` | `IpFragmentAnomalyRule` | IP | Protocol Abuse / DoS |
| 23 | `IRC_C2_BEACONING` | `IrcC2BeaconingRule` | TCP | C2 / Malware |

---

## Rule Details

### 1. `BLOCKLIST`

**Purpose:** Detect connections to or from known-malicious IP addresses.

**Mechanism:** Each packet's `src_ip` and `dst_ip` are checked against a local IP blocklist
(plain IPs and CIDR networks). The blocklist is sourced from [Feodo Tracker](https://feodotracker.abuse.ch/)
and refreshed automatically when stale (>12 hours).

**Thresholds:** None — any match triggers an alert.

**Limitations:** Only as effective as the blocklist's freshness and coverage. Does not detect
connections to unknown malicious IPs. CIDR matching can be slow for large blocklists.

**Test file:** `test_blocklist_path_handling.py`

---

### 2. `TCP_FLAG_ANOMALY`

**Purpose:** Detect malformed or impossible TCP flag combinations used in OS fingerprinting,
injection, or evasion.

**Mechanism:** Flags the following invalid/suspicious TCP flag combinations:
- `SYN + FIN` — impossible in legitimate TCP
- `SYN + RST` — impossible in legitimate TCP
- `FIN + RST` — impossible in legitimate TCP
- `NULL` (no flags) — used in stealth scans
- `Xmas` (FIN+PSH+URG) — used in Xmas scans
- `SYN + FIN + PSH + URG` — full Xmas variant with SYN

**Limitations:** Requires TCP packets. Cannot distinguish legitimate OS edge cases from attacks
without additional context.

**Test file:** `test_tcp_flag_anomaly.py`

---

### 3. `PORT_SCAN`

**Purpose:** Detect TCP port scanning (vertical: many ports on one host; horizontal: one port across many hosts).

**Mechanism:** Sliding-window counter per source IP. Tracks distinct `(dst_ip, dst_port)` pairs
observed with SYN packets. When `PORT_SCAN_THRESHOLD` distinct targets are seen within `TIME_WINDOW`
seconds, an alert fires.

**Thresholds:**
- `PORT_SCAN_THRESHOLD` = 15 distinct ports/hosts (default)
- `TIME_WINDOW` = 10 seconds (default)

**Limitations:** Legitimate services that rapidly connect to many hosts (e.g. CDN prefetching)
may trigger false positives. Add trusted hosts to `TRUSTED_HOSTS` to suppress.

**Test file:** `test_port_scan_detection.py`

---

### 4. `UDP_SCAN`

**Purpose:** Detect UDP port scanning.

**Mechanism:** Same sliding-window logic as `PORT_SCAN` but applied to UDP packets.
Distinct `(dst_ip, dst_port)` pairs within the window trigger an alert.

**Thresholds:**
- `UDP_SCAN_THRESHOLD` = 15 (default)
- `TIME_WINDOW` = 10 seconds (default)

**Test file:** `test_udp_scan_detection.py`

---

### 5. `UDP_FLOOD`

**Purpose:** Detect UDP flooding (volumetric denial of service).

**Mechanism:** Counts UDP packets from a source to a single target within `UDP_FLOOD_WINDOW`.
Two separate thresholds: standard traffic uses `UDP_FLOOD_THRESHOLD` (50), while QUIC/UDP port 443
uses the higher `UDP_FLOOD_WEB_THRESHOLD` (500) to avoid false positives from QUIC video streaming.

**Thresholds:**
- `UDP_FLOOD_THRESHOLD` = 50 packets in 5 seconds (default)
- `UDP_FLOOD_WEB_THRESHOLD` = 500 for port 443

**Test file:** `test_udp_flood.py`

---

### 6. `TCP_STEALTH_SCAN`

**Purpose:** Detect stealth TCP scans using abnormal flag combinations (FIN, NULL, Xmas).

**Mechanism:** Tracks distinct destination ports probed with FIN, NULL (no flags), or Xmas (FIN+PSH+URG)
packets from a source IP within the scan window.

**Thresholds:**
- `TCP_STEALTH_SCAN_THRESHOLD` = 15 distinct ports (default)
- `TIME_WINDOW` = 10 seconds (default)

**Test file:** `test_tcp_stealth_scan_detection.py`

---

### 7. `SYN_FLOOD`

**Purpose:** Detect SYN flood and RST flood denial-of-service attacks.

**Mechanism:** Two independent sub-detectors within the same rule:
1. **SYN flood**: Counts SYN packets (not SYN+ACK) from a source to a single target. Alerts when
   `SYN_FLOOD_THRESHOLD` is exceeded within `TIME_WINDOW`.
2. **RST flood**: Counts RST packets from a source. RSTs that correspond to a prior SYN to a closed
   port within `RST_RESPONSE_GRACE_SECONDS` are treated as benign and suppressed.

**Thresholds:**
- `SYN_FLOOD_THRESHOLD` = 100 SYNs in 10 seconds
- `RST_FLOOD_THRESHOLD` = 100 RSTs in 10 seconds

**Test file:** `test_new_rules_cycle8.py`, `test_regression_fixes.py`

---

### 8. `DISTRIBUTED_SYN_FLOOD`

**Purpose:** Detect DDoS-style SYN floods from many sources toward a single victim.

**Mechanism:** Tracks total SYN count per victim and distinct source IP count per victim.
Alerts when both `DISTRIBUTED_SYN_FLOOD_THRESHOLD` total SYNs and
`DISTRIBUTED_SYN_FLOOD_MIN_SOURCES` distinct sources are exceeded within `TIME_WINDOW`.

**Thresholds:**
- `DISTRIBUTED_SYN_FLOOD_THRESHOLD` = 500 total SYNs
- `DISTRIBUTED_SYN_FLOOD_MIN_SOURCES` = 20 distinct sources

**Test file:** `test_new_rules_cycle8.py`

---

### 9. `ICMP_SWEEP`

**Purpose:** Detect ICMP ping sweeps (network host discovery).

**Mechanism:** Counts distinct ICMP echo reply targets from a source IP within the window.
Hosts in `TRUSTED_HOSTS` are excluded from triggering.

**Thresholds:**
- `ICMP_SWEEP_THRESHOLD` = 12 distinct echo targets (default)
- `TIME_WINDOW` = 10 seconds

**Test file:** `test_icmp_sweep_detection.py`

---

### 10. `ICMP_FLOOD`

**Purpose:** Detect ICMP echo flood (ping flood) denial of service.

**Mechanism:** Counts ICMP echo requests from a source to a single target within the flood window.

**Thresholds:**
- `ICMP_FLOOD_THRESHOLD` = 50 echoes in 5 seconds

**Test file:** `test_icmp_flood.py`

---

### 11. `ARP_SPOOF`

**Purpose:** Detect ARP spoofing (IP→MAC mapping changes).

**Mechanism:** Maintains a persistent JSON table of observed IP→MAC mappings (`data/arp_table.json`).
When an ARP packet assigns a new MAC to a previously seen IP, an alert fires. The old and new MACs
are both recorded in the evidence.

**Limitations:** Legitimate DHCP lease changes and NIC replacements will trigger false positives.
Analysts should review context before classifying. Gratuitous ARPs from moving virtual machines
are a common benign cause.

**Test file:** `test_dns_and_arp_detection.py`

---

### 12. `PAYLOAD_HIT`

**Purpose:** Detect application-layer exploits through deep packet inspection (DPI).

**Mechanism:** See [Architecture — HttpParser Pipeline](ARCHITECTURE.md#7-httpparser-pipeline-payload_hit-dpi) for the full protocol-scoping diagram.
TCP payloads are parsed by `HttpParser` to determine protocol context, then matched against 18 internal DPI signatures.

#### Internal PAYLOAD_HIT Signatures

| Sig ID | Description | Protocol Scope |
|---|---|---|
| `SQL_INJECTION` | UNION SELECT, error-based, boolean SQLi patterns | HTTP, DB, non-TLS |
| `XSS` | `<script>`, `onerror=`, `javascript:` injection | HTTP |
| `CREDENTIAL_LEAK` | Passwords/secrets in cleartext HTTP requests | HTTP (redacted in evidence) |
| `CMD_INJECTION` | Shell metacharacters, pipe-chained commands, `eval(` | HTTP, cmd ports, TLS |
| `PATH_TRAVERSAL` | `../`, `%2e%2e`, absolute paths in HTTP targets | HTTP path |
| `SSRF` | Requests to localhost/metadata service from external context | HTTP |
| `LOG4SHELL` | `${jndi:ldap://` and variants (CVE-2021-44228) | HTTP, TLS, cmd ports |
| `XXE` | XML external entity injection (`<!ENTITY SYSTEM`) | HTTP |
| `SSTI` | Server-side template injection (`{{7*7}}`, `${7*7}`) | HTTP |
| `SHELLSHOCK` | Bash function injection in HTTP headers (CVE-2014-6271) | HTTP headers |
| `DESERIALIZATION` | Java/Python/PHP serialized object injection markers | HTTP |
| `HEADER_INJECTION` | CR/LF injection in HTTP headers | HTTP headers |
| `SCANNER_PROBE` | Common web scanner user-agent strings (Nikto, sqlmap) | HTTP headers |
| `SENSITIVE_FILE_PROBE` | Requests for `/etc/passwd`, `.env`, backup files | HTTP path |
| `REVERSE_SHELL_CRADLE` | `bash -i`, `/dev/tcp/`, `nc -e` patterns | HTTP, cmd ports, TLS |
| `HTTP_METHOD_TAMPERING` | Non-standard HTTP methods used for bypass | HTTP |
| `WEBSHELL_INJECTION` | PHP/ASP webshell upload patterns, `eval(base64_decode` | HTTP |
| `ICS_TRISTATION_EXPLOIT` | Triconex/TriStation ICS protocol attack patterns | ICS port 1502 only |

> [!NOTE]
> `PAYLOAD_HIT` signatures are **not** separate top-level rules — they are sub-signatures within
> the single `PayloadRule`. The `rule_name` in every alert is `PAYLOAD_HIT`; the specific
> signature ID appears in the `evidence_json` field.

**Thresholds:**
- `PAYLOAD_MAX_BYTES` = 512 bytes per packet
- `PAYLOAD_ALERT_COOLDOWN_S` = 60 seconds per flow per signature

**Test file:** `test_payload_detection.py` (76 tests)

---

### 13. `DNS_ANOMALY`

**Purpose:** Detect DNS-based covert channels, domain generation algorithms (DGA), and DNS abuse.

**Mechanism:** Multi-subtype rule with four independent detectors:

| Subtype | Trigger | Detection |
|---|---|---|
| `DNS_DGA` | High entropy domain label | Shannon entropy of longest label > `DNS_ENTROPY_THRESHOLD` (3.8 bits/char) |
| `DNS_TUNNEL` | Very long DNS label | Label length > `DNS_QUERY_MAX_LEN` (60 chars) |
| `DNS_COVERT_CHANNEL` | Hex/base64 encoding in labels | Hexadecimal or base64 patterns in DNS labels |
| `DNS_FREQ` | High query rate | > `DNS_FREQ_THRESHOLD` queries from one source in `DNS_FREQ_WINDOW` |
| `DNS_SUBDOMAIN` | Subdomain explosion | > `DNS_SUBDOMAIN_THRESHOLD` distinct subdomains in `DNS_SUBDOMAIN_WINDOW` |

**Limitations:** Legitimate CDN traffic (e.g. Akamai, Cloudflare) may have high-entropy labels.
DGA detection based solely on entropy has limited discriminative power against modern DGAs.

**Test file:** `test_dns_and_arp_detection.py`, `test_non_dns_on_dns_port.py`

---

### 14. `BRUTE_FORCE`

**Purpose:** Detect credential brute force attacks against authentication services.

**Mechanism:** Counts TCP SYN packets from a source to common authentication ports within
`BRUTE_FORCE_WINDOW`. Default monitored ports: SSH (22), FTP (21), Telnet (23), RDP (3389),
SMB (445), IMAP (143), POP3 (110), SMTP (587, 25), MySQL (3306), and any configured extra ports.

**Thresholds:**
- `BRUTE_FORCE_THRESHOLD` = 20 connection attempts in 60 seconds

**Test file:** `test_new_rules_cycle8.py`

---

### 15. `SLOW_PORT_SCAN`

**Purpose:** Detect deliberately slow port scans that evade short time-window rules.

**Mechanism:** Extends `PortScanRule`'s logic with a longer time window (`SLOW_SCAN_WINDOW` = 120s)
and a higher threshold (`SLOW_SCAN_THRESHOLD` = 30 ports). Both vertical (port) and horizontal (host)
variants are detected.

**Test file:** `test_new_rules_cycle8.py`

---

### 16. `DATA_EXFIL`

**Purpose:** Detect anomalously large outbound data transfers that may indicate exfiltration.

**Mechanism:** Tracks total bytes sent per `(src_ip, dst_ip)` pair within `DATA_EXFIL_WINDOW`.
Two thresholds: standard traffic (50 KB/30 s) and web traffic on ports 80/443 (1 MB/30 s) to
avoid false positives from legitimate large downloads.

**Limitations:** Cannot distinguish legitimate large transfers (backups, updates) from exfiltration.
Encryption makes content inspection impossible. Volume-only detection requires analyst review.

**Test file:** `test_data_exfiltration.py`

---

### 17. `TLS_ANOMALY`

**Purpose:** Detect TLS/SSL protocol anomalies that may indicate version downgrade attacks,
invalid handshake sequences, or unusual cipher negotiation.

**Mechanism:** Parses TLS ClientHello handshake fields (version, cipher suites, extensions)
from raw TCP payloads. Flags obsolete versions (SSLv2, SSLv3, TLS 1.0), suspicious SNI patterns,
and unusually short handshakes.

**Thresholds:**
- `TLS_COOLDOWN_S` = 60 seconds per-flow cooldown

**Test file:** `test_tls_anomaly.py`

---

### 18. `CLEAR_HTTP_ON_TLS_PORT`

**Purpose:** Detect cleartext HTTP being sent on TLS-only ports (443, 8443), which may indicate
protocol stripping attacks, misconfigured clients, or evasion.

**Mechanism:** Identifies TCP payloads that parse as valid HTTP requests/responses on ports
designated for TLS only. Requires `CLEAR_HTTP_TLS_MIN_REQUESTS` cleartext requests within
`CLEAR_HTTP_TLS_WINDOW_S` before alerting (reduces noisy single-packet false positives).

**Test file:** `test_clear_http_tls.py`

---

### 19. `TCP_ZERO_WINDOW`

**Purpose:** Detect TCP zero-window attacks where an attacker advertises a zero receive window
to hold server connections open (a form of Slowloris/resource exhaustion).

**Mechanism:** Counts zero-window (`WIN=0`) packets per flow pair within `TCP_ZERO_WINDOW_WINDOW`.
Requires `TCP_ZERO_WINDOW_MIN_FLOWS` concurrent affected pairs as corroboration to reduce
false positives from legitimate TCP flow control.

**Thresholds:**
- `TCP_ZERO_WINDOW_THRESHOLD` = 20 zero-window packets in 10 seconds
- `TCP_ZERO_WINDOW_MIN_FLOWS` = 3 concurrent affected pairs

**Test file:** `test_tcp_zero_window.py`

---

### 20. `NON_DNS_TRAFFIC_ON_DNS_PORT`

**Purpose:** Detect non-DNS protocol traffic on port 53 — a common covert channel and backdoor technique.

**Mechanism:** Inspects UDP and TCP traffic on port 53. If the payload does not parse as a valid
DNS message (checked by Scapy's DNS layer), an alert fires. Also detects interactive shell traffic
on TCP port 53.

**Limitations:** Encrypted DNS (DoT, DoH on port 853/443) is not covered by this rule.
DNS-over-TCP legitimate traffic may require tuning if it triggers false positives.

**Test file:** `test_non_dns_on_dns_port.py`

---

### 21. `ICMP_TUNNEL`

**Purpose:** Detect ICMP tunneling — data exfiltration or C2 channels disguised as ICMP echo traffic.

**Mechanism:** Analyses ICMP echo payloads for high Shannon entropy (> `ICMP_TUNNEL_ENTROPY_THRESHOLD` = 4.5 bits/byte)
and unusually large payloads (> `ICMP_TUNNEL_MIN_BYTES` = 64 bytes). Normal ping payloads have low
entropy (repetitive patterns); tunneled data appears random.

**Limitations:** Some legitimate ping utilities send large or random payloads. High-entropy
detection alone cannot confirm tunneling without additional flow context.

**Test file:** `test_icmp_tunnel.py`

---

### 22. `IP_FRAGMENT_ANOMALY`

**Purpose:** Detect malicious IP fragmentation — Teardrop attacks, overlapping fragments used for
IDS evasion, or fragment floods.

**Mechanism:** Tracks fragment reassembly per `(src_ip, dst_ip, ip_id)`. Flags:
- Overlapping or duplicate fragments (potential Teardrop exploit)
- Fragments that cannot be reassembled within `IP_FRAGMENT_REASSEMBLY_TIMEOUT_S`
- Excessive fragment counts from a single source (fragment flood)

**Test file:** `test_ip_fragment_anomaly.py`

---

### 23. `IRC_C2_BEACONING`

**Purpose:** Detect IRC-based command and control (C2) beaconing patterns used by older botnets.

**Mechanism:** Monitors SYN packets to IRC ports (6660–6670, 7000, 8000, 8080 when used for IRC).
When a source sends > `IRC_BEACONING_THRESHOLD` SYN packets to these ports within `IRC_BEACONING_WINDOW`,
a beaconing alert fires. State is bounded by `IRC_BEACONING_MAX_SOURCES` LRU entries.

**Thresholds:**
- `IRC_BEACONING_THRESHOLD` = 5 SYNs in 300 seconds (5 minutes)

**Limitations:** IRC client activity and IRC-based legitimate services will cause false positives
in environments with IRC use. Consider excluding known IRC server IPs via `TRUSTED_HOSTS`.

**Test file:** `test_irc_c2_beaconing.py`

---

## LRU State Bounding

> [!IMPORTANT]
> All rules that maintain per-source or per-flow state use `OrderedDict`-based LRU caches
> with configurable maximum sizes. This is enforced by `prune_stale(now)` calls that evict
> entries older than the rule's time window. This prevents unbounded memory growth during
> long-running capture sessions.

The LRU eviction is **deterministic** — the oldest entry by insertion order is always evicted
when the cache is full, ensuring O(1) amortized memory bounds.

---

## Adding a New Rule

See [DEVELOPMENT_WORKFLOW.md](DEVELOPMENT_WORKFLOW.md) for the step-by-step process.

The rule governance invariant requires every new rule to have:
- A unique detection purpose not covered by improving an existing rule
- Documented observable packet evidence
- Defined O(1) LRU state bounds
- Positive detection, benign suppression, and evasion edge-case tests

