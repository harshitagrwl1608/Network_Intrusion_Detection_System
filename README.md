# 🛡️ NetGuard IDS

> **A Lightweight, First-Principles Network Intrusion Detection System with Plain-Language SOC Visualization**

[![Status](https://img.shields.io/badge/Project_Status-In_Active_Development-orange.svg?style=flat-square)](https://github.com)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=flat-square&logo=python)](https://python.org)
[![Sniffer](https://img.shields.io/badge/Capture-Scapy_2.5%2B-red.svg?style=flat-square)](https://scapy.net/)
[![Web UI](https://img.shields.io/badge/Dashboard-Flask_3.0%2B_%7C_SSE-green.svg?style=flat-square&logo=flask)](https://flask.palletsprojects.com/)
[![Storage](https://img.shields.io/badge/Database-SQLite_%2F_PostgreSQL-informational.svg?style=flat-square&logo=postgresql)](https://postgresql.org)
[![Threat Intel](https://img.shields.io/badge/Threat_Intel-Feodo_Tracker_%2F_abuse.ch-blueviolet.svg?style=flat-square)](https://feodotracker.abuse.ch)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg?style=flat-square)](LICENSE)

> [!NOTE]
> ### 🚧 Ongoing Project Notice
> **NetGuard IDS is currently under active development.**  
> The core packet-sniffing engine, 19-rule signature and heuristic detection suite, 17-signature Deep Packet Inspection (DPI) with multi-pass decoding and evasion normalization, Shannon entropy & hex-chunk DNS covert tunneling analysis, TLS handshake SNI inspection, TCP zero-window DoS protection, and real-time Flask SOC dashboard with interactive filtering and Server-Sent Events (SSE) streaming are functional and verified across 248 unit tests and 37/37 synthetic evaluation scenarios. Upcoming milestones include **Automated Intrusion Prevention (Active Defense via iptables)**, **Machine Learning Anomaly Detection (Isolation Forest)**, and **Webhook Notifications (Discord/Slack)**.

---

## 📖 Table of Contents

- [Overview & Motivation](#-overview--motivation)
- [System Architecture](#-system-architecture)
- [Core Detection Rules](#-core-detection-rules)
- [Plain-Language SOC Dashboard](#-plain-language-soc-dashboard)
- [Evaluation vs. Suricata](#-evaluation-vs-suricata)
- [Project Structure](#-project-structure)
- [Quick Start Guide](#-quick-start-guide)
- [Configuration Reference (`.env`)](#-configuration-reference-env)
- [Running Without Root](#-running-without-root)
- [Security & Privacy Safeguards](#-security--privacy-safeguards)
- [Development Roadmap](#-development-roadmap)
- [Academic Context & Credits](#-academic-context--credits)

---

## 💡 Overview & Motivation

Home and small-office networks generate continuous connection traffic, yet small-business owners and home users rarely possess visibility into what traverses their routers. Commercial-grade Security Information and Event Management (SIEM) and Intrusion Detection Systems (e.g., Snort, Suricata, Zeek) exist, but they are built for trained security engineers: their output consists of opaque technical flags that overwhelm non-specialists.

**NetGuard IDS** is built from first principles to bridge that gap:
1. **Built from Scratch:** Packet capture, protocol dissection, sliding-window state tracking, and alert triggers are handwritten using Python and Scapy rather than black-box configurations.
2. **Plain-Language Translation:** Translates complex technical telemetry into concise, actionable English statements for everyday administrators.
3. **Enterprise-Grade UI:** Delivers a dark, responsive SOC dashboard with real-time push streaming (Server-Sent Events), GeoIP localization, MAC vendor resolution, and historical trendlines.
4. **Rigorous Benchmarking:** Includes a complete evaluation suite with synthetic attack injection and ground-truth comparison against enterprise standard **Suricata** (`eve.json`).

---

## 🏛️ System Architecture

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │                        Live Traffic (Raw Socket)                       │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                Capture & Normalization Layer (sniffer.py)              │
 │     • Protocol Decoding (Ethernet / IP / TCP / UDP / ARP / DNS)        │
 │     • Payload Extraction (Bounded Stream Buffer)                       │
 │     • FQDN Extraction & TCP Window / Timing Records                    │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                     Rule Engine Orchestrator (rules.py)                │
 │  ┌──────────────────────────────────────────────────────────────────┐  │
 │  │ 1. Threat Intel : BLOCKLIST (abuse.ch Feodo Tracker / CINS Army) │  │
 │  │ 2. Scanners     : PORT_SCAN, UDP_SCAN, TCP_STEALTH_SCAN,         │  │
 │  │                   SLOW_PORT_SCAN, ICMP_SWEEP                     │  │
 │  │ 3. Floods & DoS : SYN_FLOOD, DISTRIBUTED_SYN_FLOOD, UDP_FLOOD,   │  │
 │  │                   ICMP_FLOOD, TCP_ZERO_WINDOW (Sockstress)       │  │
 │  │ 4. Protocol/MITM: TCP_FLAG_ANOMALY, ARP_SPOOF (Persistent Table) │  │
 │  │ 5. App & Payloads: PAYLOAD_HIT (17 DPI Signatures + Multi-Pass), │  │
 │  │                   DNS_ANOMALY (Entropy + Tunneling + Hex-Chunks),│  │
 │  │                   BRUTE_FORCE (Auth Services), DATA_EXFIL,       │  │
 │  │                   TLS_ANOMALY (Direct-IP SNI),                   │  │
 │  │                   CLEAR_HTTP_ON_TLS_PORT                         │  │
 │  └──────────────────────────────────────────────────────────────────┘  │
 │                   • False-Positive Mitigations Filter                  │
 └───────────────────┬────────────────────────────────┬───────────────────┘
                     │ Alerts                         │ Devices Seen
                     ▼                                ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                 Storage Abstraction Layer (storage/db.py)              │
 │              • SQLite (Zero-config)  |  PostgreSQL (Production)        │
 └───────────────────┬────────────────────────────────────────────────────┘
                     │
         ┌───────────┴────────────────────────┐
         ▼                                    ▼
 ┌──────────────────────────────┐ ┌───────────────────────────────────────┐
 │ Analysis Engine (aggregator) │ │ Flask SOC Web Dashboard (dashboard/)  │
 │ • Threat Rating Computation  │ │ • Real-Time SSE Stream (/api/stream)  │
 │ • Attack Pattern Summary     │ │ • Interactive Rule & Severity Filters │
 │ • Plain-English Narratives   │ │ • GeoIP Origin Flagging (Cached)      │
 │ • Auto-pruning Retention     │ │ • Device MAC OUI Fingerprinting       │
 └──────────────────────────────┘ └───────────────────────────────────────┘
```

---

## 🔍 Core Detection Rules

NetGuard implements **19 detection rules** spanning stateless lookups, stateful sliding windows, deep packet inspection, TLS inspection, and algorithmic information theory:

| Rule ID | Detection Mechanism | Methodology | Tunable Defaults |
|---|---|---|---|
| **`BLOCKLIST`** | Known C2 Botnets & Ransomware IPs | Stateless $O(1)$ set lookup against synced feeds (abuse.ch Feodo Tracker, CINS Army). | Auto-updated every 24h |
| **`TCP_FLAG_ANOMALY`** | Malformed TCP Packets | Stateless inspection of illegal/contradictory TCP flags (SYN+FIN, SYN+RST, flagless probes) used for firewall evasion and OS fingerprinting. | Instant trigger |
| **`PORT_SCAN`** | Network Reconnaissance & Port Sweeps | Stateful sliding window tracking distinct ports on a single host (vertical) or across distinct hosts (horizontal). Restricts to initial TCP SYN attempts and stores only the latest observation per unique target. | $\ge 15$ ports or hosts in $10\text{s}$ |
| **`UDP_SCAN`** | UDP Port and Host Sweeps | Tracks distinct UDP destination ports or hosts per source in a sliding window; stores only latest observations per unique target and excludes replies from known service ports. | $\ge 15$ ports or hosts in $10\text{s}$ |
| **`UDP_FLOOD`** | UDP Packet Flood Denial-of-Service | Stateful sliding window counting UDP packets to single destination with port-differentiated web/QUIC threshold. | $\ge 50$ pkts (or $\ge 500$ on port 443) in $5\text{s}$ |
| **`TCP_STEALTH_SCAN`** | FIN, NULL, and Xmas Port Scans | Tracks distinct ports receiving FIN-only, flagless, or FIN/PSH/URG probes; ignores ordinary SYN, ACK, RST, and mixed handshake traffic. | $\ge 15$ ports in $10\text{s}$ |
| **`SYN_FLOOD`** | Denial-of-Service (DoS) Attacks | Stateful sliding window tracking rapid bursts of initial TCP SYN packets directed toward service ports ($< 49152$); also inspects high-rate RST floods with closed-port response grace. | $\ge 100$ SYNs (or RSTs) in $10\text{s}$ |
| **`DISTRIBUTED_SYN_FLOOD`** | Distributed Denial-of-Service (DDoS) | Counts initial TCP SYNs to one service across source IPs; requires both a high packet volume and a minimum number of distinct sources. Per-target packet/source state and active targets are bounded. | $\ge 500$ SYNs from $\ge 20$ sources in $10\text{s}$ |
| **`ICMP_SWEEP`** | Host Discovery | Counts distinct IPv4/IPv6 destinations of ICMP echo requests per source in a sliding window; ignores replies and duplicate probes to the same host. | $\ge 12$ hosts in $10\text{s}$ |
| **`ICMP_FLOOD`** | ICMP Echo Flood Denial-of-Service | Stateful sliding window tracking rapid high-frequency ICMP echo bursts directed at a single target IP. | $\ge 50$ echo requests in $5\text{s}$ |
| **`ARP_SPOOF`** | Man-in-the-Middle (MITM) & Cache Poisoning | Stateful persistent table tracking valid IPv4-to-unicast-MAC pairings with bounded identity/cooldown state. Alerts if a recognized IP suddenly claims a new hardware identity. | 120s alert cooldown |
| **`PAYLOAD_HIT`** | Deep Packet Inspection (DPI) | Bounded TCP stream & packet DPI matching 17 regex signatures with multi-pass URL decoding, form decoding, null-byte stripping, and comment normalization. | 512-byte buffer cap; 60s alert cooldown |
| **`DNS_ANOMALY`** | DGA, Length, Frequency & Tunneling | Maximum Shannon entropy across labels through registrable domain, query length, repeated parent frequency, distinct subdomain exfil, and covert hex-chunk tunneling. | Entropy $\ge 3.8$, length $> 60$, freq $\ge 20$, subdomains $\ge 20$ |
| **`BRUTE_FORCE`** | Credential Brute-Force Attacks | Stateful sliding window tracking repeated connection attempts from a source to credentialed authentication services (SSH, RDP, SMB, MySQL, FTP, Telnet). | $\ge 20$ attempts in $60\text{s}$ |
| **`SLOW_PORT_SCAN`** | Low-and-Slow Port Reconnaissance | Extended sliding window tracking stealthy horizontal or vertical scans intentionally spaced to evade rapid 10s rate detectors. | $\ge 30$ ports/hosts in $120\text{s}$; 120s cooldown |
| **`DATA_EXFIL`** | Outbound Data Exfiltration | Sliding window measuring cumulative outbound payload transfer volume to external destinations; includes web port threshold distinction and database dump detection. | $\ge 50\text{KB}$ (or $\ge 1\text{MB}$ web) in $30\text{s}$ |
| **`TLS_ANOMALY`** | TLS Handshake SNI Anomaly & Tunnels | Binary parsing of TLS 1.0–1.3 Client Hello Server Name Indication (SNI). Flags RFC 6066 literal IP violations and dynamic proxy tunnels (ngrok, duckdns, etc.). | Enabled by default; 60s cooldown |
| **`CLEAR_HTTP_ON_TLS_PORT`** | Plaintext HTTP on Encrypted Port | Detects repeated cleartext HTTP request verbs (`GET`, `POST`, `CONNECT`) transmitted on TLS ports (`443`, `8443`), indicating C2 bypass or SSL misconfiguration. | $\ge 2$ requests in $600\text{s}$; 600s cooldown |
| **`TCP_ZERO_WINDOW`** | Sockstress / Zero-Window DoS | Tracks repeated TCP Zero-Window (`win=0`) advertisements per endpoint pair, detecting persist-timer thread exhaustion and socket buffer starvation. | $\ge 20$ packets in $10\text{s}$; 60s cooldown |

### 🔬 Deep Packet Inspection (DPI) Signatures
`PayloadRule` evaluates raw packet payloads and ordered, bounded TCP streams against 17 categorized threat signatures with automatic multi-pass URL decoding (up to 3 passes), form decoding (`+` to space), null-byte stripping (`%00` and `\x00`), and inline SQL comment collapsing (`/*...*/`):

1. **`SQL_INJECTION`**: `UNION SELECT`, `' OR 1=1`, `HAVING 1=1`, `WAITFOR DELAY`, and stacked queries.
2. **`XSS`**: `<script>`, `javascript:`, and DOM event handlers (`onload=`, `onerror=`).
3. **`CREDENTIAL_LEAK`**: Plaintext credentials, passwords, private keys, and authorization headers.
4. **`CMD_INJECTION`**: Shell command concatenation (`cat /etc/passwd`, `/bin/sh`, `cmd.exe /c`, pipes).
5. **`PATH_TRAVERSAL`**: Directory traversal attacks (`../`, `..\`, `%2e%2e%2f`).
6. **`SSRF`**: Server-Side Request Forgery targeting loopback, link-local, and cloud metadata (`169.254.169.254`).
7. **`LOG4SHELL`**: Log4j JNDI injection expressions (`${jndi:ldap://...}`).
8. **`XXE`**: XML External Entity injection (`<!ENTITY ... SYSTEM ...>`).
9. **`SSTI`**: Server-Side Template Injection (`{{...}}`, `${...}`, `#{...}`).
10. **`SHELLSHOCK`**: Bash function export header exploitation (`() { :; };`).
11. **`DESERIALIZATION`**: Java serialization (`\xac\xed\x00\x05`, `rO0AB`) and Python pickle execution gadgets.
12. **`HEADER_INJECTION`**: HTTP Response Splitting and CRLF header injection (`%0d%0a`, `\r\nSet-Cookie:`).
13. **`SCANNER_PROBE`**: Automated web scanner reconnaissance (`sqlmap`, `nikto`, `nuclei`, `masscan`, `wpscan`).
14. **`SENSITIVE_FILE_PROBE`**: Access to configuration and credential files (`.env`, `.git/config`, `id_rsa`, `wp-config.php`).
15. **`REVERSE_SHELL_CRADLE`**: Interactive download cradles (`curl ... | sh`, `powershell IEX`, `/dev/tcp`, `mkfifo`).
16. **`HTTP_METHOD_TAMPERING`**: Non-standard HTTP methods & WebDAV probing (`TRACE`, `TRACK`, `PROPFIND`, `Translate: f`).
17. **`WEBSHELL_INJECTION`**: Malicious webshell execution markers (`eval(base64_decode(...))`, `system($_GET[...])`, `Runtime.getRuntime().exec()`).

### 🛡️ False-Positive Mitigations
- **Source Service Port Exemption:** Packets originating *from* well-known service ports (e.g., `53/DNS`, `80/HTTP`, `443/HTTPS`, `123/NTP`) are exempted from scanner rules to prevent high-volume DNS/Web servers from being flagged as attackers.
- **Directional Filtering:** The regular TCP scanner counts initial SYN attempts; the stealth scanner only counts FIN, NULL, and Xmas probe patterns.
- **Trusted Host Whitelist:** Gateway routers, DNS resolvers, and designated infrastructure can be specified in `GATEWAY_IP` and `IDS_TRUSTED` to eliminate false alarms on administrative traffic.

---

## 🖥️ Plain-Language SOC Dashboard

The web dashboard is designed for both security analysts and non-technical stakeholders:

* **Live Threat Streaming:** Uses **Server-Sent Events (SSE)** at `/api/stream` to push alerts to the browser instantly with sub-second latency and zero polling lag.
* **Plain-English Narratives:** The analytics aggregator parses low-level network records and outputs clear, actionable sentences covering all 19 detection rules:
  > *"⚠️ A device at 192.168.1.105 probed 30 network services in a rapid burst — this pattern typically indicates network reconnaissance or port scanning."*
* **Interactive Table Filtering & Instant Search:** Filter alerts in real-time by search query (source IP, destination IP, port, or payload text), detection rule (all 19 rules), or severity level (High, Medium, Low) across both live and historical logs.
* **19 Detection Rules Indicator:** Header status badge visually confirms the 19 active detection heuristics running in the engine.
* **Dynamic Threat Gauge:** Automatically evaluates whether the overall network status is `CLEAR`, `LOW`, or `HIGH` based on incident velocity and severity.
* **GeoIP Intelligence:** Resolves external threat destinations to their host country with interactive flags (cached locally, RFC-1918 private network classification, rate-limit protected).
* **Network Device Inventory:** Inspects all communicating hardware on the segment and resolves MAC prefixes via IEEE OUI to identify manufacturers (e.g., *Apple*, *Intel*, *Raspberry Pi Foundation*, *Cisco*).
* **Investigation Modal & Evidence Viewer:** Full forensic modal displaying structured JSON evidence, plain-language trigger explanation, and analyst True Positive (TP) / False Positive (FP) feedback loop.
* **Interactive Calendar Log Viewer:** Heatmap calendar of daily incident volumes with one-click drilldown into complete logs for any past date.
* **Historical Trends:** Visualizes 24-hour alert distribution using interactive Chart.js graphs color-coded across all 19 detection rules.

---

## 📊 Evaluation & PCAP Replay

NetGuard includes a complete evaluation pipeline to benchmark detection accuracy against **Suricata** and run offline analysis on real or synthetic capture files (e.g., `log.pcap`).

### 1. Capturing Real Network Traffic (`log.pcap`)

You can capture live traffic from your network into a `log.pcap` file using `tcpdump` or Wireshark:

```bash
# Method A: Standard binary PCAP capture (recommended)
sudo tcpdump -i <interface> -s 0 -w log.pcap

# Capture 500 packets and stop automatically:
sudo tcpdump -i <interface> -c 500 -s 0 -w log.pcap

# Method B: ASCII text log format (NetGuard's sniffer auto-detects and parses this too!)
sudo tcpdump -nn -tttt -i <interface> > log.pcap
```

> **Note:** Replace `<interface>` with your active network card (e.g., `eth0` or `wlan0`, found via `ip link show`).

### 2. Replaying `log.pcap` Through NetGuard

To analyze `log.pcap` offline without needing raw socket privileges or live root sniffing:

```bash
# Replay your custom log.pcap file through NetGuard's engine
python evaluation/replay.py --pcap log.pcap

# Or if you generated the synthetic fixture:
python evaluation/replay.py --pcap data/test_attacks.pcap
```

**How NetGuard processes `log.pcap`:**
* **Constant-Memory Streaming:** Streams binary libpcap frames iteratively instead of buffering whole multi-gigabyte captures in memory.
* **Dual Format Auto-Detection:** Automatically detects whether `log.pcap` is a binary libpcap capture or an ASCII `tcpdump` text dump (supporting both `YYYY-MM-DD` and `HH:MM:SS` timestamp formats).
* **Protocol & Field Extraction:** Decodes IP endpoints, ports, protocol flags, TCP window size, DNS query name/type, ARP mappings, and raw payloads.
* **Rule Engine Execution:** Evaluates all 19 detection rules concurrently against every packet with zero early-exit truncation.
* **Database Storage:** Inserts all detected security incidents directly into `storage/alerts.db` with durable disk spooling.

### 3. Automated Isolated Evaluation Runner

To run a complete, repeatable evaluation with isolated databases and fresh ARP state:

```bash
# Runs full evaluation on synthetic attack + benign PCAPs with ground truth:
python evaluation/run_eval.py
```

**Evaluation Results Summary:**
- **Attack Detection:** **37 / 37 labelled scenarios detected** (100.0% Recall, 100.0% Precision, 100.0% F1).
- **Benign Background Traffic:** **0 False Positives** on the 806-packet benign fixture.
- **Unit Test Suite:** **248 passed tests** (`python -m pytest -q -p no:cacheprovider`).
- *Note:* Synthetic benchmark results validate rule mechanics and do not imply 100% real-world accuracy on unlabelled production traffic.

This command runs with zero contamination:
* Replays `data/test_attacks.pcap` into an isolated temporary database.
* Evaluates detections against `evaluation/scenarios/test_labels.csv`.
* Replays `data/test_benign.pcap` into a separate isolated database with fresh ARP state.
* Verifies zero false alarms on benign traffic and prints a full breakdown of TP, FN, FP, Precision, Recall, and F1.

### 4. Visualizing Alerts in the SOC Dashboard

Launch the dashboard locally to inspect live or replayed incidents:

```bash
python -m dashboard.app
```
Open **`http://127.0.0.1:5000`** in your browser to inspect the incident feed, plain-language summaries, threat gauge, structured JSON evidence in the investigation modal, and GeoIP map.

### 5. Benchmarking Against Suricata

To compare NetGuard against Suricata on the exact same capture:

```bash
# 1. (Optional) Generate synthetic attack traffic (.pcap with port scans, syn floods, blocklist hits, ARP spoofing)
python evaluation/generate_test_pcap.py

# 2. Run Suricata against the capture file (log.pcap or test_attacks.pcap)
suricata -r log.pcap -l /tmp/suricata/

# 3. Compare detections and output precision, recall, and F1 score
python evaluation/compare.py --eve /tmp/suricata/eve.json
```

---

## 📁 Project Structure

```
Networking_Project/
├── ids_project/
│   ├── capture/
│   │   └── sniffer.py           # Scapy packet capture, field extraction & protocol decoding
│   ├── engine/
│   │   ├── rules.py             # 10 detection rules + RuleEngine orchestrator
│   │   └── blocklist.py         # abuse.ch Feodo Tracker feed loader & auto-downloader
│   ├── storage/
│   │   └── db.py                # Database abstraction layer (SQLite + PostgreSQL)
│   ├── analysis/
│   │   └── aggregator.py       # Plain-language generator & threat level evaluator
│   ├── dashboard/
│   │   ├── app.py               # Flask REST API + SSE streaming endpoints
│   │   ├── templates/           # Jinja2 HTML templates
│   │   └── static/              # CSS styles & client-side JavaScript (Chart.js)
│   ├── data/
│   │   ├── update_blocklist.py  # Standalone/cron updater for multi-source blocklists
│   │   ├── blocklist.txt        # Local threat intelligence IP cache
│   │   ├── arp_table.example.json # Sample schema for persistent ARP mappings
│   │   └── test_attacks.pcap    # Synthetic test traffic fixture
│   ├── evaluation/
│   │   ├── generate_test_pcap.py# Script to generate reproducible attack packets
│   │   ├── replay.py            # Offline PCAP replay tool for the rule engine
│   │   └── compare.py           # Comparative evaluation vs Suricata eve.json
│   ├── .env.example             # Documented environment configuration template
│   ├── config.py                # Centralized settings with environment overrides
│   ├── main.py                  # Entry point (sniffer + analyzer + dashboard threads)
│   ├── requirements.txt         # Python package dependencies
│   └── README.md
├── .gitignore                   # Security rules preventing leaks of secrets, PCAPs & DBs
└── README.md
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- **Linux** (Ubuntu, Debian, Kali, Fedora, Raspberry Pi OS)
- **Python 3.10+**
- `libpcap` installed (`sudo apt install libpcap-dev`)

### 2. Installation

```bash
# Clone the repository
git clone https://github.com/your-username/netguard-ids.git
cd netguard-ids/ids_project

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Configuration

```bash
# Copy template configuration
cp .env.example .env

# Identify your active network interface
ip link show
# Edit .env and set IDS_INTERFACE (e.g., eth0 or wlan0)
nano .env
```

### 4. Run NetGuard

NetGuard can be executed in two modes:

#### Option A: Live Monitoring Mode (Real-Time Sniffing)
Because packet capture operates on raw sockets, root or capability privileges are required:

```bash
# Start NetGuard (sniffer thread + analysis loop + web dashboard)
sudo .venv/bin/python main.py
```

#### Option B: Offline PCAP Analysis Mode (`log.pcap`)
If you want to analyze pre-recorded network traffic or do not have root capture permissions:

```bash
# 1. Replay your log.pcap file through the IDS engine
.venv/bin/python evaluation/replay.py --pcap log.pcap

# 2. Launch the web dashboard to inspect the alerts and plain-language report
.venv/bin/python -c "from dashboard.app import app; app.run(host='127.0.0.1', port=5000)"
```

Open your browser and navigate to:
👉 **`http://localhost:5000`**

---

## ⚙️ Configuration Reference (`.env`)

All parameters in `config.py` can be tuned via `.env`:

| Variable | Default | Description |
|---|---|---|
| `IDS_INTERFACE` | `eth0` | Network interface to sniff on (`ip link show`) |
| `GATEWAY_IP` | `192.168.1.1` | Local gateway IP address (exempted from scanner rules) |
| `IDS_TRUSTED` | `""` | Comma-separated list of trusted IPs, hostnames, or CIDRs |
| `DB_BACKEND` | `sqlite` | Database engine: `sqlite` or `postgres` |
| `SQLITE_PATH` | `storage/alerts.db` | Local SQLite database file location |
| `POSTGRES_URL` | `""` | PostgreSQL connection string (`postgresql://user:pass@host:5432/db`) |
| `PORT_SCAN_THRESHOLD` | `15` | Distinct destination ports probed in window to trigger alert |
| `UDP_SCAN_THRESHOLD` | `15` | Distinct UDP destination ports or hosts in `TIME_WINDOW` to trigger alert |
| `UDP_FLOOD_THRESHOLD` | `50` | UDP packets to a single destination in `UDP_FLOOD_WINDOW` to trigger flood alert |
| `UDP_FLOOD_WINDOW` | `5` | UDP flood sliding window duration in seconds |
| `UDP_FLOOD_WEB_THRESHOLD` | `500` | UDP packet threshold for web/QUIC ports (UDP 443) |
| `TCP_STEALTH_SCAN_THRESHOLD` | `15` | Distinct FIN/NULL/Xmas TCP destination ports in `TIME_WINDOW` to trigger alert |
| `SYN_FLOOD_THRESHOLD` | `100` | Per-source initial SYN packets in window to trigger alert |
| `RST_FLOOD_THRESHOLD` | `100` | Per-source RST packets in window to trigger alert |
| `RST_RESPONSE_GRACE_SECONDS` | `5.0` | Grace window to match legitimate closed-port RST responses to recent SYNs |
| `DISTRIBUTED_SYN_FLOOD_THRESHOLD` | `500` | Aggregate SYN packets to one service in window |
| `DISTRIBUTED_SYN_FLOOD_MIN_SOURCES` | `20` | Distinct source IPs required for distributed SYN alert |
| `ICMP_SWEEP_THRESHOLD` | `12` | Distinct echo-request targets in `TIME_WINDOW` to trigger alert |
| `ICMP_FLOOD_THRESHOLD` | `50` | ICMP echo requests to single target in `ICMP_FLOOD_WINDOW` to trigger alert |
| `ICMP_FLOOD_WINDOW` | `5` | ICMP flood sliding window duration in seconds |
| `BRUTE_FORCE_THRESHOLD` | `20` | Rapid authentication attempts to credentialed service ports to trigger alert |
| `BRUTE_FORCE_WINDOW` | `60` | Brute force sliding window duration in seconds |
| `BRUTE_FORCE_EXTRA_PORTS` | `""` | Optional comma-separated non-standard authentication ports (e.g., `8443,9443`) |
| `SLOW_SCAN_THRESHOLD` | `30` | Distinct destination ports/hosts across extended window to trigger alert |
| `SLOW_SCAN_WINDOW` | `120` | Extended window in seconds for low-and-slow scan detection |
| `SLOW_SCAN_COOLDOWN_S` | `120.0` | Cooldown period for duplicate low-and-slow scan alerts |
| `DATA_EXFIL_BYTE_THRESHOLD` | `50000` | Outbound payload bytes in window to trigger data exfiltration alert |
| `DATA_EXFIL_WINDOW` | `30` | Data exfiltration sliding window duration in seconds |
| `DATA_EXFIL_WEB_BYTE_THRESHOLD`| `1000000` | Outbound volume threshold for common web upload ports (80, 443) |
| `TCP_ZERO_WINDOW_THRESHOLD` | `20` | Persistent zero-window (`win=0`) advertisements in window to trigger alert |
| `TCP_ZERO_WINDOW_WINDOW` | `10` | Zero-window sliding window duration in seconds |
| `TCP_ZERO_WINDOW_COOLDOWN` | `60.0` | Per-endpoint-pair cooldown in seconds for zero-window alerts |
| `TLS_INSPECTION` | `true` | Enable TLS Client Hello SNI anomaly and tunnel detection |
| `TLS_COOLDOWN_S` | `60.0` | Cooldown period in seconds for TLS anomaly alerts |
| `CLEAR_HTTP_TLS_MIN_REQUESTS` | `2` | Minimum repeated plaintext HTTP requests on TLS port to trigger alert |
| `CLEAR_HTTP_TLS_WINDOW_S` | `600.0` | Window in seconds for tracking plaintext HTTP requests on TLS port |
| `CLEAR_HTTP_TLS_COOLDOWN_S` | `600.0` | Alert cooldown in seconds for cleartext HTTP on TLS port |
| `TIME_WINDOW` | `10` | Sliding window duration in seconds for standard stateful rules |
| `PAYLOAD_INSPECTION` | `true` | Enable regex Deep Packet Inspection (DPI) |
| `PAYLOAD_MAX_BYTES` | `512` | Maximum packet payload bytes and per-flow TCP stream buffer |
| `PAYLOAD_ALERT_COOLDOWN_S` | `60.0` | Per-flow duplicate suppression cooldown for payload signatures |
| `DNS_ENTROPY_THRESHOLD` | `3.8` | Shannon entropy threshold for relevant DNS labels |
| `DNS_QUERY_MAX_LEN` | `60` | Maximum character length for legitimate domains |
| `DNS_FREQ_THRESHOLD` | `20` | Minimum queries to one parent domain from one source inside `DNS_FREQ_WINDOW`; `0` disables this detector |
| `DNS_FREQ_WINDOW` | `60` | DNS frequency sliding-window duration in seconds |
| `DNS_SUBDOMAIN_THRESHOLD` | `20` | Minimum distinct subdomains under same parent domain to trigger exfiltration alert |
| `DNS_SUBDOMAIN_WINDOW` | `60` | Subdomain exfiltration sliding window duration in seconds |
| `ANALYSIS_INTERVAL` | `30` | Seconds between background aggregation and retention checks |
| `DASHBOARD_HOST` | `127.0.0.1` | Host/IP for the Flask dashboard. Default is loopback-only. Set to `0.0.0.0` only with a firewall/reverse-proxy in place. |
| `DASHBOARD_PORT` | `5000` | Port for Flask dashboard |
| `ALERT_RETENTION_DAYS`| `14` | Days of alerts to keep in database (`0` = keep indefinitely) |
| `HISTORY_DAYS` | `7` | Default days displayed in dashboard history tab |

---

## 🔒 Running Without Root

To run NetGuard without invoking `sudo` on every execution, grant Python the `CAP_NET_RAW` Linux capability:

```bash
# Grant raw socket capture capability to virtualenv Python binary
sudo setcap cap_net_raw+eip $(readlink -f .venv/bin/python)

# Now run without sudo:
python main.py
```

---

## 🛡️ Security & Privacy Safeguards

When running and deploying NetGuard, adhere to the following security practices:

1. **Never Commit Live Secrets:** `.env` is ignored by `.gitignore`. Keep your database passwords, API credentials, and network secrets in `.env` only. Use `.env.example` as a sanitized template.
2. **Never Commit Network Telemetry:** Live SQLite databases (`alerts.db`), runtime ARP tables (`arp_table.json`), and raw packet capture files (`log.pcap`, `test.pcap`, `*.pcap`) are explicitly ignored by `.gitignore`. They contain MAC addresses, internal IP schemes, and potentially sensitive plaintext communications from your network.
3. **Synthetic PCAPs Only:** The repository only ships with synthetic, sanitized test traffic (`data/test_attacks.pcap`) generated strictly for algorithmic validation.

---

## 🗺️ Development Roadmap

- [x] **Phase 1: Core Engine & Ingestion**
  - [x] Scapy raw packet sniffer with protocol decoding
  - [x] Normalized packet schema (Ethernet, IP, TCP, UDP, ARP, DNS, Payload)
  - [x] High-performance SQLite database layer with thread safety
- [x] **Phase 2: Advanced Detection Rules & Intelligence**
  - [x] abuse.ch Feodo Tracker C2 blocklist integration with auto-sync
  - [x] Stateful sliding-window Port Scan & SYN Flood detection
  - [x] ARP cache poisoning / MITM detection with persistent state
  - [x] Deep Packet Inspection (DPI) for SQL Injection, XSS, and credential leaks
  - [x] Shannon Entropy DNS analysis for DGA and tunneling detection
  - [x] Server response and service-port false-positive mitigations
- [x] **Phase 3: SOC Dashboard & Benchmarking**
  - [x] Flask dark SOC dashboard with Server-Sent Events (SSE) live stream
  - [x] Plain-language observation generator and threat level gauge
  - [x] Rate-limited, cached GeoIP lookups with country flags
  - [x] MAC OUI device vendor fingerprinting
  - [x] Analyst True Positive / False Positive feedback tagging system
  - [x] Suricata benchmarking suite (`replay.py`, `compare.py`, `generate_test_pcap.py`)
- [ ] **Phase 4: Active Defense & Machine Learning (In Progress)**
  - [ ] **Automated IPS (Intrusion Prevention):** Optional active defense toggle using `iptables` / `ufw` to drop attacking IPs for a configurable quarantine period.
  - [ ] **Machine Learning Anomaly Detection:** Lightweight Isolation Forest model (`scikit-learn`) to baseline traffic volume and detect zero-day anomalies.
  - [ ] **External Alerts:** Webhook dispatchers for Discord, Slack, and Telegram notifications on high-severity events.
  - [ ] **Multi-Interface Sniffing:** Simultaneous capture across multiple physical and wireless network interfaces.

---

## 🎓 Academic Context & Credits

- **Author:** Harshit Garg
- **Mentorship:** Dr. Shivi Garg
- **Institution:** J.C. Bose University of Science and Technology, YMCA
- **Threat Intelligence:** [Feodo Tracker](https://feodotracker.abuse.ch/) & [abuse.ch](https://abuse.ch/)
- **Comparative Baseline:** [Suricata IDS/IPS](https://suricata.io/)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) — see the LICENSE file for details.
