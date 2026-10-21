# 🛡️ NetGuard IDS

> **A Lightweight, First-Principles Network Intrusion Detection System with Plain-Language SOC Visualization**

[![Status](https://img.shields.io/badge/Project_Status-In_Active_Development-orange.svg?style=flat-square)](https://github.com)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=flat-square&logo=python)](https://python.org)
[![Sniffer](https://img.shields.io/badge/Capture-Scapy_2.5%2B-red.svg?style=flat-square)](https://scapy.net/)
[![Web UI](https://img.shields.io/badge/Dashboard-Flask_3.0%2B_%7C_SSE-green.svg?style=flat-square&logo=flask)](https://flask.palletsprojects.com/)
[![Storage](https://img.shields.io/badge/Database-SQLite_%2F_PostgreSQL-informational.svg?style=flat-square&logo=postgresql)](https://postgresql.org)
[![Threat Intel](https://img.shields.io/badge/Threat_Intel-Feodo_Tracker_%2F_abuse.ch-blueviolet.svg?style=flat-square)](https://feodotracker.abuse.ch)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg?style=flat-square)](LICENSE)

---

> [!NOTE]
> ### 🚧 Ongoing Project Notice
> **NetGuard IDS is currently under active development.**  
> The core packet-sniffing engine, 6-tier signature/heuristic detection suite, deep packet inspection (DPI), DNS entropy analyzer, and real-time Flask SOC dashboard are functional. Upcoming milestones include **Automated Intrusion Prevention (Active Defense via iptables)**, **Machine Learning Anomaly Detection (Isolation Forest)**, and **Webhook Notifications (Discord/Slack)**.

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
 │     • Payload Extraction (Capped at 512B)                              │
 │     • FQDN Extraction & Timing Records                                 │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                     Rule Engine Orchestrator (rules.py)                │
 │  ┌──────────────────────────────────────────────────────────────────┐  │
 │  │ 1. Blocklist Rule     : O(1) C2 Botnet IP Lookup (abuse.ch)      │  │
 │  │ 2. Port Scan Rule     : Sliding Window Distinct Port Tracking    │  │
 │  │ 3. SYN Flood Rule     : High-Frequency Connection Burst Tracking │  │
 │  │ 4. ARP Spoof Rule     : Persistent IP-to-MAC Binding Monitor     │  │
 │  │ 5. Payload DPI Rule   : Regex Inspection (SQLi, XSS, Cred Leak)  │  │
 │  │ 6. DNS Anomaly Rule   : Shannon Entropy DGA & Tunneling Detector │  │
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
 │ • Attack Pattern Summary     │ │ • GeoIP Origin Flagging (Cached)      │
 │ • Plain-English Narratives   │ │ • Device MAC OUI Fingerprinting       │
 │ • Auto-pruning Retention     │ │ • Analyst TP/FP Feedback Loop         │
 └──────────────────────────────┘ └───────────────────────────────────────┘
```

---

## 🔍 Core Detection Rules

NetGuard implements 6 distinct detection rules spanning stateless lookups, stateful sliding windows, payload pattern matching, and algorithmic information theory:

| Rule ID | Detection Mechanism | Methodology | Tunable Defaults |
|---|---|---|---|
| **`BLOCKLIST`** | Known C2 Botnets & Ransomware IPs | Stateless $O(1)$ set lookup against synced feeds (abuse.ch Feodo Tracker, CINS Army). | Auto-updated every 24h |
| **`PORT_SCAN`** | Network Reconnaissance & Port Sweeps | Stateful sliding window tracking distinct destination ports probed per source IP. Excludes legitimate server response traffic. | $> 15$ ports in $10\text{s}$ |
| **`SYN_FLOOD`** | Denial-of-Service (DoS) Attacks | Stateful sliding window tracking rapid bursts of TCP SYN packets directed toward service ports ($< 49152$). | $> 100$ SYNs in $10\text{s}$ |
| **`ARP_SPOOF`** | Man-in-the-Middle (MITM) & Cache Poisoning | Stateful persistent table tracking IP $\leftrightarrow$ MAC pairings. Alerts if a recognized IP suddenly claims a new hardware identity. | Thread-safe auto-persist |
| **`PAYLOAD_HIT`** | Deep Packet Inspection (DPI) | Regex inspection of packet data payload for SQL Injection (`UNION SELECT`, `' OR 1=1`), XSS (`<script>`), and plaintext credentials (`password=`, `Authorization: Basic`). | First 512 bytes scanned |
| **`DNS_ANOMALY`** | Domain Generation Algorithms (DGA) & DNS Tunneling | Computes Shannon Entropy ($H = -\sum p(x) \log_2 p(x)$) on DNS queries. Flags high-randomness domains ($> 3.8\text{ bits/char}$) and oversized FQDNs ($> 50\text{ chars}$). | Entropy $> 3.8$, Length $> 50$ |

### 🛡️ False-Positive Mitigations
- **Source Service Port Exemption:** Packets originating *from* well-known service ports (e.g., `53/DNS`, `80/HTTP`, `443/HTTPS`, `123/NTP`) are exempted from scanner rules to prevent high-volume DNS/Web servers from being flagged as attackers.
- **Directional Filtering:** Only connection attempts (`SYN` flags without `ACK`) count toward scanner scores.
- **Trusted Host Whitelist:** Gateway routers, DNS resolvers, and designated infrastructure can be specified in `GATEWAY_IP` and `IDS_TRUSTED` to eliminate false alarms on administrative traffic.

---

## 🖥️ Plain-Language SOC Dashboard

The web dashboard is designed for both security analysts and non-technical stakeholders:

* **Live Threat Streaming:** Uses **Server-Sent Events (SSE)** at `/api/stream` to push alerts to the browser instantly without polling lag.
* **Plain-English Narratives:** The analytics aggregator parses low-level network records and outputs clear sentences:
  > *"⚠️ A device at 192.168.1.105 probed 30 network services in a rapid burst — this pattern typically indicates network reconnaissance or port scanning."*
* **Dynamic Threat Gauge:** Automatically evaluates whether the overall network status is `CLEAR`, `LOW`, or `HIGH` based on incident velocity.
* **GeoIP Intelligence:** Resolves external threat destinations to their host country with interactive flags (cached locally, rate-limit protected).
* **Network Device Inventory:** Inspects all communicating hardware on the segment and resolves MAC prefixes via IEEE OUI to identify manufacturers (e.g., *Apple*, *Intel*, *Raspberry Pi*).
* **Analyst Feedback Loop:** Allows operators to tag alerts as **True Positive (TP)** or **False Positive (FP)** with notes directly from the UI, generating empirical accuracy stats to guide threshold tuning.
* **Historical Trends:** Visualizes 24-hour alert distribution using interactive Chart.js graphs.

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
python ids_project/evaluation/replay.py --pcap log.pcap

# Or if you generated the synthetic fixture:
python ids_project/evaluation/replay.py --pcap ids_project/data/test_attacks.pcap
```

**How NetGuard processes `log.pcap`:**
* **Dual Format Auto-Detection:** Automatically detects whether `log.pcap` is a binary libpcap capture or an ASCII `tcpdump` text dump.
* **Protocol & Field Extraction:** Decodes IP endpoints, ports, protocol flags, ARP mappings, raw payloads (DPI), and DNS queries.
* **Rule Engine Execution:** Evaluates all 6 detection rules against every packet.
* **Database Storage:** Inserts all detected security incidents directly into `storage/alerts.db`.

### 3. Visualizing Replayed Alerts

After replaying `log.pcap`, launch the dashboard to inspect the detected incidents:

```bash
cd ids_project
python -c "from dashboard.app import app; app.run(host='127.0.0.1', port=5000)"
```
Open **`http://localhost:5000`** in your browser to inspect the incident feed, plain-language summaries, threat gauge, and GeoIP map generated from `log.pcap`.

### 4. Benchmarking Against Suricata

To compare NetGuard against Suricata on the exact same capture:

```bash
# 1. (Optional) Generate synthetic attack traffic (.pcap with port scans, syn floods, blocklist hits, ARP spoofing)
python ids_project/evaluation/generate_test_pcap.py

# 2. Run Suricata against the capture file (log.pcap or test_attacks.pcap)
suricata -r log.pcap -l /tmp/suricata/

# 3. Compare detections and output precision, recall, and F1 score
python ids_project/evaluation/compare.py --eve /tmp/suricata/eve.json
```

---

## 📁 Project Structure

```
Networking_Project/
├── ids_project/
│   ├── capture/
│   │   └── sniffer.py           # Scapy packet capture, field extraction & protocol decoding
│   ├── engine/
│   │   ├── rules.py             # 6 detection rules + RuleEngine orchestrator
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
| `SYN_FLOOD_THRESHOLD` | `100` | SYN packets received in window to trigger alert |
| `TIME_WINDOW` | `10` | Sliding window duration in seconds for stateful rules |
| `PAYLOAD_INSPECTION` | `true` | Enable regex Deep Packet Inspection (DPI) |
| `PAYLOAD_MAX_BYTES` | `512` | Maximum payload bytes scanned per packet |
| `DNS_ENTROPY_THRESHOLD` | `3.8` | Shannon entropy threshold for suspicious domain names |
| `DNS_QUERY_MAX_LEN` | `50` | Maximum character length for legitimate domains |
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
3. **Synthetic PCAPs Only:** The repository only ships with synthetic, sanitized test traffic (`ids_project/data/test_attacks.pcap`) generated strictly for algorithmic validation.

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
