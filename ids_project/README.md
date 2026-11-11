# NetGuard IDS — Python Package (`ids_project`)

This directory contains the core application package for **NetGuard IDS**.

For complete system documentation, architecture guides, evaluation reports, and contributor workflows, please refer to the root [**README.md**](../README.md) and the [**docs/**](../docs/) directory.

---

## Package Architecture & Layout

```
ids_project/
├── main.py                  # IDS runtime entry point (sniffer + analyzer + dashboard threads)
├── config.py                # Centralized configuration with environment variable overrides
├── requirements.txt         # Package dependencies (Scapy, Flask, Pandas, requests, etc.)
│
├── analytics/               # Statistical baselining (Rolling Median, MAD, EWMA, quarantine mode)
│   └── baselines.py         # BaselineEngine & traffic anomaly detection
│
├── capture/
│   ├── sniffer.py           # Scapy raw socket capture, binary PCAP parser & event extraction
│   └── metrics.py           # Live capture and ring-buffer throughput metrics
│
├── engine/
│   ├── rules.py             # 23 evidence-driven detection rules + RuleEngine orchestrator
│   ├── rule_metadata.py     # Authoritative metadata registry for all 23 detection rules
│   ├── http_parser.py       # Application-aware HTTP/1.x parsing layer for DPI context
│   └── blocklist.py         # abuse.ch Feodo Tracker threat intelligence loader
│
├── forensics/               # Deep network traffic forensics & sandboxed replay
│   ├── flow_tracker.py      # Bidirectional 5-tuple flow aggregation & packet event buffer
│   ├── pcap_retention.py    # Rotating libpcap ring buffer with SHA-256 integrity & quota pruning
│   └── offline_analyzer.py  # Sandboxed background PCAP replay engine (zero live DB contamination)
│
├── notifications/           # Multi-channel asynchronous alerting
│   ├── providers.py         # Adapters for SMTP, Telegram Bot, Webhook (HMAC-SHA256), Twilio SMS
│   └── outbox.py            # Non-blocking notification outbox queue with cooldown deduplication
│
├── parallel/                # High-throughput parallel processing pipeline
│   ├── profile.py           # Hardware capability discovery (cores, cgroups, RAM) & profile selector
│   └── pipeline.py          # Lock-free parallel capture pipeline with bounded monotonic reorder buffer
│
├── reports/                 # Multi-format report generator
│   └── generator.py         # 9 report types (Daily, Weekly, Monthly, Incident, PCAP, etc.) in HTML/JSON/CSV
│
├── storage/
│   ├── db.py                # Storage abstraction layer (SQLite and PostgreSQL backends)
│   └── forensics_db.py      # Forensics schemas (flows, packet_events, cases, outbox, audit_log)
│
├── analysis/
│   └── aggregator.py        # Plain-language narrative generator & threat rating engine
│
├── dashboard/
│   ├── app.py               # Flask REST API with Server-Sent Events (SSE) live streaming & 10 workspaces
│   ├── templates/           # Jinja2 HTML templates for the SOC dashboard
│   └── static/              # CSS stylesheets and client-side visualization scripts
│
├── evaluation/
│   ├── replay.py            # Deterministic PCAP replay engine (ReplayClock + ReplayTrackingEngine)
│   ├── run_eval.py          # Synthetic scenario evaluation (42 attack scenarios + benign check)
│   └── reporting/           # Single-source-of-truth reporting standard (contract, builder, validator)
│
├── tests/                   # 878 unit and regression tests across 43 test modules
│
└── data/                    # Synthetic attack PCAP fixtures and local threat intel cache
```

---

## Quick Reference Commands

Execute these commands from the repository root:

```bash
# 1. Activate virtual environment
source ids_project/.venv/bin/activate

# 2. Run test suite (878 tests)
python3 -m pytest ids_project/tests -q

# 3. Run synthetic scenario evaluation (42 scenarios)
python3 ids_project/evaluation/run_eval.py

# 4. Replay a PCAP file offline
python3 -m ids_project.evaluation.replay --pcap path/to/capture.pcap --db /tmp/alerts.db

# 5. Start live IDS monitoring (requires root / CAP_NET_RAW)
cd ids_project && sudo python3 main.py
```

---

## Authoritative Documentation Links

- 🏛️ [System Architecture](../docs/ARCHITECTURE.md)
- 🚀 [Installation and Usage Guide](../docs/INSTALLATION_AND_USAGE.md)
- ⚙️ [Configuration Reference](../docs/CONFIGURATION.md)
- 🔍 [Detection Engine Reference (23 Rules & 18 DPI Signatures)](../docs/DETECTION_ENGINE.md)
- 🧪 [Testing & Dataset Sources](../docs/TESTING_AND_DATA_SOURCES.md)
- 📊 [Evaluation Results & Methodology](../docs/EVALUATION_RESULTS.md)
- 🛠️ [Development Workflow & Rule Authoring](../docs/DEVELOPMENT_WORKFLOW.md)
- 🔧 [Troubleshooting & Operational FAQ](../docs/TROUBLESHOOTING.md)
- 🛡️ [SOC Dashboard & Forensics Guide](../docs/DASHBOARD_AND_FORENSICS_GUIDE.md)
- ⚡ [Parallel Performance Scaling Guide](../docs/PARALLEL_PERFORMANCE_GUIDE.md)
- 📦 [PCAP Retention, Slicing & Offline Replay](../docs/PCAP_ANALYSIS_AND_RETENTION.md)
- 🔔 [Multi-Channel Notification Integrations](../docs/NOTIFICATION_INTEGRATIONS.md)
- 🏆 [SOC Dashboard & Forensics Upgrade Release Report](../docs/UPGRADE_RELEASE_REPORT.md)
