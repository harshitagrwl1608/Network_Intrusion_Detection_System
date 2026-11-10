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
├── capture/
│   └── sniffer.py           # Scapy raw socket capture, binary PCAP parser & event extraction
│
├── engine/
│   ├── rules.py             # 23 evidence-driven detection rules + RuleEngine orchestrator
│   ├── http_parser.py       # Application-aware HTTP/1.x parsing layer for DPI context
│   └── blocklist.py         # abuse.ch Feodo Tracker threat intelligence loader
│
├── storage/
│   └── db.py                # Storage abstraction layer (SQLite and PostgreSQL backends)
│
├── analysis/
│   └── aggregator.py        # Plain-language narrative generator & threat rating engine
│
├── dashboard/
│   ├── app.py               # Flask REST API with Server-Sent Events (SSE) live streaming
│   ├── templates/           # Jinja2 HTML templates for the SOC dashboard
│   └── static/              # CSS stylesheets and client-side visualization scripts
│
├── evaluation/
│   ├── replay.py            # Deterministic PCAP replay engine (ReplayClock + ReplayTrackingEngine)
│   ├── run_eval.py          # Synthetic scenario evaluation (42 attack scenarios + benign check)
│   └── reporting/           # Single-source-of-truth reporting standard (contract, builder, validator)
│
├── tests/                   # 854 unit and regression tests across 42 test modules
│
└── data/                    # Synthetic attack PCAP fixtures and local threat intel cache
```

---

## Quick Reference Commands

Execute these commands from the repository root:

```bash
# 1. Activate virtual environment
source ids_project/.venv/bin/activate

# 2. Run test suite (854 tests)
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
