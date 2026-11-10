# NetGuard IDS — Installation and Usage

---

## Prerequisites

| Requirement | Minimum version | Notes |
|---|---|---|
| Python | 3.11+ | Tested on 3.14.8 |
| Scapy | 2.5.0+ | Required for all packet operations |
| Flask | 3.0.0+ | Required for the dashboard |
| `editcap` | any | Required for `.pcapng` → `.pcap` conversion; part of **Wireshark** tools |
| `root` / `CAP_NET_RAW` | — | Required for **live capture only** |

---

## 1. Installation

```bash
# 1. Clone the repository
git clone https://github.com/harshitagrwl1608/Network_Intrusion_Detection_System.git
cd Network_Intrusion_Detection_System

# 2. Create and activate a virtual environment
python3 -m venv ids_project/.venv
source ids_project/.venv/bin/activate

# 3. Install dependencies
pip install -r ids_project/requirements.txt

# 4. (Optional) Install Wireshark tools for PCAPNG conversion
sudo apt-get install wireshark-tools     # Debian/Ubuntu
# or
sudo dnf install wireshark-cli           # Fedora/RHEL
```

> [!NOTE]
> `psycopg2-binary` is listed in `requirements.txt` for PostgreSQL support.
> If you do not plan to use PostgreSQL, you can skip it (`pip install scapy flask pandas requests python-dotenv`).

---

## 2. Configuration

All configuration is in [`ids_project/config.py`](../ids_project/config.py) and can be overridden via environment variables or a `.env` file placed at `ids_project/.env`.

See [CONFIGURATION.md](CONFIGURATION.md) for a complete reference.

**Minimum configuration for live capture** (defaults work for most scenarios):

```bash
# Set your network interface
export IDS_INTERFACE=eth0

# Set your gateway (exempt from scan rules)
export GATEWAY_IP=192.168.1.1
```

---

## 3. Live Packet Capture

Live capture requires root privileges (or `CAP_NET_RAW`):

```bash
# Start the full IDS (sniffer + dashboard + analysis loop)
cd ids_project
sudo python3 main.py

# Override interface inline
IDS_INTERFACE=wlan0 sudo -E python3 main.py
```

The dashboard is available at `http://127.0.0.1:5000` by default.

> [!CAUTION]
> Never commit the `storage/alerts.db` file or any database with captured traffic.
> These may contain sensitive network data.

---

## 4. PCAP Replay

Replay a `.pcap` file against the detection engine without live capture:

```bash
# Basic replay — writes alerts to a SQLite database
python3 -m ids_project.evaluation.replay \
    --pcap /path/to/capture.pcap \
    --db /tmp/results.db

# View help
python3 -m ids_project.evaluation.replay --help
```

### PCAPNG Conversion

NetGuard's fast binary parser requires `.pcap` format.
Convert `.pcapng` files using `editcap` (included with Wireshark tools):

```bash
editcap -F pcap input.pcapng output.pcap
```

---

## 5. Running the Test Suite

The test suite has **854 tests** across 42 test modules:

```bash
cd /path/to/Network_Intrusion_Detection_System

# Run all tests
python3 -m pytest ids_project/tests/ -q

# Run a specific module
python3 -m pytest ids_project/tests/test_payload_detection.py -v

# Run with verbose output
python3 -m pytest ids_project/tests/ -v --tb=short
```

Expected output: `854 passed` (no failures, no skips).

---

## 6. Synthetic Scenario Evaluation

The synthetic evaluation replays 42 hand-crafted attack scenarios against the detection engine using
a synthetic PCAP (`ids_project/data/test_attacks.pcap`) and verifies zero false positives on benign traffic:

```bash
python3 ids_project/evaluation/run_eval.py
```

Expected output:
```
  Total attack alerts:    42
  Total FP_benign alerts: 0
  [OK] Zero false positives on benign traffic.
```

---

## 7. Ground-Truth Benchmark (22-PCAP)

The full multi-dataset benchmark requires the external PCAPs (see [TESTING_AND_DATA_SOURCES.md](TESTING_AND_DATA_SOURCES.md)).
If the external drive is mounted:

```bash
bash scripts/evaluation/run_ground_truth_benchmark.sh
```

Results are written to `results/final_ground_truth_benchmark/`.

---

## 8. Directory Structure

```
Network_Intrusion_Detection_System/
├── ids_project/                 # Main application package
│   ├── main.py                  # Entry point (live IDS)
│   ├── config.py                # All configuration variables
│   ├── requirements.txt         # Python dependencies
│   ├── capture/
│   │   └── sniffer.py           # Packet capture and extraction
│   ├── engine/
│   │   ├── rules.py             # 23 detection rules + RuleEngine (~7500 lines)
│   │   ├── http_parser.py       # HTTP parsing for DPI context
│   │   └── blocklist.py         # IP blocklist management
│   ├── storage/
│   │   └── db.py                # SQLite schema and alert persistence
│   ├── analysis/
│   │   └── aggregator.py        # Plain-language threat-level summary
│   ├── dashboard/
│   │   └── app.py               # Flask REST API
│   ├── evaluation/
│   │   ├── replay.py            # Deterministic PCAP replay engine
│   │   ├── run_eval.py          # Synthetic evaluation (42 scenarios)
│   │   └── reporting/           # Report builder, validator, contract
│   ├── tests/                   # 854 tests across 42 modules
│   └── data/                    # Synthetic test PCAPs and blocklist
├── docs/                        # Developer documentation (this directory)
├── scripts/
│   └── evaluation/              # Benchmark and scoring scripts
├── data/
│   ├── external_benchmarks/     # Ground-truth CSVs and manifests
│   └── ciciot2023_eval/         # CICIoT2023 converted PCAPs
├── evaluation/
│   └── REPORTING_STANDARD.md   # Single-source-of-truth reporting spec
└── results/                     # Benchmark output (not committed)
```

---

## 9. Alert Database Query

After a replay or live capture, query the alert database:

```bash
sqlite3 /tmp/results.db "SELECT rule_name, severity, detail FROM alerts ORDER BY timestamp;"
sqlite3 /tmp/results.db "SELECT rule_name, COUNT(*) FROM alerts GROUP BY rule_name;"
```

