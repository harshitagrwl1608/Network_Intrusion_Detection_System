# NetGuard Engineering Workbench (`netguard-workbench`)

The **NetGuard Engineering Workbench** is a specialized Google Antigravity plugin engineered for continuous improvement, packet-level forensics, rule hardening, differential testing, and regression QA across the NetGuard Intrusion Detection System.

---

## 1. Architecture Overview

```text
.agents/plugins/netguard-workbench/
├── plugin.json               # Plugin manifest (id: netguard-workbench, v1.0.0)
├── README.md                 # Workbench architecture & operational documentation
├── hooks.json                # Lifecycle hook configuration
├── mcp_config.json           # Local PCAP and SQLite evaluation MCP servers
├── assets/
│   └── logo.svg              # NetGuard shield icon
├── rules/
│   └── AGENTS.md             # Invariants: 19-rule limit, Git & telemetry discipline
├── agents/                   # Specialist subagents
│   ├── pcap-analyst.md
│   ├── detection-rule-engineer.md
│   ├── dataset-researcher.md
│   ├── suricata-validator.md
│   ├── zeek-analyst.md
│   ├── performance-auditor.md
│   ├── regression-qa-reviewer.md
│   └── independent-security-auditor.md
├── skills/                   # Modular runbooks & procedures
│   ├── pcap-forensics/
│   ├── dataset-acquisition/
│   ├── dataset-deduplication/
│   ├── suricata-validation/
│   ├── zeek-analysis/
│   ├── rule-review/
│   ├── memory-performance-audit/
│   ├── reproducible-evaluation/
│   └── forensic-reporting/
└── scripts/                  # Standalone execution & hook scripts
    ├── session_start.py
    ├── pre_tool_guard.py
    ├── post_tool_logger.py
    ├── pre_invocation.py
    ├── stop_checkpoint.py
    ├── pcap_mcp_server.py
    └── eval_db_mcp_server.py
```

---

## 2. Core Invariants & Engineering Guardrails

1. **Strict 19-Rule Invariant**:
   `RuleEngine.rules` must contain exactly **19 rule instances**. No new detection rules, dummy rules, or inflated rule counts may be added during customization tasks.
2. **Authorized Branch Discipline**:
   All autonomous work and commits must reside exclusively on `antigravity/overnight-work`. Pushing to `main`, force-pushing (`-f`), branch deletion, or destructive resets are blocked by `pre_tool_guard.py`.
3. **Telemetry Boundary**:
   NetGuard is a packet-first detection engine operating on PCAP and live streams. Endpoint event logs (e.g. Windows EVTX) are out of scope for the packet engine.
4. **Suricata Reference Corroboration**:
   Suricata is used for comparative corroboration, not as infallible ground truth.
5. **Deterministic Validation**:
   All improvements must pass the 482+ unit test suite (`pytest ids_project/tests`) and 38 ground-truth attack scenarios (`python3 ids_project/evaluation/run_eval.py`).

---

## 3. Specialist Agents

| Agent Name | Role & Domain | Primary Responsibilities |
| :--- | :--- | :--- |
| **`pcap-analyst`** | Packet Forensics | Deep packet inspection, flow reconstruction, flag anomalies, protocol hierarchy. |
| **`detection-rule-engineer`** | Detection Logic | Hardening the 19 detection rules, boundary checks, IP/port validation, alert evidence. |
| **`dataset-researcher`** | Dataset Research | External capture discovery, publisher diversity ($\ge 4$), provenance, license tracking. |
| **`suricata-validator`** | Cross-Engine Testing | Differential validation with Suricata EVE JSON, semantic attack family mappings. |
| **`zeek-analyst`** | NSM Log Profiling | Zeek `conn.log`, `dns.log`, `ssl.log` correlation, transaction auditing. |
| **`performance-auditor`** | Memory & Performance | `OrderedDict` LRU bounds, GC patterns, `prune_stale(now=None)`, memory profiling. |
| **`regression-qa-reviewer`** | Quality Assurance | Unit test execution, ground-truth evaluation, PRNG seed reproducibility. |
| **`independent-security-auditor`** | Red-Team Audit | Evasion analysis, Git branch protection review, secret leakage prevention. |

---

## 4. Reusable Skills

1. **`pcap-forensics`**: Tshark and Scapy packet inspection, conversation tracking, TCP stream analysis.
2. **`dataset-acquisition`**: Identification, provenance logging, and acquisition of external captures.
3. **`dataset-deduplication`**: Frame-level and flow fingerprint deduplication across mirror repositories.
4. **`suricata-validation`**: EVE JSON ingestion and multi-engine concordance calculation.
5. **`zeek-analysis`**: Parsing and correlating Zeek structured logs with NetGuard alerts.
6. **`rule-review`**: Structured boundary auditing (port 1-65535, IP validation, clock drift).
7. **`memory-performance-audit`**: Memory leak detection and $O(1)$ LRU cache auditing.
8. **`reproducible-evaluation`**: Ground-truth benchmarking across all 38 attack scenarios.
9. **`forensic-reporting`**: Extraction and schema validation of alert evidence dictionaries.

---

## 5. Lifecycle Hooks

- **`SessionStart`**: Runs `scripts/session_start.py` to read Git branch, commit status, and autonomy campaign state, injecting project status into the session.
- **`PreToolUse`**: Runs `scripts/pre_tool_guard.py` before `run_command`. Parses command tokens with `shlex` and blocks:
  - Pushes to `main` (`git push origin main`, `HEAD:main`)
  - Force-pushes (`git push -f`, `--force-with-lease`)
  - Destructive resets (`git reset --hard`)
  - Branch deletion (`git branch -D`)
  - Deletion of evaluation datasets or core directories (`rm -rf ids_project/evaluation/datasets*`)
- **`PostToolUse`**: Runs `scripts/post_tool_logger.py` to record sanitized operational audit events without leaking tokens or credentials.
- **`PreInvocation`**: Runs `scripts/pre_invocation.py` to supply ephemeral workspace reminders before model turns.
- **`Stop`**: Runs `scripts/stop_checkpoint.py` to save durable progress checkpoints. **Guaranteed loop-free** by returning `decision: allow`.

---

## 6. MCP Servers

### `netguard-pcap` (Local PCAP Analyzer)
Provides JSON-RPC 2.0 tools for packet capture inspection:
- `pcap_metadata`: File size, packet counts, timestamp range, duration.
- `protocol_distribution`: Breakdown across Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP, TLS.
- `flow_summary`: 5-tuple flow statistics and top communicating endpoints.
- `tcp_flags`: Distribution of flags and anomaly detection (SYN+FIN, NULL, XMAS).
- `dns_inventory`: DNS queries, types, unique domains, and Shannon entropy.
- `suricata_eve_summary`: Summarize Suricata EVE JSON alert telemetry.
- `dataset_hash_verify`: SHA-256 and MD5 cryptographic integrity verification.

### `netguard-eval-db` (Evaluation Database Inspector)
Provides read-only SQLite inspection:
- `evaluation_db_summary`: Tables, columns, and row counts.
- `evaluation_db_query_alerts`: Parameterized read-only queries with parsed `evidence` JSON.
- `evaluation_db_rule_statistics`: Grouped alert statistics by rule name, severity, and IP counts.

---

## 7. Validation & Verification

Validate the plugin manifest and structure:
```bash
agy plugin validate --strict .agents/plugins/netguard-workbench
```

Execute workbench unit tests:
```bash
pytest ids_project/tests/test_workbench.py
```

Run core regression and ground-truth evaluation:
```bash
pytest ids_project/tests
python3 ids_project/evaluation/run_eval.py
```

