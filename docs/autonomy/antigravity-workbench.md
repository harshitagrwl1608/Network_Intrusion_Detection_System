# NetGuard Engineering Workbench — Technical Specification & User Guide

**Document Version**: 1.0.0  
**Target Architecture**: Google Antigravity (IDE & CLI 1.4.12)  
**Authorized Branch**: `antigravity/overnight-work`  
**Engine Invariant**: Strictly preserve 19 registered rules in `RuleEngine.rules`

---

## 1. Executive Summary

The **NetGuard Engineering Workbench** upgrades the NetGuard IDS repository into a customized, production-grade Antigravity engineering environment. The workbench packages **8 specialist subagents**, **9 modular engineering skills**, **5 lifecycle hooks**, and **2 local stdio MCP servers** into an official Antigravity plugin located at `.agents/plugins/netguard-workbench/`.

The entire workbench adheres strictly to the Antigravity plugin specification, passes `agy plugin validate --strict` with zero warnings, enforces Git branch discipline via pre-tool hooks, and guarantees the preservation of NetGuard's core 19-rule detection invariant.

---

## 2. Plugin Architecture

```text
.agents/plugins/netguard-workbench/
├── plugin.json               # Plugin manifest (id: netguard-workbench, v1.0.0)
├── README.md                 # Public overview and quickstart
├── hooks.json                # Lifecycle hooks configuration
├── mcp_config.json           # Stdio MCP servers configuration
├── assets/
│   └── logo.svg              # NetGuard shield vector logo
├── rules/
│   └── AGENTS.md             # Authoritative engineering & Git invariants
├── agents/                   # Plugin-bundled specialist agents
│   ├── pcap-analyst.md
│   ├── detection-rule-engineer.md
│   ├── dataset-researcher.md
│   ├── suricata-validator.md
│   ├── zeek-analyst.md
│   ├── performance-auditor.md
│   ├── regression-qa-reviewer.md
│   └── independent-security-auditor.md
├── skills/                   # Modular runbooks & procedures
│   ├── pcap-forensics/SKILL.md
│   ├── dataset-acquisition/SKILL.md
│   ├── dataset-deduplication/SKILL.md
│   ├── suricata-validation/SKILL.md
│   ├── zeek-analysis/SKILL.md
│   ├── rule-review/SKILL.md
│   ├── memory-performance-audit/SKILL.md
│   ├── reproducible-evaluation/SKILL.md
│   └── forensic-reporting/SKILL.md
└── scripts/                  # Standalone hook and MCP tools
    ├── session_start.py
    ├── pre_tool_guard.py
    ├── post_tool_logger.py
    ├── pre_invocation.py
    ├── stop_checkpoint.py
    ├── pcap_mcp_server.py
    └── eval_db_mcp_server.py
```

---

## 3. Installation, Activation & Discovery

### Discovery Mechanics
Antigravity automatically discovers customizations by traversing upwards from the current working directory to the repository root. Discovered under `.agents/plugins/netguard-workbench/`, the plugin is automatically ingested.

### Validation
To validate the plugin manifest and all bundled components strictly:
```bash
agy plugin validate --strict .agents/plugins/netguard-workbench
```

Expected output:
```text
Validating netguard-workbench (.agents/plugins/netguard-workbench/plugin.json)
  skills 9 · agents 8 · rules 1 · hooks 1 · mcpServers 2 · sidecars 0
✔ Validation passed
```

---

## 4. Specialist Subagents (`agents/`)

Each agent defines dedicated tool permissions, system prompts, and strict file boundaries:

| Agent Name | Tool Scope | File & Responsibility Scope |
| :--- | :--- | :--- |
| **`pcap-analyst`** | File inspection, shell (`tshark`, `scapy`) | PCAP inspection, flow reconstruction, flag anomalies, protocol hierarchy. Read scope: `ids_project/evaluation/datasets/` and test captures. |
| **`detection-rule-engineer`** | File read/write, shell (`pytest`, `run_eval.py`) | Hardening the 19 detection rules, port bounds (`1 <= port <= 65535`), IP validation, and alert evidence enrichment. Primary scope: `ids_project/engine/rules.py`. |
| **`dataset-researcher`** | File read/write, curl/web inspection | External capture discovery, publisher diversity ($\ge 4$ independent sources), license compliance, and provenance logging in `docs/autonomy/dataset-registry.md`. |
| **`suricata-validator`** | File read/write, shell | Differential verification against Suricata EVE JSON (`eve.json`), semantic attack family mappings, and IP/port canonicalization in `ids_project/evaluation/compare.py`. |
| **`zeek-analyst`** | File read/write, shell | Zeek NSM transaction analysis (`conn.log`, `dns.log`, `ssl.log`), connection state histories, and flow-level correlation. |
| **`performance-auditor`** | File read/write, shell (`pytest`) | Auditing memory footprint, enforcing $O(1)$ LRU state bounding via `OrderedDict`, verifying `prune_stale(now=None)`, and detecting stale references. |
| **`regression-qa-reviewer`** | File read/write, shell (`pytest`, `run_eval.py`) | Running regression test suites, verifying ground-truth evaluation (38/38 detected), PRNG seed isolation, and ensuring 0 false positives. |
| **`independent-security-auditor`** | File read, shell (read-only auditing) | Adversarial evasion testing, Git branch policy review, hook boundary validation, and credential protection. |

---

## 5. Modular Reusable Skills (`skills/`)

1. **`pcap-forensics`**: Tshark protocol hierarchies (`tshark -z io,phs`), conversation profiling, and Scapy packet stream analysis.
2. **`dataset-acquisition`**: Independent publisher vetting, license checking, SHA-256 verification, and dataset registry cataloging.
3. **`dataset-deduplication`**: Multi-tier duplicate detection (file SHA-256, frame hash normalization, 5-tuple flow fingerprinting).
4. **`suricata-validation`**: Resilient EVE JSON ingestion, timestamp normalization, and multi-engine concordance calculation.
5. **`zeek-analysis`**: Parsing Zeek connection state flags (`history` strings like `ShADadFf`) and cross-referencing alerts with DNS/SSL logs.
6. **`rule-review`**: Complete audit checklist for the 19 rules: port boundaries (`1 <= port <= 65535`), IP validation, and clock drift eviction (`timestamp > now`).
7. **`memory-performance-audit`**: Verification of `OrderedDict` with `popitem(last=False)` and `move_to_end(key)`, plus garbage collection defaults.
8. **`reproducible-evaluation`**: Executing ground-truth evaluation across all 38 attack scenarios and asserting 100% precision/recall with 0 false positives.
9. **`forensic-reporting`**: Extraction and schema validation of alert evidence dictionaries from SQLite databases.

---

## 6. Lifecycle Hooks (`hooks.json` & `scripts/`)

| Hook Event | Script | Invariant Enforced | Behavior & Return Schema |
| :--- | :--- | :--- | :--- |
| **`SessionStart`** | `scripts/session_start.py` | State awareness | Injects current Git branch, commit status, and autonomy cycle into the conversation trajectory. |
| **`PreToolUse`** | `scripts/pre_tool_guard.py` | Git & directory protection | Tokenizes commands with `shlex`. Blocks `git push origin main`, force-pushes (`-f`), `git reset --hard`, branch deletions (`-D`), and recursive deletion of datasets or core directories. Returns `decision: allow` or `decision: deny`. |
| **`PostToolUse`** | `scripts/post_tool_logger.py` | Sanitized auditing | Records operational audit events to `.agents/plugins/netguard-workbench/logs/workbench_audit.log`. Redacts tokens, passwords, and API keys. Returns `{}`. |
| **`PreInvocation`** | `scripts/pre_invocation.py` | Context injection | Injects ephemeral workspace reminders regarding the 19-rule limit and authorized branch. |
| **`Stop`** | `scripts/stop_checkpoint.py` | Durable checkpointing | Saves a structured checkpoint to `checkpoint.json`. **Guaranteed non-looping**: returns `decision: allow`. |

---

## 7. Model Context Protocol (MCP) Servers

Configured in `mcp_config.json`, the workbench exposes two dedicated local stdio MCP servers:

### A. `netguard-pcap` (`scripts/pcap_mcp_server.py`)
- **`pcap_metadata`**: File size, packet count, timestamp span, duration.
- **`protocol_distribution`**: Breakdown of packets across Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP, TLS.
- **`flow_summary`**: 5-tuple flow statistics and top communicating endpoints.
- **`tcp_flags`**: Flag distribution and anomaly detection (SYN+FIN, NULL, XMAS).
- **`dns_inventory`**: DNS queries, types, unique domains, and Shannon entropy for DGA/tunnel detection.
- **`suricata_eve_summary`**: Summarizes Suricata EVE JSON alert telemetry.
- **`dataset_hash_verify`**: Computes SHA-256 and MD5 cryptographic checksums.

### B. `netguard-eval-db` (`scripts/eval_db_mcp_server.py`)
- **`evaluation_db_summary`**: Schema, tables, and row counts of SQLite evaluation databases in read-only mode (`mode=ro`).
- **`evaluation_db_query_alerts`**: Parameterized read-only queries with parsed `evidence` JSON.
- **`evaluation_db_rule_statistics`**: Aggregates alert statistics by rule name, severity, and IP counts.

---

## 8. Orchestration & Execution Safety

### Available Orchestration Modalities
- **IDE Collaborative Modality**: Integrated chat canvas, visual diff overlays, code lenses, and subagent orchestration.
- **Subagent Delegation**: Asynchronous specialists (`pcap-analyst`, `detection-rule-engineer`, `suricata-validator`, etc.) spawned via `invoke_subagent` with reactive wakeup.
- **Model Inheritance**: All subagents inherit the user-selected model (Gemini Flash High) and available reasoning effort.
- **Workspace Isolation**: Worktrees and branch isolation prevent concurrent write collisions.

### Unattended Execution Safety
The recommended settings configuration maintains seamless automation without compromising boundaries:
- `autoExecutionPolicy`: `CASCADE_COMMANDS_AUTO_EXECUTION_EAGER` (enables automated test and build runs).
- `artifactReviewMode`: `ARTIFACT_REVIEW_MODE_TURBO`.
- Safety boundary enforced deterministically via `pre_tool_guard.py` rather than interactive prompts.

---

## 9. Known Limitations & Troubleshooting

1. **Suricata / Zeek Host Binaries**:
   `suricata` and `zeek` native binaries are not installed on this Linux host (`tshark` and `scapy` are installed). Suricata and Zeek telemetry analysis is performed via pre-generated logs (`eve.json`, `conn.log`) and Scapy PCAP replayers.
2. **Browser Tool Execution**:
   Browser JavaScript execution is disabled (`BROWSER_JS_EXECUTION_POLICY_DISABLED` in `~/.gemini/config/config.json`). Web research relies on `search_web` and direct HTTP retrievals.
3. **PCAP Size Limits**:
   Large PCAPs (>100 MB) should be inspected using `tshark` or sampled frames rather than loading entirely into memory via Scapy `rdpcap`.
4. **Hook Permissions**:
   Ensure all Python scripts in `scripts/` have execution permissions (`chmod +x scripts/*.py`).
