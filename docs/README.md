# NetGuard IDS — Documentation Index

This directory contains the complete developer and operator documentation for NetGuard IDS.

---

## Documentation Map

| Document | Description |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture, module map, packet-to-alert data flow, alert schema |
| [INSTALLATION_AND_USAGE.md](INSTALLATION_AND_USAGE.md) | Installation, live capture, PCAP replay, evaluation, CLI reference |
| [CONFIGURATION.md](CONFIGURATION.md) | All configuration variables with defaults and environment override names |
| [DETECTION_ENGINE.md](DETECTION_ENGINE.md) | All 23 detection rules — purpose, mechanism, thresholds, limitations |
| [TESTING_AND_DATA_SOURCES.md](TESTING_AND_DATA_SOURCES.md) | Test suite structure (854 tests, 42 test modules), synthetic and PCAP datasets |
| [EVALUATION_RESULTS.md](EVALUATION_RESULTS.md) | Scientifically careful evaluation results with caveats and methodology |
| [DEVELOPMENT_WORKFLOW.md](DEVELOPMENT_WORKFLOW.md) | Adding rules, branch discipline, commit conventions, extending tests |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common errors and fixes |
| [AI_ML_AUTONOMOUS_DEFENSE_ROADMAP.md](AI_ML_AUTONOMOUS_DEFENSE_ROADMAP.md) | **Future vision only** — long-term AI/ML evolution roadmap (not yet implemented) |

> [!NOTE]
> The `evaluation/` subdirectory contains in-depth evaluation methodology, ground-truth audit reports,
> and per-rule detection analysis accumulated over the project's development lifecycle.

---

## Quick Links

- **Run all tests**: `cd ids_project && python3 -m pytest tests/ -q`
- **Run synthetic evaluation**: `python3 ids_project/evaluation/run_eval.py`
- **Replay a PCAP**: `python3 -m ids_project.evaluation.replay --pcap file.pcap --db /tmp/out.db`
- **Start live IDS**: `sudo python3 ids_project/main.py`

