#!/usr/bin/env python3
"""
evaluation/run_eval.py
----------------------
Automated, reproducible evaluation harness for NetGuard IDS.

Usage:
    python evaluation/run_eval.py [--attack PCAP] [--benign PCAP] \\
        [--labels CSV] [--blocklist TXT] [--out-json FILE]

What it does:
  1. Creates brand-new temporary SQLite DBs and ARP tables each run.
     State is completely isolated and never contaminates production or earlier runs.
  2. Replays attack PCAP into attack DB, benign PCAP into benign DB.
     ARP tables are kept separate to prevent MAC contamination.
  3. Validates label CSV columns are present and non-empty.
  4. Matches each scenario label against attack alerts (bijective,
     endpoint-aware). Reports TP, FN, precision, recall, F1.
  5. Counts ALL alerts from benign replay as False Positives.
     Reports per-rule FP counts.
  6. Emits combined human-readable report + optional JSON output.

METRIC DEFINITIONS (from SYNTHETIC scenarios only — not real-world accuracy):
  TP        — labelled attack scenarios that produced a matching alert.
  FN        — labelled attack scenarios with NO matching alert (missed detections).
  FP_attack — attack-replay alerts that did NOT match any labelled scenario.
  FP_benign — alerts raised during purely benign replay.

  Precision = TP / (TP + FP_attack + FP_benign)
              (ALL alert sources reduce precision; no alert is free)
  Recall    = TP / (TP + FN)
  F1        = harmonic mean of Precision and Recall

Exit codes:
  0 — ALL scenarios detected AND zero FP_attack AND zero FP_benign.
  1 — Any FN, FP_attack, or FP_benign present.
  2 — Setup / input error (missing file, bad CSV, etc.).
"""

import argparse
import csv
import io
import ipaddress
import json
import logging
import os
import platform
import sqlite3
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone

_HERE     = os.path.dirname(os.path.abspath(__file__))
_IDS_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _IDS_ROOT)

logging.basicConfig(level=logging.INFO, format="%(levelname)-5s %(message)s")
logger = logging.getLogger("eval")

DEFAULT_ATTACK    = os.path.join(_IDS_ROOT, "data", "test_attacks.pcap")
DEFAULT_BENIGN    = os.path.join(_IDS_ROOT, "data", "test_benign.pcap")
DEFAULT_LABELS    = os.path.join(_HERE, "scenarios", "test_labels.csv")
DEFAULT_BLOCKLIST = os.path.join(_IDS_ROOT, "data", "test_blocklist.txt")


# ── helpers ──────────────────────────────────────────────────────────────────

def _fresh_tmp_db() -> str:
    fd, path = tempfile.mkstemp(prefix="netguard_eval_", suffix=".db")
    os.close(fd)
    os.unlink(path)
    return path


def _fresh_tmp_arp() -> str:
    fd, path = tempfile.mkstemp(prefix="netguard_arp_", suffix=".json")
    os.close(fd)
    os.unlink(path)
    return path


def _read_alerts(db_path: str) -> list:
    if not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT rule_name, src_ip, dst_ip, src_port, dst_port, "
            "protocol, detail, severity, confidence, timestamp "
            "FROM alerts ORDER BY timestamp"
        ).fetchall()]
    except Exception as e:
        logger.warning(f"Could not read alerts from {db_path}: {e}")
        rows = []
    finally:
        conn.close()
    return rows


def _load_labels(path: str) -> list:
    try:
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
    except FileNotFoundError:
        logger.error(f"Labels file not found: {path}")
        sys.exit(2)
    if not rows:
        logger.error("Labels CSV is empty.")
        sys.exit(2)
    missing = {"scenario_id", "expected_rule"} - set(rows[0].keys())
    if missing:
        logger.error(f"Labels CSV missing required columns: {missing}")
        sys.exit(2)
    from engine.rules import (
        ArpSpoofRule, BlocklistRule, DistributedSynFloodRule, DnsRule,
        IcmpSweepRule, PayloadRule, PortScanRule, SynFloodRule,
        TcpStealthScanRule, UdpScanRule, BruteForceRule, SlowPortScanRule,
        TcpFlagAnomalyRule, IcmpFloodRule, DataExfiltrationRule, UdpFloodRule,
    )
    known_rules = {
        rule.name for rule in (
            ArpSpoofRule, BlocklistRule, DistributedSynFloodRule, DnsRule,
            IcmpSweepRule, PayloadRule, PortScanRule, SynFloodRule,
            TcpStealthScanRule, UdpScanRule, BruteForceRule, SlowPortScanRule,
            TcpFlagAnomalyRule, IcmpFloodRule, DataExfiltrationRule, UdpFloodRule,
        )
    }
    protocols = {"TCP", "UDP", "ICMP", "ICMPV6", "ARP"}
    seen_ids = set()
    for line_number, row in enumerate(rows, start=2):
        scenario_id = (row.get("scenario_id") or "").strip()
        expected_rule = (row.get("expected_rule") or "").strip()
        if not scenario_id or scenario_id in seen_ids:
            logger.error("Labels CSV row %d has an empty or duplicate scenario_id", line_number)
            sys.exit(2)
        seen_ids.add(scenario_id)
        if expected_rule not in known_rules:
            logger.error("Labels CSV row %d references unknown rule %r", line_number, expected_rule)
            sys.exit(2)
        for endpoint in ("src_ip", "dst_ip"):
            value = (row.get(endpoint) or "").strip()
            if value:
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    logger.error("Labels CSV row %d has invalid %s %r", line_number, endpoint, value)
                    sys.exit(2)
        port = (row.get("dst_port") or "").strip()
        if port and (not port.isdigit() or not 1 <= int(port) <= 65535):
            logger.error("Labels CSV row %d has invalid dst_port %r", line_number, port)
            sys.exit(2)
        protocol = (row.get("protocol") or "").strip().upper()
        if protocol and protocol not in protocols:
            logger.error("Labels CSV row %d has unsupported protocol %r", line_number, protocol)
            sys.exit(2)
    return rows


def _run_metadata() -> dict:
    """Return reproducibility metadata without serializing secrets or host IPs."""
    import config
    from engine.rules import (
        ArpSpoofRule, BlocklistRule, DistributedSynFloodRule, DnsRule,
        IcmpSweepRule, PayloadRule, PortScanRule, SynFloodRule,
        TcpStealthScanRule, UdpScanRule, BruteForceRule, SlowPortScanRule,
        TcpFlagAnomalyRule, IcmpFloodRule, DataExfiltrationRule, UdpFloodRule,
    )

    rules = (
        ArpSpoofRule, BlocklistRule, DistributedSynFloodRule, DnsRule,
        IcmpSweepRule, PayloadRule, PortScanRule, SynFloodRule,
        TcpStealthScanRule, UdpScanRule, BruteForceRule, SlowPortScanRule,
        TcpFlagAnomalyRule, IcmpFloodRule, DataExfiltrationRule, UdpFloodRule,
    )
    setting_names = (
        "PORT_SCAN_THRESHOLD", "UDP_SCAN_THRESHOLD", "UDP_FLOOD_THRESHOLD", "UDP_FLOOD_WINDOW",
        "TCP_STEALTH_SCAN_THRESHOLD",
        "SYN_FLOOD_THRESHOLD", "RST_FLOOD_THRESHOLD",
        "DISTRIBUTED_SYN_FLOOD_THRESHOLD", "DISTRIBUTED_SYN_FLOOD_MIN_SOURCES",
        "ICMP_SWEEP_THRESHOLD", "ICMP_FLOOD_THRESHOLD", "ICMP_FLOOD_WINDOW",
        "TIME_WINDOW", "DNS_ENTROPY_THRESHOLD",
        "DNS_QUERY_MAX_LEN", "DNS_FREQ_THRESHOLD", "DNS_FREQ_WINDOW",
        "DNS_SUBDOMAIN_THRESHOLD", "DNS_SUBDOMAIN_WINDOW",
        "BRUTE_FORCE_THRESHOLD", "BRUTE_FORCE_WINDOW",
        "SLOW_SCAN_THRESHOLD", "SLOW_SCAN_WINDOW",
        "DATA_EXFIL_BYTE_THRESHOLD", "DATA_EXFIL_WINDOW",
        "PAYLOAD_INSPECTION", "PAYLOAD_MAX_BYTES",
    )
    return {
        "schema_version": 1,
        "run_id": uuid.uuid4().hex,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "python_version": platform.python_version(),
        "rule_versions": {rule.name: rule.rule_version for rule in rules},
        "settings": {name: getattr(config, name) for name in setting_names},
        "trusted_host_count": len(getattr(config, "TRUSTED_HOSTS", ())),
        "bounded_rule_state": {
            "device_dedup_keys": 65_536,
            "arp_identity_mappings": 65_536,
            "arp_alert_cooldowns": 10_000,
            "scan_keys_per_dimension": 10_000,
            "tcp_stealth_scan_keys": 10_000,
            "syn_flood_flow_keys": 8_192,
            "icmp_sweep_sources": 4_096,
            "dns_frequency_keys": 10_000,
            "dns_alert_dedup_keys": 10_000,
            "distributed_syn_targets": 2048,
            "distributed_syn_packet_timestamps_per_target": getattr(
                config, "DISTRIBUTED_SYN_FLOOD_THRESHOLD", 500
            ),
            "distributed_syn_sources_per_target": getattr(
                config, "DISTRIBUTED_SYN_FLOOD_MIN_SOURCES", 20
            ),
        },
        "payload_stream_limits": {
            "timeout_s": 30,
            "max_flows": 2048,
            "max_buffer_bytes_per_flow": getattr(config, "PAYLOAD_MAX_BYTES", 512),
            "max_reordered_segments": 8,
        },
    }


def _alert_summary(alert: dict) -> dict:
    keys = (
        "rule_name", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "severity", "confidence", "detail", "timestamp",
    )
    return {key: alert.get(key) for key in keys}


def _scenario_results(scenarios: list, tp: list, fn: list) -> list[dict]:
    matched = {sc.get("scenario_id"): alert for sc, alert in tp}
    missed = {sc.get("scenario_id") for sc in fn}
    results = []
    for scenario in scenarios:
        scenario_id = scenario.get("scenario_id")
        alert = matched.get(scenario_id)
        results.append({
            "scenario_id": scenario_id,
            "expected_rule": scenario.get("expected_rule"),
            "description": scenario.get("description", ""),
            "expected": {
                "src_ip": scenario.get("src_ip") or None,
                "dst_ip": scenario.get("dst_ip") or None,
                "dst_port": scenario.get("dst_port") or None,
                "protocol": scenario.get("protocol") or None,
            },
            "result": "TP" if alert else ("FN" if scenario_id in missed else "UNASSESSED"),
            "matched_alert": _alert_summary(alert) if alert else None,
        })
    return results


def _write_json(path: str, result: dict):
    from engine.blocklist import atomic_write_text
    atomic_write_text(path, json.dumps(result, indent=2) + "\n")


def _write_csv(path: str, result: dict):
    """Write per-scenario outcomes and every unmatched/benign alert as flat CSV rows."""
    fields = [
        "record_type", "result", "scenario_id", "expected_rule", "description",
        "expected_src_ip", "expected_dst_ip", "expected_dst_port", "expected_protocol",
        "alert_rule", "alert_src_ip", "alert_dst_ip", "alert_src_port",
        "alert_dst_port", "alert_protocol", "severity", "confidence", "detail",
    ]
    rows = []
    for scenario in result.get("scenario_results", []):
        expected = scenario.get("expected", {})
        alert = scenario.get("matched_alert") or {}
        rows.append({
            "record_type": "scenario", "result": scenario.get("result"),
            "scenario_id": scenario.get("scenario_id"),
            "expected_rule": scenario.get("expected_rule"),
            "description": scenario.get("description"),
            "expected_src_ip": expected.get("src_ip"),
            "expected_dst_ip": expected.get("dst_ip"),
            "expected_dst_port": expected.get("dst_port"),
            "expected_protocol": expected.get("protocol"),
            "alert_rule": alert.get("rule_name"),
            "alert_src_ip": alert.get("src_ip"), "alert_dst_ip": alert.get("dst_ip"),
            "alert_src_port": alert.get("src_port"), "alert_dst_port": alert.get("dst_port"),
            "alert_protocol": alert.get("protocol"), "severity": alert.get("severity"),
            "confidence": alert.get("confidence"), "detail": alert.get("detail"),
        })
    for record_type, alerts in (
        ("FP_attack", result.get("unmatched_attack_alerts", [])),
        ("FP_benign", result.get("benign_alerts", [])),
    ):
        for alert in alerts:
            rows.append({
                "record_type": record_type, "result": record_type,
                "alert_rule": alert.get("rule_name"),
                "alert_src_ip": alert.get("src_ip"), "alert_dst_ip": alert.get("dst_ip"),
                "alert_src_port": alert.get("src_port"), "alert_dst_port": alert.get("dst_port"),
                "alert_protocol": alert.get("protocol"), "severity": alert.get("severity"),
                "confidence": alert.get("confidence"), "detail": alert.get("detail"),
            })
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    from engine.blocklist import atomic_write_text
    atomic_write_text(path, output.getvalue())


def _replay_into(pcap: str, db_path: str, arp_path: str, bl_path: str):
    """Replay *pcap* into an isolated DB with replay timestamps driving GC."""
    import config
    from storage.db import get_connection, init_db
    from engine.rules import RuleEngine
    from engine.blocklist import load_blocklist
    from capture.sniffer import replay_pcap

    config.SQLITE_PATH    = db_path
    config.ARP_TABLE_PATH = arp_path

    if os.path.exists(bl_path):
        blocklist = load_blocklist(bl_path, url=None)
    else:
        logger.warning(f"Blocklist missing '{bl_path}' — BLOCKLIST rule disabled.")
        from engine.blocklist import BlocklistData
        blocklist = BlocklistData(exact=set(), networks=[])

    conn = get_connection()
    init_db(conn)

    from evaluation.replay import create_replay_engine
    tracking_engine = create_replay_engine(conn, blocklist, config)

    logger.info(f"Replaying: {pcap}")
    replay_pcap(pcap, tracking_engine)
    tracking_engine.flush()
    stats = tracking_engine.engine._stats.copy()
    logger.info(f"Stats: {stats}")
    return stats


def _match(scenarios: list, alerts: list) -> tuple:
    matched: set = set()
    tp, fn = [], []
    for sc in scenarios:
        exp_rule  = sc.get("expected_rule", "").strip()
        exp_src   = sc.get("src_ip",  "").strip()
        exp_dst   = sc.get("dst_ip",  "").strip()
        exp_port_s = sc.get("dst_port","").strip()
        exp_port  = int(exp_port_s) if exp_port_s.isdigit() else None
        exp_proto = sc.get("protocol","").strip().upper()

        found = False
        for i, a in enumerate(alerts):
            if i in matched:
                continue
            if (
                (not exp_rule  or a.get("rule_name") == exp_rule)
                and (not exp_src   or a.get("src_ip")   == exp_src)
                and (not exp_dst   or a.get("dst_ip")   == exp_dst)
                and (exp_port is None or a.get("dst_port") == exp_port)
                and (not exp_proto or (a.get("protocol") or "").upper() == exp_proto)
            ):
                matched.add(i)
                tp.append((sc, a))
                found = True
                break
        if not found:
            fn.append(sc)

    fp = [a for i, a in enumerate(alerts) if i not in matched]
    return tp, fn, fp


def _report(attack_pcap, benign_pcap, labels_path, scenarios,
            tp, fn, fp_attack, benign_alerts) -> dict:
    W = 70
    rule_stats = {}
    for sc in scenarios:
        rule_stats.setdefault(sc["expected_rule"], {"tp": 0, "fn": 0})
    for sc, _ in tp:
        rule_stats[sc["expected_rule"]]["tp"] += 1
    for sc in fn:
        rule_stats[sc["expected_rule"]]["fn"] += 1

    benign_by_rule = {}
    for a in benign_alerts:
        r = a.get("rule_name", "?")
        benign_by_rule[r] = benign_by_rule.get(r, 0) + 1

    n           = len(scenarios)
    tp_n        = len(tp)
    fn_n        = len(fn)
    fp_attack_n = len(fp_attack)
    fp_benign_n = len(benign_alerts)
    # Precision includes ALL sources of spurious alerts so that benign FPs
    # properly degrade precision rather than being reported separately without
    # affecting the headline metric.
    total_alerts = tp_n + fp_attack_n + fp_benign_n
    prec = tp_n / total_alerts if total_alerts > 0 else 0.0
    rec  = tp_n / (tp_n + fn_n) if (tp_n + fn_n) > 0 else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

    sep  = "=" * W
    dash = "-" * W
    print()
    print(sep)
    print("  NETGUARD IDS — COMBINED EVALUATION REPORT  [SYNTHETIC SCENARIOS ONLY]")
    print(sep)
    print("  NOTE: All metrics derive from SYNTHETIC test fixtures.")
    print("        They do NOT represent real-world detection accuracy.")
    print(dash)
    print(f"  Run time    : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Attack PCAP : {attack_pcap}")
    print(f"  Benign PCAP : {benign_pcap}")
    print(f"  Labels CSV  : {labels_path}")
    print(dash)
    print("  ATTACK DETECTION (synthetic labelled scenarios)")
    print(dash)
    print(f"  Scenarios (labelled)               : {n:4d}")
    print(f"  True Positives (TP)                : {tp_n:4d}")
    print(f"  False Negatives (FN)               : {fn_n:4d}")
    print(f"  FP_attack (unmatched attack alerts): {fp_attack_n:4d}")
    print(f"  FP_benign (alerts on benign PCAP)  : {fp_benign_n:4d}")
    print(dash)
    print(f"  Precision [TP/(TP+FP_atk+FP_ben)]: {prec*100:5.1f}%")
    print(f"  Recall    [TP/(TP+FN)]            : {rec*100:5.1f}%")
    print(f"  F1                                : {f1*100:5.1f}%")
    print()
    print("  Per-rule breakdown (attack scenarios):")
    for rule, c in sorted(rule_stats.items()):
        t = c["tp"] + c["fn"]
        print(f"    {rule:<22s}  TP={c['tp']}/{t}  FN={c['fn']}/{t}")
    print()
    print(dash)
    print("  BENIGN TRAFFIC (False Positive Detail)")
    print(dash)
    print(f"  Total FP_benign alerts: {fp_benign_n}")
    if fp_benign_n == 0:
        print("  [OK] Zero false positives on benign traffic.")
    else:
        print("  [WARN] Benign traffic triggered alerts — tune thresholds:")
        for rule, cnt in sorted(benign_by_rule.items()):
            print(f"    {rule:<22s}  FP={cnt}")
        print()
        for a in benign_alerts[:5]:
            print(f"    [{a.get('rule_name')}] "
                  f"{a.get('src_ip')} → {a.get('dst_ip')}  "
                  f"{str(a.get('detail',''))[:50]}")
    print(sep)

    if fn:
        print("\n  Missed scenarios (FN):")
        for sc in fn:
            print(f"    [{sc.get('expected_rule')}] "
                  f"{sc.get('src_ip','?')}→{sc.get('dst_ip','?')}:{sc.get('dst_port','?')} "
                  f"  {sc.get('description','')[:40]}")

    if fp_attack:
        print("\n  FP_attack — unmatched attack alerts (investigate):")
        for a in fp_attack[:5]:
            print(f"    [{a.get('rule_name')}] "
                  f"{a.get('src_ip')}→{a.get('dst_ip')}:{a.get('dst_port','?')} "
                  f"  {str(a.get('detail',''))[:40]}")
    print()

    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "note": "All metrics are from SYNTHETIC test scenarios only.",
        "attack_pcap": attack_pcap, "benign_pcap": benign_pcap,
        "labels_path": labels_path,
        "scenarios": n, "tp": tp_n, "fn": fn_n,
        "fp_attack": fp_attack_n, "fp_benign": fp_benign_n,
        "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        "benign_fp_by_rule": benign_by_rule,
        "per_rule": {r: dict(c) for r, c in rule_stats.items()},
    }


def _determine_exit_code(fn: list, fp_attack: list, benign_alerts: list) -> int:
    """
    Return the appropriate process exit code.

    Exit 0 only when ALL of the following are true:
      - No missed attack scenarios (fn is empty)
      - No unmatched attack alerts (fp_attack is empty)
      - No false-positive alerts on benign traffic (benign_alerts is empty)

    Any violation → exit 1.  Setup errors → exit 2 (handled elsewhere).
    """
    if fn or fp_attack or benign_alerts:
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="NetGuard IDS — automated combined attack+benign evaluation"
    )
    parser.add_argument("--attack",      default=DEFAULT_ATTACK)
    parser.add_argument("--benign",      default=DEFAULT_BENIGN)
    parser.add_argument("--labels",      default=DEFAULT_LABELS)
    parser.add_argument("--blocklist",   default=DEFAULT_BLOCKLIST)
    parser.add_argument("--out-json",    default=None)
    parser.add_argument("--out-csv",     default=None,
                        help="Optional flat CSV of scenario outcomes and FP alerts")
    parser.add_argument("--no-generate", action="store_true",
                        help="Skip generating test fixtures")
    args = parser.parse_args()

    if not args.no_generate:
        if not os.path.exists(args.attack) or not os.path.exists(args.benign):
            logger.info("Fixtures missing — generating now...")
            import importlib, sys as _sys
            orig_cwd = os.getcwd()
            os.chdir(_IDS_ROOT)
            if "evaluation.generate_test_pcap" in _sys.modules:
                del _sys.modules["evaluation.generate_test_pcap"]
            from evaluation.generate_test_pcap import generate_all
            generate_all()
            os.chdir(orig_cwd)

    for path, name in [(args.attack, "attack PCAP"), (args.benign, "benign PCAP")]:
        if not os.path.exists(path):
            logger.error(f"{name} not found: {path}")
            sys.exit(2)

    scenarios = _load_labels(args.labels)

    # Fresh isolated state for every run
    attack_db  = _fresh_tmp_db()
    attack_arp = _fresh_tmp_arp()
    benign_db  = _fresh_tmp_db()
    benign_arp = _fresh_tmp_arp()
    logger.info(f"Attack DB  : {attack_db}")
    logger.info(f"Benign DB  : {benign_db}")

    try:
        logger.info("Phase 1/2: replaying attack PCAP ...")
        attack_stats = _replay_into(args.attack, attack_db, attack_arp, args.blocklist)

        logger.info("Phase 2/2: replaying benign PCAP ...")
        benign_stats = _replay_into(args.benign, benign_db, benign_arp, args.blocklist)

        attack_alerts = _read_alerts(attack_db)
        benign_alerts = _read_alerts(benign_db)
        logger.info(f"Attack alerts={len(attack_alerts)}, Benign alerts={len(benign_alerts)}")

        tp, fn, fp_attack = _match(scenarios, attack_alerts)
        result = _report(
            args.attack, args.benign, args.labels,
            scenarios, tp, fn, fp_attack, benign_alerts,
        )
        result["metadata"] = _run_metadata()
        result["scenario_results"] = _scenario_results(scenarios, tp, fn)
        result["unmatched_attack_alerts"] = [_alert_summary(a) for a in fp_attack]
        result["benign_alerts"] = [_alert_summary(a) for a in benign_alerts]
        result["replay_stats"] = {"attack": attack_stats, "benign": benign_stats}

        if args.out_json:
            _write_json(args.out_json, result)
            logger.info(f"JSON results → {args.out_json}")
        if args.out_csv:
            _write_csv(args.out_csv, result)
            logger.info(f"CSV results → {args.out_csv}")

        persistence_failed = False
        for capture_name, stats, alerts in (
            ("attack", attack_stats, attack_alerts),
            ("benign", benign_stats, benign_alerts),
        ):
            if (stats.get("alerts_dropped", 0) or stats.get("alerts_spooled", 0)
                    or stats.get("shutdown_timeout")
                    or stats.get("alert_writes", 0) != len(alerts)):
                logger.error(
                    "%s replay persistence incomplete: stats=%s, persisted_alerts=%d",
                    capture_name, stats, len(alerts),
                )
                persistence_failed = True
        if persistence_failed:
            sys.exit(2)

        # Exit 0 only when ALL three conditions are satisfied:
        #   no missed scenarios, no unmatched attack alerts, no benign FPs.
        if fn or fp_attack or benign_alerts:
            sys.exit(1)
        sys.exit(0)

    finally:
        for p in (attack_db, attack_arp, benign_db, benign_arp):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    main()
