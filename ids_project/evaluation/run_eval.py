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
import json
import logging
import os
import sqlite3
import sys
import tempfile
import time

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
    return rows


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

    # Shared mutable cell: updated by the wrapper as each packet is processed
    # so the GC thread reads replay time, not wall-clock time.
    _clock_state = [0.0]  # [0] = latest event_timestamp seen so far

    def _event_clock():
        return _clock_state[0]

    engine = RuleEngine(conn, blocklist, config, event_clock=_event_clock)

    # Thin wrapper that advances _clock_state before delegating to the engine.
    class _TrackingEngine:
        def check(self_, record: dict):  # noqa: N805
            ts = record.get("event_timestamp", record.get("timestamp", 0.0))
            if ts and ts > _clock_state[0]:
                _clock_state[0] = ts
            return engine.check(record)
        def flush(self_):  # noqa: N805
            return engine.flush()

    tracking_engine = _TrackingEngine()
    logger.info(f"Replaying: {pcap}")
    replay_pcap(pcap, tracking_engine)
    tracking_engine.flush()
    logger.info(f"Stats: {engine._stats}")


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
        _replay_into(args.attack, attack_db, attack_arp, args.blocklist)

        logger.info("Phase 2/2: replaying benign PCAP ...")
        _replay_into(args.benign, benign_db, benign_arp, args.blocklist)

        attack_alerts = _read_alerts(attack_db)
        benign_alerts = _read_alerts(benign_db)
        logger.info(f"Attack alerts={len(attack_alerts)}, Benign alerts={len(benign_alerts)}")

        tp, fn, fp_attack = _match(scenarios, attack_alerts)
        result = _report(
            args.attack, args.benign, args.labels,
            scenarios, tp, fn, fp_attack, benign_alerts,
        )

        if args.out_json:
            with open(args.out_json, "w") as f:
                json.dump(result, f, indent=2)
            logger.info(f"JSON results → {args.out_json}")

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
