"""
ids_project/evaluation/threshold_sensitivity_study.py
-----------------------------------------------------
Reproducible empirical threshold sensitivity study for NetGuard IDS.

This study systematically measures the impact of numeric threshold perturbations
(-33%, -20%, -10%, baseline, +10%, +20%, +33%) on NetGuard's core stateful rate-based
detection rules:
  1. SYN_FLOOD (SynFloodRule, baseline threshold=100 pkts, window=10s)
  2. PORT_SCAN (PortScanRule, baseline threshold=15 ports, window=10s)
  3. SLOW_PORT_SCAN (SlowPortScanRule, baseline threshold=30 ports, window=120s)
  4. UDP_FLOOD (UdpFloodRule, baseline threshold=100 pkts, window=5s)

Methodological Scope and Transparency Note:
  - This evaluation measures parameter stability on calibration scenario datasets.
  - It assesses margin of safety against false positives and under-detection.
  - It applies exclusively to numeric rate/volume thresholds. Non-numeric rules
    (DPI signatures, L2 invariants, regex patterns, blocklists) have no numeric
    threshold to perturb and operate deterministically on exact pattern matches.
  - This is an empirical parameter sensitivity analysis, NOT a blind holdout proof
    of universal generalisation.
"""

import os
import sys
import json
import time
import argparse
import tempfile
import logging

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from storage.db import get_connection, init_db, read_all_alerts
from engine.blocklist import load_blocklist
from capture.sniffer import replay_pcap
from evaluation.replay import create_replay_engine
from engine.rules import (
    PortScanRule,
    SlowPortScanRule,
    SynFloodRule,
    UdpFloodRule,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("threshold_sensitivity")

DEFAULT_HDD_DIR = "/run/media/harshitgarg/Data1/NetGuard-datasets/verified"
DEFAULT_BL_PATH = os.path.join(PROJECT_DIR, "data", "test_blocklist.txt")
DEFAULT_ATTACK_PCAP = os.path.join(PROJECT_DIR, "data", "test_attacks.pcap")
DEFAULT_BENIGN_PCAP = os.path.join(PROJECT_DIR, "data", "test_benign.pcap")


def _read_alerts_from_db(db_path: str) -> list[dict]:
    import sqlite3
    if not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT rule_name, rule_version, src_ip, dst_ip, src_port, dst_port, "
            "protocol, detail, severity, confidence, evidence_json, timestamp "
            "FROM alerts ORDER BY timestamp"
        ).fetchall()]
        return rows
    except Exception as exc:
        logger.warning(f"Could not read alerts from {db_path}: {exc}")
        return []
    finally:
        conn.close()


def _run_rule_on_pcap(pcap_path: str, rule_instances: list, blocklist) -> list[dict]:
    """Execute isolated replay run for specific rule instances against a PCAP."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as db_f, \
         tempfile.NamedTemporaryFile(suffix=".json", delete=False) as arp_f:
        db_path = db_f.name
        arp_path = arp_f.name

    orig_sqlite = config.SQLITE_PATH
    orig_arp = config.ARP_TABLE_PATH
    config.SQLITE_PATH = db_path
    config.ARP_TABLE_PATH = arp_path

    try:
        conn = get_connection(db_path)
        init_db(conn)
        tracking_engine = create_replay_engine(conn, blocklist, config)
        # Override active rules with the test instances
        tracking_engine.engine.rules = rule_instances

        replay_pcap(pcap_path, tracking_engine)
        tracking_engine.flush()
        conn.close()

        alerts = _read_alerts_from_db(db_path)
        return alerts
    finally:
        config.SQLITE_PATH = orig_sqlite
        config.ARP_TABLE_PATH = orig_arp
        for p in (db_path, arp_path):
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except OSError:
                    pass


def run_sensitivity_study(data_dir: str = DEFAULT_HDD_DIR) -> dict:
    """Execute perturbation sweep across the 4 numeric rate rules."""
    blocklist = load_blocklist(DEFAULT_BL_PATH, url=None) if os.path.exists(DEFAULT_BL_PATH) else None

    # Identify test PCAPs
    pcap_nmap = os.path.join(data_dir, "ws_nmap_stealth_scan.pcap")
    pcap_http = os.path.join(data_dir, "ws_http_browsing.pcap")
    pcap_syn = os.path.join(data_dir, "oisf_syn_flood.pcap")
    pcap_udp = os.path.join(data_dir, "oisf_udp_flood.pcap")

    # Verify availability of PCAPs; if missing on external drive, look in local data dir
    if not os.path.isfile(pcap_http):
        pcap_http = DEFAULT_BENIGN_PCAP
    if not os.path.isfile(pcap_nmap):
        pcap_nmap = DEFAULT_ATTACK_PCAP
    if not os.path.isfile(pcap_syn):
        pcap_syn = DEFAULT_ATTACK_PCAP
    if not os.path.isfile(pcap_udp):
        pcap_udp = DEFAULT_ATTACK_PCAP

    results = {
        "metadata": {
            "study_title": "NetGuard IDS Numeric Rule Threshold Sensitivity Study",
            "evaluated_rules": ["SYN_FLOOD", "PORT_SCAN", "SLOW_PORT_SCAN", "UDP_FLOOD"],
            "perturbations_tested": ["-33%", "-20%", "-10%", "baseline", "+10%", "+20%", "+33%"],
            "data_source": "Calibration scenario PCAPs",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "scope_notes": (
                "Evaluates parameter margin of safety on numeric sliding-window rules. "
                "Non-numeric rules (DPI, L2 invariants, blocklists) are exempt from numeric perturbation."
            ),
        },
        "rules": {},
    }

    print("\n" + "=" * 70)
    print("  NETGUARD IDS — NUMERIC THRESHOLD SENSITIVITY STUDY")
    print("  Calibration PCAPs | Perturbations: -33% to +33%")
    print("=" * 70)

    # 1. PORT_SCAN (baseline=15, window=10s)
    # Scale factors: 0.67 (10), 0.80 (12), 0.90 (14), 1.0 (15), 1.10 (17), 1.20 (18), 1.33 (20)
    ps_thresholds = [10, 12, 14, 15, 17, 18, 20]
    ps_results = []
    print("\n[1/4] Evaluating PORT_SCAN (Baseline threshold=15, window=10s)")
    if os.path.isfile(pcap_nmap) and os.path.isfile(pcap_http):
        for th in ps_thresholds:
            pct_diff = round((th - 15) / 15 * 100)
            r = PortScanRule(threshold=th, window=10)
            alerts_benign = _run_rule_on_pcap(pcap_http, [r], blocklist)
            alerts_attack = _run_rule_on_pcap(pcap_nmap, [r], blocklist)
            detected = len(alerts_attack) > 0
            no_fp = len(alerts_benign) == 0
            status = "STABLE" if (detected and no_fp) else ("FP_RISK" if not no_fp else "DETECTION_DROPPED")
            entry = {
                "threshold": th,
                "perturbation": f"{pct_diff:+d}%",
                "benign_alerts_fp": len(alerts_benign),
                "attack_alerts_tp": len(alerts_attack),
                "status": status,
            }
            ps_results.append(entry)
            print(f"  Threshold {th:2d} ({pct_diff:+3d}%): TP={len(alerts_attack):2d}, FP={len(alerts_benign):2d} -> {status}")
    else:
        print("  Skipped: Required calibration PCAPs not found on path.")
    results["rules"]["PORT_SCAN"] = ps_results

    # 2. SLOW_PORT_SCAN (baseline=30, window=120s)
    # Scale factors: 0.67 (20), 0.80 (24), 0.90 (27), 1.0 (30), 1.10 (33), 1.20 (36), 1.33 (40)
    slow_thresholds = [20, 24, 27, 30, 33, 36, 40]
    slow_results = []
    print("\n[2/4] Evaluating SLOW_PORT_SCAN (Baseline threshold=30, window=120s)")
    if os.path.isfile(pcap_nmap) and os.path.isfile(pcap_http):
        for th in slow_thresholds:
            pct_diff = round((th - 30) / 30 * 100)
            r = SlowPortScanRule(threshold=th, window=120)
            alerts_benign = _run_rule_on_pcap(pcap_http, [r], blocklist)
            alerts_attack = _run_rule_on_pcap(pcap_nmap, [r], blocklist)
            detected = len(alerts_attack) > 0
            no_fp = len(alerts_benign) == 0
            status = "STABLE" if (detected and no_fp) else ("FP_RISK" if not no_fp else "DETECTION_DROPPED")
            entry = {
                "threshold": th,
                "perturbation": f"{pct_diff:+d}%",
                "benign_alerts_fp": len(alerts_benign),
                "attack_alerts_tp": len(alerts_attack),
                "status": status,
            }
            slow_results.append(entry)
            print(f"  Threshold {th:2d} ({pct_diff:+3d}%): TP={len(alerts_attack):2d}, FP={len(alerts_benign):2d} -> {status}")
    else:
        print("  Skipped: Required calibration PCAPs not found on path.")
    results["rules"]["SLOW_PORT_SCAN"] = slow_results

    # 3. SYN_FLOOD (baseline=100, window=10s)
    # Scale factors: 0.67 (67), 0.80 (80), 0.90 (90), 1.0 (100), 1.10 (110), 1.20 (120), 1.33 (133)
    syn_thresholds = [67, 80, 90, 100, 110, 120, 133]
    syn_results = []
    print("\n[3/4] Evaluating SYN_FLOOD (Baseline threshold=100, window=10s)")
    if os.path.isfile(pcap_syn) and os.path.isfile(pcap_http):
        for th in syn_thresholds:
            pct_diff = round((th - 100) / 100 * 100)
            r = SynFloodRule(threshold=th, window=10)
            alerts_benign = _run_rule_on_pcap(pcap_http, [r], blocklist)
            alerts_attack = _run_rule_on_pcap(pcap_syn, [r], blocklist)
            detected = len(alerts_attack) > 0
            no_fp = len(alerts_benign) == 0
            status = "STABLE" if (detected and no_fp) else ("FP_RISK" if not no_fp else "DETECTION_DROPPED")
            entry = {
                "threshold": th,
                "perturbation": f"{pct_diff:+d}%",
                "benign_alerts_fp": len(alerts_benign),
                "attack_alerts_tp": len(alerts_attack),
                "status": status,
            }
            syn_results.append(entry)
            print(f"  Threshold {th:3d} ({pct_diff:+3d}%): TP={len(alerts_attack):2d}, FP={len(alerts_benign):2d} -> {status}")
    else:
        print("  Skipped: Required calibration PCAPs not found on path.")
    results["rules"]["SYN_FLOOD"] = syn_results

    # 4. UDP_FLOOD (baseline=50, window=5s)
    # Scale factors: 0.67 (33), 0.80 (40), 0.90 (45), 1.0 (50), 1.10 (55), 1.20 (60), 1.33 (67)
    udp_thresholds = [33, 40, 45, 50, 55, 60, 67]
    udp_results = []
    print("\n[4/4] Evaluating UDP_FLOOD (Baseline threshold=50, window=5s)")
    if os.path.isfile(pcap_udp) and os.path.isfile(pcap_http):
        for th in udp_thresholds:
            pct_diff = round((th - 50) / 50 * 100)
            r = UdpFloodRule(threshold=th, window=5)
            alerts_benign = _run_rule_on_pcap(pcap_http, [r], blocklist)
            alerts_attack = _run_rule_on_pcap(pcap_udp, [r], blocklist)
            detected = any(a.get("rule_name") == "UDP_FLOOD" for a in alerts_attack)
            no_fp = not any(a.get("rule_name") == "UDP_FLOOD" for a in alerts_benign)
            status = "STABLE" if (detected and no_fp) else ("FP_RISK" if not no_fp else "DETECTION_DROPPED")
            entry = {
                "threshold": th,
                "perturbation": f"{pct_diff:+d}%",
                "benign_alerts_fp": len([a for a in alerts_benign if a.get("rule_name") == "UDP_FLOOD"]),
                "attack_alerts_tp": len([a for a in alerts_attack if a.get("rule_name") == "UDP_FLOOD"]),
                "status": status,
            }
            udp_results.append(entry)
            print(f"  Threshold {th:2d} ({pct_diff:+3d}%): TP={entry['attack_alerts_tp']:2d}, FP={entry['benign_alerts_fp']:2d} -> {status}")
    else:
        print("  Skipped: Required calibration PCAPs not found on path.")
    results["rules"]["UDP_FLOOD"] = udp_results

    print("\n" + "=" * 70)
    print("  STUDY COMPLETE: Numeric threshold sensitivity results recorded.")
    print("=" * 70 + "\n")

    return results


def main():
    parser = argparse.ArgumentParser(description="NetGuard IDS Numeric Rule Threshold Sensitivity Study")
    parser.add_argument("--data-dir", default=DEFAULT_HDD_DIR, help="Path to verified calibration PCAPs")
    parser.add_argument("--out", default=None, help="Optional output JSON path for results")
    args = parser.parse_args()

    results = run_sensitivity_study(args.data_dir)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"Saved results to {args.out}")


if __name__ == "__main__":
    main()
