"""
evaluation/compare.py
---------------------
Compare custom IDS alerts vs Suricata alerts for the same traffic.
Reads custom alerts from SQLite/PostgreSQL and Suricata eve.json,
then computes TP / FP / FN and prints a summary table.

Usage:
  python evaluation/compare.py --eve /tmp/suricata/eve.json

Prerequisite:
  Run replay.py first to populate the custom engine's alert database.
  Then run Suricata on the same .pcap:
    suricata -r capture.pcap -l /tmp/suricata/
"""

import sys
import os
import json
import argparse
import logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

import config
from storage.db import get_connection, read_all_alerts

# How close (seconds) two alerts must be to be considered the same event
TIMESTAMP_TOLERANCE = 5.0


def load_suricata_alerts(eve_path: str) -> list[dict]:
    """Parse eve.json and return list of alert dicts."""
    alerts = []
    with open(eve_path) as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                if event.get("event_type") == "alert":
                    ts_str = event.get("timestamp", "")
                    # Parse ISO timestamp → unix float
                    try:
                        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        ts = dt.timestamp()
                    except Exception:
                        ts = 0.0
                    alerts.append({
                        "timestamp":   ts,
                        "src_ip":      event.get("src_ip"),
                        "dst_ip":      event.get("dest_ip"),
                        "dst_port":    event.get("dest_port"),
                        "signature":   event.get("alert", {}).get("signature", ""),
                        "category":    event.get("alert", {}).get("category", ""),
                    })
            except json.JSONDecodeError:
                continue
    logging.info(f"Suricata alerts loaded: {len(alerts)}")
    return alerts


def match_alerts(custom: list[dict], suricata: list[dict]) -> dict:
    """
    Simple matching: two alerts match if src_ip and dst_ip agree
    and timestamps are within TIMESTAMP_TOLERANCE seconds.
    Returns counts of TP, FP, FN.
    """
    matched_suricata = set()
    true_positives = []
    false_positives = []

    for ca in custom:
        found = False
        for i, sa in enumerate(suricata):
            if i in matched_suricata:
                continue
            ip_match = (ca.get("src_ip") == sa.get("src_ip") and
                        ca.get("dst_ip") == sa.get("dst_ip"))
            time_diff = abs((ca.get("timestamp") or 0) - (sa.get("timestamp") or 0))
            if ip_match and time_diff <= TIMESTAMP_TOLERANCE:
                matched_suricata.add(i)
                true_positives.append((ca, sa))
                found = True
                break
        if not found:
            false_positives.append(ca)

    false_negatives = [sa for i, sa in enumerate(suricata) if i not in matched_suricata]

    return {
        "tp": true_positives,
        "fp": false_positives,
        "fn": false_negatives,
    }


def print_report(results: dict):
    tp = len(results["tp"])
    fp = len(results["fp"])
    fn = len(results["fn"])

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    print("\n" + "=" * 60)
    print("  IDS EVALUATION REPORT")
    print("=" * 60)
    print(f"  True Positives  (both detect):      {tp:4d}")
    print(f"  False Positives (custom only):       {fp:4d}")
    print(f"  False Negatives (Suricata only):     {fn:4d}")
    print("-" * 60)
    print(f"  Precision:   {precision * 100:.1f}%")
    print(f"  Recall:      {recall    * 100:.1f}%")
    print(f"  F1 Score:    {f1        * 100:.1f}%")
    print("=" * 60)

    if results["fp"]:
        print("\n  Top False Positives (tune thresholds for these):")
        for a in results["fp"][:5]:
            print(f"    [{a['rule_name']}] {a['src_ip']} → {a['dst_ip']}:{a.get('dst_port','?')}  {a.get('detail','')[:60]}")

    if results["fn"]:
        print("\n  Sample False Negatives (missed by custom engine):")
        for a in results["fn"][:5]:
            print(f"    {a['src_ip']} → {a['dst_ip']}  {a.get('signature','')[:60]}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Compare custom IDS vs Suricata")
    parser.add_argument("--eve", required=True, help="Path to Suricata eve.json")
    args = parser.parse_args()

    if not os.path.exists(args.eve):
        print(f"ERROR: {args.eve} not found")
        sys.exit(1)

    conn = get_connection()
    custom_alerts = read_all_alerts(conn)
    logging.info(f"Custom engine alerts: {len(custom_alerts)}")

    suricata_alerts = load_suricata_alerts(args.eve)
    results = match_alerts(custom_alerts, suricata_alerts)
    print_report(results)


if __name__ == "__main__":
    main()
