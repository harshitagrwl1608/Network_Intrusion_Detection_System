"""
evaluation/compare.py
---------------------
Compare NetGuard IDS alerts vs Suricata alerts for the same traffic.

This script runs in two explicitly distinct modes (§3.10 of roadmap):

  --mode agreement  (default)
      Compares NetGuard and Suricata output using a documented match key.
      Reports agreement and disagreement — NOT ground-truth TP/FP/FN.
      Suricata is treated as a comparative baseline, NOT as ground truth.

  --mode ground-truth
      Compares NetGuard output against a labelled scenario CSV
      (see evaluation/scenarios/ for format).  This is the only mode
      that supports valid precision/recall/F1 interpretation.

Usage:
  # Engine-agreement comparison (no ground truth):
  python evaluation/compare.py --eve /tmp/suricata/eve.json

  # Ground-truth evaluation (requires a scenario labels CSV):
  python evaluation/compare.py \\
      --mode ground-truth \\
      --labels evaluation/scenarios/test_labels.csv

Prerequisite for agreement mode:
  Run replay.py first to populate the custom engine alert database.
  Then run Suricata on the same .pcap:
    suricata -r capture.pcap -l /tmp/suricata/

Match key (agreement mode):
  src_ip, dst_ip, dst_port, protocol (if available) and timestamp within
  TIMESTAMP_TOLERANCE seconds.  One Suricata event cannot match more than
  one NetGuard alert (bijective matching).

Interpretation note:
  An alert produced ONLY by NetGuard is a "NetGuard-only" event —
  NOT automatically a false positive.  An alert produced ONLY by Suricata
  is a "Suricata-only" event — NOT automatically a false negative.
  Different engines have different rules, thresholds and coverage.
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


def _get_conn(db_path: str | None = None):
    """Return a DB connection, optionally overriding the configured path."""
    if db_path:
        config.SQLITE_PATH = db_path
    return get_connection()


# ---------------------------------------------------------------------------
# Suricata eve.json loader
# ---------------------------------------------------------------------------

def load_suricata_alerts(eve_path: str) -> list[dict]:
    """Parse eve.json and return list of alert dicts."""
    alerts = []
    with open(eve_path) as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                if event.get("event_type") == "alert":
                    ts_str = event.get("timestamp", "")
                    try:
                        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        ts = dt.timestamp()
                    except Exception:
                        ts = 0.0
                    alerts.append({
                        "timestamp":  ts,
                        "src_ip":     event.get("src_ip"),
                        "dst_ip":     event.get("dest_ip"),
                        "src_port":   event.get("src_port"),
                        "dst_port":   event.get("dest_port"),
                        "protocol":   event.get("proto", "").upper(),
                        "signature":  event.get("alert", {}).get("signature", ""),
                        "category":   event.get("alert", {}).get("category", ""),
                        "severity":   event.get("alert", {}).get("severity"),
                    })
            except json.JSONDecodeError:
                continue
    logging.info(f"Suricata alerts loaded: {len(alerts)}")
    return alerts


# ---------------------------------------------------------------------------
# Matching helper
# ---------------------------------------------------------------------------

def _events_match(a: dict, b: dict, tolerance: float = TIMESTAMP_TOLERANCE) -> bool:
    """
    Two events match if src_ip, dst_ip and dst_port agree AND timestamps
    are within tolerance.  Protocol is included when both sides provide it.
    """
    if a.get("src_ip") != b.get("src_ip"):
        return False
    if a.get("dst_ip") != b.get("dst_ip"):
        return False
    # Threshold rules aggregate packets across multiple destination ports, so
    # the final packet that crosses the threshold can differ between engines.
    # Compare those known scan families at host-pair scope; keep exact 5-tuples
    # for every other alert type.
    family_a = _scan_family(a)
    family_b = _scan_family(b)
    semantic_scan_match = family_a is not None and family_a == family_b
    if not semantic_scan_match and a.get("dst_port") != b.get("dst_port"):
        return False
    # Protocol check only when both sides have a non-empty value
    proto_a = (a.get("protocol") or "").upper()
    proto_b = (b.get("protocol") or "").upper()
    if proto_a and proto_b and proto_a != proto_b:
        return False
    time_diff = abs((a.get("timestamp") or 0) - (b.get("timestamp") or 0))
    allowed_time = max(tolerance, 120.0 if family_a == "slow_tcp_scan" else 10.0) if semantic_scan_match else tolerance
    return time_diff <= allowed_time


def _scan_family(event: dict) -> str | None:
    """Normalize the paired TCP scan rules used by NetGuard and local Suricata."""
    rule = str(event.get("rule_name") or "").upper()
    signature = str(event.get("signature") or "").lower()
    if rule == "SLOW_PORT_SCAN" or "local slow tcp syn burst" in signature:
        return "slow_tcp_scan"
    if rule == "PORT_SCAN" or "local tcp syn scan-like burst" in signature:
        return "tcp_scan"
    return None


# ---------------------------------------------------------------------------
# Agreement mode (§3.10)
# ---------------------------------------------------------------------------

def match_alerts_agreement(netguard: list[dict], suricata: list[dict]) -> dict:
    """
    Bijective matching: each Suricata event can match at most one NetGuard alert.
    Returns structured agreement/disagreement lists — NOT TP/FP/FN in the
    ground-truth sense.
    """
    matched_suricata: set = set()
    both: list = []          # matched in both engines
    netguard_only: list = [] # NetGuard fired, Suricata did not (on same event)
    suricata_only: list = [] # Suricata fired, NetGuard did not (on same event)

    for ng in netguard:
        found = False
        for i, sur in enumerate(suricata):
            if i in matched_suricata:
                continue
            if _events_match(ng, sur):
                matched_suricata.add(i)
                both.append((ng, sur))
                found = True
                break
        if not found:
            netguard_only.append(ng)

    for i, sur in enumerate(suricata):
        if i not in matched_suricata:
            suricata_only.append(sur)

    return {
        "both": both,
        "netguard_only": netguard_only,
        "suricata_only": suricata_only,
    }


def print_agreement_report(results: dict):
    both          = len(results["both"])
    ng_only       = len(results["netguard_only"])
    sur_only      = len(results["suricata_only"])
    total_ng      = both + ng_only
    total_sur     = both + sur_only

    agreement_pct = both / max(total_ng, total_sur, 1) * 100

    print("\n" + "=" * 65)
    print("  ENGINE AGREEMENT REPORT  (NetGuard vs Suricata)")
    print("  NOTE: Suricata is a COMPARISON BASELINE, not ground truth.")
    print("  'NetGuard-only' events are NOT automatically false positives.")
    print("  'Suricata-only' events are NOT automatically missed attacks.")
    print("=" * 65)
    print(f"  NetGuard total alerts:       {total_ng:4d}")
    print(f"  Suricata total alerts:       {total_sur:4d}")
    print(f"  Matched by both engines:     {both:4d}")
    print(f"  NetGuard-only:               {ng_only:4d}")
    print(f"  Suricata-only:               {sur_only:4d}")
    print(f"  Agreement rate:              {agreement_pct:.1f}%")
    print("-" * 65)
    print("  Match key: exact events Δt≤5s; recognized TCP scan families use host pair and rule window")
    print("=" * 65)

    if results["netguard_only"]:
        print("\n  NetGuard-only events (investigate for FP potential):")
        for a in results["netguard_only"][:5]:
            print(
                f"    [{a.get('rule_name','?')}] "
                f"{a.get('src_ip')} → {a.get('dst_ip')}:{a.get('dst_port','?')} "
                f"  {str(a.get('detail',''))[:55]}"
            )

    if results["suricata_only"]:
        print("\n  Suricata-only events (investigate for coverage gaps):")
        for a in results["suricata_only"][:5]:
            print(
                f"    {a.get('src_ip')} → {a.get('dst_ip')}:{a.get('dst_port','?')} "
                f"  {str(a.get('signature',''))[:55]}"
            )
    print()


# ---------------------------------------------------------------------------
# Ground-truth mode (§3.10)
# ---------------------------------------------------------------------------

def run_ground_truth(labels_path: str, db_path: str | None = None):
    """
    Compare NetGuard alerts against a labelled scenario CSV.

    CSV schema (generated by generate_test_pcap.py):
      scenario_id, expected_rule, src_ip, dst_ip, dst_port, protocol,
      description

    Matching uses all non-empty columns.  One alert can match at most one
    scenario (bijective). A scenario without a matching alert is a FN;
    an alert without a matching scenario is a potential FP.
    """
    import csv

    conn = _get_conn(db_path)
    alerts = read_all_alerts(conn)
    if not alerts:
        print("WARNING: No alerts found in database. Did you run replay first?")

    try:
        with open(labels_path, newline="") as f:
            reader = csv.DictReader(f)
            scenarios = list(reader)
            # Assert required columns are present
            required = {"scenario_id", "expected_rule"}
            if scenarios:
                missing = required - set(scenarios[0].keys())
                if missing:
                    print(f"ERROR: labels CSV is missing required columns: {missing}")
                    sys.exit(1)
    except FileNotFoundError:
        print(f"ERROR: labels file not found: {labels_path}")
        sys.exit(1)

    print("\n" + "=" * 65)
    print("  GROUND-TRUTH EVALUATION REPORT")
    if db_path:
        print(f"  Database: {db_path}")
    print("=" * 65)

    matched_alerts: set = set()
    tp_scenarios: list = []
    fn_scenarios: list = []

    for sc in scenarios:
        expected_rule = sc.get("expected_rule", "").strip()
        exp_src   = sc.get("src_ip", "").strip()
        exp_dst   = sc.get("dst_ip", "").strip()
        exp_port_str = sc.get("dst_port", "").strip()
        exp_port  = int(exp_port_str) if exp_port_str.isdigit() else None
        exp_proto = sc.get("protocol", "").strip().upper()

        found = False
        for i, alert in enumerate(alerts):
            if i in matched_alerts:
                continue
            # Match on all non-empty label fields (not rule name alone)
            rule_match  = (not expected_rule or
                           alert.get("rule_name") == expected_rule)
            src_match   = (not exp_src   or alert.get("src_ip")   == exp_src)
            dst_match   = (not exp_dst   or alert.get("dst_ip")   == exp_dst)
            port_match  = (exp_port is None or
                           alert.get("dst_port") == exp_port)
            proto_match = (not exp_proto or
                           (alert.get("protocol") or "").upper() == exp_proto)
            if rule_match and src_match and dst_match and port_match and proto_match:
                matched_alerts.add(i)
                tp_scenarios.append((sc, alert))
                found = True
                break
        if not found:
            fn_scenarios.append(sc)

    fp_alerts = [a for i, a in enumerate(alerts) if i not in matched_alerts]

    tp = len(tp_scenarios)
    fp = len(fp_alerts)
    fn = len(fn_scenarios)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) \
                if (precision + recall) > 0 else 0.0

    print(f"  Scenarios (labelled expected):        {len(scenarios):4d}")
    print(f"  Detected  (TP — scenario matched):    {tp:4d}")
    print(f"  Missed    (FN — no matching alert):   {fn:4d}")
    print(f"  Extra     (FP — no matching scenario):{fp:4d}")
    print("-" * 65)
    print(f"  Precision:   {precision * 100:.1f}%")
    print(f"  Recall:      {recall    * 100:.1f}%")
    print(f"  F1 Score:    {f1        * 100:.1f}%")
    print("  NOTE: metrics are ground-truth only when scenario labels")
    print("        match concrete event attributes (src/dst/port/protocol).")
    print("=" * 65)

    if fn_scenarios:
        print("\n  Missed scenarios (FN):")
        for sc in fn_scenarios[:5]:
            print(f"    [{sc.get('expected_rule')}] "
                  f"{sc.get('src_ip')} → {sc.get('dst_ip')}:{sc.get('dst_port')} "
                  f"  {sc.get('description','')[:40]}")

    if fp_alerts:
        print("\n  Unmatched NetGuard alerts (potential FP — investigate):")
        for a in fp_alerts[:5]:
            print(f"    [{a.get('rule_name')}] "
                  f"{a.get('src_ip')} → {a.get('dst_ip')}:{a.get('dst_port','?')} "
                  f"  {str(a.get('detail',''))[:40]}")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="NetGuard — compare with Suricata (agreement) or labelled scenarios (ground-truth)"
    )
    parser.add_argument(
        "--mode",
        choices=["agreement", "ground-truth"],
        default="agreement",
        help=(
            "agreement: compare NetGuard vs Suricata output (default). "
            "ground-truth: compare against a labelled scenario CSV."
        ),
    )
    parser.add_argument(
        "--eve",
        help="Path to Suricata eve.json (required for agreement mode)",
    )
    parser.add_argument(
        "--labels",
        help="Path to labelled scenario CSV (required for ground-truth mode)",
    )
    parser.add_argument(
        "--db",
        default=None,
        help=(
            "SQLite database path to read NetGuard alerts from. "
            "Must match the --db path used during replay for isolated evaluation. "
            "Defaults to config.SQLITE_PATH when not provided."
        ),
    )
    args = parser.parse_args()

    if args.mode == "ground-truth":
        if not args.labels:
            print("ERROR: --labels is required for ground-truth mode")
            sys.exit(1)
        run_ground_truth(args.labels, db_path=args.db)
        return

    # Agreement mode (default)
    if not args.eve:
        print("ERROR: --eve is required for agreement mode")
        sys.exit(1)
    if not os.path.exists(args.eve):
        print(f"ERROR: {args.eve} not found")
        sys.exit(1)

    conn = _get_conn(args.db)
    netguard_alerts = read_all_alerts(conn)
    logging.info(f"NetGuard alerts: {len(netguard_alerts)}")

    suricata_alerts = load_suricata_alerts(args.eve)
    results = match_alerts_agreement(netguard_alerts, suricata_alerts)
    print_agreement_report(results)


if __name__ == "__main__":
    main()
