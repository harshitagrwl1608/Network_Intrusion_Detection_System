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
import ipaddress
import logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

import config
from storage.db import get_connection, read_all_alerts

# How close (seconds) two alerts must be to be considered the same event
TIMESTAMP_TOLERANCE = 5.0


def _norm_ip(ip) -> str:
    """Normalize IPv4/IPv6 string representation, stripping spaces and canonicalizing format."""
    if ip is None:
        return ""
    s = str(ip).strip()
    if not s:
        return ""
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return s


def _norm_port(port) -> int | None:
    """Normalize integer/string port to 0-65535 int or None."""
    if port is None:
        return None
    try:
        val = int(port)
        return val if 0 <= val <= 65535 else None
    except (ValueError, TypeError):
        return None


def _get_conn(db_path: str | None = None):
    """Return a DB connection without modifying global config.SQLITE_PATH."""
    return get_connection(db_path=db_path)


# ---------------------------------------------------------------------------
# Suricata eve.json loader
# ---------------------------------------------------------------------------

def load_suricata_alerts(eve_path: str) -> list[dict]:
    """Parse eve.json and return list of alert dicts."""
    alerts = []
    with open(eve_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                event = json.loads(line_str)
                if not isinstance(event, dict):
                    continue
                if event.get("event_type") == "alert":
                    alert_obj = event.get("alert")
                    if not isinstance(alert_obj, dict):
                        alert_obj = {}
                    ts_raw = event.get("timestamp")
                    ts = 0.0
                    if isinstance(ts_raw, (int, float)):
                        ts = float(ts_raw)
                    elif isinstance(ts_raw, str) and ts_raw.strip():
                        ts_str = ts_raw.strip()
                        try:
                            cleaned_ts = ts_str.replace("Z", "+00:00")
                            if len(cleaned_ts) >= 5 and cleaned_ts[-5] in ("+", "-") and cleaned_ts[-3] != ":":
                                cleaned_ts = cleaned_ts[:-2] + ":" + cleaned_ts[-2:]
                            dt = datetime.fromisoformat(cleaned_ts)
                            ts = dt.timestamp()
                        except Exception:
                            try:
                                ts = float(ts_str)
                            except Exception:
                                ts = 0.0

                    src_ip = _norm_ip(event.get("src_ip"))
                    dst_ip = _norm_ip(event.get("dest_ip") or event.get("dst_ip"))
                    src_port = _norm_port(event.get("src_port"))
                    dst_port = _norm_port(event.get("dest_port") or event.get("dst_port"))
                    proto = str(event.get("proto") or "").strip().upper()
                    sig = str(alert_obj.get("signature") or "").strip()
                    cat = str(alert_obj.get("category") or "").strip()
                    sev = alert_obj.get("severity")
                    app_proto = str(event.get("app_proto") or "").strip().lower()
                    flow_id = event.get("flow_id")

                    alerts.append({
                        "timestamp":  ts,
                        "src_ip":     src_ip,
                        "dst_ip":     dst_ip,
                        "src_port":   src_port,
                        "dst_port":   dst_port,
                        "protocol":   proto,
                        "signature":  sig,
                        "category":   cat,
                        "severity":   sev,
                        "app_proto":  app_proto,
                        "flow_id":    flow_id,
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
    src_a = _norm_ip(a.get("src_ip"))
    src_b = _norm_ip(b.get("src_ip"))
    if not src_a or not src_b or src_a != src_b:
        return False
    dst_a = _norm_ip(a.get("dst_ip"))
    dst_b = _norm_ip(b.get("dst_ip"))
    if not dst_a or not dst_b or dst_a != dst_b:
        return False
    # Threshold rules aggregate packets across multiple destination ports, so
    # the final packet that crosses the threshold can differ between engines.
    # Compare those known scan families at host-pair scope; keep exact 5-tuples
    # for every other alert type.
    family_a = _scan_family(a)
    family_b = _scan_family(b)
    semantic_scan_match = family_a is not None and family_a == family_b
    port_a = _norm_port(a.get("dst_port"))
    port_b = _norm_port(b.get("dst_port"))
    # Protocol check only when both sides provide a non-empty value
    proto_a = (a.get("protocol") or "").strip().upper()
    proto_b = (b.get("protocol") or "").strip().upper()
    if proto_a and proto_b and proto_a != proto_b:
        return False
    if proto_a == "ICMP" or proto_b == "ICMP":
        # ICMP does not have transport layer ports; treat None and 0 as equivalent
        if port_a in (None, 0) and port_b in (None, 0):
            pass
        elif port_a != port_b:
            return False
    elif not semantic_scan_match and port_a != port_b:
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
    if rule == "PORT_SCAN" or "local tcp syn scan-like burst" in signature or "potential port scan" in signature:
        return "tcp_scan"
    if rule in ("TCP_FLAG_ANOMALY", "TCP_STEALTH_SCAN") or "nmap" in signature or "tcp flag combination" in signature:
        return "tcp_stealth_scan"
    return None


def _semantic_family(event: dict) -> str | None:
    """Map only event families with a defensible cross-engine interpretation."""
    scan = _scan_family(event)
    if scan:
        return scan
    rule = str(event.get("rule_name") or "").upper()
    signature = str(event.get("signature") or "").lower()
    detail = str(event.get("detail") or "").lower()
    evidence_obj = event.get("evidence")
    evidence_str = (str(event.get("evidence_json") or "") + " " + str(evidence_obj or "")).lower()
    port = _norm_port(event.get("dst_port"))

    if rule == "CLEAR_HTTP_ON_TLS_PORT":
        return "cleartext_http_on_tls_port"
    if port in (443, 8443) and (signature.startswith("suricata http") or "http request missing protocol" in signature):
        return "cleartext_http_on_tls_port"

    # Web payload attack families (independently observable in HTTP/TCP stream payloads)
    if rule == "PAYLOAD_HIT":
        if "sql_injection" in detail or "sql_injection" in evidence_str:
            return "sql_injection"
        if "cmd_injection" in detail or "cmd_injection" in evidence_str or "shellshock" in detail or "shellshock" in evidence_str:
            return "command_injection"
        if "log4shell" in detail or "log4shell" in evidence_str:
            return "log4shell"
        if "path_traversal" in detail or "path_traversal" in evidence_str:
            return "path_traversal"
        if "xss" in detail or "xss" in evidence_str:
            return "xss"
        if "ssrf" in detail or "ssrf" in evidence_str:
            return "ssrf"
        if "ics_tristation_exploit" in detail or "ics_tristation_exploit" in evidence_str or "tristation" in detail:
            return "ics_scada_exploit"
    if "sql injection" in signature or "sqli" in signature:
        return "sql_injection"
    if "command injection" in signature or "cmd injection" in signature or "shellshock" in signature:
        return "command_injection"
    if "log4j" in signature or "log4shell" in signature or "cve-2021-44228" in signature:
        return "log4shell"
    if "path traversal" in signature or "directory traversal" in signature:
        return "path_traversal"
    if "cross-site scripting" in signature or "cross site scripting" in signature or "xss" in signature:
        return "xss"
    if "ssrf" in signature or "cloud metadata" in signature:
        return "ssrf"
    if any(k in signature for k in ["tristation", "triconex", "triton", "trisis", "modbus", "dnp3", "cip"]):
        return "ics_scada_exploit"

    # Authentication brute-force
    if rule == "BRUTE_FORCE" or "brute force" in signature or "bruteforce" in signature or "login attempt" in signature:
        return "brute_force"

    # TCP Zero-Window anomalies
    if rule == "TCP_ZERO_WINDOW" or "zero window" in signature or "sockstress" in signature:
        return "tcp_zero_window"

    # Flood families (network packet rate / count anomalies)
    if rule in ("SYN_FLOOD", "DISTRIBUTED_SYN_FLOOD") or "syn flood" in signature:
        return "syn_flood"
    if rule == "UDP_FLOOD" or "udp flood" in signature:
        return "udp_flood"
    if rule == "ICMP_FLOOD" or "icmp flood" in signature or "echo flood" in signature:
        return "icmp_flood"
    if rule == "ICMP_SWEEP" or "icmp sweep" in signature or "ping sweep" in signature:
        return "icmp_sweep"

    # Covert Data Exfiltration & Tunneling
    if rule == "ICMP_TUNNEL" or (rule == "DATA_EXFIL" and (event.get("protocol") or "").strip().upper() == "ICMP"):
        return "icmp_tunnel"
    if "icmp tunnel" in signature or "suspicious icmp" in signature or "icmp payload" in signature:
        return "icmp_tunnel"
    if rule == "DATA_EXFIL" or "data exfiltration" in signature or "exfiltration" in signature:
        return "data_exfil"
    if rule == "NON_DNS_TRAFFIC_ON_DNS_PORT" or ("dns" in signature and any(k in signature for k in ["non-dns", "shell", "not dns", "non dns"])):
        return "non_dns_on_dns_port"

    # Threat Intelligence & Host Anomalies
    if rule == "BLOCKLIST" or any(k in signature for k in ["drop listed", "threat intelligence", "compromised host", "reputation"]):
        return "blocklist_threat_intel"
    if rule == "ARP_SPOOF" or "arp spoof" in signature or "arp cache poisoning" in signature:
        return "arp_spoof"
    if rule == "IRC_C2_BEACONING" or any(k in signature for k in ["irc ", "irc pong", "irc user", "irc nick", "irc c2", "botnet"]):
        return "botnet_c2"
    if rule == "IP_FRAGMENT_ANOMALY" or any(k in signature for k in ["teardrop", "fragment overlap", "tiny fragment", "oversized fragment", "ping of death"]):
        return "ip_fragment_anomaly"
    if any(k in signature for k in ["executable", "elf file download", "malware download"]):
        return "malicious_binary_transfer"

    # DNS tunneling / exfiltration / DGA
    if rule == "DNS_ANOMALY":
        if any(k in detail or k in evidence_str for k in ["dns_tunnel", "dns_exfil"]):
            return "dns_tunnel"
        if any(k in detail or k in evidence_str for k in ["dns_dga", "dga"]):
            return "dns_dga"
        return "dns_anomaly"
    if "dns tunnel" in signature or "dns exfiltration" in signature:
        return "dns_tunnel"
    if "dns dga" in signature:
        return "dns_dga"
    if "dns" in signature and any(k in signature for k in ["entropy", "suspicious", "anomalous"]):
        return "dns_anomaly"

    # TLS anomalies
    if rule == "TLS_ANOMALY" or ("tls" in signature and ("sni" in signature or "certificate" in signature)):
        return "tls_anomaly"

    return None


def _endpoint_correlations(netguard: list[dict], suricata: list[dict]) -> list[dict]:
    """Summarize mapped family overlap by endpoint, deliberately ignoring time.

    This is a review aid for engines that aggregate or timestamp parser findings
    differently. It does not change exact event matches or the agreement rate.
    """
    def collect(events):
        counts = {}
        for event in events:
            family = _semantic_family(event)
            if not family:
                continue
            protocol = str(event.get("protocol") or "").strip().upper()
            port = _norm_port(event.get("dst_port"))
            src_ip = _norm_ip(event.get("src_ip"))
            dst_ip = _norm_ip(event.get("dst_ip"))
            key = (family, src_ip, dst_ip, port, protocol)
            counts[key] = counts.get(key, 0) + 1
        return counts

    ng_counts = collect(netguard)
    sur_counts = collect(suricata)
    shared = []
    for key in ng_counts.keys() & sur_counts.keys():
        family, src_ip, dst_ip, dst_port, protocol = key
        shared.append({
            "family": family, "src_ip": src_ip, "dst_ip": dst_ip,
            "dst_port": dst_port, "protocol": protocol,
            "netguard_events": ng_counts[key],
            "suricata_events": sur_counts[key],
        })
    return sorted(
        shared,
        key=lambda row: (
            row["family"], str(row["src_ip"]), str(row["dst_ip"]),
            row["dst_port"] or 0,
        ),
    )


# ---------------------------------------------------------------------------
# Agreement mode (§3.10)
# ---------------------------------------------------------------------------

def match_alerts_agreement(netguard: list[dict], suricata: list[dict]) -> dict:
    """
    Bijective matching: each Suricata event can match at most one NetGuard alert.
    Delineates:
      - Exact 5-tuple event matches (Δt <= 5s, same src, dst, port, protocol).
      - Semantic scan-family matches (host-pair scope, rule-specific window).
      - Endpoint-family overlaps (family matches between endpoints, timestamps not aligned).
      - NetGuard-only alerts.
      - Suricata-only alerts.
    Returns structured agreement/disagreement lists — NOT TP/FP/FN in the
    ground-truth sense.
    """
    matched_suricata: set = set()
    exact_5tuple_matches: list = []
    semantic_scan_matches: list = []
    both: list = []          # all matched (exact + semantic scan)
    netguard_only: list = [] # NetGuard fired, Suricata did not (on same event)
    suricata_only: list = [] # Suricata fired, NetGuard did not (on same event)

    for ng in netguard:
        found = False
        for i, sur in enumerate(suricata):
            if i in matched_suricata:
                continue
            if _events_match(ng, sur):
                matched_suricata.add(i)
                found = True
                family_a = _scan_family(ng)
                family_b = _scan_family(sur)
                is_scan = (family_a is not None and family_a == family_b)
                port_a = _norm_port(ng.get("dst_port"))
                port_b = _norm_port(sur.get("dst_port"))
                time_diff = abs((ng.get("timestamp") or 0) - (sur.get("timestamp") or 0))

                if is_scan and (port_a != port_b or time_diff > TIMESTAMP_TOLERANCE):
                    semantic_scan_matches.append((ng, sur))
                else:
                    exact_5tuple_matches.append((ng, sur))
                both.append((ng, sur))
                break
        if not found:
            netguard_only.append(ng)

    for i, sur in enumerate(suricata):
        if i not in matched_suricata:
            suricata_only.append(sur)

    return {
        "both": both,
        "exact_5tuple_matches": exact_5tuple_matches,
        "semantic_scan_matches": semantic_scan_matches,
        "netguard_only": netguard_only,
        "suricata_only": suricata_only,
        "endpoint_correlations": _endpoint_correlations(netguard, suricata),
    }


def print_agreement_report(results: dict):
    both          = len(results["both"])
    exact         = len(results.get("exact_5tuple_matches", []))
    scan_matches  = len(results.get("semantic_scan_matches", []))
    ng_only       = len(results["netguard_only"])
    sur_only      = len(results["suricata_only"])
    total_ng      = both + ng_only
    total_sur     = both + sur_only

    exact_pct     = exact / max(total_ng, total_sur, 1) * 100
    overall_pct   = both / max(total_ng, total_sur, 1) * 100

    print("\n" + "=" * 65)
    print("  ENGINE AGREEMENT REPORT  (NetGuard vs Suricata)")
    print("  NOTE: Suricata is a COMPARISON BASELINE, not ground truth.")
    print("  'NetGuard-only' events are NOT automatically false positives.")
    print("  'Suricata-only' events are NOT automatically missed attacks.")
    print("=" * 65)
    print(f"  NetGuard total alerts:          {total_ng:4d}")
    print(f"  Suricata total alerts:          {total_sur:4d}")
    print(f"  Exact 5-tuple event matches:    {exact:4d}")
    print(f"  Semantic scan-family matches:   {scan_matches:4d}")
    print(f"  Matched by both engines:        {both:4d}")
    print(f"  NetGuard-only:                  {ng_only:4d}")
    print(f"  Suricata-only:                  {sur_only:4d}")
    print(f"  Exact 5-tuple agreement rate:   {exact_pct:.1f}%")
    print(f"  Overall agreement rate:         {overall_pct:.1f}%")
    print("-" * 65)
    print("  Match key: exact events Δt≤5s; recognized TCP scan families use host pair and rule window")
    print("  Endpoint correlations ignore time and do not affect agreement rate.")
    correlations = results.get("endpoint_correlations", [])
    if correlations:
        print("  Shared mapped endpoint families:")
        for row in correlations[:10]:
            print(
                f"    [{row['family']}] {row['src_ip']} → {row['dst_ip']}:{row['dst_port']} "
                f"({row['protocol'] or '?'}) — NetGuard {row['netguard_events']}, "
                f"Suricata {row['suricata_events']} event(s); timestamps not matched"
            )
    else:
        print("  Shared mapped endpoint families: 0")
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
# Zeek conn.log loader & cross-telemetry corroboration (§3.10)
# ---------------------------------------------------------------------------

def load_zeek_connections(conn_path: str, max_records: int | None = None) -> list[dict]:
    """Parse Zeek conn.log (supports TSV with #fields header or JSON lines)."""
    records = []
    fields = None
    with open(conn_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue

            # JSON format detection
            if line_str.startswith("{") and line_str.endswith("}"):
                try:
                    obj = json.loads(line_str)
                    if isinstance(obj, dict):
                        ts = float(obj.get("ts", 0.0) or 0.0)
                        src_ip = _norm_ip(obj.get("id.orig_h") or obj.get("src_ip"))
                        dst_ip = _norm_ip(obj.get("id.resp_h") or obj.get("dst_ip"))
                        src_port = _norm_port(obj.get("id.orig_p") or obj.get("src_port"))
                        dst_port = _norm_port(obj.get("id.resp_p") or obj.get("dst_port"))
                        proto = str(obj.get("proto") or "").strip().upper()
                        service = str(obj.get("service") or "").strip()
                        state = str(obj.get("conn_state") or "").strip()
                        history = str(obj.get("history") or "").strip()
                        orig_bytes = int(obj.get("orig_bytes") or 0) if str(obj.get("orig_bytes") or "").isdigit() else 0
                        resp_bytes = int(obj.get("resp_bytes") or 0) if str(obj.get("resp_bytes") or "").isdigit() else 0
                        orig_pkts = int(obj.get("orig_pkts") or 0) if str(obj.get("orig_pkts") or "").isdigit() else 0
                        label = str(obj.get("label") or "").strip()
                        uid = str(obj.get("uid") or "").strip()
                        if not uid:
                            uid = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{proto}@{ts}"
                        records.append({
                            "timestamp": ts, "src_ip": src_ip, "dst_ip": dst_ip,
                            "src_port": src_port, "dst_port": dst_port, "protocol": proto,
                            "service": service, "conn_state": state, "history": history,
                            "orig_bytes": orig_bytes, "resp_bytes": resp_bytes,
                            "orig_pkts": orig_pkts, "label": label, "uid": uid,
                        })
                except Exception:
                    continue
                if max_records and len(records) >= max_records:
                    break
                continue

            # Standard TSV format with #fields header
            if line_str.startswith("#fields"):
                raw_fields = line_str.split("\t")[1:]
                fields = []
                for rf in raw_fields:
                    if " " in rf:
                        fields.extend([f.strip() for f in rf.split() if f.strip()])
                    else:
                        fields.append(rf)
                continue
            if line_str.startswith("#"):
                continue
            if not fields:
                continue

            parts = line_str.split("\t")
            if len(parts) < len(fields) and parts:
                last = parts.pop()
                parts.extend(last.split())
            if len(parts) < len(fields):
                continue
            row = dict(zip(fields, parts))

            def _clean_val(v):
                return "" if v in ("-", "(empty)", None) else str(v).strip()

            def _to_float(v):
                c = _clean_val(v)
                try:
                    return float(c) if c else 0.0
                except (ValueError, TypeError):
                    return 0.0

            def _to_int(v):
                c = _clean_val(v)
                try:
                    return int(c) if c else 0
                except (ValueError, TypeError):
                    return 0

            ts = _to_float(row.get("ts"))
            src_ip = _norm_ip(_clean_val(row.get("id.orig_h")))
            dst_ip = _norm_ip(_clean_val(row.get("id.resp_h")))
            src_port = _norm_port(_clean_val(row.get("id.orig_p")))
            dst_port = _norm_port(_clean_val(row.get("id.resp_p")))
            proto = _clean_val(row.get("proto")).upper()
            service = _clean_val(row.get("service"))
            state = _clean_val(row.get("conn_state"))
            history = _clean_val(row.get("history"))
            orig_bytes = _to_int(row.get("orig_bytes"))
            resp_bytes = _to_int(row.get("resp_bytes"))
            orig_pkts = _to_int(row.get("orig_pkts"))
            label = _clean_val(row.get("label"))
            detailed_label = _clean_val(row.get("detailed-label"))
            uid = _clean_val(row.get("uid"))
            if not uid:
                uid = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{proto}@{ts}"

            records.append({
                "timestamp": ts, "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port, "protocol": proto,
                "service": service, "conn_state": state, "history": history,
                "orig_bytes": orig_bytes, "resp_bytes": resp_bytes,
                "orig_pkts": orig_pkts, "label": label, "detailed_label": detailed_label, "uid": uid,
            })
            if max_records and len(records) >= max_records:
                break

    logging.info(f"Zeek connections loaded: {len(records)}")
    return records


def _flow_uid(f: dict) -> str:
    """Return explicit uid or generate deterministic fallback connection key."""
    uid = f.get("uid")
    if uid:
        return str(uid)
    return f"{f.get('src_ip')}:{f.get('src_port')}->{f.get('dst_ip')}:{f.get('dst_port')}/{f.get('protocol')}@{f.get('timestamp')}"


def correlate_netguard_zeek(netguard_alerts: list[dict], zeek_conns: list[dict], tolerance: float = 30.0) -> dict:
    """
    Corroborates NetGuard alerts against Zeek connection flow state and telemetry.
    Implements a strict 5-tier classification:
      1. RULE_SEMANTICALLY_CORROBORATED: Zeek state matches rule attack semantics
         (e.g., S0/REJ for scans, high volume for data exfiltration, confirmed IRC beaconing).
      2. FLOW_OBSERVED_ONLY: Zeek recorded traffic matching endpoints, port/protocol,
         and time window, but without rule-specific attack evidence.
      3. ENDPOINT_PAIR_ONLY: Zeek recorded traffic between the endpoints, but outside
         the requested time window or on different ports/protocols.
      4. UNMATCHED: No corresponding Zeek connection activity between the endpoints.
      5. UNASSESSED: Alert rule has no meaningful Zeek conn.log representation (e.g., L2 ARP).

    Enforces:
      - 4-tuple indexing by (src_ip, dst_ip, dst_port, protocol) where destination port is meaningful.
      - Transport protocol matching.
      - Strict time window filtering (no fallback to unfiltered list).
      - Mapped flow tracking (prevents flow reuse across unrelated alerts, aggregates multi-flow scans).
    """
    semantically_corroborated = []
    flow_observed_only = []
    endpoint_pair_only = []
    unmatched = []
    unassessed = []

    # Rules that aggregate probes across multiple ports or sources
    AGGREGATED_SCAN_RULES = {
        "PORT_SCAN", "SLOW_PORT_SCAN", "UDP_SCAN", "TCP_STEALTH_SCAN",
        "SYN_FLOOD", "DISTRIBUTED_SYN_FLOOD", "ICMP_SWEEP", "ICMP_FLOOD", "UDP_FLOOD"
    }

    # Rules operating outside Zeek conn.log telemetry boundary (e.g. Layer 2 ARP)
    UNASSESSED_RULES = {"ARP_SPOOF"}

    # Index Zeek connections
    zeek_by_pair: dict[tuple[str, str], list[dict]] = {}
    zeek_by_src_proto_port: dict[tuple[str, str, int], list[dict]] = {}
    zeek_by_dst_proto_port: dict[tuple[str, str, int], list[dict]] = {}

    for z in zeek_conns:
        s_ip = z["src_ip"]
        d_ip = z["dst_ip"]
        z_proto = (z.get("protocol") or "").strip().upper()
        d_port = z.get("dst_port")

        zeek_by_pair.setdefault((s_ip, d_ip), []).append(z)
        if d_port is not None and d_port != 0:
            zeek_by_src_proto_port.setdefault((s_ip, z_proto, d_port), []).append(z)
            zeek_by_dst_proto_port.setdefault((d_ip, z_proto, d_port), []).append(z)

    used_flow_uids: set[str] = set()

    for alert in netguard_alerts:
        src = _norm_ip(alert.get("src_ip"))
        dst = _norm_ip(alert.get("dst_ip"))
        rule = str(alert.get("rule_name") or "")
        proto = str(alert.get("protocol") or "").strip().upper()
        alert_dport = _norm_port(alert.get("dst_port"))
        alert_ts = float(alert.get("timestamp") or 0.0)

        # 1. Tier: UNASSESSED
        if rule in UNASSESSED_RULES:
            entry = {
                "alert": alert,
                "tier": "UNASSESSED",
                "corroboration_type": "UNASSESSED_TELEMETRY_GAP",
                "evidence": f"Rule {rule} operates on protocol layers not captured in Zeek conn.log (e.g. Layer 2 ARP)",
            }
            unassessed.append(entry)
            continue

        # Extract evidence dict to determine scan/aggregation structure
        evidence_dict = alert.get("evidence")
        if not isinstance(evidence_dict, dict) and alert.get("evidence_json"):
            try:
                evidence_dict = json.loads(alert["evidence_json"])
            except Exception:
                evidence_dict = None

        scan_type = evidence_dict.get("scan_type") if isinstance(evidence_dict, dict) else None
        is_horizontal = (
            scan_type in ("slow_horizontal", "horizontal")
            or (rule in ("SLOW_PORT_SCAN", "PORT_SCAN") and isinstance(evidence_dict, dict) and "distinct_hosts" in evidence_dict)
        )
        is_distributed = (
            rule in ("DISTRIBUTED_SYN_FLOOD",)
            or (isinstance(evidence_dict, dict) and "distinct_sources" in evidence_dict)
        )
        scanned_port = (
            (evidence_dict.get("scanned_port") if isinstance(evidence_dict, dict) else None)
            or alert_dport
        )

        # Look up candidate flows:
        # Aggregated horizontal scans represent probes to multiple destination targets on scanned_port.
        # Distributed attacks represent probes from multiple sources to victim dst on alert_dport.
        if is_horizontal and scanned_port:
            fwd_flows = zeek_by_pair.get((src, dst), [])
            other_flows = zeek_by_src_proto_port.get((src, proto or "TCP", scanned_port), [])
            seen_uids = set()
            any_pair_flows = []
            for f in fwd_flows + other_flows:
                uid = _flow_uid(f)
                if uid not in seen_uids:
                    seen_uids.add(uid)
                    any_pair_flows.append(f)
        elif is_distributed and alert_dport:
            fwd_flows = zeek_by_pair.get((src, dst), [])
            other_flows = zeek_by_dst_proto_port.get((dst, proto or "TCP", alert_dport), [])
            seen_uids = set()
            any_pair_flows = []
            for f in fwd_flows + other_flows:
                uid = _flow_uid(f)
                if uid not in seen_uids:
                    seen_uids.add(uid)
                    any_pair_flows.append(f)
        else:
            fwd_flows = zeek_by_pair.get((src, dst), [])
            rev_flows = zeek_by_pair.get((dst, src), [])
            any_pair_flows = fwd_flows + rev_flows

        # 2. Tier: UNMATCHED (no candidate flows at all)
        if not any_pair_flows:
            unmatched.append({
                "alert": alert,
                "tier": "UNMATCHED",
                "reason": "NO_MATCHING_FLOW",
                "evidence": f"Zeek recorded zero connection events between {src} and {dst}",
            })
            continue

        # Filter by transport protocol if specified in alert
        if proto:
            matching_proto = [
                f for f in any_pair_flows
                if not f.get("protocol") or f["protocol"].upper() == proto
            ]
        else:
            matching_proto = any_pair_flows

        # Filter by port if not an aggregated scan rule
        if rule in AGGREGATED_SCAN_RULES:
            matching_port = matching_proto
        else:
            if alert_dport is not None and alert_dport != 0 and proto != "ICMP":
                matching_port = [
                    f for f in matching_proto
                    if f.get("dst_port") == alert_dport or f.get("src_port") == alert_dport
                ]
            else:
                matching_port = matching_proto

        # Determine effective detection window
        evidence_win = None
        if isinstance(evidence_dict, dict) and "window_s" in evidence_dict:
            try:
                evidence_win = float(evidence_dict["window_s"])
            except (ValueError, TypeError):
                pass

        RULE_WINDOWS = {
            "SLOW_PORT_SCAN": 120.0,
            "IRC_C2_BEACONING": 300.0,
            "BRUTE_FORCE": 60.0,
            "DATA_EXFIL": 30.0,
            "PORT_SCAN": 10.0,
            "SYN_FLOOD": 10.0,
            "DISTRIBUTED_SYN_FLOOD": 10.0,
            "UDP_FLOOD": 10.0,
            "UDP_SCAN": 10.0,
            "ICMP_FLOOD": 10.0,
            "ICMP_SWEEP": 10.0,
            "TCP_STEALTH_SCAN": 10.0,
        }
        rule_win = evidence_win if evidence_win is not None else RULE_WINDOWS.get(rule, 10.0)
        win = max(tolerance, rule_win)

        # Filter by timestamp window (strictly, no fallback)
        if alert_ts > 0.0:
            matching_window = [
                f for f in matching_port
                if f["timestamp"] == 0.0 or abs(f["timestamp"] - alert_ts) <= win
            ]
        else:
            matching_window = matching_port

        # 3. Tier: ENDPOINT_PAIR_ONLY
        # If no flows survived port/protocol/time filtering, but endpoint traffic exists
        if not matching_window:
            endpoint_pair_only.append({
                "alert": alert,
                "tier": "ENDPOINT_PAIR_ONLY",
                "reason": "ENDPOINT_PAIR_ONLY",
                "evidence": (
                    f"Zeek observed {len(any_pair_flows)} flow(s) between endpoints, "
                    f"but none matched port={alert_dport}, proto={proto or 'ANY'}, or Δt<={win:.1f}s"
                ),
            })
            continue

        # Check flow reuse
        if rule in AGGREGATED_SCAN_RULES:
            unclaimed = [f for f in matching_window if _flow_uid(f) not in used_flow_uids]
            if not unclaimed:
                unmatched.append({
                    "alert": alert,
                    "tier": "UNMATCHED",
                    "reason": "ALL_FLOWS_ALREADY_CLAIMED",
                    "evidence": "All candidate flows were already claimed by earlier NetGuard alerts",
                })
                continue
            active_flows = unclaimed
        else:
            unclaimed = [f for f in matching_window if _flow_uid(f) not in used_flow_uids]
            if not unclaimed:
                unmatched.append({
                    "alert": alert,
                    "tier": "UNMATCHED",
                    "reason": "FLOW_ALREADY_CLAIMED",
                    "evidence": "Candidate flow was already claimed by an earlier NetGuard alert",
                })
                continue
            active_flows = unclaimed

        # Evaluate Semantic Corroboration vs Flow Observed Only
        corroboration_type = None
        evidence_notes = []
        claimed_uids = []

        if rule in ("PORT_SCAN", "SLOW_PORT_SCAN", "TCP_STEALTH_SCAN", "SYN_FLOOD", "DISTRIBUTED_SYN_FLOOD"):
            s0_flows = [f for f in active_flows if f["conn_state"] == "S0" or f["history"] == "S"]
            rej_flows = [f for f in active_flows if f["conn_state"] in ("REJ", "RSTOS0", "RSTR")]
            if s0_flows:
                corroboration_type = "UNANSWERED_SYN_SCAN"
                ports = {f["dst_port"] for f in s0_flows if f.get("dst_port")}
                dst_targets = {f["dst_ip"] for f in s0_flows if f.get("dst_ip")}
                if len(dst_targets) > 1:
                    evidence_notes.append(f"{len(s0_flows)} Zeek flow(s) in S0 state across {len(dst_targets)} destination target(s)")
                else:
                    evidence_notes.append(f"{len(s0_flows)} Zeek flow(s) in S0 state (unacknowledged SYNs) across {len(ports)} probe port(s)")
                claimed_uids = [_flow_uid(f) for f in s0_flows]
            elif rej_flows:
                corroboration_type = "REJECTED_CONNECTION_PROBE"
                evidence_notes.append(f"{len(rej_flows)} Zeek connection(s) rejected/reset by target host")
                claimed_uids = [_flow_uid(f) for f in rej_flows]
            else:
                corroboration_type = "ESTABLISHED_FLOW_WITHOUT_SCAN_STATE"
                evidence_notes.append(f"Zeek observed {len(active_flows)} established connection(s) without scan indicators")
                claimed_uids = [_flow_uid(active_flows[0])]

        elif rule == "UDP_SCAN":
            s0_flows = [
                f for f in active_flows
                if f.get("conn_state") in ("S0", "OTH") or (f.get("orig_pkts", 0) > 0 and f.get("resp_pkts", 0) == 0)
            ]
            rej_flows = [
                f for f in active_flows
                if f.get("conn_state") in ("REJ", "RSTR")
            ]
            if s0_flows:
                corroboration_type = "UNANSWERED_UDP_PROBE"
                ports = {f["dst_port"] for f in s0_flows if f.get("dst_port")}
                evidence_notes.append(f"{len(s0_flows)} Zeek UDP flow(s) without response across {len(ports)} probe port(s)")
                claimed_uids = [_flow_uid(f) for f in s0_flows]
            elif rej_flows:
                corroboration_type = "REJECTED_UDP_PROBE"
                evidence_notes.append(f"{len(rej_flows)} Zeek UDP flow(s) rejected by destination (ICMP unreachable)")
                claimed_uids = [_flow_uid(f) for f in rej_flows]
            else:
                corroboration_type = "ESTABLISHED_UDP_FLOW"
                evidence_notes.append(f"Zeek observed {len(active_flows)} bidirectional UDP flow(s)")
                claimed_uids = [_flow_uid(active_flows[0])]

        elif rule == "UDP_FLOOD":
            udp_flows = [f for f in active_flows if f.get("protocol") == "UDP"]
            high_vol = [
                f for f in udp_flows
                if f.get("orig_pkts", 0) >= 50 or f.get("orig_bytes", 0) >= 10000
            ]
            if high_vol or len(udp_flows) >= 10:
                corroboration_type = "HIGH_RATE_UDP_FLOOD_CONFIRMED"
                evidence_notes.append(f"Zeek confirmed high-rate UDP flooding ({len(udp_flows)} flow(s))")
                claimed_uids = [_flow_uid(f) for f in (high_vol or udp_flows)]
            else:
                corroboration_type = "FLOW_OBSERVED"
                evidence_notes.append(f"Zeek observed {len(udp_flows)} UDP flow(s) below flood threshold")
                claimed_uids = [_flow_uid(active_flows[0])]

        elif rule in ("ICMP_FLOOD", "ICMP_SWEEP"):
            icmp_flows = [f for f in active_flows if f.get("protocol") == "ICMP"]
            if icmp_flows:
                corroboration_type = "ICMP_ACTIVITY_CONFIRMED"
                evidence_notes.append(f"Zeek recorded {len(icmp_flows)} ICMP flow(s) between endpoints")
                claimed_uids = [_flow_uid(f) for f in icmp_flows]
            else:
                corroboration_type = "FLOW_OBSERVED"
                evidence_notes.append("Zeek observed non-ICMP flow between endpoints")
                claimed_uids = [_flow_uid(active_flows[0])]

        elif rule == "TCP_FLAG_ANOMALY":
            abnormal = [
                f for f in active_flows
                if f.get("conn_state") in ("OTH", "REJ", "RSTOS0", "RSTO")
                or any(h in f.get("history", "") for h in ("F", "R", "C"))
            ]
            if abnormal:
                corroboration_type = "ANOMALOUS_TCP_STATE_CONFIRMED"
                evidence_notes.append(f"Zeek recorded anomalous TCP connection state ({abnormal[0].get('conn_state')}, history: {abnormal[0].get('history')})")
                claimed_uids = [_flow_uid(abnormal[0])]
            else:
                corroboration_type = "FLOW_OBSERVED"
                evidence_notes.append("Zeek observed standard TCP connection without abnormal flags")
                claimed_uids = [_flow_uid(active_flows[0])]

        elif rule == "NON_DNS_TRAFFIC_ON_DNS_PORT":
            non_dns = [
                f for f in active_flows
                if f.get("dst_port") == 53 and f.get("service") and f.get("service") != "dns"
            ]
            if non_dns:
                corroboration_type = "NON_DNS_PROTOCOL_ON_DNS_PORT_CONFIRMED"
                evidence_notes.append(f"Zeek confirmed non-DNS service ({non_dns[0].get('service')}) on port 53")
                claimed_uids = [_flow_uid(non_dns[0])]
            else:
                corroboration_type = "FLOW_OBSERVED"
                evidence_notes.append("Zeek observed port 53 flow without non-DNS service identification")
                claimed_uids = [_flow_uid(active_flows[0])]

        elif rule == "ICMP_TUNNEL":
            large_icmp = [
                f for f in active_flows
                if f.get("protocol") == "ICMP" and f.get("orig_bytes", 0) >= 500
            ]
            if large_icmp:
                corroboration_type = "ICMP_TUNNEL_PAYLOAD_CONFIRMED"
                evidence_notes.append(f"Zeek observed large ICMP payload ({large_icmp[0].get('orig_bytes')} bytes)")
                claimed_uids = [_flow_uid(large_icmp[0])]
            else:
                corroboration_type = "FLOW_OBSERVED"
                evidence_notes.append("Zeek observed standard ICMP traffic")
                claimed_uids = [_flow_uid(active_flows[0])]

        elif rule == "BLOCKLIST":
            corroboration_type = "BLOCKLIST_COMMUNICATION_CONFIRMED"
            evidence_notes.append("Zeek confirmed communication between endpoints involving blocklisted IP")
            claimed_uids = [_flow_uid(active_flows[0])]

        elif rule == "PAYLOAD_HIT":
            http_flows = [
                f for f in active_flows
                if f.get("service") == "http" or f.get("dst_port") in (80, 8080, 8000, 8888, 443)
            ]
            if http_flows:
                corroboration_type = "HTTP_APPLICATION_TRANSACTION_CONFIRMED"
                evidence_notes.append(f"Zeek observed HTTP transaction to service port {http_flows[0].get('dst_port')}")
                claimed_uids = [_flow_uid(http_flows[0])]
            else:
                corroboration_type = "FLOW_OBSERVED"
                evidence_notes.append("Zeek observed flow without HTTP application payload confirmation")
                claimed_uids = [_flow_uid(active_flows[0])]

        elif rule == "DATA_EXFIL":
            high_vol = [f for f in active_flows if f["orig_bytes"] >= 50000 or f["orig_pkts"] >= 50]
            if high_vol:
                corroboration_type = "HIGH_VOLUME_EGRESS"
                max_bytes = max(f["orig_bytes"] for f in high_vol)
                evidence_notes.append(f"Zeek recorded outbound flow with {max_bytes} bytes")
                claimed_uids = [_flow_uid(high_vol[0])]
            else:
                corroboration_type = "LOW_VOLUME_FLOW"
                max_bytes = max(f["orig_bytes"] for f in active_flows)
                evidence_notes.append(f"Zeek recorded flow with normal/low byte volume ({max_bytes} bytes)")
                claimed_uids = [_flow_uid(active_flows[0])]

        elif rule == "IRC_C2_BEACONING":
            irc_ports = (194, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6697)
            irc_flows = [
                f for f in active_flows
                if f.get("dst_port") in irc_ports or f.get("service") == "irc"
            ]
            if irc_flows:
                suspicious = [f for f in irc_flows if f["conn_state"] in ("S0", "RSTOS0", "REJ", "RSTO")]
                if len(irc_flows) >= 2 or suspicious:
                    corroboration_type = "IRC_SESSION_CONFIRMED"
                    evidence_notes.append(f"Zeek confirmed {len(irc_flows)} connection(s) to IRC service ports with C2/beaconing pattern")
                    claimed_uids = [_flow_uid(f) for f in irc_flows]
                else:
                    corroboration_type = "IRC_FLOW_WITHOUT_C2_BEACONING"
                    evidence_notes.append("Zeek recorded a single standard IRC connection without anomalous C2 beaconing evidence")
                    claimed_uids = [_flow_uid(irc_flows[0])]
            else:
                corroboration_type = "NON_IRC_PORT_FLOW"
                evidence_notes.append("Zeek observed flow between endpoints, but not on recognized IRC ports")
                claimed_uids = [_flow_uid(active_flows[0])]

        elif rule == "CLEAR_HTTP_ON_TLS_PORT":
            http_flows = [f for f in active_flows if f.get("service") == "http"]
            if http_flows:
                corroboration_type = "CLEARTEXT_HTTP_ON_TLS_PORT_CONFIRMED"
                evidence_notes.append("Zeek confirmed HTTP cleartext protocol on TLS port")
                claimed_uids = [_flow_uid(http_flows[0])]
            else:
                corroboration_type = "FLOW_OBSERVED"
                evidence_notes.append("Zeek observed flow on port 443 without explicit HTTP protocol classification")
                claimed_uids = [_flow_uid(active_flows[0])]

        elif rule == "BRUTE_FORCE":
            failed = [f for f in active_flows if f["conn_state"] in ("REJ", "RSTO", "RSTR", "S0")]
            if len(active_flows) >= 3 or failed:
                corroboration_type = "MULTIPLE_FAILED_AUTH_ATTEMPTS"
                evidence_notes.append(f"Zeek recorded {len(active_flows)} connection attempt(s) ({len(failed)} rejected/reset)")
                claimed_uids = [_flow_uid(f) for f in active_flows]
            else:
                corroboration_type = "FLOW_OBSERVED"
                evidence_notes.append("Zeek observed connection without multiple failed attempt pattern")
                claimed_uids = [_flow_uid(active_flows[0])]

        elif rule == "TCP_ZERO_WINDOW":
            zw = [f for f in active_flows if "W0" in f.get("history", "") or f.get("conn_state") in ("RSTP", "RSTO")]
            if zw:
                corroboration_type = "TCP_ZERO_WINDOW_CONFIRMED"
                evidence_notes.append("Zeek recorded zero-window advertisement or connection reset")
                claimed_uids = [_flow_uid(zw[0])]
            else:
                corroboration_type = "FLOW_OBSERVED"
                evidence_notes.append("Zeek observed TCP connection without zero-window state")
                claimed_uids = [_flow_uid(active_flows[0])]

        # Default generic flow observation
        if not corroboration_type:
            corroboration_type = "FLOW_OBSERVED"
            evidence_notes.append(f"Zeek observed {len(active_flows)} flow(s) between endpoints matching port and protocol")
            claimed_uids = [_flow_uid(active_flows[0])]

        # Mark claimed uids
        for u in claimed_uids:
            used_flow_uids.add(u)

        # Classify into tier
        is_semantic = corroboration_type in (
            "UNANSWERED_SYN_SCAN",
            "REJECTED_CONNECTION_PROBE",
            "UNANSWERED_UDP_PROBE",
            "REJECTED_UDP_PROBE",
            "HIGH_VOLUME_EGRESS",
            "HIGH_RATE_UDP_FLOOD_CONFIRMED",
            "ICMP_ACTIVITY_CONFIRMED",
            "ANOMALOUS_TCP_STATE_CONFIRMED",
            "IRC_SESSION_CONFIRMED",
            "CLEARTEXT_HTTP_ON_TLS_PORT_CONFIRMED",
            "MULTIPLE_FAILED_AUTH_ATTEMPTS",
            "TCP_ZERO_WINDOW_CONFIRMED",
            "NON_DNS_PROTOCOL_ON_DNS_PORT_CONFIRMED",
            "ICMP_TUNNEL_PAYLOAD_CONFIRMED",
            "BLOCKLIST_COMMUNICATION_CONFIRMED",
            "HTTP_APPLICATION_TRANSACTION_CONFIRMED",
        )

        entry = {
            "alert": alert,
            "tier": "RULE_SEMANTICALLY_CORROBORATED" if is_semantic else "FLOW_OBSERVED_ONLY",
            "corroboration_type": corroboration_type,
            "flow_count": len(active_flows),
            "evidence": "; ".join(evidence_notes),
            "sample_flow": active_flows[0],
            "probe_flow_count": len(claimed_uids) if rule in AGGREGATED_SCAN_RULES else 1,
            "probe_destination_count": len({f["dst_ip"] for f in active_flows if f.get("dst_ip")}) if is_horizontal else 1,
        }

        if is_semantic:
            semantically_corroborated.append(entry)
        else:
            flow_observed_only.append(entry)

    total = len(netguard_alerts)
    sem_rate = len(semantically_corroborated) / max(total, 1)
    flow_presence_rate = (len(semantically_corroborated) + len(flow_observed_only)) / max(total, 1)

    return {
        "total_alerts": total,
        "semantically_corroborated": semantically_corroborated,
        "flow_observed_only": flow_observed_only,
        "endpoint_pair_only": endpoint_pair_only,
        "unmatched": unmatched,
        "unassessed": unassessed,
        "total_flows_claimed": len(used_flow_uids),
        # Backward compatibility aliases
        "corroborated": semantically_corroborated,
        "corroboration_rate": sem_rate,
        "semantic_corroboration_rate": sem_rate,
        "flow_presence_rate": flow_presence_rate,
    }


def print_zeek_corroboration_report(results: dict):
    total = results["total_alerts"]
    sem_corr = len(results.get("semantically_corroborated", results.get("corroborated", [])))
    flow_only = len(results.get("flow_observed_only", []))
    ep_only = len(results.get("endpoint_pair_only", []))
    unmatched = len(results.get("unmatched", []))
    unassessed = len(results.get("unassessed", []))
    flows_claimed = results.get("total_flows_claimed", 0)

    sem_rate = results.get("semantic_corroboration_rate", sem_corr / max(total, 1)) * 100
    flow_rate = results.get("flow_presence_rate", (sem_corr + flow_only) / max(total, 1)) * 100

    print("\n" + "=" * 65)
    print("  ZEEK CROSS-ENGINE TELEMETRY CORROBORATION REPORT")
    print("  NOTE: Zeek logs independent flow telemetry for corroboration.")
    print("  Delineates rule semantic corroboration from generic flow presence.")
    print("=" * 65)
    print(f"  NetGuard total alerts:              {total:4d}")
    print(f"  Corroborated by Zeek:               {sem_corr:4d} ({sem_rate:.1f}%)")
    print(f"  - Rule Semantically Corroborated:   {sem_corr:4d} ({sem_rate:.1f}%)")
    print(f"  - Flow Observed Only (no attack):   {flow_only:4d} (presence {flow_rate:.1f}%)")
    if flows_claimed:
        print(f"  - Zeek flows claimed by alerts:     {flows_claimed:4d} (zero flow reuse)")
    print(f"  Endpoint Pair Only (time/port gap): {ep_only:4d}")
    print(f"  Unmatched:                          {unmatched:4d}")
    print(f"  Unassessed (telemetry boundary):    {unassessed:4d}")
    print("-" * 65)
    print("  CRITICAL: Generic flow presence is NOT semantic attack corroboration.")
    if sem_corr:
        print("  Sample Semantically Corroborated Findings:")
        for item in results.get("semantically_corroborated", results.get("corroborated", []))[:6]:
            a = item["alert"]
            print(
                f"    [{a.get('rule_name')}] {a.get('src_ip')} → {a.get('dst_ip')} "
                f"({item['corroboration_type']}): {item['evidence']}"
            )
    if flow_only:
        print("  Sample Flow Observed Only Findings (non-attack background):")
        for item in results.get("flow_observed_only", [])[:4]:
            a = item["alert"]
            print(
                f"    [{a.get('rule_name')}] {a.get('src_ip')} → {a.get('dst_ip')} "
                f"({item['corroboration_type']}): {item['evidence']}"
            )
    print("=" * 65)


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

    # Check if scenario labels have exhaustive or partial coverage
    is_exhaustive = True
    for sc in scenarios:
        cov = sc.get("coverage", "").strip().lower()
        if cov in ("partial", "sample", "incomplete"):
            is_exhaustive = False
            break

    for sc in scenarios:
        expected_rule = sc.get("expected_rule", "").strip()
        expected_fam  = sc.get("expected_family", "").strip().lower()
        exp_src   = _norm_ip(sc.get("src_ip", "").strip())
        exp_dst   = _norm_ip(sc.get("dst_ip", "").strip())
        exp_port  = _norm_port(sc.get("dst_port", "").strip())
        exp_proto = sc.get("protocol", "").strip().upper()

        win_start = sc.get("start_time") or sc.get("timestamp")
        win_end   = sc.get("end_time")
        win_tolerance = float(sc.get("window", TIMESTAMP_TOLERANCE))

        found = False
        for i, alert in enumerate(alerts):
            if i in matched_alerts:
                continue

            # 1. Rule / Family matching
            rule_match = True
            if expected_rule and alert.get("rule_name") != expected_rule:
                if expected_fam and _semantic_family(alert) == expected_fam:
                    rule_match = True
                else:
                    rule_match = False
            elif expected_fam and _semantic_family(alert) != expected_fam:
                rule_match = False

            if not rule_match:
                continue

            # 2. Protocol matching
            if exp_proto and (alert.get("protocol") or "").strip().upper() != exp_proto:
                continue

            # 3. Bidirectional endpoint matching
            a_src   = _norm_ip(alert.get("src_ip"))
            a_dst   = _norm_ip(alert.get("dst_ip"))
            a_dport = _norm_port(alert.get("dst_port"))
            a_sport = _norm_port(alert.get("src_port"))

            forward_match = (
                (not exp_src or a_src == exp_src) and
                (not exp_dst or a_dst == exp_dst) and
                (exp_port is None or a_dport == exp_port)
            )
            reverse_match = (
                bool(exp_src and exp_dst) and
                (a_src == exp_dst) and
                (a_dst == exp_src) and
                (exp_port is None or a_sport == exp_port)
            )

            if not (forward_match or reverse_match):
                continue

            # 4. Timestamp window matching
            alert_ts = alert.get("timestamp")
            if alert_ts is not None and win_start:
                try:
                    ts_val = float(alert_ts)
                    t_start = float(win_start) - win_tolerance
                    t_end   = (float(win_end) + win_tolerance) if win_end else (float(win_start) + win_tolerance)
                    if ts_val < t_start or ts_val > t_end:
                        continue
                except (ValueError, TypeError):
                    pass

            matched_alerts.add(i)
            tp_scenarios.append((sc, alert))
            found = True
            break

        if not found:
            fn_scenarios.append(sc)

    extra_alerts = [a for i, a in enumerate(alerts) if i not in matched_alerts]

    tp = len(tp_scenarios)
    fn = len(fn_scenarios)

    if is_exhaustive:
        fp = len(extra_alerts)
        unassessed = 0
    else:
        fp = 0
        unassessed = len(extra_alerts)

    precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if tp > 0 else 0.0)
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) \
                if (precision + recall) > 0 else 0.0

    print(f"  Scenarios (labelled expected):        {len(scenarios):4d}")
    print(f"  Detected  (TP — scenario matched):    {tp:4d}")
    print(f"  Missed    (FN — no matching alert):   {fn:4d}")
    if is_exhaustive:
        print(f"  Extra     (FP — no matching scenario):{fp:4d}")
    else:
        print(f"  Unassessed (partial label coverage):  {unassessed:4d}")
    print("-" * 65)
    if is_exhaustive:
        print(f"  Precision:   {precision * 100:.1f}%")
    else:
        print(f"  Precision:   N/A (partial label coverage — extra alerts unassessed)")
    print(f"  Recall:      {recall    * 100:.1f}%")
    if is_exhaustive:
        print(f"  F1 Score:    {f1        * 100:.1f}%")
    else:
        print(f"  F1 Score:    N/A")
    print("  NOTE: metrics are ground-truth only when scenario labels")
    print("        match concrete event attributes (src/dst/port/protocol).")
    print("=" * 65)

    if fn_scenarios:
        print("\n  Missed scenarios (FN):")
        for sc in fn_scenarios[:5]:
            print(f"    [{sc.get('expected_rule')}] "
                  f"{sc.get('src_ip')} → {sc.get('dst_ip')}:{sc.get('dst_port')} "
                  f"  {sc.get('description','')[:40]}")

    if extra_alerts:
        label_type = "potential FP — investigate" if is_exhaustive else "unassessed in partial label set"
        print(f"\n  Unmatched NetGuard alerts ({label_type}):")
        for a in extra_alerts[:5]:
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
        help="Path to Suricata eve.json (required for agreement mode unless --zeek provided)",
    )
    parser.add_argument(
        "--zeek",
        help="Path to Zeek conn.log for cross-engine flow corroboration",
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

    # Zeek cross-engine corroboration mode
    if args.zeek:
        if not os.path.exists(args.zeek):
            print(f"ERROR: {args.zeek} not found")
            sys.exit(1)
        if args.db and args.db.endswith(".json") and os.path.exists(args.db):
            with open(args.db, "r", encoding="utf-8") as f:
                data = json.load(f)
                netguard_alerts = data.get("alerts_sample") or data.get("alerts") or []
        else:
            conn = _get_conn(args.db)
            netguard_alerts = read_all_alerts(conn)
        logging.info(f"NetGuard alerts: {len(netguard_alerts)}")
        zeek_conns = load_zeek_connections(args.zeek)
        z_results = correlate_netguard_zeek(netguard_alerts, zeek_conns)
        print_zeek_corroboration_report(z_results)
        if not args.eve:
            return

    # Agreement mode (default with Suricata)
    if not args.eve:
        print("ERROR: --eve is required for agreement mode")
        sys.exit(1)
    if not os.path.exists(args.eve):
        print(f"ERROR: {args.eve} not found")
        sys.exit(1)

    if not args.zeek:
        if args.db and args.db.endswith(".json") and os.path.exists(args.db):
            with open(args.db, "r", encoding="utf-8") as f:
                data = json.load(f)
                netguard_alerts = data.get("alerts_sample") or data.get("alerts") or []
        else:
            conn = _get_conn(args.db)
            netguard_alerts = read_all_alerts(conn)
        logging.info(f"NetGuard alerts: {len(netguard_alerts)}")

    suricata_alerts = load_suricata_alerts(args.eve)
    results = match_alerts_agreement(netguard_alerts, suricata_alerts)
    print_agreement_report(results)


if __name__ == "__main__":
    main()
