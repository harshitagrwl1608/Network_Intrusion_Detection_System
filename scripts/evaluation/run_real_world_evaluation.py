#!/usr/bin/env python3
"""
NetGuard Real-World PCAP Evaluation Suite
=========================================
Executes a fully reproducible, isolated evaluation of NetGuard IDS across
19 real-world network packet captures:
  - 7 CICIoT2023 raw attack captures (PingSweep, SQLi, XSS, CmdInj, Upload, BrowserHijack, BruteForce)
  - 4 Benign captures (Somfy IoT doorlock, SCADA Modbus, HTTP browsing, Skype/IRC)
  - 8 Targeted external attack captures (TCP stealth scan, Teardrop fragmentation, DNS remote shell,
    TLS SNI anomaly, SYN flood burst, ARP storm, Hakai botnet, Log4Shell exploit)

Guarantees:
  - Strict isolation: Each capture is executed with its own dedicated SQLite DB and ARP table.
  - Zero cross-talk: Replay state is reset between captures.
  - Preserved timestamps: ReplayClock preserves PCAP wire timestamps.
  - Structured exports: Alerts CSV, capture stats CSV, rule matrix CSV, and canonical JSON.
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import sqlite3
import subprocess
import sys
import time
from typing import Dict, List, Any, Optional

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts.audits.ctu48_1_ground_truth_audit_v3_1 import PcapParser

RESULTS_DIR = os.path.join(REPO_ROOT, "results/real_world_evaluation")
DBS_DIR = os.path.join(RESULTS_DIR, "dbs")
ARP_DIR = os.path.join(RESULTS_DIR, "arp_tables")
LOGS_DIR = os.path.join(RESULTS_DIR, "logs")
EXPORTS_DIR = os.path.join(RESULTS_DIR, "exports")

# Manifest of 19 captures
CAPTURES_MANIFEST = [
    # --- 7 CICIoT2023 Captures ---
    {
        "id": "ciciot_pingsweep",
        "name": "CICIoT2023 Recon-PingSweep",
        "path": "data/ciciot2023_eval/Recon-PingSweep.pcap",
        "family": "CICIoT2023",
        "category": "attack",
        "attack_type": "ICMP Ping Sweep Reconnaissance",
        "target_rules": ["ICMP_SWEEP"],
        "description": "ICMP echo sweep targeting IoT devices across the local subnet.",
    },
    {
        "id": "ciciot_sqli",
        "name": "CICIoT2023 SqlInjection",
        "path": "data/ciciot2023_eval/SqlInjection.pcap",
        "family": "CICIoT2023",
        "category": "attack",
        "attack_type": "SQL Injection Web Exploitation",
        "target_rules": ["PAYLOAD_HIT"],
        "description": "Automated and manual SQL injection vectors against HTTP web interfaces.",
    },
    {
        "id": "ciciot_xss",
        "name": "CICIoT2023 XSS",
        "path": "data/ciciot2023_eval/XSS.pcap",
        "family": "CICIoT2023",
        "category": "attack",
        "attack_type": "Cross-Site Scripting (XSS)",
        "target_rules": ["PAYLOAD_HIT"],
        "description": "Cross-site scripting injection vectors in HTTP request parameters.",
    },
    {
        "id": "ciciot_cmdinj",
        "name": "CICIoT2023 CommandInjection",
        "path": "data/ciciot2023_eval/CommandInjection.pcap",
        "family": "CICIoT2023",
        "category": "attack",
        "attack_type": "OS Command Injection",
        "target_rules": ["PAYLOAD_HIT"],
        "description": "OS shell command injection payload delivery targeting web interfaces.",
    },
    {
        "id": "ciciot_upload",
        "name": "CICIoT2023 Uploading_Attack",
        "path": "data/ciciot2023_eval/Uploading_Attack.pcap",
        "family": "CICIoT2023",
        "category": "attack",
        "attack_type": "Malicious File Upload / Web Shell",
        "target_rules": ["PAYLOAD_HIT"],
        "description": "Arbitrary file upload exploit attempting web shell installation.",
    },
    {
        "id": "ciciot_browserhijack",
        "name": "CICIoT2023 BrowserHijacking",
        "path": "data/ciciot2023_eval/BrowserHijacking.pcap",
        "family": "CICIoT2023",
        "category": "attack",
        "attack_type": "Browser Hijacking / Web Exploit",
        "target_rules": ["PAYLOAD_HIT"],
        "description": "Client-side browser manipulation and redirection attacks.",
    },
    {
        "id": "ciciot_bruteforce",
        "name": "CICIoT2023 DictionaryBruteForce",
        "path": "data/ciciot2023_eval/DictionaryBruteForce.pcap",
        "family": "CICIoT2023",
        "category": "attack",
        "attack_type": "Credential Dictionary Brute Force",
        "target_rules": ["BRUTE_FORCE"],
        "description": "High-volume dictionary authentication attempts on administrative services.",
    },

    # --- 4 Benign Baseline Captures ---
    {
        "id": "benign_iot23_doorlock",
        "name": "IoT-23 Honeypot Somfy Doorlock",
        "path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/iot23_honeypot_4_1.pcap",
        "family": "CTU-IoT-23",
        "category": "benign",
        "attack_type": "Benign IoT Hardware Operations",
        "target_rules": ["FP_BENIGN_VERIFICATION"],
        "description": "Real hardware benign operational traffic from Somfy smart doorlock.",
    },
    {
        "id": "benign_oisf_modbus",
        "name": "OISF Modbus/TCP Industrial Control",
        "path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/oisf_modbus.pcap",
        "family": "OISF-QA",
        "category": "benign",
        "attack_type": "Benign SCADA Modbus Polling",
        "target_rules": ["FP_BENIGN_VERIFICATION"],
        "description": "Industrial control system Modbus protocol polling and telemetry.",
    },
    {
        "id": "benign_ws_http",
        "name": "Wireshark HTTP Web Browsing",
        "path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/ws_http_browsing.pcap",
        "family": "Wireshark-Sample",
        "category": "benign",
        "attack_type": "Benign Web Browsing",
        "target_rules": ["FP_BENIGN_VERIFICATION"],
        "description": "Normal human HTTP browsing session with image and page requests.",
    },
    {
        "id": "benign_ws_skype_irc",
        "name": "Wireshark Skype and IRC Traffic",
        "path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/ws_skype_irc.pcap",
        "family": "Wireshark-Sample",
        "category": "benign",
        "attack_type": "Benign Chat & Voice Telemetry",
        "target_rules": ["FP_BENIGN_VERIFICATION"],
        "description": "VoIP voice framing and IRC chat communications in benign enterprise setting.",
    },

    # --- 8 Targeted External Attack Captures ---
    {
        "id": "attack_ws_nmap_stealth",
        "name": "Wireshark Nmap Stealth Scan",
        "path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/ws_nmap_stealth_scan.pcap",
        "family": "Wireshark-Sample",
        "category": "attack",
        "attack_type": "TCP SYN Stealth Scan",
        "target_rules": ["TCP_STEALTH_SCAN", "TCP_FLAG_ANOMALY"],
        "description": "Nmap half-open SYN scan across common server ports.",
    },
    {
        "id": "attack_ws_teardrop",
        "name": "Wireshark Teardrop IP Exploit",
        "path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/ws_teardrop.pcap",
        "family": "Wireshark-Sample",
        "category": "attack",
        "attack_type": "Overlapping IP Fragment Crash Attack",
        "target_rules": ["IP_FRAGMENT_ANOMALY"],
        "description": "Teardrop/Bonk exploit with overlapping fragment offsets.",
    },
    {
        "id": "attack_ws_dns_remoteshell",
        "name": "Wireshark DNS Remote Shell",
        "path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/ws_dns_remoteshell.pcap",
        "family": "Wireshark-Sample",
        "category": "attack",
        "attack_type": "Non-DNS Backdoor on DNS Port 53",
        "target_rules": ["NON_DNS_TRAFFIC_ON_DNS_PORT"],
        "description": "Interactive command shell tunnelled over raw UDP/TCP port 53.",
    },
    {
        "id": "attack_oisf_sni_anomaly",
        "name": "OISF TLS SNI Enforcement",
        "path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/oisf_tls_sni_anomaly.pcap",
        "family": "OISF-QA",
        "category": "attack",
        "attack_type": "TLS SNI Mismatch / Malformed Handshake",
        "target_rules": ["TLS_ANOMALY"],
        "description": "TLS ClientHello with abnormal SNI or evasion formatting.",
    },
    {
        "id": "attack_oisf_syn_flood",
        "name": "OISF TCP SYN Flood Burst",
        "path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/oisf_syn_flood.pcap",
        "family": "OISF-QA",
        "category": "attack",
        "attack_type": "High-Rate TCP SYN Flood DoS",
        "target_rules": ["SYN_FLOOD"],
        "description": "High-frequency TCP SYN packet burst without completing three-way handshake.",
    },
    {
        "id": "attack_ws_arp_storm",
        "name": "Wireshark ARP Storm / Spoofing",
        "path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/ws_arp_storm.pcap",
        "family": "Wireshark-Sample",
        "category": "attack",
        "attack_type": "ARP Spoofing / Poisoning Storm",
        "target_rules": ["ARP_SPOOF"],
        "description": "Gratuitous ARP storm with contradictory IP-MAC mappings.",
    },
    {
        "id": "attack_iot23_hakai",
        "name": "IoT-23 Hakai Botnet Capture",
        "path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/iot23_malware_8_1.pcap",
        "family": "CTU-IoT-23",
        "category": "attack",
        "attack_type": "Hakai Botnet Scanning & Telnet Brute Force",
        "target_rules": ["PORT_SCAN", "SLOW_PORT_SCAN", "BRUTE_FORCE"],
        "description": "Live Hakai botnet propagating via port scanning and Telnet dictionary attacks.",
    },
    {
        "id": "attack_foxit_log4shell",
        "name": "Fox-IT Log4Shell JNDI RCE Exploit",
        "path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/foxit_log4shell.pcap",
        "family": "Fox-IT",
        "category": "attack",
        "attack_type": "Log4Shell CVE-2021-44228 JNDI Injection",
        "target_rules": ["PAYLOAD_HIT"],
        "description": "HTTP request containing nested obfuscated JNDI LDAP lookup strings.",
    },
]


def resolve_path(p: str) -> str:
    """Resolve a relative or absolute path against repository root."""
    if os.path.isabs(p):
        return p
    return os.path.abspath(os.path.join(REPO_ROOT, p))


def compute_sha256(filepath: str) -> str:
    """Compute full SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def count_packets(filepath: str) -> int:
    """Count packets in a classic libpcap file."""
    with PcapParser(filepath) as parser:
        return sum(1 for _ in parser.iter_packets())


def setup_directories():
    """Ensure all required output directories exist."""
    for d in [RESULTS_DIR, DBS_DIR, ARP_DIR, LOGS_DIR, EXPORTS_DIR]:
        os.makedirs(d, exist_ok=True)


def verify_manifest() -> List[Dict[str, Any]]:
    """Verify that all manifest captures exist and compute their basic metadata."""
    verified_manifest = []
    print("=" * 80)
    print("NETGUARD REAL-WORLD PCAP EVALUATION — MANIFEST VERIFICATION")
    print("=" * 80)
    total_bytes = 0

    for item in CAPTURES_MANIFEST:
        full_path = resolve_path(item["path"])
        if not os.path.exists(full_path):
            raise FileNotFoundError(f"Required capture missing: {full_path}")
        size = os.path.getsize(full_path)
        total_bytes += size
        entry = dict(item)
        entry["resolved_path"] = full_path
        entry["size_bytes"] = size
        verified_manifest.append(entry)
        print(f"  [OK] {item['id']:25} | {size / (1024*1024):6.2f} MB | {item['name']}")

    print("-" * 80)
    print(f"Total captures: {len(verified_manifest)} | Total volume: {total_bytes / (1024*1024):.2f} MiB")
    print("=" * 80 + "\n")
    return verified_manifest


def run_single_capture(entry: Dict[str, Any], blocklist_path: str) -> Dict[str, Any]:
    """Execute replay for a single capture under complete isolation."""
    cid = entry["id"]
    pcap_path = entry["resolved_path"]
    db_path = os.path.join(DBS_DIR, f"{cid}.db")
    arp_path = os.path.join(ARP_DIR, f"{cid}.arp.json")
    log_path = os.path.join(LOGS_DIR, f"{cid}.log")

    # Clean existing database and ARP table to ensure fresh isolation
    if os.path.exists(db_path):
        os.remove(db_path)
    if os.path.exists(arp_path):
        os.remove(arp_path)

    cmd = [
        sys.executable,
        "-m",
        "ids_project.evaluation.replay",
        "--pcap",
        pcap_path,
        "--db",
        db_path,
        "--arp-table",
        arp_path,
        "--blocklist",
        blocklist_path,
        "--log-mode",
        "summary",
    ]

    t_start = time.time()
    with open(log_path, "w") as f_log:
        proc = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            stdout=f_log,
            stderr=subprocess.STDOUT,
            text=True,
        )
    t_end = time.time()
    elapsed = max(0.001, t_end - t_start)

    if proc.returncode != 0:
        raise RuntimeError(f"Replay failed for {cid} (code {proc.returncode}). See {log_path}")

    # Inspect the generated alerts in SQLite
    alerts = []
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, timestamp, rule_name, rule_version, src_ip, dst_ip,
                   src_port, dst_port, protocol, detail, severity, confidence, evidence_json
            FROM alerts
            ORDER BY timestamp ASC
            """
        )
        for row in cur.fetchall():
            alerts.append(
                {
                    "id": row[0],
                    "timestamp": row[1],
                    "rule_name": row[2],
                    "rule_version": row[3],
                    "src_ip": row[4],
                    "dst_ip": row[5],
                    "src_port": row[6],
                    "dst_port": row[7],
                    "protocol": row[8],
                    "detail": row[9],
                    "severity": row[10],
                    "confidence": row[11],
                    "evidence_json": row[12],
                }
            )
        conn.close()

    # Rule breakdown
    rule_counts: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {}
    for a in alerts:
        rn = a["rule_name"]
        sev = a["severity"]
        rule_counts[rn] = rule_counts.get(rn, 0) + 1
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Packet count
    pcap_pkts = count_packets(pcap_path)
    pps = pcap_pkts / elapsed

    result = {
        "id": cid,
        "name": entry["name"],
        "family": entry["family"],
        "category": entry["category"],
        "attack_type": entry["attack_type"],
        "target_rules": entry["target_rules"],
        "pcap_path": pcap_path,
        "pcap_size_bytes": entry["size_bytes"],
        "sha256": compute_sha256(pcap_path),
        "packet_count": pcap_pkts,
        "elapsed_seconds": round(elapsed, 3),
        "throughput_pps": round(pps, 1),
        "alert_count": len(alerts),
        "rule_counts": rule_counts,
        "severity_counts": severity_counts,
        "alerts": alerts,
    }
    return result


def export_results(results: List[Dict[str, Any]]):
    """Export standardized CSV and JSON reports."""
    alerts_csv = os.path.join(EXPORTS_DIR, "alerts_summary.csv")
    capture_stats_csv = os.path.join(EXPORTS_DIR, "capture_statistics.csv")
    rule_matrix_csv = os.path.join(EXPORTS_DIR, "rule_coverage_matrix.csv")
    summary_json = os.path.join(EXPORTS_DIR, "evaluation_summary.json")

    # 1. Alerts Summary CSV
    with open(alerts_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "capture_id",
            "category",
            "alert_id",
            "timestamp",
            "rule_name",
            "rule_version",
            "severity",
            "confidence",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "detail",
        ])
        for r in results:
            for a in r["alerts"]:
                writer.writerow([
                    r["id"],
                    r["category"],
                    a["id"],
                    a["timestamp"],
                    a["rule_name"],
                    a.get("rule_version", ""),
                    a["severity"],
                    a["confidence"],
                    a["src_ip"],
                    a["dst_ip"],
                    a["src_port"],
                    a["dst_port"],
                    a["protocol"],
                    a["detail"],
                ])

    # 2. Capture Statistics CSV
    with open(capture_stats_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "capture_id",
            "dataset_family",
            "category",
            "attack_type",
            "pcap_filename",
            "pcap_size_bytes",
            "sha256",
            "packet_count",
            "elapsed_seconds",
            "throughput_pps",
            "alert_count",
            "rules_fired",
        ])
        for r in results:
            writer.writerow([
                r["id"],
                r["family"],
                r["category"],
                r["attack_type"],
                os.path.basename(r["pcap_path"]),
                r["pcap_size_bytes"],
                r["sha256"],
                r["packet_count"],
                r["elapsed_seconds"],
                r["throughput_pps"],
                r["alert_count"],
                ";".join(f"{k}:{v}" for k, v in sorted(r["rule_counts"].items())),
            ])

    # 3. Rule Coverage Matrix CSV
    all_rules = set()
    for r in results:
        all_rules.update(r["rule_counts"].keys())

    rule_stats = {}
    for rule in sorted(all_rules):
        rule_stats[rule] = {
            "total_alerts": 0,
            "attack_alerts": 0,
            "benign_alerts": 0,
            "captures_fired": [],
        }

    for r in results:
        for rule, count in r["rule_counts"].items():
            rule_stats[rule]["total_alerts"] += count
            if r["category"] == "attack":
                rule_stats[rule]["attack_alerts"] += count
            else:
                rule_stats[rule]["benign_alerts"] += count
            rule_stats[rule]["captures_fired"].append(r["id"])

    with open(rule_matrix_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "rule_name",
            "total_alerts",
            "attack_alerts",
            "benign_alerts",
            "captures_fired_count",
            "captures_list",
        ])
        for rule, data in sorted(rule_stats.items()):
            writer.writerow([
                rule,
                data["total_alerts"],
                data["attack_alerts"],
                data["benign_alerts"],
                len(data["captures_fired"]),
                ";".join(data["captures_fired"]),
            ])

    # 4. Canonical Summary JSON
    summary_data = {
        "evaluation_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_captures": len(results),
        "total_packets": sum(r["packet_count"] for r in results),
        "total_size_bytes": sum(r["pcap_size_bytes"] for r in results),
        "total_elapsed_seconds": round(sum(r["elapsed_seconds"] for r in results), 2),
        "average_throughput_pps": round(
            sum(r["packet_count"] for r in results) / max(0.001, sum(r["elapsed_seconds"] for r in results)),
            1,
        ),
        "total_alerts": sum(r["alert_count"] for r in results),
        "attack_alerts": sum(r["alert_count"] for r in results if r["category"] == "attack"),
        "benign_alerts": sum(r["alert_count"] for r in results if r["category"] == "benign"),
        "captures": [
            {
                "id": r["id"],
                "name": r["name"],
                "family": r["family"],
                "category": r["category"],
                "attack_type": r["attack_type"],
                "target_rules": r["target_rules"],
                "pcap_file": os.path.basename(r["pcap_path"]),
                "size_bytes": r["pcap_size_bytes"],
                "sha256": r["sha256"],
                "packet_count": r["packet_count"],
                "elapsed_seconds": r["elapsed_seconds"],
                "throughput_pps": r["throughput_pps"],
                "alert_count": r["alert_count"],
                "rule_counts": r["rule_counts"],
                "severity_counts": r["severity_counts"],
            }
            for r in results
        ],
        "rule_coverage_summary": rule_stats,
    }

    with open(summary_json, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    print("=" * 80)
    print("EXPORTS GENERATED SUCCESSFULLY:")
    print(f"  - Alerts Summary:        {alerts_csv}")
    print(f"  - Capture Statistics:    {capture_stats_csv}")
    print(f"  - Rule Coverage Matrix:  {rule_matrix_csv}")
    print(f"  - Canonical JSON:        {summary_json}")
    print("=" * 80 + "\n")


def print_evaluation_summary(results: List[Dict[str, Any]]):
    """Print clean formatted evaluation table to terminal."""
    print("=" * 110)
    print(f"{'Capture ID':26} | {'Cat':6} | {'Packets':8} | {'Time(s)':7} | {'Speed(pps)':10} | {'Alerts':6} | {'Fired Rules'}")
    print("-" * 110)
    for r in results:
        rules_str = ", ".join(f"{k}:{v}" for k, v in sorted(r["rule_counts"].items())) or "(none)"
        print(
            f"{r['id']:26} | {r['category']:6} | {r['packet_count']:8d} | {r['elapsed_seconds']:7.2f} | "
            f"{r['throughput_pps']:10.1f} | {r['alert_count']:6d} | {rules_str}"
        )
    print("=" * 110)

    total_pkts = sum(r["packet_count"] for r in results)
    total_time = sum(r["elapsed_seconds"] for r in results)
    total_alerts = sum(r["alert_count"] for r in results)
    benign_alerts = sum(r["alert_count"] for r in results if r["category"] == "benign")
    attack_alerts = sum(r["alert_count"] for r in results if r["category"] == "attack")

    print(f"Grand Totals: {len(results)} Captures | {total_pkts:,} Packets | {total_time:.2f}s Elapsed | "
          f"{total_pkts / max(0.001, total_time):.1f} Overall PPS")
    print(f"Alert Summary: {total_alerts} Total Alerts ({attack_alerts} Attack, {benign_alerts} Benign / FP)")
    print("=" * 110 + "\n")


def main():
    parser = argparse.ArgumentParser(description="NetGuard Real-World PCAP Evaluation Suite")
    parser.add_argument("--dry-run", action="store_true", help="Verify files and show plan without running replays")
    parser.add_argument("--only", type=str, default=None, help="Run only a specific capture ID")
    parser.add_argument(
        "--blocklist",
        type=str,
        default=os.path.join(REPO_ROOT, "ids_project/data/test_blocklist.txt"),
        help="Path to test blocklist file",
    )
    args = parser.parse_args()

    setup_directories()
    manifest = verify_manifest()

    if args.dry_run:
        print("[DRY-RUN] Verification complete. All files exist and are ready for execution.")
        return

    if args.only:
        manifest = [m for m in manifest if m["id"] == args.only]
        if not manifest:
            print(f"ERROR: Capture ID '{args.only}' not found in manifest.")
            sys.exit(1)

    print(f"Starting execution of {len(manifest)} captures with preserved timestamps and complete isolation...")
    results = []
    for idx, entry in enumerate(manifest, 1):
        print(f"[{idx}/{len(manifest)}] Replaying: {entry['id']} ({entry['name']})...")
        res = run_single_capture(entry, args.blocklist)
        results.append(res)
        print(f"    --> Done in {res['elapsed_seconds']}s ({res['throughput_pps']:.1f} pps). "
              f"Alerts: {res['alert_count']} ({res['rule_counts']})")

    print_evaluation_summary(results)
    export_results(results)


if __name__ == "__main__":
    main()
