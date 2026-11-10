#!/usr/bin/env python3
"""
Build Final Ground-Truth Benchmark Manifest
===========================================
Inventories all extracted GeNIS PCAPNG files, assigns ground-truth mapping,
incorporates verified local captures, computes hashes, and writes:
  data/external_benchmarks/ground_truth/manifest.csv
"""

import csv
import glob
import hashlib
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
GENIS_PACKETS_DIR = os.path.join(REPO_ROOT, "data/external_benchmarks/genis/1-packets")
GENIS_GT_FILE = os.path.join(REPO_ROOT, "data/external_benchmarks/genis/0-info/0-info/genis-ground-truth.csv")
MANIFEST_OUT = os.path.join(REPO_ROOT, "data/external_benchmarks/ground_truth/manifest.csv")


def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def build_manifest():
    os.makedirs(os.path.dirname(MANIFEST_OUT), exist_ok=True)
    manifest_rows = []
    total_pcap_bytes = 0

    # 1. Inventory GeNIS raw captures
    genis_files = sorted(
        glob.glob(os.path.join(GENIS_PACKETS_DIR, "**/*.pcapng"), recursive=True) +
        glob.glob(os.path.join(GENIS_PACKETS_DIR, "**/*.pcap"), recursive=True)
    )

    print(f"Discovered {len(genis_files)} GeNIS packet captures in {GENIS_PACKETS_DIR}:")
    for fpath in genis_files:
        base = os.path.basename(fpath)
        sz = os.path.getsize(fpath)
        total_pcap_bytes += sz
        sha = compute_sha256(fpath)
        cid = "genis_" + os.path.splitext(base)[0].replace("-", "_").replace(".", "_")

        # Determine category and scenario from filename
        lower_name = base.lower()
        if "benign" in lower_name:
            cat = "benign"
            scenario = "benign_activity"
            target_rules = "FP_BENIGN_VERIFICATION"
        else:
            cat = "attack"
            scenario = os.path.splitext(base)[0]
            target_rules = "FLOW_MATCHED_RULES"

        manifest_rows.append({
            "capture_id": cid,
            "name": f"GeNIS {base}",
            "family": "GeNIS",
            "category": cat,
            "scenario": scenario,
            "pcap_path": os.path.relpath(fpath, REPO_ROOT),
            "ground_truth_source": os.path.relpath(GENIS_GT_FILE, REPO_ROOT),
            "target_rules": target_rules,
            "size_bytes": sz,
            "sha256": sha,
            "notes": "Official GeNIS raw capture with flow-level ground truth",
        })
        print(f"  [GeNIS] {base:35} | {sz / (1024*1024):7.2f} MB | {sha[:16]}")

    # 2. Add verified local multi-family captures
    local_additions = [
        # CTU-IoT-23 Benign Doorlock
        {
            "capture_id": "benign_iot23_doorlock",
            "name": "IoT-23 Honeypot Somfy Doorlock",
            "family": "CTU-IoT-23",
            "category": "benign",
            "scenario": "benign_iot_hardware",
            "pcap_path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/iot23_honeypot_4_1.pcap",
            "ground_truth_source": "",
            "target_rules": "FP_BENIGN_VERIFICATION",
            "notes": "Verified authentic Somfy smart doorlock operational IoT traffic",
        },
        # CICIoT2023 Attack Scenarios
        {
            "capture_id": "ciciot_pingsweep",
            "name": "CICIoT2023 Recon-PingSweep",
            "family": "CICIoT2023",
            "category": "attack",
            "scenario": "recon_pingsweep",
            "pcap_path": "data/ciciot2023_eval/Recon-PingSweep.pcap",
            "ground_truth_source": "",
            "target_rules": "ICMP_SWEEP",
            "notes": "Official CICIoT2023 ICMP echo sweep reconnaissance",
        },
        {
            "capture_id": "ciciot_sqli",
            "name": "CICIoT2023 SqlInjection",
            "family": "CICIoT2023",
            "category": "attack",
            "scenario": "web_sqli",
            "pcap_path": "data/ciciot2023_eval/SqlInjection.pcap",
            "ground_truth_source": "",
            "target_rules": "PAYLOAD_HIT",
            "notes": "Official CICIoT2023 SQL injection web exploit",
        },
        {
            "capture_id": "ciciot_xss",
            "name": "CICIoT2023 XSS",
            "family": "CICIoT2023",
            "category": "attack",
            "scenario": "web_xss",
            "pcap_path": "data/ciciot2023_eval/XSS.pcap",
            "ground_truth_source": "",
            "target_rules": "PAYLOAD_HIT",
            "notes": "Official CICIoT2023 Cross-Site Scripting web exploit",
        },
        {
            "capture_id": "ciciot_cmdinj",
            "name": "CICIoT2023 CommandInjection",
            "family": "CICIoT2023",
            "category": "attack",
            "scenario": "web_command_injection",
            "pcap_path": "data/ciciot2023_eval/CommandInjection.pcap",
            "ground_truth_source": "",
            "target_rules": "PAYLOAD_HIT;NON_DNS_TRAFFIC_ON_DNS_PORT",
            "notes": "Official CICIoT2023 OS command injection & reverse shell",
        },
        {
            "capture_id": "ciciot_upload",
            "name": "CICIoT2023 Uploading_Attack",
            "family": "CICIoT2023",
            "category": "attack",
            "scenario": "web_upload_webshell",
            "pcap_path": "data/ciciot2023_eval/Uploading_Attack.pcap",
            "ground_truth_source": "",
            "target_rules": "PAYLOAD_HIT",
            "notes": "Official CICIoT2023 Arbitrary file upload / PHP web shell",
        },
        {
            "capture_id": "ciciot_browserhijack",
            "name": "CICIoT2023 BrowserHijacking",
            "family": "CICIoT2023",
            "category": "attack",
            "scenario": "web_browser_hijack",
            "pcap_path": "data/ciciot2023_eval/BrowserHijacking.pcap",
            "ground_truth_source": "",
            "target_rules": "PAYLOAD_HIT;UDP_FLOOD",
            "notes": "Official CICIoT2023 Client-side browser hijacking & redirection",
        },
        {
            "capture_id": "ciciot_bruteforce",
            "name": "CICIoT2023 DictionaryBruteForce",
            "family": "CICIoT2023",
            "category": "attack",
            "scenario": "auth_bruteforce",
            "pcap_path": "data/ciciot2023_eval/DictionaryBruteForce.pcap",
            "ground_truth_source": "",
            "target_rules": "BRUTE_FORCE;ARP_SPOOF",
            "notes": "Official CICIoT2023 SSH credential brute force & ARP poisoning",
        },
        # Protocol Anomaly Fixtures
        {
            "capture_id": "attack_ws_teardrop",
            "name": "Wireshark Teardrop IP Exploit",
            "family": "Wireshark-Sample",
            "category": "attack",
            "scenario": "ip_fragment_overlap",
            "pcap_path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/ws_teardrop.pcap",
            "ground_truth_source": "",
            "target_rules": "IP_FRAGMENT_ANOMALY",
            "notes": "Wireshark Teardrop overlapping IP fragment reassembly crash exploit",
        },
        {
            "capture_id": "attack_ws_dns_remoteshell",
            "name": "Wireshark DNS Remote Shell",
            "family": "Wireshark-Sample",
            "category": "attack",
            "scenario": "dns_port_backdoor",
            "pcap_path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/ws_dns_remoteshell.pcap",
            "ground_truth_source": "",
            "target_rules": "NON_DNS_TRAFFIC_ON_DNS_PORT",
            "notes": "Wireshark non-DNS interactive command shell over port 53",
        },
        {
            "capture_id": "attack_foxit_log4shell",
            "name": "Fox-IT Log4Shell JNDI RCE Exploit",
            "family": "Fox-IT",
            "category": "attack",
            "scenario": "log4shell_jndi_rce",
            "pcap_path": "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/foxit_log4shell.pcap",
            "ground_truth_source": "",
            "target_rules": "PAYLOAD_HIT",
            "notes": "CVE-2021-44228 Log4Shell JNDI LDAP lookup exploit payload",
        },
    ]

    for item in local_additions:
        p = item["pcap_path"]
        if not os.path.isabs(p):
            p = os.path.abspath(os.path.join(REPO_ROOT, p))
        if os.path.exists(p):
            sz = os.path.getsize(p)
            total_pcap_bytes += sz
            sha = compute_sha256(p)
            entry = dict(item)
            entry["size_bytes"] = sz
            entry["sha256"] = sha
            manifest_rows.append(entry)
            print(f"  [Local] {os.path.basename(p):35} | {sz / (1024*1024):7.2f} MB | {sha[:16]}")

    with open(MANIFEST_OUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "capture_id", "name", "family", "category", "scenario",
            "pcap_path", "ground_truth_source", "target_rules",
            "size_bytes", "sha256", "notes"
        ])
        writer.writeheader()
        for r in manifest_rows:
            writer.writerow(r)

    print("=" * 80)
    print(f"MANIFEST GENERATED: {MANIFEST_OUT}")
    print(f"Total Captures: {len(manifest_rows)}")
    print(f"Total Extracted PCAP Volume: {total_pcap_bytes / (1024**3):.3f} GiB ({total_pcap_bytes:,} bytes)")
    if total_pcap_bytes >= 1_073_741_824:
        print(f"VERIFICATION PASS: Extracted volume >= 1 GiB requirement satisfied!")
    else:
        print(f"VERIFICATION PENDING: Extracted volume is currently below 1 GiB ({total_pcap_bytes / (1024**3):.3f} GiB)")
    print("=" * 80)


if __name__ == "__main__":
    build_manifest()

