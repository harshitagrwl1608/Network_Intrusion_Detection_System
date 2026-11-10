"""
Unit tests for NetGuard IDS Ground-Truth Benchmark scoring integrity.
Verifies bidirectional 5-tuple flow matching, port verification, incomplete record
handling, conflicting labels, authoritative 23-rule catalog, and exact 582 alert reconciliation.
"""

import os
import sys
import json
import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts.evaluation.run_ground_truth_benchmark import (
    detect_pcap_format,
    ALL_23_RULES,
)
from scripts.evaluation.rescore_benchmark import (
    AUTHORITATIVE_23_RULES,
    GroundTruthDatabase,
    FlowMatchingEngine,
)


def test_detect_pcap_format_classic(tmp_path):
    pcap_file = tmp_path / "classic.pcap"
    # Classic libpcap magic little endian: 0xd4c3b2a1
    pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16)
    assert detect_pcap_format(str(pcap_file)) == "pcap"


def test_detect_pcap_format_pcapng(tmp_path):
    pcapng_file = tmp_path / "sample.pcapng"
    # PCAPNG Section Header Block magic: 0x0a0d0d0a
    pcapng_file.write_bytes(b"\x0a\x0d\x0d\x0a\x1c\x00\x00\x00" + b"\x00" * 20)
    assert detect_pcap_format(str(pcapng_file)) == "pcapng"


def test_authoritative_23_rules_catalog():
    """Verify that all 23 authoritative rules match RuleEngine and TCP_STEALTH_SCAN is present."""
    assert len(AUTHORITATIVE_23_RULES) == 23
    assert len(ALL_23_RULES) == 23
    assert "TCP_STEALTH_SCAN" in AUTHORITATIVE_23_RULES
    assert "TCP_STEALTH_SCAN" in ALL_23_RULES
    assert "WEBSHELL_INJECTION" not in AUTHORITATIVE_23_RULES
    assert "WEBSHELL_INJECTION" not in ALL_23_RULES


def test_flow_matching_bidirectional_and_port(tmp_path):
    gt_file = tmp_path / "test_gt.csv"
    gt_file.write_text(
        "StartTime,LastTime,Proto,SrcAddr,Sport,DstAddr,Dport,Label\n"
        "100.0,110.0,udp,192.168.1.10,53000,192.168.1.20,53,recon-dns\n"
    )
    db = GroundTruthDatabase(str(gt_file))
    engine = FlowMatchingEngine(db, grace_window_sec=2.0)

    # 1. Forward match
    alert_fwd = {
        "timestamp": 105.0,
        "rule_name": "DNS_ANOMALY",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "src_port": 53000,
        "dst_port": 53,
        "protocol": "UDP",
    }
    status, reason, label, flow_id = engine.match_alert(alert_fwd, "attack", True, "cap1")
    assert status == "TP"
    assert label == "recon-dns"

    # 2. Reverse match (swapped ports and IPs)
    alert_rev = {
        "timestamp": 105.0,
        "rule_name": "DNS_ANOMALY",
        "src_ip": "192.168.1.20",
        "dst_ip": "192.168.1.10",
        "src_port": 53,
        "dst_port": 53000,
        "protocol": "UDP",
    }
    status, reason, label, flow_id = engine.match_alert(alert_rev, "attack", True, "cap1")
    assert status == "TP"

    # 3. Wrong port -> unscorable/unmatched
    alert_wrong_port = {
        "timestamp": 105.0,
        "rule_name": "DNS_ANOMALY",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "src_port": 53000,
        "dst_port": 80,  # Wrong port!
        "protocol": "UDP",
    }
    status, reason, label, flow_id = engine.match_alert(alert_wrong_port, "attack", True, "cap1")
    assert status == "UNSCORABLE_INCIDENTAL"

    # 4. Wrong protocol -> unscorable/unmatched
    alert_wrong_proto = {
        "timestamp": 105.0,
        "rule_name": "DNS_ANOMALY",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "src_port": 53000,
        "dst_port": 53,
        "protocol": "TCP",  # Wrong protocol!
    }
    status, reason, label, flow_id = engine.match_alert(alert_wrong_proto, "attack", True, "cap1")
    assert status == "UNSCORABLE_INCIDENTAL"


def test_flow_matching_incomplete_gt_record(tmp_path):
    """Incomplete GT record (missing DstAddr) must be marked unscorable."""
    gt_file = tmp_path / "incomplete_gt.csv"
    gt_file.write_text(
        "StartTime,LastTime,Proto,SrcAddr,Sport,DstAddr,Dport,Label\n"
        "100.0,110.0,tcp,192.168.1.10,,,recon-nmap\n"
    )
    db = GroundTruthDatabase(str(gt_file))
    engine = FlowMatchingEngine(db, grace_window_sec=2.0)

    alert = {
        "timestamp": 105.0,
        "rule_name": "PORT_SCAN",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "src_port": 50000,
        "dst_port": 80,
        "protocol": "TCP",
    }
    status, reason, label, flow_id = engine.match_alert(alert, "attack", True, "cap1")
    assert status == "UNSCORABLE_INCIDENTAL"
    assert "incomplete_ground_truth_record" in reason


def test_flow_matching_conflicting_labels(tmp_path):
    """Overlapping intervals with conflicting attack labels must be marked unscorable."""
    gt_file = tmp_path / "conflicting_gt.csv"
    gt_file.write_text(
        "StartTime,LastTime,Proto,SrcAddr,Sport,DstAddr,Dport,Label\n"
        "100.0,110.0,tcp,192.168.1.10,,192.168.1.20,,recon-nmap\n"
        "100.0,110.0,tcp,192.168.1.10,,192.168.1.20,80,dos-slowloris\n"
    )
    db = GroundTruthDatabase(str(gt_file))
    engine = FlowMatchingEngine(db, grace_window_sec=2.0)

    alert = {
        "timestamp": 105.0,
        "rule_name": "PORT_SCAN",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "protocol": "TCP",
        "evidence_json": json.dumps({"transport": "TCP", "target_host": "192.168.1.20"}),
    }
    status, reason, label, flow_id = engine.match_alert(alert, "attack", True, "cap1")
    assert status == "UNSCORABLE_INCIDENTAL"
    assert "conflicting_ground_truth_labels" in reason


def test_aggregate_rule_evidence_support(tmp_path):
    """Aggregate rules (BRUTE_FORCE, SYN_FLOOD) verify evidence auth_port and target_port."""
    gt_file = tmp_path / "brute_gt.csv"
    gt_file.write_text(
        "StartTime,LastTime,Proto,SrcAddr,Sport,DstAddr,Dport,Label\n"
        "100.0,110.0,,192.168.1.10,,192.168.1.20,22,bruteforce-ssh\n"
        "200.0,210.0,,192.168.1.10,,192.168.1.20,80,dos-pushack\n"
    )
    db = GroundTruthDatabase(str(gt_file))
    engine = FlowMatchingEngine(db, grace_window_sec=2.0)

    # 1. BRUTE_FORCE matching auth_port 22
    alert_bf = {
        "timestamp": 105.0,
        "rule_name": "BRUTE_FORCE",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "src_port": 45000,
        "dst_port": 22,
        "protocol": "TCP",
        "evidence_json": json.dumps({"auth_port": 22}),
    }
    status, reason, label, flow_id = engine.match_alert(alert_bf, "attack", True, "cap1")
    assert status == "TP"
    assert label == "bruteforce-ssh"

    # 2. SYN_FLOOD matching port 80
    alert_syn = {
        "timestamp": 205.0,
        "rule_name": "SYN_FLOOD",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "src_port": 45000,
        "dst_port": 80,
        "protocol": "TCP",
        "evidence_json": json.dumps({"target_port": 80}),
    }
    status, reason, label, flow_id = engine.match_alert(alert_syn, "attack", True, "cap1")
    assert status == "TP"
    assert label == "dos-pushack"


def test_benchmark_reconciliation_offline():
    """Verify that the generated benchmark results reconcile 100% across all 582 alerts."""
    summary_path = os.path.join(REPO_ROOT, "results/final_ground_truth_benchmark/evaluation_summary.json")
    assert os.path.exists(summary_path)

    with open(summary_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rec = data["reconciliation"]
    assert rec["total_alerts"] == 582
    assert rec["reconciles_exactly"] is True
    assert rec["tp_alerts"] == 156
    assert rec["fp_alerts"] == 137
    assert rec["unscorable_flow_alerts"] == 26
    assert rec["scenario_alerts"] == 263
    assert rec["unmatched_attack_alerts"] == 0
    assert (
        rec["tp_alerts"]
        + rec["fp_alerts"]
        + rec["unscorable_flow_alerts"]
        + rec["scenario_alerts"]
        + rec["unmatched_attack_alerts"]
        == 582
    )
