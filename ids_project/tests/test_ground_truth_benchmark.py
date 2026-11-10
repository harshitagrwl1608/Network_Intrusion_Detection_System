"""
Unit tests for scripts/evaluation/run_ground_truth_benchmark.py
"""

import os
import sys
import tempfile
import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts.evaluation.run_ground_truth_benchmark import (
    detect_pcap_format,
    GroundTruthMatcher,
    LABEL_TO_RULES_MAP,
    ALL_23_RULES,
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


def test_ground_truth_matcher_tp(tmp_path):
    gt_file = tmp_path / "sample_gt.csv"
    gt_file.write_text(
        "StartTime,LastTime,Proto,SrcAddr,Sport,DstAddr,Dport,Label\n"
        "100.0,110.0,TCP,192.168.1.10,50000,192.168.1.20,22,bruteforce-ssh\n"
    )
    matcher = GroundTruthMatcher(str(gt_file))

    # Alert matching the label
    alert = {
        "timestamp": 105.0,
        "rule_name": "BRUTE_FORCE",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "dst_port": 22,
        "protocol": "TCP",
    }
    status, reason, label = matcher.match_alert(alert, "attack")
    assert status == "TP"
    assert label == "bruteforce-ssh"
    assert "matched_label:bruteforce-ssh" in reason


def test_ground_truth_matcher_incidental(tmp_path):
    gt_file = tmp_path / "sample_gt.csv"
    gt_file.write_text(
        "StartTime,LastTime,Proto,SrcAddr,Sport,DstAddr,Dport,Label\n"
        "100.0,110.0,TCP,192.168.1.10,50000,192.168.1.20,22,bruteforce-ssh\n"
    )
    matcher = GroundTruthMatcher(str(gt_file))

    # Alert outside the expected rule during an attack interval
    alert = {
        "timestamp": 105.0,
        "rule_name": "DNS_ANOMALY",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "dst_port": 53,
        "protocol": "UDP",
    }
    status, reason, label = matcher.match_alert(alert, "attack")
    assert status == "UNSCORABLE_INCIDENTAL"
    assert label == "bruteforce-ssh"


def test_ground_truth_matcher_benign(tmp_path):
    matcher = GroundTruthMatcher(None)
    alert = {
        "timestamp": 105.0,
        "rule_name": "PORT_SCAN",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
    }
    status, reason, label = matcher.match_alert(alert, "benign")
    assert status == "FP"
    assert reason == "alert_in_benign_capture"


def test_all_23_rules_catalog():
    assert len(ALL_23_RULES) == 23
    assert "ARP_SPOOF" in ALL_23_RULES
    assert "BRUTE_FORCE" in ALL_23_RULES
    assert "PORT_SCAN" in ALL_23_RULES
    assert "SYN_FLOOD" in ALL_23_RULES
