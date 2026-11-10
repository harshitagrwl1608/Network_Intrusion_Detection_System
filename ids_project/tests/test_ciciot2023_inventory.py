"""
NetGuard IDS — Test Suite for CICIoT2023 Inventory & Budget Validation
Exercises real PCAP framing verification and resource budget logic using
controlled synthetic fixtures without requiring private dataset files to exist.
"""

import os
import struct
import sys
import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts.evaluation.ciciot2023_inventory_audit import (
    validate_pcap_file,
    calculate_inventory_budget,
)


def _create_synthetic_pcap(filepath: str, packet_count: int = 3, truncate_last: bool = False):
    """Generate a synthetically valid PCAP file with known packet headers."""
    # Global header: magic (little-endian), v2.4, thiszone=0, sigfigs=0, snaplen=65535, DLT_EN10MB (1)
    global_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    # 14-byte Ethernet + 20-byte IP header (IPv4, total length 34, TCP protocol)
    payload = b"\x00" * 14 + b"\x45\x00\x00\x22\x00\x01\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02"

    with open(filepath, "wb") as f:
        f.write(global_hdr)
        for i in range(packet_count):
            incl_len = len(payload)
            orig_len = len(payload)
            ts_sec = 1700000000 + i
            ts_usec = i * 1000

            if truncate_last and i == packet_count - 1:
                # Write a packet header claiming 34 bytes, but write only 10 bytes of payload (truncated!)
                pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
                f.write(pkt_hdr)
                f.write(payload[:10])
            else:
                pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
                f.write(pkt_hdr)
                f.write(payload)


def test_01_validate_valid_pcap_fixture(tmp_path):
    """Test validate_pcap_file on a completely intact synthetic PCAP fixture."""
    pcap_path = str(tmp_path / "valid.pcap")
    _create_synthetic_pcap(pcap_path, packet_count=5, truncate_last=False)

    res = validate_pcap_file(pcap_path)
    assert res["valid"] is True
    assert res["packet_count"] == 5
    assert res["size_bytes"] == len(open(pcap_path, "rb").read())
    assert res["sha256"] is not None and len(res["sha256"]) == 64
    assert res["error"] is None


def test_02_validate_truncated_pcap_fixture(tmp_path):
    """Test validate_pcap_file correctly detects truncated packet payloads and fails closed."""
    pcap_path = str(tmp_path / "truncated.pcap")
    _create_synthetic_pcap(pcap_path, packet_count=5, truncate_last=True)

    res = validate_pcap_file(pcap_path)
    assert res["valid"] is False
    assert "Truncated PCAP packet data" in res["error"] or "ValueError" in res["error"]
    assert res["packet_count"] == 4  # Parsed 4 valid packets before truncation


def test_03_validate_missing_file():
    """Test validate_pcap_file on a non-existent filepath fails safely."""
    res = validate_pcap_file("/nonexistent/file/capture.pcap")
    assert res["valid"] is False
    assert res["error"] == "File does not exist on disk"
    assert res["packet_count"] == 0


def test_04_budget_calculation_compliant():
    """Test calculate_inventory_budget when under download and packet limits with >= 3 families."""
    attacks = [
        {"filename": "a.pcap", "category": "Recon", "size_bytes": 10 * 1024 * 1024, "packet_count": 10000},
        {"filename": "b.pcap", "category": "Web", "size_bytes": 15 * 1024 * 1024, "packet_count": 20000},
        {"filename": "c.pcap", "category": "BruteForce", "size_bytes": 20 * 1024 * 1024, "packet_count": 30000},
    ]
    benign = [
        {"filename": "benign.pcap", "size_bytes": 100 * 1024 * 1024, "packet_count": 100000}
    ]

    res = calculate_inventory_budget(attacks, benign, download_budget_mib=300.0, packet_budget=3000000)
    assert res["has_three_families"] is True
    assert res["budget_exceeded"] is False
    assert res["stop_condition_triggered"] is False
    # Combined = (10 + 15 + 20) + 100 = 145 MiB <= 300 MiB
    assert res["combined_min_mib"] == 145.0
    assert len(res["reasons"]) == 0


def test_05_budget_calculation_insufficient_families():
    """Test calculate_inventory_budget triggers stop condition when fewer than 3 families exist."""
    attacks = [
        {"filename": "a.pcap", "category": "Web", "size_bytes": 10 * 1024 * 1024, "packet_count": 10000},
        {"filename": "b.pcap", "category": "Web", "size_bytes": 15 * 1024 * 1024, "packet_count": 20000},
    ]
    benign = [
        {"filename": "benign.pcap", "size_bytes": 50 * 1024 * 1024, "packet_count": 50000}
    ]

    res = calculate_inventory_budget(attacks, benign, download_budget_mib=300.0, packet_budget=3000000)
    assert res["has_three_families"] is False
    assert res["budget_exceeded"] is True
    assert res["stop_condition_triggered"] is True
    assert any("Fewer than 3 distinct attack families" in r for r in res["reasons"])


def test_06_budget_calculation_download_ceiling_exceeded():
    """Test calculate_inventory_budget triggers stop condition when combined size exceeds budget."""
    attacks = [
        {"filename": "ping.pcap", "category": "Recon", "size_bytes": 8 * 1024 * 1024, "packet_count": 20000},
        {"filename": "upload.pcap", "category": "Web", "size_bytes": 4 * 1024 * 1024, "packet_count": 10000},
        {"filename": "brute.pcap", "category": "BruteForce", "size_bytes": 40 * 1024 * 1024, "packet_count": 100000},
    ]
    # Benign capture is 270 MiB; combined = 52 MiB + 270 MiB = 322 MiB > 300 MiB limit
    benign = [
        {"filename": "BenignTraffic3.pcap", "size_bytes": 270 * 1024 * 1024, "packet_count": 500000}
    ]

    res = calculate_inventory_budget(attacks, benign, download_budget_mib=300.0, packet_budget=3000000)
    assert res["has_three_families"] is True
    assert res["budget_exceeded"] is True
    assert res["stop_condition_triggered"] is True
    assert any("exceeds download ceiling" in r for r in res["reasons"])


def test_07_budget_calculation_packet_ceiling_exceeded():
    """Test calculate_inventory_budget triggers stop condition when combined packet count exceeds 3 million."""
    attacks = [
        {"filename": "a.pcap", "category": "Recon", "size_bytes": 10 * 1024 * 1024, "packet_count": 1500000},
        {"filename": "b.pcap", "category": "Web", "size_bytes": 10 * 1024 * 1024, "packet_count": 1000000},
        {"filename": "c.pcap", "category": "BruteForce", "size_bytes": 10 * 1024 * 1024, "packet_count": 1000000},
    ]
    # Total packets = 3,500,000 > 3,000,000 limit
    benign = [
        {"filename": "benign.pcap", "size_bytes": 10 * 1024 * 1024, "packet_count": 500000}
    ]

    res = calculate_inventory_budget(attacks, benign, download_budget_mib=300.0, packet_budget=3000000)
    assert res["budget_exceeded"] is True
    assert res["stop_condition_triggered"] is True
    assert any("exceeds limit" in r for r in res["reasons"])
