import sys
import os
import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts.evaluation.ciciot2023_inventory_audit import get_inventory_data

def test_ciciot2023_inventory_structure():
    data = get_inventory_data()
    assert "downloaded_attack_pcaps" in data
    assert "benign_inventory" in data
    assert data["hard_download_budget_mib"] == 300.0
    assert len(data["benign_inventory"]) == 4

    # Verify each attack file has valid attributes
    for p in data["downloaded_attack_pcaps"]:
        assert p["valid"] is True
        assert p["size_bytes"] > 0
        assert p["packet_count"] > 0
        assert len(p["sha256"]) == 64

    # Verify stop condition flag
    assert data["budget_exceeded"] is True
    assert data["smallest_3_family_attack_mib"] + 260.0 > 300.0
