#!/usr/bin/env python3
"""
CICIoT2023 Official Inventory & Resource Budget Verification
============================================================
Evaluates availability, structure, sizes, and integrity of candidate PCAP files
from the official UNB CIC repository (https://www.unb.ca/cic/datasets/iotdataset-2023.html).

Verifies whether a selection meeting:
  1. Benign traffic capture
  2. At least three distinct attack families
  3. Aggregate download <= budget ceiling (e.g. 300 MiB or 500 MiB)
  4. Aggregate packets <= 3,000,000
can be satisfied without using truncated 128-byte derivatives or synthetic slicing.
"""

import os
import sys
import hashlib
from typing import Dict, Any, List

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts.audits.ctu48_1_ground_truth_audit_v3_1 import PcapParser


def calculate_sha256(filepath: str) -> str:
    """Calculate SHA-256 digest of a closed file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def validate_pcap_file(filepath: str) -> Dict[str, Any]:
    """
    Validate binary PCAP framing and packet integrity without sampling.
    Returns metadata dictionary including validity status, packet count, and SHA-256.
    """
    if not os.path.exists(filepath):
        return {
            "valid": False,
            "filepath": filepath,
            "error": "File does not exist on disk",
            "size_bytes": 0,
            "size_mib": 0.0,
            "packet_count": 0,
            "sha256": None,
        }

    size = os.path.getsize(filepath)
    sha = calculate_sha256(filepath)
    packet_count = 0

    try:
        with PcapParser(filepath) as parser:
            for _ in parser.iter_packets():
                packet_count += 1
        return {
            "valid": True,
            "filepath": filepath,
            "size_bytes": size,
            "size_mib": round(size / (1024 * 1024), 2),
            "packet_count": packet_count,
            "sha256": sha,
            "error": None,
        }
    except Exception as e:
        return {
            "valid": False,
            "filepath": filepath,
            "size_bytes": size,
            "size_mib": round(size / (1024 * 1024), 2),
            "packet_count": packet_count,
            "sha256": sha,
            "error": f"{type(e).__name__}: {e}",
        }


def calculate_inventory_budget(
    attack_candidates: List[Dict[str, Any]],
    benign_candidates: List[Dict[str, Any]],
    download_budget_mib: float = 300.0,
    packet_budget: int = 3000000,
) -> Dict[str, Any]:
    """
    Evaluate candidate PCAP selections against resource budgets and diversity invariants.
    Pure calculation logic suitable for automated validation.
    """
    # Group attack files by distinct family
    families = {}
    total_attack_bytes = 0
    total_attack_pkts = 0

    for ac in attack_candidates:
        fam = ac.get("category", "Unknown")
        sz = ac.get("size_bytes", 0)
        pkts = ac.get("packet_count", 0)
        total_attack_bytes += sz
        total_attack_pkts += pkts
        if fam not in families or sz < families[fam]["size_bytes"]:
            families[fam] = ac

    has_three_families = len(families) >= 3

    # Smallest 3 distinct attack families
    if has_three_families:
        sorted_fams = sorted(families.values(), key=lambda x: x.get("size_bytes", 0))
        smallest_3 = sorted_fams[:3]
        smallest_3_bytes = sum(x.get("size_bytes", 0) for x in smallest_3)
        smallest_3_pkts = sum(x.get("packet_count", 0) for x in smallest_3)
        smallest_3_mib = round(smallest_3_bytes / (1024 * 1024), 2)
    else:
        smallest_3 = []
        smallest_3_bytes = 0
        smallest_3_pkts = 0
        smallest_3_mib = 0.0

    # Smallest benign candidate
    if benign_candidates:
        smallest_benign = min(benign_candidates, key=lambda x: x.get("size_bytes", 0))
        smallest_benign_bytes = smallest_benign.get("size_bytes", 0)
        smallest_benign_mib = round(smallest_benign_bytes / (1024 * 1024), 2)
        smallest_benign_pkts = smallest_benign.get("packet_count", 0)
    else:
        smallest_benign = None
        smallest_benign_bytes = 0
        smallest_benign_mib = 0.0
        smallest_benign_pkts = 0

    combined_min_bytes = smallest_3_bytes + smallest_benign_bytes
    combined_min_mib = round(combined_min_bytes / (1024 * 1024), 2)
    combined_min_pkts = smallest_3_pkts + smallest_benign_pkts

    reasons = []
    budget_exceeded = False

    if not has_three_families:
        budget_exceeded = True
        reasons.append(f"Fewer than 3 distinct attack families present ({len(families)} available)")

    if combined_min_mib > download_budget_mib:
        budget_exceeded = True
        reasons.append(
            f"Combined size ({combined_min_mib} MiB) exceeds download ceiling ({download_budget_mib} MiB)"
        )

    if combined_min_pkts > packet_budget:
        budget_exceeded = True
        reasons.append(
            f"Combined packet count ({combined_min_pkts:,}) exceeds limit ({packet_budget:,})"
        )

    return {
        "distinct_family_count": len(families),
        "distinct_families": list(families.keys()),
        "has_three_families": has_three_families,
        "total_attack_mib": round(total_attack_bytes / (1024 * 1024), 2),
        "total_attack_packets": total_attack_pkts,
        "smallest_3_family_mib": smallest_3_mib,
        "smallest_3_family_packets": smallest_3_pkts,
        "smallest_benign_mib": smallest_benign_mib,
        "combined_min_mib": combined_min_mib,
        "combined_min_packets": combined_min_pkts,
        "download_budget_mib": download_budget_mib,
        "packet_budget": packet_budget,
        "budget_exceeded": budget_exceeded,
        "stop_condition_triggered": budget_exceeded,
        "reasons": reasons,
    }


def get_inventory_data(data_dir: str = None) -> Dict[str, Any]:
    """Scan local directory for official candidate PCAPs if present on disk."""
    if data_dir is None:
        data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../data/ciciot2023_eval"))

    candidates_meta = [
        {"filename": "Recon-PingSweep.pcap", "category": "Reconnaissance"},
        {"filename": "SqlInjection.pcap", "category": "Web-based"},
        {"filename": "XSS.pcap", "category": "Web-based"},
        {"filename": "CommandInjection.pcap", "category": "Web-based"},
        {"filename": "Uploading_Attack.pcap", "category": "Web-based"},
        {"filename": "BrowserHijacking.pcap", "category": "Web-based"},
        {"filename": "DictionaryBruteForce.pcap", "category": "Brute Force"},
    ]

    verified = []
    if os.path.exists(data_dir):
        for c in candidates_meta:
            p = os.path.join(data_dir, c["filename"])
            if os.path.exists(p):
                res = validate_pcap_file(p)
                res["category"] = c["category"]
                res["filename"] = c["filename"]
                verified.append(res)

    benign_inventory = [
        {
            "filename": "BenignTraffic3.pcap",
            "matching_csv": "BenignTraffic3.pcap.csv (25.61 MiB)",
            "estimated_pcap_size_mib": "> 260.00 MiB (exceeded 260 MiB threshold)",
            "size_bytes": 272629760,  # Lower bound observed
            "packet_count": 422041,
            "status": "Exceeds remaining download budget when paired with 3 attack families",
        },
        {
            "filename": "BenignTraffic1.pcap",
            "matching_csv": "BenignTraffic1.pcap.csv (58.42 MiB)",
            "estimated_pcap_size_mib": "~550 - 650 MiB",
            "size_bytes": 600 * 1024 * 1024,
            "packet_count": 1000000,
            "status": "Exceeds entire budget alone",
        },
    ]

    budget_check = calculate_inventory_budget(
        verified, benign_inventory, download_budget_mib=300.0, packet_budget=3000000
    )

    return {
        "downloaded_attack_pcaps": verified,
        "benign_inventory": benign_inventory,
        "budget_evaluation": budget_check,
    }


if __name__ == "__main__":
    res = get_inventory_data()
    print("=== CICIoT2023 INVENTORY VERIFICATION ===")
    print(f"Downloaded attack PCAPs: {len(res['downloaded_attack_pcaps'])}")
    for p in res['downloaded_attack_pcaps']:
        print(f"  - {p['filename']} ({p.get('category')}): {p['size_mib']} MiB, {p['packet_count']:,} pkts")
    b_eval = res["budget_evaluation"]
    print(f"Smallest 3-family attack combination: {b_eval['smallest_3_family_mib']} MiB")
    print(f"Smallest benign capture: {b_eval['smallest_benign_mib']} MiB")
    print(f"Combined minimum volume: {b_eval['combined_min_mib']} MiB (Limit: {b_eval['download_budget_mib']} MiB)")
    print(f"Stop condition triggered: {b_eval['stop_condition_triggered']}")
    if b_eval['reasons']:
        print("Reasons:")
        for r in b_eval['reasons']:
            print(f"  - {r}")
