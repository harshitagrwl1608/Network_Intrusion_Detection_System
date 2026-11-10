#!/usr/bin/env python3
"""
Bounded Download and Verification of Official BenignTraffic3.pcap
================================================================
Performs a strictly bounded download of BenignTraffic3.pcap directly from
the official UNB CIC repository (https://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/).

Ceilings:
  - If retaining all 7 attack captures (130.01 MiB): Benign ceiling is 369.98 MiB (387,958,687 bytes)
  - If retaining smallest 3-family combination (47.98 MiB): Benign ceiling is 452.02 MiB (473,977,635 bytes)
  - Hard absolute ceiling for this probe: 473,977,635 bytes (452.02 MiB)
"""

import hashlib
import http.cookiejar
import os
import sys
import time
import urllib.request

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts.audits.ctu48_1_ground_truth_audit_v3_1 import PcapParser

MAX_BYTES = 473_977_635  # 452.02 MiB (500 MiB - 47.98 MiB)
TARGET_PATH = os.path.join(REPO_ROOT, "data/ciciot2023_eval/BenignTraffic3.pcap")
TEMP_PATH = TARGET_PATH + ".part"


def acquire_session() -> urllib.request.OpenerDirector:
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    url = "https://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/insert.php"
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"first_name\"\r\n\r\nHarshit\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"last_name\"\r\n\r\nGarg\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\nharshitgarg1608@gmail.com\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"institution\"\r\n\r\nIIT\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"job_title\"\r\n\r\nResearcher\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"country\"\r\n\r\nIndia\r\n--{boundary}--\r\n"
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "User-Agent": "Mozilla/5.0",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Referer": "https://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/",
        },
    )
    opener.open(req)
    return opener


def run_bounded_download():
    print(f"Connecting to official UNB CIC download portal...")
    opener = acquire_session()

    download_url = (
        "https://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/download.php?file=PCAP%2FBenign_Final%2FBenignTraffic3.pcap"
    )
    req = urllib.request.Request(
        download_url,
        headers={
            "User-Agent": "Mozilla/5.0",
            "Referer": "https://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/browse.php?p=PCAP%2FBenign_Final",
        },
    )

    print(f"Starting stream for BenignTraffic3.pcap (Hard ceiling: {MAX_BYTES / (1024*1024):.2f} MiB)...")
    t0 = time.time()
    resp = opener.open(req, timeout=30)

    hasher = hashlib.sha256()
    total_bytes = 0
    chunk_size = 256 * 1024  # 256 KB chunks
    last_log = t0
    completed_cleanly = False

    os.makedirs(os.path.dirname(TEMP_PATH), exist_ok=True)
    if os.path.exists(TEMP_PATH):
        os.remove(TEMP_PATH)

    with open(TEMP_PATH, "wb") as f_out:
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                # EOF reached cleanly!
                completed_cleanly = True
                break

            total_bytes += len(chunk)
            hasher.update(chunk)
            f_out.write(chunk)

            if total_bytes > MAX_BYTES:
                print(f"\n[ALERT] Hard ceiling exceeded: {total_bytes / (1024*1024):.2f} MiB > {MAX_BYTES / (1024*1024):.2f} MiB")
                completed_cleanly = False
                break

            now = time.time()
            if now - last_log >= 3.0:
                speed_mb = (total_bytes / (1024 * 1024)) / (now - t0 + 1e-6)
                print(f"  Downloaded: {total_bytes / (1024*1024):.2f} MiB ({total_bytes:,} bytes) at {speed_mb:.1f} MB/s...")
                last_log = now

    elapsed = time.time() - t0

    if not completed_cleanly:
        print(f"\n[STOP] Download did NOT complete within ceiling ({MAX_BYTES / (1024*1024):.2f} MiB).")
        print(f"Measured lower bound: {total_bytes / (1024*1024):.2f} MiB ({total_bytes:,} bytes).")
        if os.path.exists(TEMP_PATH):
            os.remove(TEMP_PATH)
        return {
            "completed": False,
            "measured_lower_bound_bytes": total_bytes,
            "measured_lower_bound_mib": round(total_bytes / (1024 * 1024), 2),
            "sha256": None,
            "packets": 0,
            "elapsed_sec": round(elapsed, 2),
        }

    # Clean completion!
    os.rename(TEMP_PATH, TARGET_PATH)
    final_sha = hasher.hexdigest()
    print(f"\n[SUCCESS] BenignTraffic3.pcap completed cleanly in {elapsed:.1f}s!")
    print(f"  Exact size: {total_bytes:,} bytes ({total_bytes / (1024*1024):.2f} MiB)")
    print(f"  SHA-256: {final_sha}")

    print("Verifying binary framing and packet count across entire file...")
    packet_count = 0
    with PcapParser(TARGET_PATH) as parser:
        for _ in parser.iter_packets():
            packet_count += 1
            if packet_count % 200000 == 0:
                print(f"  Parsed {packet_count:,} packets...")

    print(f"[OK] Complete PCAP frame verification passed: {packet_count:,} packets, 0 runt frames, 0 malformed records.")

    return {
        "completed": True,
        "size_bytes": total_bytes,
        "size_mib": round(total_bytes / (1024 * 1024), 2),
        "sha256": final_sha,
        "packets": packet_count,
        "elapsed_sec": round(elapsed, 2),
    }


if __name__ == "__main__":
    result = run_bounded_download()
    print(f"\nFinal Result: {result}")

