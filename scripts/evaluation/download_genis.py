#!/usr/bin/env python3
"""
GeNIS Benchmark Acquisition & Verification
===========================================
Downloads and cryptographically verifies:
  - 0-info.zip (already fetched)
  - 2-flows.zip (labeled flow files)
  - 1-packets.zip (raw PCAPNG captures)
from Zenodo record 14919237 (GeNIS: GECAD Network Intrusion Scenarios).

Verifies publisher MD5 checksums, unpacks archives into data/external_benchmarks/genis/,
and inventories all extracted PCAP/PCAPNG files.
"""

import hashlib
import json
import os
import sys
import time
import urllib.request
import zipfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
ARCHIVES_DIR = os.path.join(REPO_ROOT, "data/external_benchmarks/archives")
GENIS_DIR = os.path.join(REPO_ROOT, "data/external_benchmarks/genis")

FILES_TO_DOWNLOAD = [
    {
        "name": "2-flows.zip",
        "url": "https://zenodo.org/api/records/14919237/files/2-flows.zip/content",
        "expected_size": 380755720,
        "expected_md5": "063b7a2ec6e6b73cc302151d2b3ba6d7",
        "target_path": os.path.join(ARCHIVES_DIR, "2-flows.zip"),
        "extract_dir": os.path.join(GENIS_DIR, "2-flows"),
    },
    {
        "name": "1-packets.zip",
        "url": "https://zenodo.org/api/records/14919237/files/1-packets.zip/content",
        "expected_size": 1028741083,
        "expected_md5": "5afbceaadfe3c3476f54723434d59b4a",
        "target_path": os.path.join(ARCHIVES_DIR, "1-packets.zip"),
        "extract_dir": os.path.join(GENIS_DIR, "1-packets"),
    },
]


def download_file(item: dict):
    path = item["target_path"]
    name = item["name"]
    expected_size = item["expected_size"]
    expected_md5 = item["expected_md5"]

    if os.path.exists(path) and os.path.getsize(path) == expected_size:
        print(f"[{name}] Archive exists with expected size ({expected_size:,} bytes). Checking MD5...")
        md5 = hashlib.md5()
        with open(path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                md5.update(chunk)
        calc_md5 = md5.hexdigest()
        if calc_md5 == expected_md5:
            print(f"[{name}] MD5 verified: {calc_md5}")
            return path
        print(f"[{name}] MD5 mismatch ({calc_md5} != {expected_md5}). Re-downloading...")

    print(f"[{name}] Starting download from Zenodo ({expected_size / (1024*1024):.2f} MiB)...")
    req = urllib.request.Request(item["url"], headers={"User-Agent": "Mozilla/5.0 NetGuard-Evaluation/1.0"})
    t0 = time.time()
    last_log = t0
    downloaded = 0
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    tmp_path = path + ".tmp"
    with urllib.request.urlopen(req, timeout=60) as resp, open(tmp_path, "wb") as f_out:
        while True:
            chunk = resp.read(512 * 1024)
            if not chunk:
                break
            downloaded += len(chunk)
            md5.update(chunk)
            sha256.update(chunk)
            f_out.write(chunk)
            now = time.time()
            if now - last_log >= 5.0:
                elapsed = now - t0
                speed = (downloaded / (1024 * 1024)) / max(0.1, elapsed)
                pct = (downloaded / expected_size) * 100 if expected_size else 0.0
                print(f"  --> {downloaded / (1024*1024):.2f} / {expected_size / (1024*1024):.2f} MiB ({pct:.1f}%) at {speed:.2f} MiB/s")
                last_log = now

    calc_md5 = md5.hexdigest()
    calc_sha256 = sha256.hexdigest()
    elapsed = max(0.1, time.time() - t0)
    print(f"[{name}] Download complete in {elapsed:.1f}s ({downloaded / (1024*1024*elapsed):.2f} MiB/s).")
    print(f"[{name}] MD5:    {calc_md5}")
    print(f"[{name}] SHA256: {calc_sha256}")

    if calc_md5 != expected_md5:
        raise ValueError(f"Checksum mismatch for {name}: {calc_md5} != {expected_md5}")

    os.rename(tmp_path, path)
    return path


def extract_archive(archive_path: str, target_dir: str):
    print(f"Extracting {os.path.basename(archive_path)} to {target_dir}...")
    os.makedirs(target_dir, exist_ok=True)
    with zipfile.ZipFile(archive_path, "r") as z:
        z.extractall(target_dir)
    print(f"Done extracting {os.path.basename(archive_path)}.")


def main():
    os.makedirs(ARCHIVES_DIR, exist_ok=True)
    os.makedirs(GENIS_DIR, exist_ok=True)

    for item in FILES_TO_DOWNLOAD:
        download_file(item)
        extract_archive(item["target_path"], item["extract_dir"])

    print("\nGeNIS acquisition complete.")


if __name__ == "__main__":
    main()

