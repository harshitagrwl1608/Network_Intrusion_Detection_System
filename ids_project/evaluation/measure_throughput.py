#!/usr/bin/env python3
"""
Measure effective network download throughput against an authoritative host.
"""

import os
import sys
import time
import urllib.request


def measure(url: str, output_path: str):
    print(f"Testing download throughput from: {url}")
    t0 = time.perf_counter()
    urllib.request.urlretrieve(url, output_path)
    t1 = time.perf_counter()

    size_bytes = os.path.getsize(output_path)
    elapsed = max(0.001, t1 - t0)

    mb = size_bytes / (1024 * 1024)
    mbs = mb / elapsed
    mbps = (size_bytes * 8) / (elapsed * 1_000_000)

    print(f"Downloaded: {size_bytes:,} bytes ({mb:.3f} MB) in {elapsed:.2f}s")
    print(f"Effective Throughput: {mbs:.2f} MB/s ({mbps:.2f} Mbps)")
    return {
        "bytes": size_bytes,
        "elapsed_s": elapsed,
        "mb_s": mbs,
        "mbps": mbps,
    }


if __name__ == "__main__":
    test_url = "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/arp-storm.pcap"
    out_file = "/run/media/harshitgarg/Data1/NetGuard-datasets/incoming/speedtest_sample.pcap"
    try:
        measure(test_url, out_file)
    finally:
        if os.path.exists(out_file):
            # Remove test file
            try:
                os.remove(out_file)
            except OSError:
                pass

