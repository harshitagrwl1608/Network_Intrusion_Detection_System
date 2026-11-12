"""
benchmark/live_12k/run_benchmark.py
-----------------------------------
Automated benchmarking harness for NetGuard IDS Live Capture Processing Instrumentation.
Executes controlled 12,000 PPS traffic injection across virtual Ethernet pair (veth-tx -> veth-rx),
measures interface hardware counters, Scapy callback throughput, extraction throughput,
RuleEngine check throughput, latency distribution (avg, p50, p95, p99), and system resource usage.
"""

import os
import sys
import time
import json
import csv
import shutil
import sqlite3
import argparse
import subprocess
import threading
import psutil
from typing import Any

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "ids_project"))

import config
from storage.db import get_connection, init_db
from engine.blocklist import load_blocklist
from engine.rules import RuleEngine
from capture.sniffer import start_sniff
from capture.metrics import PacketProcessingMetrics, set_active_metrics


def get_interface_stats(iface: str) -> dict[str, int]:
    """Read hardware packet and byte counters from sysfs."""
    stats_dir = f"/sys/class/net/{iface}/statistics"
    if not os.path.exists(stats_dir):
        # Fallback to /proc/net/dev
        rx_pkts, tx_pkts = 0, 0
        rx_bytes, tx_bytes = 0, 0
        try:
            with open("/proc/net/dev", "r") as f:
                for line in f:
                    if iface in line:
                        parts = line.split(":")[1].split()
                        rx_bytes = int(parts[0])
                        rx_pkts = int(parts[1])
                        tx_bytes = int(parts[8])
                        tx_pkts = int(parts[9])
                        break
        except Exception:
            pass
        return {
            "rx_packets": rx_pkts,
            "tx_packets": tx_pkts,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
        }

    def read_val(name: str) -> int:
        try:
            with open(os.path.join(stats_dir, name), "r") as f:
                return int(f.read().strip())
        except Exception:
            return 0

    return {
        "rx_packets": read_val("rx_packets"),
        "tx_packets": read_val("tx_packets"),
        "rx_bytes": read_val("rx_bytes"),
        "tx_bytes": read_val("tx_bytes"),
        "rx_dropped": read_val("rx_dropped"),
        "rx_errors": read_val("rx_errors"),
    }


def run_benchmark(
    duration_s: int,
    rate_pps: int = 12000,
    pcap_path: str = "benchmark/live_12k/traffic.pcap",
    rx_iface: str = "veth-rx",
    tx_iface: str = "veth-tx",
    output_dir: str = "results/live_12k_benchmark",
    run_name: str = "60s",
) -> dict[str, Any]:
    """
    Run controlled live veth benchmark for duration_s at rate_pps.
    """
    os.makedirs(output_dir, exist_ok=True)
    pcap_abs = os.path.abspath(pcap_path)
    if not os.path.exists(pcap_abs):
        raise FileNotFoundError(f"PCAP not found: {pcap_abs}")

    # Determine packet count in PCAP
    # traffic.pcap has 12,000 packets
    pcap_pkt_count = 12000
    loops = max(1, int(round((duration_s * rate_pps) / pcap_pkt_count)))
    total_expected_tx = loops * pcap_pkt_count

    print("=" * 70)
    print(f"  NETGUARD LIVE BENCHMARK [{run_name.upper()}]: {duration_s}s @ {rate_pps} PPS")
    print(f"  Target Duration : {duration_s} seconds")
    print(f"  Target Rate     : {rate_pps:,} PPS")
    print(f"  Loops           : {loops} ({total_expected_tx:,} packets)")
    print(f"  Interface Pair  : {tx_iface} -> {rx_iface}")
    print("=" * 70)

    # 1. Initialize fresh DB
    db_path = f"/tmp/netguard_live_{run_name}_{int(time.time())}.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    init_db(conn)

    # 2. Initialize RuleEngine and Metrics
    blocklist = load_blocklist(config.BLOCKLIST_PATH, config.BLOCKLIST_URL)
    engine = RuleEngine(conn, blocklist, config)

    metrics = PacketProcessingMetrics(latency_ring_size=20000)
    set_active_metrics(metrics)

    # Baseline interface stats
    veth_rx_start = get_interface_stats(rx_iface)
    veth_tx_start = get_interface_stats(tx_iface)

    # Sniffer thread control
    stop_sniff_event = threading.Event()

    def _sniffer_worker():
        try:
            start_sniff(
                interface=rx_iface,
                rule_engine=engine,
                packet_filter="udp and port 9999",
                metrics=metrics,
                stop_filter=lambda p: stop_sniff_event.is_set(),
            )
        except Exception as e:
            print(f"[ERROR] Sniffer error: {e}")

    sniffer_thread = threading.Thread(target=_sniffer_worker, name="bench-sniffer", daemon=True)
    sniffer_thread.start()
    time.sleep(1.0)  # Grace period for Scapy/BPF binding

    # Prepare timeseries recording
    timeseries_data = []
    resource_data = []

    # Current process and system monitoring
    process = psutil.Process(os.getpid())
    process.cpu_percent(interval=None)
    psutil.cpu_percent(interval=None)

    last_time = time.monotonic()
    last_rx_pkts = get_interface_stats(rx_iface)["rx_packets"]
    last_tx_pkts = get_interface_stats(tx_iface)["tx_packets"]
    start_bench_time = last_time

    # 3. Launch tcpreplay in background
    cmd = [
        "tcpreplay",
        f"--pps={rate_pps}",
        f"--intf1={tx_iface}",
        f"--loop={loops}",
        pcap_abs,
    ]
    print(f"[INFO] Executing: {' '.join(cmd)}")
    tcpreplay_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # 4. Sampling loop: collect 1s intervals during traffic transmission
    print("[INFO] Replay started. Sampling pipeline & interface metrics every 1.0s...")

    while tcpreplay_proc.poll() is None:
        time.sleep(1.0)
        now = time.monotonic()
        dt = max(0.0001, now - last_time)

        rx_stats = get_interface_stats(rx_iface)
        tx_stats = get_interface_stats(tx_iface)

        curr_rx_pkts = rx_stats["rx_packets"]
        curr_tx_pkts = tx_stats["tx_packets"]

        veth_rx_delta = curr_rx_pkts - last_rx_pkts
        veth_tx_delta = curr_tx_pkts - last_tx_pkts

        veth_rx_pps = veth_rx_delta / dt
        veth_tx_pps = veth_tx_delta / dt

        # Pipeline tick
        pt = metrics.tick(now=now)

        # Resource sampling
        proc_cpu = process.cpu_percent(interval=None)
        sys_cpu = psutil.cpu_percent(interval=None)
        mem_info = process.memory_info()
        mem_rss_mb = round(mem_info.rss / (1024 * 1024), 2)
        sys_mem = psutil.virtual_memory()

        elapsed_rel = round(now - start_bench_time, 2)

        ts_point = {
            "timestamp_rel_s": elapsed_rel,
            "veth_tx_pps": round(veth_tx_pps, 1),
            "veth_rx_pps": round(veth_rx_pps, 1),
            "callback_pps": pt["callback_pps"],
            "extraction_pps": pt["extraction_pps"],
            "engine_pps": pt["engine_pps"],
            "cumulative_veth_tx": curr_tx_pkts - veth_tx_start["tx_packets"],
            "cumulative_veth_rx": curr_rx_pkts - veth_rx_start["rx_packets"],
            "cumulative_callback": pt["cumulative_callback"],
            "cumulative_extracted": pt["cumulative_extracted"],
            "cumulative_engine": pt["cumulative_engine"],
        }
        timeseries_data.append(ts_point)

        res_point = {
            "timestamp_rel_s": elapsed_rel,
            "process_cpu_pct": round(proc_cpu, 1),
            "system_cpu_pct": round(sys_cpu, 1),
            "process_rss_mb": mem_rss_mb,
            "system_mem_used_pct": round(sys_mem.percent, 1),
            "system_mem_avail_mb": round(sys_mem.available / (1024 * 1024), 1),
        }
        resource_data.append(res_point)

        print(
            f"  [{elapsed_rel:>5.1f}s] "
            f"veth-rx: {veth_rx_pps:>8.1f} pps | "
            f"Callback: {pt['callback_pps']:>8.1f} pps | "
            f"Engine: {pt['engine_pps']:>8.1f} pps | "
            f"Latency avg: {pt['avg_latency_us']:>6.1f} us (p95 {pt['p95_latency_us']:>6.1f} us) | "
            f"CPU: {proc_cpu:>5.1f}% | RSS: {mem_rss_mb} MB"
        )

        last_time = now
        last_rx_pkts = curr_rx_pkts
        last_tx_pkts = curr_tx_pkts

    stdout, stderr = tcpreplay_proc.communicate()
    print("[INFO] tcpreplay injection completed.")

    # Parse tcpreplay actual packets sent
    tcpreplay_actual_tx = total_expected_tx
    for line in (stdout + "\n" + stderr).splitlines():
        if "Actual:" in line and "packets" in line:
            try:
                parts = line.split("Actual:")[1].split("packets")[0].strip()
                tcpreplay_actual_tx = int(parts)
            except Exception:
                pass
        elif "Successful packets:" in line:
            try:
                tcpreplay_actual_tx = int(line.split(":")[1].strip())
            except Exception:
                pass

    # Pipeline drain grace period
    time.sleep(2.0)
    stop_sniff_event.set()
    metrics.stop_reporter()

    # Final interface stats
    veth_rx_end = get_interface_stats(rx_iface)
    veth_tx_end = get_interface_stats(tx_iface)

    veth_tx_transmitted = veth_tx_end["tx_packets"] - veth_tx_start["tx_packets"]
    veth_rx_received = veth_rx_end["rx_packets"] - veth_rx_start["rx_packets"]

    snapshot = metrics.get_snapshot()
    counters = snapshot["counters"]
    throughput = snapshot["throughput"]
    latency = snapshot["latency"]

    # 5. Flush and clean up RuleEngine
    engine.flush()
    try:
        conn.close()
    except Exception:
        pass

    results_summary = {
        "run_name": run_name,
        "target_duration_s": duration_s,
        "target_rate_pps": rate_pps,
        "actual_elapsed_s": snapshot["elapsed_seconds"],
        "comparison_metrics": {
            "tcpreplay_transmitted_packets": tcpreplay_actual_tx,
            "veth_rx_interface_rx_packets": veth_rx_received,
            "scapy_callback_packets": counters["callback_packets"],
            "successfully_extracted_packets": counters["extracted_packets"],
            "completed_rule_engine_checks": counters["completed_checks"],
        },
        "drop_and_loss_analysis": {
            "interface_to_callback_gap": veth_rx_received - counters["callback_packets"],
            "interface_loss_rate_pct": round(
                ((veth_rx_received - counters["callback_packets"]) / max(1, veth_rx_received)) * 100.0, 2
            ),
            "extraction_drop_count": counters["ignored_packets"] + counters["extraction_exceptions"],
            "engine_drop_count": counters["engine_exceptions"],
        },
        "throughput": throughput,
        "latency": latency,
        "resource_averages": {
            "avg_process_cpu_pct": round(
                sum(r["process_cpu_pct"] for r in resource_data) / max(1, len(resource_data)), 2
            ),
            "peak_process_cpu_pct": max((r["process_cpu_pct"] for r in resource_data), default=0.0),
            "avg_system_cpu_pct": round(
                sum(r["system_cpu_pct"] for r in resource_data) / max(1, len(resource_data)), 2
            ),
            "avg_process_rss_mb": round(
                sum(r["process_rss_mb"] for r in resource_data) / max(1, len(resource_data)), 2
            ),
            "peak_process_rss_mb": max((r["process_rss_mb"] for r in resource_data), default=0.0),
        },
    }

    # 6. Save deliverables
    json_path = os.path.join(output_dir, f"processing_metrics_{run_name}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results_summary, f, indent=2)

    tp_path = os.path.join(output_dir, f"throughput_timeseries_{run_name}.csv")
    with open(tp_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp_rel_s",
            "veth_tx_pps",
            "veth_rx_pps",
            "callback_pps",
            "extraction_pps",
            "engine_pps",
            "cumulative_veth_tx",
            "cumulative_veth_rx",
            "cumulative_callback",
            "cumulative_extracted",
            "cumulative_engine",
        ])
        for p in timeseries_data:
            writer.writerow([
                p["timestamp_rel_s"],
                p["veth_tx_pps"],
                p["veth_rx_pps"],
                p["callback_pps"],
                p["extraction_pps"],
                p["engine_pps"],
                p["cumulative_veth_tx"],
                p["cumulative_veth_rx"],
                p["cumulative_callback"],
                p["cumulative_extracted"],
                p["cumulative_engine"],
            ])

    lat_path = os.path.join(output_dir, f"latency_metrics_{run_name}.csv")
    metrics.save_timeseries_csv(os.path.join(output_dir, f"_tmp_tp_{run_name}.csv"), lat_path)
    if os.path.exists(os.path.join(output_dir, f"_tmp_tp_{run_name}.csv")):
        os.remove(os.path.join(output_dir, f"_tmp_tp_{run_name}.csv"))

    res_path = os.path.join(output_dir, f"resource_utilization_{run_name}.csv")
    with open(res_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp_rel_s",
            "process_cpu_pct",
            "system_cpu_pct",
            "process_rss_mb",
            "system_mem_used_pct",
            "system_mem_avail_mb",
        ])
        for r in resource_data:
            writer.writerow([
                r["timestamp_rel_s"],
                r["process_cpu_pct"],
                r["system_cpu_pct"],
                r["process_rss_mb"],
                r["system_mem_used_pct"],
                r["system_mem_avail_mb"],
            ])

    # Also save canonical default files for primary benchmark
    if run_name == "60s" or not os.path.exists(os.path.join(output_dir, "processing_metrics.json")):
        shutil.copyfile(json_path, os.path.join(output_dir, "processing_metrics.json"))
        shutil.copyfile(tp_path, os.path.join(output_dir, "throughput_timeseries.csv"))
        shutil.copyfile(lat_path, os.path.join(output_dir, "latency_metrics.csv"))
        shutil.copyfile(res_path, os.path.join(output_dir, "resource_utilization.csv"))

    # Print summary
    print("\n" + "=" * 70)
    print(f"  BENCHMARK [{run_name.upper()}] SUMMARY RESULTS")
    print("=" * 70)
    print(f"  tcpreplay Transmitted Packets : {tcpreplay_actual_tx:,}")
    print(f"  veth-rx Interface RX Packets  : {veth_rx_received:,}")
    print(f"  Scapy Callback Packets        : {counters['callback_packets']:,}")
    print(f"  Successfully Extracted Packets: {counters['extracted_packets']:,}")
    print(f"  Completed RuleEngine.check    : {counters['completed_checks']:,}")
    print("-" * 70)
    print(f"  Completed Engine Throughput   : {throughput['engine_pps_avg']:,.1f} PPS (peak {throughput['engine_pps_peak']:,.1f} PPS)")
    print(f"  Average Processing Latency    : {latency['avg_latency_us']} us ({latency['avg_latency_ms']} ms)")
    print(f"  p95 Processing Latency        : {latency['p95_latency_us']} us ({latency['p95_latency_ms']} ms)")
    print(f"  p99 Processing Latency        : {latency['p99_latency_us']} us ({latency['p99_latency_ms']} ms)")
    print(f"  Average Process CPU           : {results_summary['resource_averages']['avg_process_cpu_pct']}% (peak {results_summary['resource_averages']['peak_process_cpu_pct']}%)")
    print(f"  Memory Footprint (RSS)        : {results_summary['resource_averages']['avg_process_rss_mb']} MB (peak {results_summary['resource_averages']['peak_process_rss_mb']} MB)")
    print("=" * 70 + "\n")

    return {
        "summary": results_summary,
        "timeseries": timeseries_data,
        "resources": resource_data,
        "snapshot": snapshot,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetGuard IDS Live 12k Benchmark")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds")
    parser.add_argument("--rate", type=int, default=12000, help="Target PPS")
    parser.add_argument("--outdir", type=str, default="results/live_12k_benchmark", help="Output directory")
    parser.add_argument("--name", type=str, default="60s", help="Run name identifier")
    args = parser.parse_args()

    res = run_benchmark(
        duration_s=args.duration,
        rate_pps=args.rate,
        output_dir=args.outdir,
        run_name=args.name,
    )
