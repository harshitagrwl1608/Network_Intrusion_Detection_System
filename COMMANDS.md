# NetGuard IDS — Ground-Truth Benchmark Commands Reference

This reference documents the commands to verify, execute, and inspect the NetGuard IDS Ground-Truth Benchmark.

---

## 1. Acquisition & Integrity Verification

To verify that the dataset archives and raw PCAP/PCAPNG files are present and match publisher checksums:

```bash
# Verify archive integrity against official Zenodo record 14919237 checksums
md5sum data/external_benchmarks/archives/*.zip

# Verify extracted PCAP/PCAPNG volume and packet counts
python3 -c "
import os, glob
from scripts.evaluation.run_ground_truth_benchmark import detect_pcap_format, get_capinfos_metadata
pcaps = sorted(glob.glob('data/external_benchmarks/genis/1-packets/*.*'))
total_bytes = sum(os.path.getsize(f) for f in pcaps)
print(f'Total GeNIS PCAP files: {len(pcaps)} | Total Volume: {total_bytes / (1024**3):.3f} GiB ({total_bytes:,} bytes)')
for p in pcaps[:5]:
    meta = get_capinfos_metadata(p)
    print(f'  {os.path.basename(p):35} | {os.path.getsize(p)/(1024*1024):6.2f} MB | {meta[\"packet_count\"]} pkts')
"
```

---

## 2. Benchmark Preflight (Dry Run)

To verify the complete manifest, confirm all capture paths, check PCAP/PCAPNG formats, and display the execution plan without replaying:

```bash
python3 scripts/evaluation/run_ground_truth_benchmark.py \
    --manifest data/external_benchmarks/ground_truth/manifest.csv \
    --dry-run
```

---

## 3. Full Benchmark Execution (One-Shot Command)

To execute the complete replay, flow-level and scenario-level ground truth scoring, and report generation under complete process and state isolation:

```bash
# Option A (Recommended — runs from any terminal directory):
/home/harshitgarg/Downloads/Networking_Project/scripts/evaluation/run_ground_truth_benchmark.sh

# Option B (From repository root):
cd /home/harshitgarg/Downloads/Networking_Project
python3 scripts/evaluation/run_ground_truth_benchmark.py \
    --manifest data/external_benchmarks/ground_truth/manifest.csv \
    --output results/final_ground_truth_benchmark
```

### What This Command Executes:
1. **Manifest Validation**: Verifies all captures exist and computes on-disk SHA-256 digests.
2. **PCAPNG Conversion**: For any PCAPNG file, auto-converts to classic libpcap (`editcap -F pcap`) while preserving exact wire timestamps and verifying packet counts.
3. **Isolated Replay**: Replays each capture through `ids_project.evaluation.replay` with:
   - Fresh dedicated SQLite DB: `results/final_ground_truth_benchmark/dbs/<capture_id>.db`
   - Fresh isolated ARP state: `results/final_ground_truth_benchmark/arp_tables/<capture_id>.arp.json`
   - Isolated test blocklist: `ids_project/data/test_blocklist.txt`
   - Dedicated capture log: `results/final_ground_truth_benchmark/logs/<capture_id>.log`
4. **Defensible Ground-Truth Matching**:
   - Matches alerts to publisher ground truth intervals (`genis-ground-truth.csv`).
   - Distinguishes True Positives (attack alerts matching label), False Positives (benign alerts), and Unscorable Incidental alerts.
5. **23-Rule Matrix**: Evaluates all 23 NetGuard detection rules, explicitly classifying rules as `exercised_with_tp`, `exercised_unfired`, or `not_exercised`.

---

## 4. Deliverables Inspection

Once execution finishes, deliverables are available in `results/final_ground_truth_benchmark/`:

```bash
# View summary metrics table
column -s, -t < results/final_ground_truth_benchmark/per_capture_metrics.csv | head -n 30

# View 23-rule coverage matrix
column -s, -t < results/final_ground_truth_benchmark/rule_coverage_matrix.csv

# View flow-level ground truth matching decisions
head -n 25 results/final_ground_truth_benchmark/flow_matches.csv

# Open the comprehensive evaluation report
less results/final_ground_truth_benchmark/FINAL_GROUND_TRUTH_BENCHMARK_REPORT.md
```

