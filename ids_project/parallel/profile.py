"""
parallel/profile.py
-------------------
System resource detection and performance profiling for NetGuard IDS.
Selects adaptive worker counts and queue limits based on CPU cores, available RAM,
and system load.
"""

import os
import sys
import math
import logging
from typing import Any

logger = logging.getLogger(__name__)


def get_available_memory_mb() -> float:
    """Read available system memory in MB from /proc/meminfo or fallback."""
    try:
        if os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        parts = line.split()
                        return round(int(parts[1]) / 1024, 1)
                    elif line.startswith("MemFree:") and "mem_free" not in locals():
                        parts = line.split()
                        mem_free = round(int(parts[1]) / 1024, 1)
            if "mem_free" in locals():
                return mem_free
    except Exception:
        pass
    # Fallback default (assume 4096 MB)
    return 4096.0


def get_cpu_quota_cores() -> float:
    """Check cgroup CPU limits if running inside container, else os.cpu_count()."""
    # cgroup v2
    if os.path.exists("/sys/fs/cgroup/cpu.max"):
        try:
            with open("/sys/fs/cgroup/cpu.max", "r") as f:
                content = f.read().strip().split()
                if len(content) == 2 and content[0] != "max":
                    quota = int(content[0])
                    period = int(content[1])
                    return max(1.0, quota / period)
        except Exception:
            pass

    # cgroup v1
    quota_path = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"
    period_path = "/sys/fs/cgroup/cpu/cpu.cfs_period_us"
    if os.path.exists(quota_path) and os.path.exists(period_path):
        try:
            with open(quota_path, "r") as f_q, open(period_path, "r") as f_p:
                quota = int(f_q.read().strip())
                period = int(f_p.read().strip())
                if quota > 0 and period > 0:
                    return max(1.0, quota / period)
        except Exception:
            pass

    return float(os.cpu_count() or 2)


def get_system_capabilities() -> dict[str, Any]:
    """Inspect and return hardware capacity and load."""
    cpu_cores = os.cpu_count() or 2
    quota_cores = get_cpu_quota_cores()
    avail_mem_mb = get_available_memory_mb()

    load_1m = 0.0
    try:
        load_1m = os.getloadavg()[0]
    except Exception:
        pass

    return {
        "physical_cores": cpu_cores,
        "effective_cpu_quota": quota_cores,
        "available_ram_mb": avail_mem_mb,
        "load_avg_1m": load_1m,
    }


def resolve_performance_profile(profile_override: str | None = None, profile_name: str | None = None) -> dict[str, Any]:
    """
    Select performance profile ('low', 'balanced', 'throughput', or 'auto').
    """
    caps = get_system_capabilities()
    cores = caps["effective_cpu_quota"]
    ram_mb = caps["available_ram_mb"]

    req_profile = (profile_override or profile_name or os.getenv("IDS_WORKERS", "auto")).lower().strip()

    if req_profile == "low":
        selected_workers = 1
        chunk_size = 32
        queue_max = 500
        reorder_max = 200
        chosen_name = "low"

    elif req_profile == "balanced":
        selected_workers = max(1, int(cores // 2))
        chunk_size = 64
        queue_max = 1000
        reorder_max = 500
        chosen_name = "balanced"

    elif req_profile == "throughput":
        selected_workers = max(1, int(cores - 1))
        chunk_size = 128
        queue_max = 2000
        reorder_max = 1000
        chosen_name = "throughput"

    else:  # 'auto' or unrecognized
        if cores <= 2.0 or ram_mb < 3000.0:
            chosen_name = "low (auto-selected for resource-constrained system)"
            selected_workers = 1
            chunk_size = 32
            queue_max = 500
            reorder_max = 200
        elif cores <= 4.0 or ram_mb < 7000.0:
            chosen_name = "balanced (auto-selected for mid-tier workstation)"
            selected_workers = max(1, int(cores // 2))
            chunk_size = 64
            queue_max = 1000
            reorder_max = 500
        else:
            chosen_name = "throughput (auto-selected for multi-core server)"
            selected_workers = max(2, int(cores - 1))
            chunk_size = 128
            queue_max = 2000
            reorder_max = 1000

    return {
        "profile": chosen_name,
        "worker_count": selected_workers,
        "chunk_size": chunk_size,
        "queue_max": queue_max,
        "reorder_max": reorder_max,
        "system_capabilities": caps,
    }


select_performance_profile = resolve_performance_profile
