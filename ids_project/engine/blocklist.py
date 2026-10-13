"""
engine/blocklist.py
-------------------
Loads and manages the IP blocklist.
Downloads from abuse.ch if the file doesn't exist or is older than 24h.
"""

import os
import time
import logging

logger = logging.getLogger(__name__)

BLOCKLIST_MAX_AGE_HOURS = 24


def download_blocklist(url: str, path: str) -> bool:
    """Download blocklist from URL, save to path. Returns True on success."""
    try:
        import requests
        logger.info(f"Downloading blocklist from {url} ...")
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(r.text)
        logger.info(f"Blocklist saved to {path} ({len(r.text)} bytes)")
        return True
    except Exception as e:
        logger.error(f"Failed to download blocklist: {e}")
        return False


def load_blocklist(path: str, url: str = None) -> set:
    """
    Load blocklist from file. If file is missing or stale and url is provided,
    attempt to download it first.
    Returns a set of IP strings.
    """
    # Auto-download if needed
    needs_download = False
    if not os.path.exists(path):
        needs_download = True
        logger.warning(f"Blocklist not found at {path}")
    else:
        age_hours = (time.time() - os.path.getmtime(path)) / 3600
        if age_hours > BLOCKLIST_MAX_AGE_HOURS:
            needs_download = True
            logger.info(f"Blocklist is {age_hours:.1f}h old — refreshing")

    if needs_download and url:
        success = download_blocklist(url, path)
        if not success and not os.path.exists(path):
            logger.error("No blocklist available. BLOCKLIST rule disabled.")
            return set()

    # Parse file
    ips = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                # Some feeds include CIDR or extra columns — take first token
                ip = line.split(",")[0].split()[0]
                if ip:
                    ips.add(ip)

    logger.info(f"Blocklist loaded: {len(ips)} IPs")
    return ips
