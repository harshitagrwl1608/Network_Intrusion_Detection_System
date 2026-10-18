"""
engine/blocklist.py
-------------------
Loads and manages the IP blocklist.
Downloads from abuse.ch if the file doesn't exist or is older than 24h.

Returns a BlocklistData namedtuple with:
  .exact   -- set of plain IPv4/IPv6 strings (O(1) lookup)
  .networks -- list of ipaddress.ip_network objects (CIDR entries)

BlocklistRule in rules.py uses both fields so that entries like
  203.0.113.0/24  match any address in that range.
"""

import ipaddress
import os
import time
import logging
from collections import namedtuple

logger = logging.getLogger(__name__)

BLOCKLIST_MAX_AGE_HOURS = 24

# Public container returned by load_blocklist()
BlocklistData = namedtuple("BlocklistData", ["exact", "networks"])


def download_blocklist(url: str, path: str) -> bool:
    """Download blocklist from URL, save to path atomically. Returns True on success."""
    try:
        import requests
        logger.info(f"Downloading blocklist from {url} ...")
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # Write to a temp file first, then rename for atomicity
        tmp_path = path + ".tmp"
        with open(tmp_path, "w") as f:
            f.write(r.text)
        os.replace(tmp_path, path)
        logger.info(f"Blocklist saved to {path} ({len(r.text)} bytes)")
        return True
    except Exception as e:
        logger.error(f"Failed to download blocklist: {e}")
        return False


def load_blocklist(path: str, url: str = None) -> BlocklistData:
    """
    Load blocklist from file. If file is missing or stale and url is provided,
    attempt to download it first.

    Returns a BlocklistData with:
      .exact    -- set of valid plain IP strings (fast O(1) lookup)
      .networks -- list of ip_network objects for CIDR range matching
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
            return BlocklistData(exact=set(), networks=[])

    # Parse file into exact IPs and CIDR networks
    exact: set = set()
    networks: list = []
    skipped = 0

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Some feeds include extra columns — take first token
            token = line.split(",")[0].split()[0]
            if not token:
                continue
            if "/" in token:
                # CIDR network entry
                try:
                    net = ipaddress.ip_network(token, strict=False)
                    networks.append(net)
                except ValueError:
                    skipped += 1
            else:
                # Plain IP address — canonicalize so equivalent spellings
                # (e.g. '::0:1' == '::1') map to the same key. (P2)
                try:
                    exact.add(str(ipaddress.ip_address(token)))
                except ValueError:
                    skipped += 1

    if skipped:
        logger.warning(f"Blocklist: skipped {skipped} invalid entries")
    logger.info(
        f"Blocklist loaded: {len(exact)} plain IPs, {len(networks)} CIDR networks"
    )
    return BlocklistData(exact=exact, networks=networks)
