"""
data/update_blocklist.py  (also runnable as a cron job)
---------------------------------------------------------
Downloads and merges multiple threat intelligence blocklists
into data/blocklist.txt.

Sources:
  - Feodo Tracker (C2 IPs for banking trojans / ransomware)
  - abuse.ch URLhaus (hosts serving malware)
  - CINS Army (scanning / attacking IPs)

Usage:
  python data/update_blocklist.py           # run manually
  Cron:  0 */6 * * * cd /path/to/ids_project && .venv/bin/python data/update_blocklist.py >> data/blocklist_update.log 2>&1
"""

import os
import sys
import time
import logging
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("blocklist-updater")

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

BLOCKLIST_SOURCES = [
    {
        "name": "Feodo Tracker (C2 IPs)",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "comment_char": "#",
    },
    {
        "name": "CINS Army (Scanners/Attackers)",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "comment_char": "#",
    },
]

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "blocklist.txt")


def fetch_ips(source: dict) -> set:
    """Fetch and parse one blocklist source. Returns a set of IP strings."""
    ips = set()
    try:
        logger.info(f"Fetching: {source['name']} ...")
        r = requests.get(source["url"], timeout=20, headers={"User-Agent": "IDS-Updater/1.0"})
        r.raise_for_status()
        comment = source.get("comment_char", "#")
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith(comment):
                continue
            # Take first token (some feeds have extra columns)
            ip = line.split(",")[0].split()[0]
            if ip:
                ips.add(ip)
        logger.info(f"  -> {len(ips)} IPs from {source['name']}")
    except Exception as e:
        logger.error(f"  -> Failed to fetch {source['name']}: {e}")
    return ips


def load_existing(path: str) -> set:
    """Load existing blocklist (preserves manual additions)."""
    if not os.path.exists(path):
        return set()
    ips = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                ips.add(line.split(",")[0].split()[0])
    return ips


def write_blocklist(path: str, ips: set):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(f"# IDS Blocklist — auto-updated {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Sources: {', '.join(s['name'] for s in BLOCKLIST_SOURCES)}\n")
        f.write(f"# Total IPs: {len(ips)}\n\n")
        for ip in sorted(ips):
            f.write(ip + "\n")
    logger.info(f"Blocklist written: {len(ips)} IPs -> {path}")


def main():
    logger.info("=" * 50)
    logger.info("Blocklist update started")
    logger.info("=" * 50)

    # Keep manual entries
    existing = load_existing(OUTPUT_PATH)
    logger.info(f"Existing entries: {len(existing)}")

    # Fetch all sources
    all_ips = set(existing)
    for source in BLOCKLIST_SOURCES:
        all_ips.update(fetch_ips(source))

    write_blocklist(OUTPUT_PATH, all_ips)
    logger.info("Blocklist update complete.")


if __name__ == "__main__":
    main()
