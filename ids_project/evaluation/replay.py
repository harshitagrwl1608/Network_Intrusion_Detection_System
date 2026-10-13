"""
evaluation/replay.py
--------------------
Replay a saved .pcap file through the custom IDS engine.
Produces an alert log in the database exactly as live capture would.

Usage:
  sudo python evaluation/replay.py --pcap capture.pcap
"""

import sys
import os
import argparse
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

import config
from storage.db import get_connection, init_db
from engine.blocklist import load_blocklist
from engine.rules import RuleEngine
from capture.sniffer import replay_pcap


def main():
    parser = argparse.ArgumentParser(description="Replay .pcap through IDS engine")
    parser.add_argument("--pcap", required=True, help="Path to .pcap file")
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"ERROR: {args.pcap} not found")
        sys.exit(1)

    conn = get_connection()
    init_db(conn)
    blocklist = load_blocklist(config.BLOCKLIST_PATH, config.BLOCKLIST_URL)
    engine = RuleEngine(conn, blocklist, config)

    replay_pcap(args.pcap, engine)
    engine.flush()
    print("Replay complete. Check the alerts database.")


if __name__ == "__main__":
    main()
