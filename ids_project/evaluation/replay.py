"""
evaluation/replay.py
--------------------
Replay a saved .pcap file through the custom IDS engine.
Produces an alert log in the database exactly as live capture would.

Timestamps from the PCAP are preserved through _extract() (§3.1),
making results deterministic and independent of replay speed.

Usage:
  # Replay with production blocklist:
  python evaluation/replay.py --pcap capture.pcap

  # Replay with an isolated test blocklist (for evaluation):
  python evaluation/replay.py \\
      --pcap data/test_attacks.pcap \\
      --blocklist data/test_blocklist.txt

  # Replay in a clean evaluation DB (does not touch the production DB):
  python evaluation/replay.py \\
      --pcap data/test_attacks.pcap \\
      --blocklist data/test_blocklist.txt \\
      --db /tmp/eval_alerts.db
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
    parser = argparse.ArgumentParser(
        description="Replay .pcap through IDS engine with preserved timestamps"
    )
    parser.add_argument("--pcap", required=True,
                        help="Path to .pcap or tcpdump text log")
    parser.add_argument("--blocklist", default=None,
                        help=(
                            "Path to blocklist file to use (overrides config). "
                            "Use data/test_blocklist.txt for evaluation runs "
                            "to keep the test indicator out of production data."
                        ))
    parser.add_argument("--db", default=None,
                        help=(
                            "Path to SQLite DB file to write alerts into. "
                            "Defaults to config.SQLITE_PATH. "
                            "Pass a temp path for isolated evaluation runs."
                        ))
    parser.add_argument("--arp-table", default=None,
                        help=(
                            "Path to ARP table JSON used by ArpSpoofRule. "
                            "Pass a fresh temp path for isolated evaluation runs "
                            "so previous replay state does not contaminate results."
                        ))
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"ERROR: PCAP not found: {args.pcap}")
        sys.exit(1)

    # Override DB path if requested (isolated evaluation run)
    if args.db:
        config.SQLITE_PATH = args.db
        logging.info(f"Using evaluation DB: {args.db}")

    # Override ARP table path if requested (isolated evaluation run)
    if args.arp_table:
        config.ARP_TABLE_PATH = args.arp_table
        logging.info(f"Using isolated ARP table: {args.arp_table}")

    conn = get_connection()
    init_db(conn)

    # Load blocklist — use override if given, otherwise production path
    bl_path = args.blocklist or config.BLOCKLIST_PATH
    bl_url  = config.BLOCKLIST_URL if not args.blocklist else None

    # Fail clearly if the blocklist file is missing and there is no URL to
    # download from. Without this, load_blocklist() would crash with a
    # confusing FileNotFoundError on the open() call. (P0)
    if not os.path.exists(bl_path):
        if bl_url:
            logging.info(f"Blocklist missing at '{bl_path}' — will download from URL")
        else:
            logging.warning(
                f"Blocklist not found at '{bl_path}' and no download URL configured. "
                "BLOCKLIST rule will be DISABLED for this replay. "
                "Pass --blocklist <path> or set BLOCKLIST_URL in config to enable it."
            )
            # Return an empty, explicitly disabled blocklist
            from engine.blocklist import BlocklistData
            blocklist = BlocklistData(exact=set(), networks=[])
            conn = get_connection()
            init_db(conn)
            engine = RuleEngine(conn, blocklist, config)
            logging.info(f"Replaying: {args.pcap}")
            replay_pcap(args.pcap, engine)
            engine.flush()
            logging.info("Replay complete. Alerts written to database.")
            print(f"Done. Alerts are in: {config.SQLITE_PATH}")
            return

    blocklist = load_blocklist(bl_path, url=bl_url)
    engine = RuleEngine(conn, blocklist, config)

    logging.info(f"Replaying: {args.pcap}")
    replay_pcap(args.pcap, engine)
    engine.flush()

    logging.info("Replay complete. Alerts written to database.")
    print(f"Done. Alerts are in: {config.SQLITE_PATH}")


if __name__ == "__main__":
    main()
