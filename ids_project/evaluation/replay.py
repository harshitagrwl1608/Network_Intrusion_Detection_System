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

import threading
import config
from storage.db import get_connection, init_db
from engine.blocklist import load_blocklist, BlocklistData
from engine.rules import RuleEngine
from capture.sniffer import replay_pcap


class ReplayClock:
    """
    Thread-safe monotonic event clock driven by replayed packet timestamps.
    Used during PCAP and text log replay to advance simulated time deterministically.
    """
    def __init__(self, initial_time: float = 0.0):
        self._time = float(initial_time)
        self._lock = threading.Lock()

    def update(self, ts: float):
        if ts is not None:
            ts_f = float(ts)
            if ts_f > self._time:
                with self._lock:
                    if ts_f > self._time:
                        self._time = ts_f

    def __call__(self) -> float:
        with self._lock:
            return self._time

    @property
    def current_time(self) -> float:
        with self._lock:
            return self._time


class ReplayTrackingEngine:
    """
    Thin wrapper that intercepts check(record), extracts event timestamps to
    advance the ReplayClock, and forwards calls to the underlying RuleEngine.
    Exposes check(), flush(), prune_stale(), and pass-through attribute access.
    """
    def __init__(self, engine: RuleEngine, clock: ReplayClock):
        self.engine = engine
        self.clock = clock

    def check(self, record: dict):
        ts = record.get("event_timestamp", record.get("timestamp", 0.0))
        if ts:
            self.clock.update(ts)
        return self.engine.check(record)

    def flush(self):
        return self.engine.flush()

    def prune_stale(self, now: float = None):
        return self.engine.prune_stale(now)

    def __getattr__(self, name):
        return getattr(self.engine, name)


def create_replay_engine(conn, blocklist, cfg) -> ReplayTrackingEngine:
    """
    Construct a RuleEngine wired with a replay-aware event clock and wrapped
    in a ReplayTrackingEngine to advance the clock as packets are processed.
    """
    clock = ReplayClock()
    engine = RuleEngine(conn, blocklist, cfg, event_clock=clock)
    return ReplayTrackingEngine(engine, clock)


def run_standalone_replay(pcap_path: str, blocklist_path: str = None,
                          db_path: str = None, arp_table_path: str = None,
                          cfg = None) -> ReplayTrackingEngine:
    """
    Execute standalone replay for a PCAP or text log through the IDS engine.
    Ensures every execution path uses a replay-aware event clock.
    """
    c = cfg or config
    if db_path:
        c.SQLITE_PATH = db_path
        logging.info(f"Using evaluation DB: {db_path}")

    if arp_table_path:
        c.ARP_TABLE_PATH = arp_table_path
        logging.info(f"Using isolated ARP table: {arp_table_path}")

    conn = get_connection()
    init_db(conn)

    bl_path = blocklist_path or c.BLOCKLIST_PATH
    bl_url  = c.BLOCKLIST_URL if not blocklist_path else None

    if not os.path.exists(bl_path):
        if bl_url:
            logging.info(f"Blocklist missing at '{bl_path}' — will download from URL")
            blocklist = load_blocklist(bl_path, url=bl_url)
        else:
            logging.warning(
                f"Blocklist not found at '{bl_path}' and no download URL configured. "
                "BLOCKLIST rule will be DISABLED for this replay. "
                "Pass --blocklist <path> or set BLOCKLIST_URL in config to enable it."
            )
            blocklist = BlocklistData(exact=set(), networks=[])
    else:
        blocklist = load_blocklist(bl_path, url=bl_url)

    tracking_engine = create_replay_engine(conn, blocklist, c)
    logging.info(f"Replaying: {pcap_path}")
    replay_pcap(pcap_path, tracking_engine)
    tracking_engine.flush()
    logging.info("Replay complete. Alerts written to database.")
    print(f"Done. Alerts are in: {c.SQLITE_PATH}")
    return tracking_engine


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

    run_standalone_replay(
        pcap_path=args.pcap,
        blocklist_path=args.blocklist,
        db_path=args.db,
        arp_table_path=args.arp_table,
    )


if __name__ == "__main__":
    main()
