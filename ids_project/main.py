"""
main.py — IDS Entry Point
--------------------------
Starts three concurrent components:
  1. Analysis loop   (background thread, runs every ANALYSIS_INTERVAL seconds)
  2. Packet sniffer  (background thread, runs continuously)
  3. Flask dashboard (main thread, blocking)

Run with:
  sudo python main.py

Required privilege: root / CAP_NET_RAW for raw socket access.

Environment overrides (see config.py):
  IDS_INTERFACE=wlan0 sudo -E python main.py
"""

import sys
import os
import threading
import time
import logging

# ── Logging setup (before any imports that log) ──
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("ids.main")

# Allow relative imports from project root
sys.path.insert(0, os.path.dirname(__file__))

import config
from storage.db import get_connection, init_db, register_alert_persistence_hook
from engine.blocklist import load_blocklist
from engine.rules import RuleEngine
from capture.sniffer import start_sniff
from analysis.aggregator import run_analysis
from storage.db import prune_old_alerts
from dashboard.app import app as flask_app, _baseline_engine
from forensics.flow_tracker import FlowTracker
from notifications.outbox import get_outbox_manager, on_alert_persisted
from analytics.baselines import BaselineCollector


# ---------------------------------------------------------------------------
# Background threads
# ---------------------------------------------------------------------------

def analysis_loop(conn):
    """Periodically run the analysis/plain-language layer.
    Also runs daily pruning to enforce ALERT_RETENTION_DAYS.
    """
    logger.info(f"Analysis loop started (interval: {config.ANALYSIS_INTERVAL}s)")
    _prune_interval = 86400          # run pruning once per day
    _last_prune     = time.time()
    while True:
        try:
            result = run_analysis(conn)
            logger.info(
                f"Analysis: threat={result['threat_level']}  "
                f"alerts={result['alert_count']}  "
                f"observations={len(result['observations'])}"
            )
        except Exception as e:
            logger.error(f"Analysis error: {e}")

        # Daily pruning — enforce retention window
        now = time.time()
        if config.ALERT_RETENTION_DAYS > 0 and (now - _last_prune) >= _prune_interval:
            try:
                deleted = prune_old_alerts(conn, config.ALERT_RETENTION_DAYS)
                if deleted:
                    logger.info(f"Pruned {deleted} rows older than {config.ALERT_RETENTION_DAYS} days")
            except Exception as e:
                logger.error(f"Pruning error: {e}")
            _last_prune = now

        time.sleep(config.ANALYSIS_INTERVAL)


def sniffer_thread(interface: str, engine: RuleEngine, flow_tracker=None):
    """Capture packets in a background thread."""
    try:
        start_sniff(interface, engine, flow_tracker=flow_tracker)
    except PermissionError:
        logger.critical(
            "Permission denied — packet capture requires root.\n"
            "Run: sudo python main.py\n"
            "Or set capability: sudo setcap cap_net_raw+eip $(which python3)\n"
            "Continuing without sniffer..."
        )
    except Exception as e:
        logger.critical(f"Sniffer crashed: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    logger.info("=" * 50)
    logger.info("  NetGuard IDS Starting")
    logger.info(f"  Interface : {config.INTERFACE}")
    logger.info(f"  DB backend: {config.DB_BACKEND}")
    logger.info(f"  Dashboard : http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")
    logger.info("=" * 50)

    # ── 1. Database ──
    conn = get_connection()
    init_db(conn)
    logger.info("Database ready")

    # ── 2. Blocklist ──
    blocklist = load_blocklist(config.BLOCKLIST_PATH, config.BLOCKLIST_URL)

    # ── 3. Rule engine & Flow Tracker ──
    flow_tracker = FlowTracker(db_conn=conn)
    engine = RuleEngine(conn, blocklist, config)
    engine.set_flow_tracker(flow_tracker)
    logger.info(f"Rule engine ready ({len(engine.rules)} rules) with forensic FlowTracker")

    # ── 4. Notifications Outbox ──
    outbox_mgr = get_outbox_manager(conn=conn)
    register_alert_persistence_hook(on_alert_persisted)
    outbox_mgr.start_worker(interval_s=2.0)
    logger.info("Notification outbox worker started")

    # ── 5. Analytics & Baseline Telemetry Collector ──
    baseline_collector = BaselineCollector(_baseline_engine, flow_tracker=flow_tracker, conn=conn, interval_s=5.0)
    baseline_collector.start()
    logger.info("Statistical baseline collector started")

    # ── 6. Analysis loop thread ──
    t_analysis = threading.Thread(
        target=analysis_loop,
        args=(conn,),
        name="analysis-loop",
        daemon=True,
    )
    t_analysis.start()

    # ── 7. Sniffer thread ──
    t_sniffer = threading.Thread(
        target=sniffer_thread,
        args=(config.INTERFACE, engine, flow_tracker),
        name="packet-sniffer",
        daemon=True,
    )
    t_sniffer.start()
    logger.info(f"Packet sniffer started on '{config.INTERFACE}'")

    # ── 8. Flask dashboard (blocking — main thread) ──
    logger.info(f"Starting dashboard at http://localhost:{config.DASHBOARD_PORT}")
    flask_app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=config.DASHBOARD_DEBUG,
        use_reloader=False,  # reloader would fork and break threads
    )


if __name__ == "__main__":
    main()
