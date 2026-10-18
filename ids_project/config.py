# =============================================================================
# IDS Configuration
# All tuneable parameters live here. Adjust thresholds after Suricata evaluation.
# =============================================================================

import os

# Load .env file if present (requires python-dotenv, listed in requirements.txt)
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    pass  # python-dotenv not installed — fall back to plain os.getenv()

# --- Network ---
INTERFACE = os.getenv("IDS_INTERFACE", "eth0")  # override with: export IDS_INTERFACE=wlan0

# --- Storage ---
# SQLite (default) — set DB_BACKEND="postgres" and provide POSTGRES_URL to switch
DB_BACKEND = os.getenv("DB_BACKEND", "sqlite")          # "sqlite" | "postgres"
SQLITE_PATH = os.getenv("SQLITE_PATH", "storage/alerts.db")
POSTGRES_URL = os.getenv("POSTGRES_URL", "")            # e.g. postgresql://user:pass@host/dbname

# --- Blocklist ---
BLOCKLIST_PATH = os.getenv("BLOCKLIST_PATH", "data/blocklist.txt")
BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

# --- ARP table (persistent IP→MAC mapping) ---
ARP_TABLE_PATH = "data/arp_table.json"

# --- Detection Thresholds ---
# After each change, replay a known-benign PCAP and verify FP rate stays low.
# Then replay a known-attack PCAP and verify TPs still fire.
PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", 15))   # distinct ports OR hosts in window
SYN_FLOOD_THRESHOLD = int(os.getenv("SYN_FLOOD_THRESHOLD", 100))  # SYN packets in window
TIME_WINDOW = int(os.getenv("TIME_WINDOW", 10))                    # seconds

# --- Trusted Hosts (never flagged by PortScan / SYNFlood) ---
# Add your gateway, local DNS server, CDN ranges, or CIDR blocks.
# Accepts: individual IPs, hostnames (as they appear in tcpdump), CIDR ranges.
# Configurable via GATEWAY_IP and IDS_TRUSTED in .env
TRUSTED_HOSTS: set = set()

_gateway = os.getenv("GATEWAY_IP", "192.168.1.1").strip()
if _gateway:
    TRUSTED_HOSTS.add(_gateway)

# Extra trusted hosts from env: IDS_TRUSTED=1.2.3.4,5.6.7.8,router.local
_extra_trusted = os.getenv("IDS_TRUSTED", "")
if _extra_trusted:
    TRUSTED_HOSTS.update(h.strip() for h in _extra_trusted.split(",") if h.strip())

# --- Feedback ---
# File where analyst feedback (TP/FP classifications) is stored as JSONL
FEEDBACK_PATH = os.getenv("FEEDBACK_PATH", "data/feedback.jsonl")

# --- Deep Packet Inspection (PayloadRule 1.1) ---
PAYLOAD_INSPECTION  = os.getenv("PAYLOAD_INSPECTION", "true").lower() == "true"
PAYLOAD_MAX_BYTES   = int(os.getenv("PAYLOAD_MAX_BYTES", 512))   # cap per-packet bytes scanned

# --- DNS / DGA Detection (DnsRule) ---
# entropy_threshold: raise if too many FPs on random-looking but legit names.
# Typical DGA entropy >= 3.8; short human-readable labels are ~2.5–3.2.
DNS_ENTROPY_THRESHOLD = float(os.getenv("DNS_ENTROPY_THRESHOLD", 3.8))  # bits/char
DNS_QUERY_MAX_LEN     = int(os.getenv("DNS_QUERY_MAX_LEN", 60))         # chars; legit domains <60
# Query-frequency detection: alert if src queries same parent domain >= N times in T seconds.
DNS_FREQ_THRESHOLD    = int(os.getenv("DNS_FREQ_THRESHOLD", 20))         # queries in window
DNS_FREQ_WINDOW       = int(os.getenv("DNS_FREQ_WINDOW", 60))            # seconds

# --- Analysis ---
ANALYSIS_INTERVAL = int(os.getenv("ANALYSIS_INTERVAL", 30))       # seconds between runs

# --- Dashboard ---
# Default to 127.0.0.1 so unauthenticated interface is not exposed to the local network
DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", 5000))
DASHBOARD_DEBUG = os.getenv("DASHBOARD_DEBUG", "false").lower() == "true"

# --- History & Retention ---
# How many days of alerts to keep in the database (older rows are pruned).
# Set to 0 to disable auto-pruning (keep forever).
ALERT_RETENTION_DAYS = int(os.getenv("ALERT_RETENTION_DAYS", 7))

# Default time window shown by the dashboard history view (days).
HISTORY_DAYS = int(os.getenv("HISTORY_DAYS", 7))
