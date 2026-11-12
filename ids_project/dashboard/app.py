"""
dashboard/app.py
----------------
Flask web dashboard for the IDS.

Routes:
  GET  /                        → main dashboard page (HTML)
  GET  /api/status              → JSON: threat level + counts
  GET  /api/alerts              → JSON: recent alerts (last 1h) with GeoIP
  GET  /api/alerts/<id>         → JSON: single alert detail for investigation
  GET  /api/observations        → JSON: plain-language messages
  GET  /api/chart               → JSON: hourly alert counts for Chart.js
  GET  /api/devices             → JSON: all seen devices with vendor
  GET  /api/stream              → SSE: live alert push (replaces polling)
  POST /api/feedback            → Submit TP/FP classification for an alert
  GET  /api/feedback/stats      → JSON: TP/FP counts per rule (tuning summary)
"""

import sys
import os
import time
import json
import logging
import ipaddress
import threading
import uuid
import csv
import io
import struct
import secrets
import hmac

# Allow imports from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, jsonify, render_template, request, Response, stream_with_context, session, has_request_context
import config
from storage.db import (
    get_connection, init_db, adapt_sql,
    read_recent_alerts, read_alerts_range, read_all_devices,
    read_recent_observations, count_alerts_by_hour,
    count_alerts_by_day, read_alerts_for_date,
    write_feedback, read_feedback, feedback_stats
)
from analysis.aggregator import run_analysis, compute_threat_level
from engine.rule_metadata import get_rule_metadata_inventory, RULE_METADATA
from storage.db import register_alert_persistence_hook
from storage.forensics_db import write_audit_log
from analytics.baselines import BaselineEngine, BaselineCollector
from notifications.outbox import NotificationOutboxManager, on_alert_persisted
from reports.generator import ReportGenerator, REPORT_TYPES, SUPPORTED_FORMATS
from notifications.email_utils import parse_all_recipients
from notifications.email_render import render_report_email
from notifications.report_delivery import (
    MAX_ATTACHMENT_BYTES,
    ReportDeliveryError,
    ReportTooLargeError,
    build_report_payload,
    generate_artifact,
    prune_artifacts,
)
from forensics.offline_analyzer import OfflinePcapAnalyzer
from parallel.profile import get_system_capabilities, select_performance_profile
from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB max upload limit

# --- Flask session-signing key (NETGUARD_SECRET_KEY) ---
# This key signs session cookies and must be stable across all workers and restarts.
# It is INDEPENDENT from NETGUARD_ENCRYPTION_KEY (credential encryption).
# In production: set NETGUARD_SECRET_KEY to a strong, stable value and keep it consistent
# across all worker processes (gunicorn, uwsgi, etc.).
# Multi-worker requirement: ALL workers MUST share the same NETGUARD_SECRET_KEY to validate sessions.
# Rotation: changing this key invalidates all existing session cookies (users must re-login).
_configured_secret_key = getattr(config, "SECRET_KEY", None) or os.environ.get("NETGUARD_SECRET_KEY")
_is_production_config = not (
    os.environ.get("NETGUARD_TESTING") == "1" or
    os.environ.get("DASHBOARD_DEBUG", "false").lower() == "true" or
    getattr(config, "DASHBOARD_DEBUG", False)
)

if not _configured_secret_key:
    if _is_production_config:
        # Fail closed: require explicit key in production / non-debug operation
        import warnings
        warnings.warn(
            "NETGUARD_SECRET_KEY is not set. Session cookies will be signed with an ephemeral key. "
            "Sessions will NOT persist across restarts or multiple workers. "
            "Set NETGUARD_SECRET_KEY for production deployments.",
            RuntimeWarning,
            stacklevel=1,
        )
    # Use ephemeral random key (safe for single-process dev/test, not production multi-worker)
    _configured_secret_key = secrets.token_hex(32)

app.secret_key = _configured_secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=getattr(config, "SESSION_COOKIE_SECURE", False),
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
if os.environ.get("NETGUARD_HTTPS", "false").lower() == "true":
    app.config["SESSION_COOKIE_SECURE"] = True

_baseline_engine = BaselineEngine()
_outbox_manager = NotificationOutboxManager()
_offline_analyzer = None
_app_start_time = time.time()
_baseline_collector: BaselineCollector | None = None


def db_exec(cur, sql: str, params: tuple | list | None = None):
    """Execute SQL query with automatic backend dialect adaptation."""
    adapted = adapt_sql(sql)
    if params is not None:
        return cur.execute(adapted, params)
    return cur.execute(adapted)


def get_session_csrf_token() -> str:
    """Return active session-bound CSRF token, generating if needed."""
    if has_request_context():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(32)
        return session["_csrf_token"]
    return ""


@app.before_request
def check_auth_and_csrf():
    """Enforce Basic Authentication and session-bound CSRF token validation on state-changing requests."""
    # 1. Basic Authentication check
    if getattr(config, "DASHBOARD_AUTH_ENABLED", False):
        expected_user = getattr(config, "DASHBOARD_USERNAME", "admin")
        expected_pass = getattr(config, "DASHBOARD_PASSWORD", None) or os.environ.get("DASHBOARD_PASSWORD")
        if not expected_pass or expected_pass == "netguard":
            logger.critical("SECURITY VIOLATION: DASHBOARD_AUTH_ENABLED requires DASHBOARD_PASSWORD to be explicitly configured and cannot be default 'netguard'. Failing closed.")
            return Response(
                "Configuration error: DASHBOARD_PASSWORD must be explicitly configured with a non-default password when authentication is enabled.", 500
            )
        auth = request.authorization
        if not auth or auth.username != expected_user or not hmac.compare_digest(auth.password, expected_pass):
            return Response(
                "Unauthorized: NetGuard SOC credentials required", 401,
                {"WWW-Authenticate": 'Basic realm="NetGuard SOC Dashboard"'}
            )

    # 2. Binding security warning when exposed beyond localhost with default credentials
    bind_host = getattr(config, "DASHBOARD_HOST", "127.0.0.1")
    if bind_host not in ("127.0.0.1", "localhost", "::1"):
        secret_env = os.environ.get("NETGUARD_SECRET_KEY") or getattr(config, "SECRET_KEY", None)
        if not secret_env or secret_env == "netguard-soc-default-master-key-seed-32b":
            logger.critical("SECURITY WARNING: NetGuard dashboard exposed beyond localhost (%s) without an explicit strong SECRET_KEY.", bind_host)

    # 3. Session-bound CSRF Token enforcement on state-modifying verbs
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if not getattr(config, "DASHBOARD_CSRF_ENABLED", True):
            return

        token = request.headers.get("X-CSRFToken") or request.headers.get("X-CSRF-Token")
        if not token and request.is_json:
            token = (request.get_json(silent=True) or {}).get("csrf_token")
        elif not token and request.form:
            token = request.form.get("csrf_token")

        valid = False
        if token and "_csrf_token" in session:
            if hmac.compare_digest(str(token), str(session["_csrf_token"])):
                valid = True

        if not valid:
            return jsonify({"error": "CSRF token missing or invalid"}), 403


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"error": "Uploaded payload exceeds maximum allowed size (100MB)"}), 413


def get_offline_analyzer():
    global _offline_analyzer
    db = get_db()
    if _offline_analyzer is None:
        _offline_analyzer = OfflinePcapAnalyzer(main_conn=db)
    else:
        _offline_analyzer._main_conn = db
    return _offline_analyzer


def get_baseline_collector():
    global _baseline_collector
    if _baseline_collector is None:
        _baseline_collector = BaselineCollector(_baseline_engine, conn=get_db(), interval_s=10.0)
    return _baseline_collector

# ---------------------------------------------------------------------------
# ━━ GeoIP — Alert-only, cached, rate-limit-aware (Feature 2.2)
# ---------------------------------------------------------------------------
# Strategy:
#   1. Only look up IPs that actually FIRED a rule (not every packet).
#   2. Skip RFC-1918 / loopback / link-local IPs immediately — no API call.
#   3. Maintain a persistent in-process cache: once looked up, never again.
#   4. Track API call count per minute; if near the free-tier limit (45/min),
#      stop lookups for that minute and return cached/None gracefully.
#   5. Batch: when enriching a list of alerts, group by unique DST IP so even
#      if 100 alerts hit the same IP, only 1 API call is made.
# ---------------------------------------------------------------------------

_GEO_CACHE: dict[str, dict] = {}   # ip → {country, country_code, city}
_GEO_LOCK   = threading.Lock()
_GEO_CALLS_THIS_MINUTE = 0
_GEO_MINUTE_RESET      = time.time()
_GEO_RATE_LIMIT        = 40        # conservative margin below ip-api.com's 45/min

# RFC-1918 / special ranges with human-readable labels
# Order matters — more specific ranges before broader ones
_LOCAL_NETS: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str, str]] = [
    # (network,                    country label,            city / subnet context)
    (ipaddress.ip_network("127.0.0.0/8"),      "Loopback",              "localhost"),
    (ipaddress.ip_network("169.254.0.0/16"),   "Link-Local (APIPA)",    "No DHCP — auto-assigned"),
    (ipaddress.ip_network("10.0.0.0/8"),       "Private Network",       "10.0.0.0/8 — Corporate/VPN"),
    (ipaddress.ip_network("172.16.0.0/12"),    "Private Network",       "172.16.0.0/12 — Docker/VPN"),
    (ipaddress.ip_network("192.168.0.0/16"),   "Private Network",       "192.168.0.0/16 — Home/Office LAN"),
    (ipaddress.ip_network("::1/128"),           "Loopback (IPv6)",       "localhost"),
    (ipaddress.ip_network("fc00::/7"),          "Private Network (IPv6)","ULA — Unique Local Address"),
]


def _classify_local(ip: str) -> dict | None:
    """
    If ip is a private/loopback/link-local address, return a rich local
    context dict without making any external API call.
    Returns None if ip is a public address (needs external lookup).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # Hostname or garbage — treat as unknown local
        return {"country": "Unresolved Host", "country_code": "LCL", "city": ip}

    for net, label, detail in _LOCAL_NETS:
        if addr in net:
            return {"country": label, "country_code": "LCL", "city": detail}
    return None  # public IP — caller should hit the external API


def _geo_lookup(ip: str) -> dict | None:
    """
    Look up origin context for any IP — private or public.
    - Private/local IPs: classified instantly from _LOCAL_NETS, no API call.
    - Public IPs: looked up via ip-api.com, cached forever after first hit.
    - Rate limit: stops at _GEO_RATE_LIMIT calls/min; returns None gracefully.
    """
    global _GEO_CALLS_THIS_MINUTE, _GEO_MINUTE_RESET

    # ── Private / local range — rich local classifier, zero API calls ──
    local = _classify_local(ip)
    if local is not None:
        return local  # instant, free, always works — no rate limit consumed

    # ── Public IP — check cache first ──
    with _GEO_LOCK:
        if ip in _GEO_CACHE:
            return _GEO_CACHE[ip]

        # Rate-limit guard: reset counter each minute
        now = time.time()
        if now - _GEO_MINUTE_RESET >= 60:
            _GEO_CALLS_THIS_MINUTE = 0
            _GEO_MINUTE_RESET = now

        if _GEO_CALLS_THIS_MINUTE >= _GEO_RATE_LIMIT:
            logger.warning(f"GeoIP rate limit reached ({_GEO_RATE_LIMIT}/min) — skipping {ip}")
            return None  # graceful degradation — no crash, no hang

        _GEO_CALLS_THIS_MINUTE += 1

    # ── API call outside the lock to avoid blocking other threads ──
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city"
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            geo = {
                "country":      data.get("country", ""),
                "country_code": data.get("countryCode", ""),
                "city":         data.get("city", ""),
            }
        else:
            geo = {"country": "", "country_code": "", "city": ""}
    except Exception as e:
        logger.debug(f"GeoIP lookup failed for {ip}: {e}")
        geo = None

    if geo is not None:
        with _GEO_LOCK:
            _GEO_CACHE[ip] = geo
    return geo


def _enrich_alerts_with_geo(alerts: list[dict]) -> list[dict]:
    """
    Enrich a list of alert dicts with GeoIP.
    • Groups alerts by unique src_ip → only one API call per unique IP.
    • Skips alerts that already have country data stored in the DB.
    • Returns the same list, mutated in-place for efficiency.
    """
    # Collect IPs that still need lookup (not yet in DB column)
    ips_to_lookup = {
        a["src_ip"]
        for a in alerts
        if a.get("src_ip") and not a.get("country")
    }
    # One lookup per unique IP
    geo_map: dict[str, dict | None] = {}
    for ip in ips_to_lookup:
        geo_map[ip] = _geo_lookup(ip)

    # Attach results to every alert with that IP
    for a in alerts:
        src = a.get("src_ip")
        if src and not a.get("country"):
            geo = geo_map.get(src)
            if geo:
                a["country"]      = geo["country"]
                a["country_code"] = geo["country_code"]
                a["city"]         = geo["city"]
    return alerts


def _country_flag(code: str) -> str:
    """Convert ISO-3166-1 alpha-2 country code to flag emoji. Pure Python, zero deps."""
    if not code:
        return "🌐"
    # 'LCL' is our internal sentinel for private/loopback/link-local addresses
    if code == "LCL":
        return "🏠"
    if len(code) != 2:
        return "🌐"
    return chr(0x1F1E6 + ord(code[0]) - ord('A')) + chr(0x1F1E6 + ord(code[1]) - ord('A'))


# ---------------------------------------------------------------------------
# ━━ OUI Vendor Lookup — MAC Address Fingerprinting (Feature 2.3)
# ---------------------------------------------------------------------------
# Bundled top-100 vendor prefixes — covers most common network gear.
# Full OUI DB download is opt-in (too large to bundle).
# ---------------------------------------------------------------------------

_OUI_BUILTIN: dict[str, str] = {
    "000C29": "VMware", "000569": "VMware", "005056": "VMware",
    "B827EB": "Raspberry Pi Foundation", "DCA632": "Raspberry Pi Foundation",
    "E45F01": "Raspberry Pi Foundation", "2CCF67": "Raspberry Pi Foundation",
    "A4CF12": "Raspberry Pi Foundation",
    "001A2B": "Cisco", "00000C": "Cisco", "0050A2": "Cisco", "001C58": "Cisco",
    "001BD4": "Cisco", "001E13": "Cisco", "003094": "Cisco",
    "3C9EF8": "Apple", "F0DB43": "Apple", "A8BE27": "Apple",
    "001451": "Apple", "0019E3": "Apple", "7C6D62": "Apple",
    "34363B": "Apple", "6C4008": "Apple", "F4F15A": "Apple",
    "886B0F": "Intel", "8086F2": "Intel", "34DE1A": "Intel",
    "4437E6": "Intel",
    "B47C9C": "Samsung", "4C3488": "Samsung", "8C8D28": "Samsung",
    "2C4401": "Samsung", "A0821F": "Samsung",
    "68A0F6": "Amazon", "40B4CD": "Amazon", "74C246": "Amazon",
    "34D270": "Amazon",
    "7C2EBD": "Google", "F88FCA": "Google", "54600A": "Google",
    "A47733": "Huawei", "001E10": "Huawei", "2C9D65": "Huawei",
    "B4B362": "TP-Link", "50C7BF": "TP-Link", "C46E1F": "TP-Link",
    "5422F8": "TP-Link", "A84E3F": "TP-Link",
    "C83A35": "Netgear", "20E52A": "Netgear", "984B4A": "Netgear",
    "001B2F": "Netgear",
    "1C1B0D": "ASUSTek", "107B44": "ASUSTek", "0090A9": "ASUSTek",
    "74D435": "Dell", "F0761C": "Dell", "B083FE": "Dell",
    "00D0C9": "D-Link", "1CAFF7": "D-Link", "78321B": "D-Link",
    "84A9C4": "Xiaomi", "286C07": "Xiaomi", "A08633": "Xiaomi",
    "F8A2D6": "Xiaomi", "40A5EF": "OnePlus",
    "000D3A": "Microsoft", "001DD8": "Microsoft", "0017FA": "Microsoft",
    "28187E": "Microsoft",
}


def _mac_to_vendor(mac: str) -> str:
    """Look up vendor from MAC OUI prefix (first 3 bytes), with randomized MAC detection."""
    if not mac:
        return "Unknown"
    clean = mac.upper().replace(":", "").replace("-", "")
    if len(clean) >= 2:
        try:
            first_byte = int(clean[:2], 16)
            if first_byte & 0x02:
                return "Randomized / Private MAC"
        except ValueError:
            pass
    prefix = clean[:6]
    return _OUI_BUILTIN.get(prefix, "Unknown Manufacturer")


# ---------------------------------------------------------------------------
# DB connection (re-used across requests — safe for SQLite with check_same_thread=False)
# ---------------------------------------------------------------------------
_db_conn = None

def get_db():
    global _db_conn
    if _db_conn is None:
        _db_conn = get_connection()
        init_db(_db_conn)
        register_alert_persistence_hook(on_alert_persisted)
        _outbox_manager.set_connection(_db_conn)
        _baseline_engine.set_connection(_db_conn)
    return _db_conn


def _is_postgres() -> bool:
    return getattr(config, "DB_BACKEND", "sqlite").lower() == "postgres"


def _get_latest_alert_id(db) -> int:
    """Return the highest alert ID currently in the DB (0 if empty)."""
    from storage.db import _sqlite_lock
    sql = "SELECT MAX(id) FROM alerts"
    with _sqlite_lock:
        cur = db.cursor()
        cur.execute(sql)
        row = cur.fetchone()
        cur.close()
    val = row[0] if row else None
    return int(val) if val else 0


def _get_alerts_since_id(db, last_id: int) -> list[dict]:
    """Return all alerts with id > last_id, oldest first."""
    from storage.db import _sqlite_lock
    sql = "SELECT * FROM alerts WHERE id > ? ORDER BY id ASC" \
        if config.DB_BACKEND == "sqlite" \
        else "SELECT * FROM alerts WHERE id > %s ORDER BY id ASC"
    with _sqlite_lock:
        cur = db.cursor()
        cur.execute(sql, (last_id,))
        rows = cur.fetchall()
        cur.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", csrf_token=get_session_csrf_token())


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.route("/api/status")
def api_status():
    """Current threat level and summary counts."""
    db = get_db()
    alerts = read_recent_alerts(db, minutes=60)
    threat_level = compute_threat_level(alerts)

    rule_counts = {}
    sev_counts = {"high": 0, "medium": 0, "low": 0}
    for a in alerts:
        r = a.get("rule_name", "UNKNOWN")
        rule_counts[r] = rule_counts.get(r, 0) + 1
        s = (a.get("severity") or "medium").lower()
        if s in sev_counts:
            sev_counts[s] += 1

    active_rules = len(RULE_METADATA)
    try:
        from engine.rules import RuleEngine
        active_rules = len(RuleEngine(None, set(), config).rules)
    except Exception:
        pass

    return jsonify({
        "threat_level": threat_level,
        "alert_count_1h": len(alerts),
        "rule_breakdown": rule_counts,
        "severity_breakdown": sev_counts,
        "active_rules_count": active_rules,
        "server_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "geo_cache_size": len(_GEO_CACHE),
    })


@app.route("/api/metrics")
def api_metrics():
    """Live capture processing metrics snapshot."""
    try:
        from capture.metrics import get_active_metrics
        return jsonify(get_active_metrics().get_snapshot())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/rules")
def api_rules():
    """Return complete metadata inventory for all 23 detection rules."""
    return jsonify(get_rule_metadata_inventory())


@app.route("/api/csrf-token")
def api_csrf_token():
    """Return active session CSRF token."""
    return jsonify({"csrf_token": get_session_csrf_token()})


@app.route("/api/auth/rotate-password", methods=["POST"])
def api_auth_rotate_password():
    """Rotate dashboard access password for credential lifecycle."""
    data = request.get_json(silent=True) or {}
    new_password = data.get("new_password", "").strip()
    if not new_password or len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    setattr(config, "DASHBOARD_PASSWORD", new_password)
    from storage.forensics_db import save_system_setting
    save_system_setting(get_db(), "dashboard_password_updated", time.time())
    return jsonify({"status": "ok", "message": "Password rotated successfully"})


@app.route("/api/alerts")
def api_alerts():
    """Last N hours of raw alerts, enriched with GeoIP.
    Query param: ?hours=N  (default 1, max 24)
    """
    db = get_db()
    hours = min(int(request.args.get("hours", 1)), 24)
    alerts = read_recent_alerts(db, minutes=hours * 60)
    alerts = _enrich_alerts_with_geo(alerts)   # ← smart GeoIP enrichment
    for a in alerts:
        ts = a.get("timestamp", 0)
        a["time_str"] = time.strftime("%H:%M:%S", time.localtime(ts))
        a["date_str"] = time.strftime("%Y-%m-%d", time.localtime(ts))
        # Add flag emoji for the frontend
        a["flag"] = _country_flag(a.get("country_code", ""))
    return jsonify(alerts)


@app.route("/api/alerts/history")
def api_alerts_history():
    """Historical alerts for the last N days (up to ALERT_RETENTION_DAYS).
    Query param: ?days=N  (default HISTORY_DAYS from config, max ALERT_RETENTION_DAYS)
    """
    db = get_db()
    max_days = max(config.ALERT_RETENTION_DAYS, 1)
    default_days = getattr(config, "HISTORY_DAYS", 7)
    days = max(1, min(int(request.args.get("days", default_days)), max_days))
    alerts = read_alerts_range(db, days=days, limit=5000)
    alerts = _enrich_alerts_with_geo(alerts)
    for a in alerts:
        ts = a.get("timestamp", 0)
        a["time_str"]  = time.strftime("%H:%M:%S", time.localtime(ts))
        a["date_str"]  = time.strftime("%Y-%m-%d", time.localtime(ts))
        a["datetime_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        a["flag"] = _country_flag(a.get("country_code", ""))
    return jsonify({
        "days": days,
        "total": len(alerts),
        "alerts": alerts,
    })


@app.route("/api/alerts/calendar")
def api_alerts_calendar():
    """
    Return per-day alert counts + severity flag for a given month.
    Used to paint the calendar heatmap.
    Query params: ?year=YYYY&month=MM  (defaults: current month)
    Returns: { year, month, days: [{date_str, count, has_high}, ...] }
    """
    import datetime as _dt
    today = _dt.date.today()
    year  = int(request.args.get("year",  today.year))
    month = int(request.args.get("month", today.month))
    # Clamp to sane values
    year  = max(2020, min(year,  today.year + 1))
    month = max(1,    min(month, 12))
    db = get_db()
    rows = count_alerts_by_day(db, year, month)
    return jsonify({"year": year, "month": month, "days": rows})


@app.route("/api/alerts/by-date")
def api_alerts_by_date():
    """
    Return all alerts for a specific calendar day.
    Query param: ?date=YYYY-MM-DD
    """
    date_str = request.args.get("date", "")
    if not date_str:
        return jsonify({"error": "date param required (YYYY-MM-DD)"}), 400
    db = get_db()
    alerts = read_alerts_for_date(db, date_str)
    alerts = _enrich_alerts_with_geo(alerts)
    for a in alerts:
        ts = a.get("timestamp", 0)
        a["time_str"]     = time.strftime("%H:%M:%S", time.localtime(ts))
        a["datetime_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        a["flag"] = _country_flag(a.get("country_code", ""))
    return jsonify({"date": date_str, "total": len(alerts), "alerts": alerts})


@app.route("/api/stream")
def api_stream():
    """
    SSE endpoint — pushes new alerts to all connected browsers in real-time.
    Replaces the 30-second JS polling interval.
    Each event is a JSON-encoded alert dict, identical to /api/alerts items.
    """
    db = get_db()

    def event_stream():
        last_id = _get_latest_alert_id(db)
        while True:
            time.sleep(2)  # poll DB every 2s — negligible load
            new_alerts = _get_alerts_since_id(db, last_id)
            for alert in new_alerts:
                last_id = alert["id"]
                alert["time_str"] = time.strftime("%H:%M:%S", time.localtime(alert.get("timestamp", 0)))
                # Enrich with GeoIP inline (cache means this is usually free)
                geo = _geo_lookup(alert.get("src_ip", "") or "")
                if geo:
                    alert.update(geo)
                alert["flag"] = _country_flag(alert.get("country_code", ""))
                payload = json.dumps(alert)
                yield f"data: {payload}\n\n"

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering if proxied
        },
    )


@app.route("/api/observations")
def api_observations():
    """Recent plain-language observations."""
    db = get_db()
    obs = read_recent_observations(db, limit=20)
    for o in obs:
        ts = o.get("timestamp", 0)
        o["time_str"] = time.strftime("%H:%M:%S", time.localtime(ts))
    return jsonify(obs)


@app.route("/api/chart")
def api_chart():
    """
    Hourly alert counts for the last 24h, formatted for Chart.js.
    Returns: { labels: [...], datasets: [{label, data, ...}] }
    """
    db = get_db()
    rows = count_alerts_by_hour(db, hours=24)

    # Build hour labels (last 24)
    now = time.time()
    hour_labels = []
    for i in range(23, -1, -1):
        t = now - i * 3600
        hour_labels.append(time.strftime("%H:00", time.localtime(t)))

    # Collect all rule names present
    rule_names = list({r["rule_name"] for r in rows})
    rule_colors = {
        name: meta.get("color", "rgba(100, 100, 100, 0.8)")
        for name, meta in RULE_METADATA.items()
    }

    datasets = []
    for rule in rule_names:
        data = [0] * 24
        for r in rows:
            if r["rule_name"] == rule:
                hour_idx = int(r.get("hour_offset", 0))
                # Clamp to valid range; negative offsets (data older than window)
                # and offsets > 23 (rounding artefacts) are dropped safely.
                if 0 <= hour_idx <= 23:
                    data[23 - hour_idx] = r["count"]
        datasets.append({
            "label": rule.replace("_", " "),
            "data": data,
            "backgroundColor": rule_colors.get(rule, "rgba(100, 100, 100, 0.8)"),
            "borderColor": rule_colors.get(rule, "rgba(100, 100, 100, 1)"),
            "borderWidth": 1,
        })

    return jsonify({"labels": hour_labels, "datasets": datasets})


@app.route("/api/devices")
def api_devices():
    """All seen devices with vendor fingerprint."""
    db = get_db()
    devices = read_all_devices(db)
    for d in devices:
        d["last_seen_str"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(d.get("last_seen", 0))
        )
        d["first_seen_str"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(d.get("first_seen", 0))
        )
        # Vendor fingerprint from OUI (2.3)
        if not d.get("vendor"):
            d["vendor"] = _mac_to_vendor(d.get("mac", ""))
    return jsonify(devices)


@app.route("/api/refresh-analysis")
def api_refresh_analysis():
    """Manually trigger an analysis run (useful for testing)."""
    db = get_db()
    result = run_analysis(db)
    return jsonify(result)


@app.route("/api/alerts/<int:alert_id>")
def api_alert_detail(alert_id: int):
    """
    Return full detail for a single alert — used by the investigation modal.
    Includes all stored fields plus any existing feedback for this alert.
    """
    db = get_db()
    sql = ("SELECT * FROM alerts WHERE id = ?" if config.DB_BACKEND == "sqlite"
           else "SELECT * FROM alerts WHERE id = %s")
    from storage.db import _sqlite_lock
    with _sqlite_lock:
        cur = db.cursor()
        cur.execute(sql, (alert_id,))
        row = cur.fetchone()
        cur.close()
    if not row:
        return jsonify({"error": "Alert not found"}), 404
    alert = dict(row)
    alert["time_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(alert.get("timestamp", 0)))
    if alert.get("evidence_json"):
        try:
            alert["evidence"] = json.loads(alert["evidence_json"])
        except Exception:
            alert["evidence"] = None
    else:
        alert["evidence"] = None

    # Attach existing feedback if any
    fb_sql = ("SELECT * FROM feedback WHERE alert_id = ? ORDER BY timestamp DESC LIMIT 1"
              if config.DB_BACKEND == "sqlite"
              else "SELECT * FROM feedback WHERE alert_id = %s ORDER BY timestamp DESC LIMIT 1")
    with _sqlite_lock:
        cur = db.cursor()
        cur.execute(fb_sql, (alert_id,))
        fb = cur.fetchone()
        cur.close()
    alert["feedback"] = dict(fb) if fb else None

    # Add rule-specific explanation for the investigation panel
    explanations = {
        "BLOCKLIST": (
            "The destination or source IP matched an entry in the threat intelligence blocklist "
            "(e.g., abuse.ch Feodo Tracker / CINS Army). This indicates contact with a known botnet C2, "
            "ransomware distribution node, or malicious infrastructure."
        ),
        "TCP_FLAG_ANOMALY": (
            "A TCP packet with an illegal or contradictory flag combination (e.g. SYN+FIN, SYN+RST, "
            "or all flags set) was observed. Attackers craft illegal flags to probe firewall state tables "
            "or elicit OS-specific responses for fingerprinting."
        ),
        "PORT_SCAN": (
            "This alert fired because a single source IP sent initial TCP SYN packets to more than "
            f"{config.PORT_SCAN_THRESHOLD} distinct ports on a target host (vertical scan) or across "
            f"distinct hosts (horizontal sweep) within {config.TIME_WINDOW} seconds. "
            "Check if the source IP is an authorized scanner or an unexpected reconnaissance tool."
        ),
        "UDP_SCAN": (
            f"A single source IP sent UDP probes to more than {getattr(config, 'UDP_SCAN_THRESHOLD', 15)} "
            f"distinct ports or target hosts within {config.TIME_WINDOW} seconds. Because UDP is connectionless, "
            "scanners send rapid datagrams to identify open UDP services (such as DNS, SNMP, NTP)."
        ),
        "UDP_FLOOD": (
            f"A high volume of UDP packets (≥{getattr(config, 'UDP_FLOOD_THRESHOLD', 50)} pkts in {getattr(config, 'UDP_FLOOD_WINDOW', 5)}s, "
            f"or ≥{getattr(config, 'UDP_FLOOD_WEB_THRESHOLD', 500)} pkts on web/QUIC ports) was directed at a target. "
            "High-rate UDP streams can saturate interface bandwidth and exhaust socket buffers in a Denial-of-Service attempt."
        ),
        "TCP_STEALTH_SCAN": (
            f"A source sent FIN, NULL, or Xmas (FIN+PSH+URG) packets to more than {getattr(config, 'TCP_STEALTH_SCAN_THRESHOLD', 15)} "
            f"distinct ports within {config.TIME_WINDOW} seconds. These stealth scans exploit RFC 793 to identify "
            "closed ports via RSTs while bypassing simple SYN-logging firewalls."
        ),
        "SYN_FLOOD": (
            f"This alert fired because more than {config.SYN_FLOOD_THRESHOLD} initial TCP SYN packets "
            f"(or {getattr(config, 'RST_FLOOD_THRESHOLD', 100)} RST packets) were sent to a service port "
            f"within {config.TIME_WINDOW} seconds without completing handshakes. Could be a misconfigured service "
            "or a genuine DoS attempt."
        ),
        "DISTRIBUTED_SYN_FLOOD": (
            f"A target service received at least {getattr(config, 'DISTRIBUTED_SYN_FLOOD_THRESHOLD', 500)} initial SYNs "
            f"across at least {getattr(config, 'DISTRIBUTED_SYN_FLOOD_MIN_SOURCES', 20)} distinct source IP addresses "
            f"within {config.TIME_WINDOW} seconds. This signature indicates a coordinated Distributed Denial-of-Service (DDoS) flood."
        ),
        "ICMP_SWEEP": (
            f"A single host sent ICMP echo requests (pings) to more than {getattr(config, 'ICMP_SWEEP_THRESHOLD', 12)} "
            f"distinct IP addresses within {config.TIME_WINDOW} seconds. Network scanners use ICMP sweeps for automated "
            "host-discovery and subnet mapping."
        ),
        "ICMP_FLOOD": (
            f"A target received more than {getattr(config, 'ICMP_FLOOD_THRESHOLD', 50)} ICMP echo requests within "
            f"{getattr(config, 'ICMP_FLOOD_WINDOW', 5)} seconds. High-frequency ICMP bursts saturate bandwidth and "
            "consume CPU processing cycles on the target system."
        ),
        "ARP_SPOOF": (
            "An IP address was previously seen claiming one MAC address, but now claims a different one. "
            "This can indicate ARP poisoning (MITM attack) or a legitimate device change "
            "(e.g. router replaced, VM migration, or network reconfiguration)."
        ),
        "PAYLOAD_HIT": (
            "A suspicious payload pattern (SQL injection, XSS, credential leakage, command injection, path traversal, "
            "SSRF, Log4Shell, XXE, SSTI, Shellshock, deserialization, scanner probe, sensitive file probe, reverse shell cradle, "
            "HTTP method tampering, or webshell) was detected via Deep Packet Inspection (DPI) in unencrypted application traffic. "
            "Inspect the matched pattern and evidence payload."
        ),
        "DNS_ANOMALY": (
            f"A DNS query had unusually high Shannon entropy (≥{config.DNS_ENTROPY_THRESHOLD:.1f} bits/char), "
            f"exceeded maximum expected length ({config.DNS_QUERY_MAX_LEN} chars), reached repeated query frequency "
            f"(≥{config.DNS_FREQ_THRESHOLD} queries in {config.DNS_FREQ_WINDOW}s), exceeded distinct subdomain limits "
            f"(≥{getattr(config, 'DNS_SUBDOMAIN_THRESHOLD', 20)} subdomains), or contained low-entropy hex-chunk tunnels. "
            "This indicates possible DGA malware, covert DNS data tunneling, or reconnaissance."
        ),
        "BRUTE_FORCE": (
            f"A single source IP attempted {getattr(config, 'BRUTE_FORCE_THRESHOLD', 20)} or more connections to an authentication "
            f"or administration service (SSH, RDP, SMB, MySQL, FTP, Telnet) within {getattr(config, 'BRUTE_FORCE_WINDOW', 60)} seconds. "
            "This rapid retry pattern typically indicates automated password guessing or credential stuffing."
        ),
        "SLOW_PORT_SCAN": (
            f"A source scanned at least {getattr(config, 'SLOW_SCAN_THRESHOLD', 30)} distinct ports or hosts over an extended "
            f"window of {getattr(config, 'SLOW_SCAN_WINDOW', 120)} seconds. Attackers use low-and-slow scanning intervals "
            "to fly under the radar of fast sliding-window detectors."
        ),
        "DATA_EXFIL": (
            f"Outbound network transfer from a local device exceeded volume thresholds (≥{getattr(config, 'DATA_EXFIL_BYTE_THRESHOLD', 50000)} bytes "
            f"to arbitrary ports, or ≥{getattr(config, 'DATA_EXFIL_WEB_BYTE_THRESHOLD', 1000000)} bytes to web ports in {getattr(config, 'DATA_EXFIL_WINDOW', 30)}s) "
            "or contained database/archive signature dumps. This could indicate sensitive data theft or unauthorized exfiltration."
        ),
        "TLS_ANOMALY": (
            "A TLS Client Hello packet contained an RFC 6066 violation (literal IPv4 or IPv6 address specified as the Server Name "
            "Indication / SNI) or a suspicious dynamic DNS / reverse-proxy tunneling domain (e.g. ngrok, duckdns, localtunnel). "
            "Malicious C2 frameworks use direct IP SNI or reverse tunnels to circumvent domain-based inspection."
        ),
        "CLEAR_HTTP_ON_TLS_PORT": (
            f"Cleartext HTTP request lines (e.g. GET/POST/CONNECT) were detected on standard encrypted TLS ports (443 or 8443) "
            f"with repeated occurrences (≥{getattr(config, 'CLEAR_HTTP_TLS_MIN_REQUESTS', 2)}). This pattern highlights "
            "unencrypted C2 beaconing disguised on port 443, proxy protocol confusion, or server misconfiguration."
        ),
        "TCP_ZERO_WINDOW": (
            f"A host sent {getattr(config, 'TCP_ZERO_WINDOW_THRESHOLD', 20)} or more TCP zero-window (win=0) advertisements to a server "
            f"within {getattr(config, 'TCP_ZERO_WINDOW_WINDOW', 10)} seconds. This signature indicates a Sockstress or zero-window "
            "resource-exhaustion attack, designed to tie up server connection buffers and trigger persist-timer starvation."
        ),
        "NON_DNS_TRAFFIC_ON_DNS_PORT": (
            "Interactive shell prompts (cmd.exe, /bin/sh, powershell), cleartext HTTP commands, or high-ratio "
            "printable ASCII streams were observed on DNS port 53 (TCP/UDP). Threat actors frequently abuse port 53 "
            "to establish reverse shells or bypass restrictive perimeter egress firewalls."
        ),
        "ICMP_TUNNEL": (
            "Covert ICMP data tunneling or reverse shell traffic (ptunnel magic, embedded PE/ELF executables, "
            "interactive command prompts, or high-entropy oversized Echo payloads) was detected inside ICMP Echo "
            "Request or Reply packets. Legitimate diagnostics carry predictable sequential or zeroed padding."
        ),
        "IP_FRAGMENT_ANOMALY": (
            "Anomalous IP packet fragmentation was detected, such as overlapping fragment offsets (Teardrop / Bonk "
            "TCP/IP reassembly crash attacks), conflicting payload bytes across retransmissions, or tiny initial fragments "
            "(RFC 1858 firewall evasion splitting the transport header)."
        ),
        "IRC_C2_BEACONING": (
            "Periodic beaconing or botnet command-and-control activity was detected on IRC ports (e.g. 6667). "
            "Confirmed C2 classification requires observable botnet registration tokens (e.g. #botnet, bot_*) paired "
            "with malicious command syntax (e.g. !flood, !attack, download) across regular connection intervals."
        ),
    }
    alert["explanation"] = explanations.get(alert.get("rule_name", ""), "No explanation available.")
    # Attach GeoIP flag for the modal
    alert["flag"] = _country_flag(alert.get("country_code", ""))
    return jsonify(alert)


@app.route("/api/feedback", methods=["POST"])
def api_submit_feedback():
    """
    Analyst submits TP/FP classification for an alert.
    Body (JSON): { alert_id, classification, analyst_note }
    classification: 'true_positive' | 'false_positive'
    """
    data = request.get_json(silent=True) or {}
    alert_id = data.get("alert_id")
    classification = data.get("classification", "").strip()
    analyst_note = data.get("analyst_note", "").strip()

    if not alert_id or classification not in ("true_positive", "false_positive"):
        return jsonify({"error": "alert_id and classification (true_positive|false_positive) required"}), 400

    # Fetch alert details to store with feedback
    db = get_db()
    sql = ("SELECT rule_name, src_ip, dst_ip FROM alerts WHERE id = ?"
           if config.DB_BACKEND == "sqlite"
           else "SELECT rule_name, src_ip, dst_ip FROM alerts WHERE id = %s")
    from storage.db import _sqlite_lock
    with _sqlite_lock:
        cur = db.cursor()
        cur.execute(sql, (alert_id,))
        row = cur.fetchone()
        cur.close()
    if not row:
        return jsonify({"error": "Alert not found"}), 404

    row = dict(row)
    write_feedback(
        db, alert_id=alert_id, classification=classification,
        analyst_note=analyst_note, rule_name=row.get("rule_name", ""),
        src_ip=row.get("src_ip", ""), dst_ip=row.get("dst_ip", ""),
    )
    logger.info(f"Feedback saved: alert {alert_id} → {classification}")
    return jsonify({"status": "ok", "alert_id": alert_id, "classification": classification})


@app.route("/api/feedback/stats")
def api_feedback_stats():
    """Return TP/FP counts per rule — useful for threshold tuning decisions."""
    db = get_db()
    stats = feedback_stats(db)
    recent = read_feedback(db, limit=20)
    for r in recent:
        r["time_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.get("timestamp", 0)))
    return jsonify({"stats": stats, "recent": recent})


@app.route("/api/feedback/reclassify", methods=["POST"])
def api_feedback_reclassify():
    """Reclassify an existing alert, recording audit trail without double-counting."""
    data = request.get_json(silent=True) or {}
    alert_id = data.get("alert_id")
    new_class = data.get("new_classification", data.get("classification", "")).strip()
    note = data.get("analyst_note", "").strip()

    if not alert_id or new_class not in ("true_positive", "false_positive"):
        return jsonify({"error": "alert_id and new_classification (true_positive|false_positive) required"}), 400

    db = get_db()
    from storage.db import _sqlite_lock
    with _sqlite_lock:
        cur = db.cursor()
        db_exec(cur, "SELECT rule_name, src_ip, dst_ip FROM alerts WHERE id = ?", (alert_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            return jsonify({"error": "Alert not found"}), 404
        r_info = dict(row)
        cur.close()

    write_feedback(
        db, alert_id=alert_id, classification=new_class,
        analyst_note=f"[Reclassified] {note}".strip(),
        rule_name=r_info.get("rule_name", ""),
        src_ip=r_info.get("src_ip", ""),
        dst_ip=r_info.get("dst_ip", ""),
    )

    with _sqlite_lock:
        cur = db.cursor()
        status_val = "closed" if new_class == "false_positive" else "verified"
        db_exec(cur, "UPDATE alerts SET status = ? WHERE id = ?", (status_val, alert_id))
        db.commit()
        cur.close()

    write_audit_log(db, "analyst", "reclassify_alert", "alerts", str(alert_id), {"new_classification": new_class, "note": note})
    return jsonify({"status": "ok", "alert_id": alert_id, "new_classification": new_class})


# ---------------------------------------------------------------------------
# Traffic Explorer APIs (Phase 2)
# ---------------------------------------------------------------------------

@app.route("/api/traffic")
def api_traffic():
    """
    Server-side search, filtering, and pagination over normalized network flows.
    Supports structured KQL (?kql=...) alongside standard field filters.
    """
    db = get_db()
    t_start = time.time()
    page = max(1, int(request.args.get("page", 1)))
    page_size = max(1, min(int(request.args.get("page_size", request.args.get("limit", 50))), 200))
    sort_by_raw = request.args.get("sort_by", "last_seen")
    order = "ASC" if request.args.get("order", "desc").lower() == "asc" else "DESC"

    col_map = {
        "last_time": "last_seen",
        "last_seen": "last_seen",
        "start_time": "start_time",
        "packets": "packet_count",
        "packet_count": "packet_count",
        "bytes": "byte_count",
        "byte_count": "byte_count",
        "alert_count": "alert_count",
    }
    sort_by = col_map.get(sort_by_raw, "last_seen")

    conditions = []
    params = []

    # 1. KQL structured query parsing
    kql_query = request.args.get("kql") or request.args.get("q")
    if kql_query and kql_query.strip():
        from forensics.kql_parser import parse_kql_to_sql, KqlParseError
        try:
            backend = "postgres" if _is_postgres() else "sqlite"
            kql_where, kql_params = parse_kql_to_sql(kql_query.strip(), backend=backend)
            if kql_where and kql_where != "1=1":
                conditions.append(kql_where)
                params.extend(kql_params)
        except KqlParseError as kpe:
            return jsonify({"error": f"KQL Syntax Error: {kpe}", "pos": getattr(kpe, "pos", None)}), 400

    is_pg = _is_postgres()

    def _build_traffic_ip_clause(col: str, val_str: str):
        val_str = val_str.strip()
        if "/" in val_str:
            try:
                import ipaddress
                net = ipaddress.ip_network(val_str, strict=False)
                if is_pg:
                    return f"{col}::inet <<= ?::inet", [str(net)]
                else:
                    return f"cidr_match({col}, ?)", [str(net)]
            except Exception:
                pass
        try:
            import ipaddress
            ipaddress.ip_address(val_str)
            return f"{col} = ?", [val_str]
        except Exception:
            return f"{col} LIKE ?", [f"%{val_str}%"]

    ip_search = request.args.get("search") or request.args.get("ip")
    if ip_search:
        src_clause, src_p = _build_traffic_ip_clause("src_ip", ip_search)
        dst_clause, dst_p = _build_traffic_ip_clause("dst_ip", ip_search)
        conditions.append(f"({src_clause} OR {dst_clause})")
        params.extend(src_p + dst_p)

    if request.args.get("src_ip"):
        clause, p = _build_traffic_ip_clause("src_ip", request.args.get("src_ip"))
        conditions.append(clause)
        params.extend(p)

    if request.args.get("dst_ip"):
        clause, p = _build_traffic_ip_clause("dst_ip", request.args.get("dst_ip"))
        conditions.append(clause)
        params.extend(p)

    port = request.args.get("port")
    if port and port.isdigit():
        conditions.append("(src_port = ? OR dst_port = ?)")
        p_val = int(port)
        params.extend([p_val, p_val])

    if request.args.get("src_port") and request.args.get("src_port").isdigit():
        conditions.append("src_port = ?")
        params.append(int(request.args.get("src_port")))

    if request.args.get("dst_port") and request.args.get("dst_port").isdigit():
        conditions.append("dst_port = ?")
        params.append(int(request.args.get("dst_port")))

    if request.args.get("protocol"):
        conditions.append("protocol = ?")
        params.append(request.args.get("protocol").strip().upper())

    if request.args.get("direction"):
        conditions.append("direction = ?")
        params.append(request.args.get("direction").strip().lower())

    has_alerts = request.args.get("has_alerts", "all").lower()
    if has_alerts == "true":
        conditions.append("alert_count > 0")
    elif has_alerts == "false":
        conditions.append("alert_count = 0")

    if request.args.get("start_time"):
        try:
            conditions.append("start_time >= ?")
            params.append(float(request.args.get("start_time")))
        except ValueError:
            pass

    if request.args.get("end_time"):
        try:
            conditions.append("last_seen <= ?")
            params.append(float(request.args.get("end_time")))
        except ValueError:
            pass

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    from storage.db import _sqlite_lock
    with _sqlite_lock:
        cur = db.cursor()
        count_sql = f"SELECT COUNT(*) FROM network_flows {where_clause}"
        db_exec(cur, count_sql, params)
        total = cur.fetchone()[0]

        offset = (page - 1) * page_size
        query_sql = f"""
            SELECT * FROM network_flows
            {where_clause}
            ORDER BY {sort_by} {order}
            LIMIT ? OFFSET ?
        """
        db_exec(cur, query_sql, params + [page_size, offset])
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()

    duration_ms = round((time.time() - t_start) * 1000, 2)

    for r in rows:
        st = r.get("start_time", 0) or 0
        lt = r.get("last_seen", 0) or 0
        dur = max(0.0, lt - st) if (lt and st) else 0.0
        r["duration_seconds"] = dur
        r["duration_str"] = f"{dur:.2f}s"
        r["start_time_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st)) if st else "—"
        r["last_seen_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(lt)) if lt else "—"
        r["last_time_str"] = r["last_seen_str"]
        r["packets"] = r.get("packet_count", 0)
        r["bytes"] = r.get("byte_count", 0)

    return jsonify({
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
        "flows": rows,
        "duration_ms": duration_ms,
        "kql": kql_query or "",
    })


@app.route("/api/traffic/assistant", methods=["POST"])
def api_traffic_assistant():
    """Deterministic Query Generation Assistant converting intent into KQL."""
    data = request.get_json(silent=True) or {}
    intent = data.get("intent", "").strip()
    if not intent:
        return jsonify({"error": "intent is required"}), 400
    from forensics.kql_parser import generate_kql_from_intent
    kql = generate_kql_from_intent(intent)
    return jsonify({"intent": intent, "kql": kql})


@app.route("/api/dns/reverse", methods=["GET", "POST"])
def api_reverse_dns():
    """Asynchronous Reverse DNS (PTR) hostname enrichment with dual-cache."""
    from analytics.reverse_dns import get_reverse_dns_resolver
    resolver = get_reverse_dns_resolver()
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        ips = data.get("ips", [])
        if not isinstance(ips, list):
            return jsonify({"error": "ips must be a list"}), 400
        results = resolver.resolve_batch([str(ip).strip() for ip in ips[:100]])
        return jsonify({"results": results})
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip parameter required"}), 400
    hostname = resolver.resolve(ip)
    return jsonify({"ip": ip, "hostname": hostname, "status": "resolved" if hostname else "unavailable"})


@app.route("/api/hunting/search")
def api_hunting_search():
    """
    Hypothesis-driven threat hunting across flows, packet events, anomalies, and alerts.
    """
    db = get_db()
    t_start = time.time()
    search_type = request.args.get("type", "preset").lower()
    preset = request.args.get("preset", "").lower()
    query = (request.args.get("q") or request.args.get("query") or "").strip()
    hours = float(request.args.get("hours", 24))
    limit = max(1, min(int(request.args.get("limit", 50)), 200))
    since = time.time() - (hours * 3600)

    results = []
    from storage.db import _sqlite_lock

    with _sqlite_lock:
        cur = db.cursor()

        if search_type == "preset":
            if preset == "high_entropy_dns":
                db_exec(cur, 
                    """
                    SELECT id, timestamp, rule_name, src_ip, dst_ip, src_port, dst_port, protocol, detail, 'Existing IDS alert' as classification
                    FROM alerts
                    WHERE rule_name = 'DNS_ANOMALY' AND timestamp >= ? AND (detail LIKE '%entropy%' OR evidence_json LIKE '%entropy%')
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (since, limit)
                )
                results.extend([dict(r) for r in cur.fetchall()])
                db_exec(cur, 
                    """
                    SELECT flow_id as id, timestamp, 'SUSPICIOUS_DNS_QUERY' as rule_name, src_ip, dst_ip, src_port, dst_port, protocol, payload_preview as detail, 'Suspicious traffic indicator' as classification
                    FROM packet_events
                    WHERE payload_preview LIKE '%DNS%' AND timestamp >= ?
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (since, limit)
                )
                results.extend([dict(r) for r in cur.fetchall()])

            elif preset == "stealth_scan":
                db_exec(cur, 
                    """
                    SELECT id, timestamp, rule_name, src_ip, dst_ip, src_port, dst_port, protocol, detail, 'Existing IDS alert' as classification
                    FROM alerts
                    WHERE rule_name = 'TCP_STEALTH_SCAN' AND timestamp >= ?
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (since, limit)
                )
                results.extend([dict(r) for r in cur.fetchall()])
                db_exec(cur, 
                    """
                    SELECT flow_id as id, last_seen as timestamp, 'STEALTH_PROBE_FLOW' as rule_name, src_ip, dst_ip, src_port, dst_port, protocol,
                           'TCP connection with stealth flags' as detail, 'Suspicious traffic indicator' as classification
                    FROM network_flows
                    WHERE protocol = 'TCP' AND tcp_flags in ('FIN', 'NULL', 'XMAS', '0x01', '0x00', '0x29') AND last_seen >= ?
                    ORDER BY last_seen DESC LIMIT ?
                    """,
                    (since, limit)
                )
                results.extend([dict(r) for r in cur.fetchall()])

            elif preset == "icmp_tunnel":
                db_exec(cur, 
                    """
                    SELECT id, timestamp, rule_name, src_ip, dst_ip, src_port, dst_port, protocol, detail, 'Existing IDS alert' as classification
                    FROM alerts
                    WHERE rule_name = 'ICMP_TUNNEL' AND timestamp >= ?
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (since, limit)
                )
                results.extend([dict(r) for r in cur.fetchall()])
                db_exec(cur, 
                    """
                    SELECT flow_id as id, last_seen as timestamp, 'LARGE_ICMP_PAYLOAD' as rule_name, src_ip, dst_ip, src_port, dst_port, protocol,
                           'High byte volume ICMP flow (>500 bytes)' as detail, 'Suspicious traffic indicator' as classification
                    FROM network_flows
                    WHERE protocol = 'ICMP' AND byte_count > 500 AND last_seen >= ?
                    ORDER BY last_seen DESC LIMIT ?
                    """,
                    (since, limit)
                )
                results.extend([dict(r) for r in cur.fetchall()])

            elif preset == "fragment_anomaly":
                db_exec(cur, 
                    """
                    SELECT id, timestamp, rule_name, src_ip, dst_ip, src_port, dst_port, protocol, detail, 'Existing IDS alert' as classification
                    FROM alerts
                    WHERE rule_name = 'IP_FRAGMENT_ANOMALY' AND timestamp >= ?
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (since, limit)
                )
                results.extend([dict(r) for r in cur.fetchall()])

            elif preset == "cleartext_on_443":
                db_exec(cur, 
                    """
                    SELECT id, timestamp, rule_name, src_ip, dst_ip, src_port, dst_port, protocol, detail, 'Existing IDS alert' as classification
                    FROM alerts
                    WHERE rule_name = 'CLEAR_HTTP_ON_TLS_PORT' AND timestamp >= ?
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (since, limit)
                )
                results.extend([dict(r) for r in cur.fetchall()])
                db_exec(cur, 
                    """
                    SELECT flow_id as id, last_seen as timestamp, 'CLEARTEXT_PORT_443' as rule_name, src_ip, dst_ip, src_port, dst_port, protocol,
                           'TCP traffic to port 443' as detail, 'Suspicious traffic indicator' as classification
                    FROM network_flows
                    WHERE dst_port = 443 AND protocol = 'TCP' AND last_seen >= ?
                    ORDER BY last_seen DESC LIMIT ?
                    """,
                    (since, limit)
                )
                results.extend([dict(r) for r in cur.fetchall()])

            elif preset == "irc_beaconing":
                db_exec(cur, 
                    """
                    SELECT id, timestamp, rule_name, src_ip, dst_ip, src_port, dst_port, protocol, detail, 'Existing IDS alert' as classification
                    FROM alerts
                    WHERE rule_name = 'IRC_C2_BEACONING' AND timestamp >= ?
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (since, limit)
                )
                results.extend([dict(r) for r in cur.fetchall()])
                db_exec(cur, 
                    """
                    SELECT flow_id as id, last_seen as timestamp, 'IRC_PORT_FLOW' as rule_name, src_ip, dst_ip, src_port, dst_port, protocol,
                           'Traffic to standard IRC port (6667)' as detail, 'Suspicious traffic indicator' as classification
                    FROM network_flows
                    WHERE dst_port in (6667, 6697) AND last_seen >= ?
                    ORDER BY last_seen DESC LIMIT ?
                    """,
                    (since, limit)
                )
                results.extend([dict(r) for r in cur.fetchall()])

        elif search_type == "rule":
            db_exec(cur, 
                """
                SELECT id, timestamp, rule_name, src_ip, dst_ip, src_port, dst_port, protocol, detail, 'Existing IDS alert' as classification
                FROM alerts
                WHERE rule_name = ? AND timestamp >= ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (query, since, limit)
            )
            results.extend([dict(r) for r in cur.fetchall()])

        elif search_type == "ip":
            db_exec(cur, 
                """
                SELECT id, timestamp, rule_name, src_ip, dst_ip, src_port, dst_port, protocol, detail, 'Existing IDS alert' as classification
                FROM alerts
                WHERE (src_ip = ? OR dst_ip = ?) AND timestamp >= ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (query, query, since, limit)
            )
            results.extend([dict(r) for r in cur.fetchall()])
            db_exec(cur, 
                """
                SELECT flow_id as id, last_seen as timestamp, 'HOST_SESSION' as rule_name, src_ip, dst_ip, src_port, dst_port, protocol,
                       'Historical network session' as detail, 'Unclassified observation' as classification
                FROM network_flows
                WHERE (src_ip = ? OR dst_ip = ?) AND last_seen >= ?
                ORDER BY last_seen DESC LIMIT ?
                """,
                (query, query, since, limit)
            )
            results.extend([dict(r) for r in cur.fetchall()])

        elif search_type == "port":
            port_num = int(query) if query.isdigit() else 80
            db_exec(cur, 
                """
                SELECT id, timestamp, rule_name, src_ip, dst_ip, src_port, dst_port, protocol, detail, 'Existing IDS alert' as classification
                FROM alerts
                WHERE (src_port = ? OR dst_port = ?) AND timestamp >= ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (port_num, port_num, since, limit)
            )
            results.extend([dict(r) for r in cur.fetchall()])
            db_exec(cur, 
                """
                SELECT flow_id as id, last_seen as timestamp, 'PORT_SESSION' as rule_name, src_ip, dst_ip, src_port, dst_port, protocol,
                       'Historical port session' as detail, 'Unclassified observation' as classification
                FROM network_flows
                WHERE (src_port = ? OR dst_port = ?) AND last_seen >= ?
                ORDER BY last_seen DESC LIMIT ?
                """,
                (port_num, port_num, since, limit)
            )
            results.extend([dict(r) for r in cur.fetchall()])

        elif search_type == "domain":
            p = f"%{query}%"
            db_exec(cur, 
                """
                SELECT event_id as id, timestamp, 'SUSPICIOUS_DOMAIN_EVENT' as rule_name, src_ip, dst_ip, src_port, dst_port, protocol,
                       payload_preview as detail, 'Suspicious traffic indicator' as classification
                FROM packet_events
                WHERE payload_preview LIKE ? AND timestamp >= ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (p, since, limit)
            )
            results.extend([dict(r) for r in cur.fetchall()])
            db_exec(cur, 
                """
                SELECT id, timestamp, rule_name, src_ip, dst_ip, src_port, dst_port, protocol, detail, 'Existing IDS alert' as classification
                FROM alerts
                WHERE (detail LIKE ? OR evidence_json LIKE ?) AND timestamp >= ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (p, p, since, limit)
            )
            results.extend([dict(r) for r in cur.fetchall()])

        elif search_type == "cidr":
            clean_cidr = query.split("/")[0].rsplit(".", 1)[0] + ".%" if "/" in query else f"{query}%"
            db_exec(cur, 
                """
                SELECT id, timestamp, rule_name, src_ip, dst_ip, src_port, dst_port, protocol, detail, 'Existing IDS alert' as classification
                FROM alerts
                WHERE (src_ip LIKE ? OR dst_ip LIKE ?) AND timestamp >= ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (clean_cidr, clean_cidr, since, limit)
            )
            results.extend([dict(r) for r in cur.fetchall()])
            db_exec(cur, 
                """
                SELECT flow_id as id, last_seen as timestamp, 'SUBNET_FLOW' as rule_name, src_ip, dst_ip, src_port, dst_port, protocol,
                       'Subnet traffic session' as detail, 'Unclassified observation' as classification
                FROM network_flows
                WHERE (src_ip LIKE ? OR dst_ip LIKE ?) AND last_seen >= ?
                ORDER BY last_seen DESC LIMIT ?
                """,
                (clean_cidr, clean_cidr, since, limit)
            )
            results.extend([dict(r) for r in cur.fetchall()])

        elif search_type == "string":
            p = f"%{query}%"
            db_exec(cur, 
                """
                SELECT id, timestamp, rule_name, src_ip, dst_ip, src_port, dst_port, protocol, detail, 'Existing IDS alert' as classification
                FROM alerts
                WHERE (detail LIKE ? OR evidence_json LIKE ?) AND timestamp >= ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (p, p, since, limit)
            )
            results.extend([dict(r) for r in cur.fetchall()])

        elif search_type == "anomaly":
            p = f"%{query}%" if query else "%"
            db_exec(cur, 
                """
                SELECT id, timestamp, metric_name as rule_name, '127.0.0.1' as src_ip, '127.0.0.1' as dst_ip, NULL as src_port, NULL as dst_port, 'IP' as protocol,
                       explanation as detail, 'Statistical anomaly' as classification
                FROM traffic_anomalies
                WHERE (metric_name LIKE ? OR explanation LIKE ?) AND timestamp >= ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (p, p, since, limit)
            )
            results.extend([dict(r) for r in cur.fetchall()])

        elif search_type in ("kql", "query"):
            from forensics.kql_parser import parse_kql_to_sql, KqlParseError
            try:
                sql_where, kql_params = parse_kql_to_sql(query, backend="postgres" if _is_postgres() else "sqlite")
                sql = f"""
                    SELECT flow_id as id, last_seen as timestamp,
                           CASE WHEN alert_count > 0 THEN 'ALERTED_FLOW' ELSE 'TELEMETRY_FLOW' END as rule_name,
                           src_ip, dst_ip, src_port, dst_port, protocol,
                           'KQL matched session' as detail,
                           CASE WHEN alert_count > 0 THEN 'Existing IDS alert' ELSE 'Unclassified observation' END as classification
                    FROM network_flows
                    WHERE {sql_where} AND last_seen >= ?
                    ORDER BY last_seen DESC LIMIT ?
                """
                db_exec(cur, sql, kql_params + [since, limit])
                results.extend([dict(r) for r in cur.fetchall()])
            except KqlParseError as e:
                cur.close()
                return jsonify({"error": f"KQL error: {e}"}), 400

        cur.close()

    # Deduplicate results by (rule_name, src_ip, dst_ip, int(timestamp))
    seen = set()
    deduped = []
    for r in results:
        key = (r.get("rule_name"), r.get("src_ip"), r.get("dst_ip"), int(r.get("timestamp") or 0))
        if key not in seen:
            seen.add(key)
            ts = r.get("timestamp", 0) or 0
            r["time_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "—"
            r["indicator"] = r.get("src_ip") if (r.get("src_ip") and r.get("src_ip") != "127.0.0.1") else (r.get("rule_name") or r.get("indicator") or "Unknown")
            r["context"] = r.get("rule_name") or "Network"
            r["proto_port"] = f"{r.get('protocol', 'IP')}:{r.get('dst_port') or ''}"
            deduped.append(r)

    duration_ms = round((time.time() - t_start) * 1000, 2)
    return jsonify({
        "type": search_type,
        "preset": preset,
        "total": len(deduped),
        "duration_ms": duration_ms,
        "results": deduped[:limit]
    })


@app.route("/api/traffic/<flow_id>")
def api_traffic_detail(flow_id: str):
    """
    Return comprehensive session detail for a single flow, including
    associated alerts and recent packet event snapshots.
    """
    db = get_db()
    from storage.db import _sqlite_lock
    with _sqlite_lock:
        cur = db.cursor()
        db_exec(cur, "SELECT * FROM network_flows WHERE flow_id = ?", (flow_id,))
        flow_row = cur.fetchone()
        if not flow_row:
            cur.close()
            return jsonify({"error": "Flow not found"}), 404
        flow = dict(flow_row)

        db_exec(cur, "SELECT * FROM alerts WHERE flow_id = ? ORDER BY timestamp ASC", (flow_id,))
        alerts = [dict(r) for r in cur.fetchall()]

        db_exec(cur, "SELECT * FROM packet_events WHERE flow_id = ? ORDER BY packet_index ASC LIMIT 100", (flow_id,))
        packet_events = [dict(r) for r in cur.fetchall()]
        cur.close()

    flow["start_time_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(flow.get("start_time", 0)))
    flow["last_time_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(flow.get("last_time", 0)))

    for a in alerts:
        a["time_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a.get("timestamp", 0)))
        if a.get("evidence_json"):
            try:
                a["evidence"] = json.loads(a["evidence_json"])
            except Exception:
                pass

    for p in packet_events:
        p["time_str"] = time.strftime("%H:%M:%S", time.localtime(p.get("timestamp", 0)))

    return jsonify({
        "flow": flow,
        "alerts": alerts,
        "packet_events": packet_events,
    })


@app.route("/api/traffic/<flow_id>/pcap")
def api_traffic_pcap(flow_id: str):
    """Download PCAP segment or reconstituted packet events for flow."""
    db = get_db()
    from storage.db import _sqlite_lock
    with _sqlite_lock:
        cur = db.cursor()
        db_exec(cur, "SELECT timestamp, raw_hex, packet_len FROM packet_events WHERE flow_id = ? AND raw_hex IS NOT NULL ORDER BY packet_index ASC", (flow_id,))
        rows = cur.fetchall()
        cur.close()

    if not rows:
        return jsonify({"error": f"No raw packet capture retained for flow {flow_id}"}), 404

    # Assemble libpcap format (little-endian standard: magic \xd4\xc3\xb2\xa1, linktype 1 DLT_EN10MB Ethernet)
    buf = io.BytesIO()
    buf.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for r in rows:
        ts = r[0] or time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1e6)
        raw_bytes = bytes.fromhex(r[1])
        incl_len = len(raw_bytes)
        orig_len = r[2] or incl_len
        buf.write(struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len))
        buf.write(raw_bytes)

    pcap_data = buf.getvalue()
    return Response(
        pcap_data,
        mimetype="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f"attachment; filename=flow_{flow_id[:16]}.pcap"}
    )


@app.route("/api/traffic/export")
def api_traffic_export():
    """Export filtered network flows as CSV."""
    db = get_db()
    conditions = []
    params = []
    ip_search = request.args.get("search") or request.args.get("ip")
    if ip_search:
        conditions.append("(src_ip LIKE ? OR dst_ip LIKE ?)")
        params.extend([f"%{ip_search}%", f"%{ip_search}%"])
    if request.args.get("protocol"):
        conditions.append("protocol = ?")
        params.append(request.args.get("protocol").strip().upper())
    if request.args.get("direction"):
        conditions.append("direction = ?")
        params.append(request.args.get("direction").strip().lower())

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"SELECT * FROM network_flows {where_clause} ORDER BY last_seen DESC LIMIT 5000"

    from storage.db import _sqlite_lock
    with _sqlite_lock:
        cur = db.cursor()
        db_exec(cur, sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["flow_id", "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "direction", "packets", "bytes", "start_time", "last_seen", "duration_seconds", "alert_count", "threat_score"])
    for r in rows:
        st = r.get("start_time", 0) or 0
        lt = r.get("last_seen", 0) or 0
        dur = max(0.0, lt - st) if (lt and st) else 0.0
        writer.writerow([
            r.get("flow_id"), r.get("protocol"), r.get("src_ip"), r.get("src_port"),
            r.get("dst_ip"), r.get("dst_port"), r.get("direction"), r.get("packet_count"),
            r.get("byte_count"), st, lt, f"{dur:.2f}",
            r.get("alert_count"), 0,
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=traffic_flows.csv"}
    )


@app.route("/api/saved-searches", methods=["GET", "POST"])
@app.route("/api/traffic/saved-searches", methods=["GET", "POST"])
def api_saved_searches():
    """Manage saved search queries."""
    db = get_db()
    from storage.db import _sqlite_lock
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        name = data.get("name", "").strip()
        query_json = json.dumps(data.get("query", {}))
        desc = data.get("description", "").strip()
        if not name:
            return jsonify({"error": "name is required"}), 400
        now = time.time()
        with _sqlite_lock:
            cur = db.cursor()
            if _is_postgres():
                cur.execute(
                    "INSERT INTO saved_searches (name, query_params_json, description, created_at) VALUES (%s, %s, %s, %s) RETURNING id",
                    (name, query_json, desc, now)
                )
                search_id = cur.fetchone()[0]
            else:
                cur.execute(
                    "INSERT INTO saved_searches (name, query_params_json, description, created_at) VALUES (?, ?, ?, ?)",
                    (name, query_json, desc, now)
                )
                search_id = cur.lastrowid
            db.commit()
            cur.close()
        write_audit_log(db, "analyst", "create_saved_search", "saved_searches", str(search_id), {"name": name})
        return jsonify({"status": "ok", "id": search_id, "name": name})

    with _sqlite_lock:
        cur = db.cursor()
        db_exec(cur, "SELECT * FROM saved_searches ORDER BY created_at DESC")
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
    for r in rows:
        try:
            r["query"] = json.loads(r.get("query_params_json", "{}"))
        except Exception:
            r["query"] = {}
    return jsonify(rows)


@app.route("/api/saved-searches/<int:search_id>", methods=["DELETE"])
def api_delete_saved_search(search_id: int):
    """Delete a saved search query."""
    db = get_db()
    from storage.db import _sqlite_lock
    with _sqlite_lock:
        cur = db.cursor()
        db_exec(cur, "DELETE FROM saved_searches WHERE id = ?", (search_id,))
        db.commit()
        cur.close()
    write_audit_log(db, "analyst", "delete_saved_search", "saved_searches", str(search_id))
    return jsonify({"status": "ok", "id": search_id})


# ---------------------------------------------------------------------------
# PCAP Offline Analysis APIs (Phase 5)
# ---------------------------------------------------------------------------

@app.route("/api/pcap/upload", methods=["POST"])
def api_pcap_upload():
    """Upload PCAP capture file for isolated offline replay with security validation."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    raw_name = file.filename or ""
    filename = secure_filename(raw_name)
    if not filename:
        filename = f"capture_{uuid.uuid4().hex[:8]}.pcap"

    ext = os.path.splitext(filename)[1].lower()
    if ext not in (".pcap", ".pcapng", ".cap"):
        return jsonify({"error": f"Invalid extension '{ext}'. Only .pcap, .pcapng, and .cap supported"}), 400

    upload_dir = getattr(config, "PCAP_UPLOAD_DIR", "data/uploads")
    os.makedirs(upload_dir, exist_ok=True)
    temp_path = os.path.join(upload_dir, f"upload_{int(time.time())}_{uuid.uuid4().hex}_{filename}")
    file.save(temp_path)

    # Validate PCAP magic bytes to prevent non-capture file processing
    try:
        with open(temp_path, "rb") as mf:
            magic = mf.read(4)
            valid_magics = (
                b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
                b"\x0a\x0d\x0d\x0a",  # PCAP-NG
                b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"  # Nanosecond PCAP
            )
            if magic not in valid_magics:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                return jsonify({"error": f"Invalid PCAP file header: unsupported magic {magic.hex()}"}), 400
    except Exception as exc:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({"error": f"Failed to validate PCAP header: {exc}"}), 400

    analyzer = get_offline_analyzer()
    try:
        job = analyzer.create_job(filename, temp_path)
        analyzer.run_job_async(job["job_id"])
        write_audit_log(get_db(), "analyst", "pcap_upload", "pcap_jobs", job["job_id"], {"filename": filename})
        return jsonify({
            "status": "queued",
            "job_id": job["job_id"],
            "filename": filename,
            "file_size": job["file_size"],
            "sha256": job["sha256"],
        })
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
        return jsonify({"error": str(e)}), 400


@app.route("/api/pcap/jobs")
def api_pcap_jobs():
    """List offline PCAP analysis jobs."""
    analyzer = get_offline_analyzer()
    return jsonify(analyzer.list_jobs(limit=100))


@app.route("/api/pcap/jobs/<job_id>")
def api_pcap_job_detail(job_id: str):
    """Get offline PCAP analysis job status and isolated alerts."""
    analyzer = get_offline_analyzer()
    job = analyzer.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@app.route("/api/pcap/jobs/<job_id>/export")
def api_pcap_job_export(job_id: str):
    """Export alerts from an offline PCAP job."""
    analyzer = get_offline_analyzer()
    job = analyzer.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    fmt = request.args.get("format", "json").lower()
    alerts = []
    if job.get("result_summary_json"):
        try:
            summary = json.loads(job["result_summary_json"])
            alerts = summary.get("alerts", [])
        except Exception:
            pass

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "time", "rule_name", "severity", "src_ip", "src_port", "dst_ip", "dst_port", "detail"])
        for a in alerts:
            writer.writerow([
                a.get("id"), a.get("timestamp"), a.get("rule_name"),
                a.get("severity"), a.get("src_ip"), a.get("src_port"),
                a.get("dst_ip"), a.get("dst_port"), a.get("detail"),
            ])
        return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=job_{job_id}_alerts.csv"})

    return jsonify({"job_id": job_id, "alerts": alerts})


# ---------------------------------------------------------------------------
# Baselines & Anomaly Analytics APIs (Phase 4)
# ---------------------------------------------------------------------------

@app.route("/api/baselines")
def api_baselines():
    """Return historical baseline profile and rolling metrics."""
    _baseline_engine.set_connection(get_db())
    return jsonify(_baseline_engine.get_all_baselines())


@app.route("/api/anomalies")
def api_anomalies():
    """Return recent detected traffic anomalies."""
    _baseline_engine.set_connection(get_db())
    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify(_baseline_engine.get_recent_anomalies(limit=limit))


@app.route("/api/baselines/quarantine", methods=["POST"])
def api_baseline_quarantine():
    """Enable or disable baseline quarantine to protect statistics during attack."""
    data = request.get_json(silent=True) or {}
    quarantine = bool(data.get("quarantine", True))
    _baseline_engine.set_quarantine(quarantine)
    write_audit_log(get_db(), "analyst", "toggle_baseline_quarantine", "baselines", details={"quarantine": quarantine})
    return jsonify({"status": "ok", "quarantined": bool(_baseline_engine.is_quarantined)})


# ---------------------------------------------------------------------------
# Cases & Incident Management APIs (Phase 7)
# ---------------------------------------------------------------------------

@app.route("/api/cases", methods=["GET", "POST"])
def api_cases():
    """List or create incident investigation cases."""
    db = get_db()
    from storage.db import _sqlite_lock
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        title = data.get("title", "").strip()
        if not title:
            return jsonify({"error": "title is required"}), 400
        desc = data.get("description", "").strip()
        valid_severities = {"low", "medium", "high", "critical"}
        sev = str(data.get("severity", "medium")).lower()
        if sev not in valid_severities:
            return jsonify({"error": f"Invalid severity '{sev}'. Must be one of: {', '.join(sorted(valid_severities))}"}), 400
        assigned = data.get("assigned_to", "SOC Analyst").strip()
        alert_ids = data.get("alert_ids", [])
        clean_aids = []
        if alert_ids:
            try:
                clean_aids = [int(x) for x in alert_ids]
            except (ValueError, TypeError):
                return jsonify({"error": "Invalid alert_ids: all must be integers"}), 400

        now = time.time()
        case_id = f"CASE-{time.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

        with _sqlite_lock:
            cur = db.cursor()
            try:
                if clean_aids:
                    param = "%s" if _is_postgres() else "?"
                    placeholders = ",".join([param] * len(clean_aids))
                    cur.execute(f"SELECT id FROM alerts WHERE id IN ({placeholders})", clean_aids)
                    found = {r[0] for r in cur.fetchall()}
                    missing = set(clean_aids) - found
                    if missing:
                        cur.close()
                        return jsonify({"error": f"Alert IDs not found: {sorted(missing)}"}), 404

                db_exec(
                    cur,
                    """
                    INSERT INTO cases (case_id, title, description, status, severity, assignee, created_at, updated_at)
                    VALUES (?, ?, ?, 'open', ?, ?, ?, ?)
                    """,
                    (case_id, title, desc, sev, assigned, now, now)
                )
                for aid in set(clean_aids):
                    if _is_postgres():
                        cur.execute("INSERT INTO case_alerts (case_id, alert_id, added_at) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING", (case_id, int(aid), now))
                    else:
                        cur.execute("INSERT OR IGNORE INTO case_alerts (case_id, alert_id, added_at) VALUES (?, ?, ?)", (case_id, int(aid), now))
                db.commit()
            except Exception as e:
                db.rollback()
                cur.close()
                return jsonify({"error": f"Database error creating case: {e}"}), 500
            cur.close()

        write_audit_log(db, assigned, "create_case", "cases", case_id, {"title": title, "alert_count": len(clean_aids)})
        return jsonify({"status": "ok", "case_id": case_id, "title": title})

    status_filter = request.args.get("status")
    sev_filter = request.args.get("severity")
    conditions = []
    params = []
    if status_filter and status_filter.lower() != "all":
        conditions.append("c.status = ?")
        params.append(status_filter.lower())
    if sev_filter and sev_filter.lower() != "all":
        conditions.append("c.severity = ?")
        params.append(sev_filter.lower())

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"""
        SELECT c.*, COUNT(ca.alert_id) as alert_count
        FROM cases c
        LEFT JOIN case_alerts ca ON c.case_id = ca.case_id
        {where_clause}
        GROUP BY c.case_id
        ORDER BY c.created_at DESC
    """
    with _sqlite_lock:
        cur = db.cursor()
        db_exec(cur, sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()

    for r in rows:
        r["assigned_to"] = r.get("assignee")
        r["created_str"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(r.get("created_at", 0)))
        r["updated_str"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(r.get("updated_at", 0)))
    return jsonify(rows)


@app.route("/api/cases/<case_id>", methods=["GET", "PATCH"])
def api_case_detail(case_id: str):
    """Retrieve or update single incident case."""
    db = get_db()
    from storage.db import _sqlite_lock
    if request.method == "PATCH":
        data = request.get_json(silent=True) or {}
        valid_statuses = {"open", "investigating", "resolved", "closed"}
        valid_severities = {"low", "medium", "high", "critical"}
        allowed_transitions = {
            "open": {"open", "investigating"},
            "investigating": {"investigating", "resolved", "open"},
            "resolved": {"resolved", "closed", "investigating"},
            "closed": {"closed", "open"},
        }

        # Validate severity if provided
        if "severity" in data:
            sev_val = str(data["severity"]).lower()
            if sev_val not in valid_severities:
                return jsonify({"error": f"Invalid severity '{sev_val}'. Must be one of: {', '.join(sorted(valid_severities))}"}), 400
            data["severity"] = sev_val

        # Validate status and state machine transitions if provided
        now = time.time()
        close_ts = None
        if "status" in data:
            st_val = str(data["status"]).lower()
            if st_val not in valid_statuses:
                return jsonify({"error": f"Invalid status '{st_val}'. Must be one of: {', '.join(sorted(valid_statuses))}"}), 400

            with _sqlite_lock:
                cur = db.cursor()
                db_exec(cur, "SELECT status FROM cases WHERE case_id = ?", (case_id,))
                current_row = cur.fetchone()
                cur.close()
            if not current_row:
                return jsonify({"error": "Case not found"}), 404

            current_status = str(current_row["status"]).lower()
            if st_val not in allowed_transitions.get(current_status, set()):
                return jsonify({
                    "error": f"Invalid status transition from '{current_status}' to '{st_val}'. "
                             f"Allowed transitions from '{current_status}': {', '.join(sorted(allowed_transitions.get(current_status, set())))}"
                }), 400
            data["status"] = st_val
            if st_val == "closed":
                close_ts = now
            elif current_status == "closed" and st_val in ("open", "investigating"):
                close_ts = 0.0

        updates = []
        params = []
        field_map = {"title": "title", "description": "description", "status": "status", "severity": "severity", "assigned_to": "assignee", "assignee": "assignee"}
        for k, v in data.items():
            if k in field_map:
                updates.append(f"{field_map[k]} = ?")
                params.append(v)
        if close_ts is not None:
            if close_ts == 0.0:
                updates.append("closed_at = NULL")
            else:
                updates.append("closed_at = ?")
                params.append(close_ts)

        if not updates:
            return jsonify({"status": "no changes"})
        updates.append("updated_at = ?")
        params.extend([now, case_id])
        with _sqlite_lock:
            cur = db.cursor()
            db_exec(cur, f"UPDATE cases SET {', '.join(updates)} WHERE case_id = ?", params)
            db.commit()
            cur.close()
        write_audit_log(db, "analyst", "update_case", "cases", case_id, data)
        return jsonify({"status": "ok", "case_id": case_id})

    with _sqlite_lock:
        cur = db.cursor()
        db_exec(cur, "SELECT * FROM cases WHERE case_id = ?", (case_id,))
        case_row = cur.fetchone()
        if not case_row:
            cur.close()
            return jsonify({"error": "Case not found"}), 404
        case = dict(case_row)

        db_exec(cur, """
            SELECT a.* FROM alerts a
            JOIN case_alerts ca ON a.id = ca.alert_id
            WHERE ca.case_id = ?
            ORDER BY a.timestamp ASC
        """, (case_id,))
        alerts = [dict(r) for r in cur.fetchall()]

        db_exec(cur, "SELECT * FROM case_notes WHERE case_id = ? ORDER BY created_at ASC", (case_id,))
        notes = [dict(r) for r in cur.fetchall()]
        cur.close()

    case["assigned_to"] = case.get("assignee")
    case["created_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(case.get("created_at", 0)))
    case["updated_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(case.get("updated_at", 0)))
    for a in alerts:
        a["time_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a.get("timestamp", 0)))
    for n in notes:
        n["time_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(n.get("created_at", 0)))

    return jsonify({"case": case, "alerts": alerts, "notes": notes})


@app.route("/api/cases/<case_id>/alerts", methods=["POST"])
def api_case_add_alerts(case_id: str):
    """Link alerts to case."""
    data = request.get_json(silent=True) or {}
    alert_ids = data.get("alert_ids", [])
    if not alert_ids:
        return jsonify({"error": "alert_ids list required"}), 400
    try:
        clean_aids = [int(x) for x in alert_ids]
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid alert_ids: all must be integers"}), 400

    db = get_db()
    now = time.time()
    from storage.db import _sqlite_lock
    with _sqlite_lock:
        cur = db.cursor()
        # 1. Verify case exists
        db_exec(cur, "SELECT case_id FROM cases WHERE case_id = ?", (case_id,))
        if not cur.fetchone():
            cur.close()
            return jsonify({"error": "Case not found"}), 404

        # 2. Verify all alerts exist
        param = "%s" if _is_postgres() else "?"
        placeholders = ",".join([param] * len(clean_aids))
        cur.execute(f"SELECT id FROM alerts WHERE id IN ({placeholders})", clean_aids)
        found = {r[0] for r in cur.fetchall()}
        missing = set(clean_aids) - found
        if missing:
            cur.close()
            return jsonify({"error": f"Alert IDs not found: {sorted(missing)}"}), 404

        for aid in set(clean_aids):
            if _is_postgres():
                cur.execute("INSERT INTO case_alerts (case_id, alert_id, added_at) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING", (case_id, int(aid), now))
            else:
                cur.execute("INSERT OR IGNORE INTO case_alerts (case_id, alert_id, added_at) VALUES (?, ?, ?)", (case_id, int(aid), now))
        db_exec(cur, "UPDATE cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        db.commit()
        cur.close()
    write_audit_log(db, "analyst", "link_alerts_to_case", "cases", case_id, {"alert_ids": clean_aids})
    return jsonify({"status": "ok", "linked_count": len(clean_aids)})


@app.route("/api/cases/<case_id>/alerts/<int:alert_id>", methods=["DELETE"])
def api_case_remove_alert(case_id: str, alert_id: int):
    """Unlink an alert association from a case."""
    db = get_db()
    now = time.time()
    from storage.db import _sqlite_lock
    with _sqlite_lock:
        cur = db.cursor()
        db_exec(cur, "SELECT case_id FROM cases WHERE case_id = ?", (case_id,))
        if not cur.fetchone():
            cur.close()
            return jsonify({"error": "Case not found"}), 404
        db_exec(cur, "DELETE FROM case_alerts WHERE case_id = ? AND alert_id = ?", (case_id, alert_id))
        db_exec(cur, "UPDATE cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        db.commit()
        cur.close()
    write_audit_log(db, "analyst", "unlink_alert_from_case", "cases", case_id, {"alert_id": alert_id})
    return jsonify({"status": "ok", "unlinked_alert_id": alert_id})


@app.route("/api/cases/<case_id>/notes", methods=["POST"])
def api_case_add_note(case_id: str):
    """Add note to case."""
    data = request.get_json(silent=True) or {}
    note = data.get("note", "").strip()
    author = data.get("author", "Analyst").strip()
    if not note:
        return jsonify({"error": "note is required"}), 400
    db = get_db()
    now = time.time()
    from storage.db import _sqlite_lock
    with _sqlite_lock:
        cur = db.cursor()
        db_exec(cur, "SELECT case_id FROM cases WHERE case_id = ?", (case_id,))
        if not cur.fetchone():
            cur.close()
            return jsonify({"error": "Case not found"}), 404
        db_exec(cur, "INSERT INTO case_notes (case_id, author, note, created_at) VALUES (?, ?, ?, ?)", (case_id, author, note, now))
        db_exec(cur, "UPDATE cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        db.commit()
        cur.close()
    write_audit_log(db, author, "add_case_note", "cases", case_id, {"note_len": len(note)})
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Notifications Outbox APIs (Phase 7)
# ---------------------------------------------------------------------------

@app.route("/api/notifications/providers")
def api_notifications_providers():
    """Return status of notification providers."""
    _outbox_manager.set_connection(get_db())
    return jsonify(_outbox_manager.get_providers_status())


@app.route("/api/notifications/outbox")
def api_notifications_outbox():
    """Return recent notification attempts and delivery status."""
    db = get_db()
    from storage.db import _sqlite_lock
    with _sqlite_lock:
        cur = db.cursor()
        cur.execute("SELECT * FROM notification_outbox ORDER BY created_at DESC LIMIT 50")
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
    for r in rows:
        r["created_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.get("created_at", 0)))
    return jsonify(rows)


@app.route("/api/notifications/config", methods=["GET", "POST"])
def api_notifications_config():
    """Read or update notification provider configuration."""
    _outbox_manager.set_connection(get_db())
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        provider = data.get("provider", "").lower()
        cfg = data.get("config", {})
        if not provider:
            return jsonify({"error": "provider name is required"}), 400
        ok, msg = _outbox_manager.configure_provider(provider, cfg, persist=True)
        write_audit_log(get_db(), "analyst", "configure_notification", "notifications", provider, {"status": ok})
        if ok:
            return jsonify({"status": "ok", "message": msg, "config": _outbox_manager.get_provider_config(provider)})
        return jsonify({"error": msg}), 400

    # GET: return all provider configs
    _outbox_manager.reload_providers_from_db()
    all_cfg = {}
    for p_name in ("email", "telegram", "webhook", "sms"):
        all_cfg[p_name] = _outbox_manager.get_provider_config(p_name)
    return jsonify(all_cfg)


@app.route("/api/notifications/test", methods=["POST"])
def api_notifications_test():
    """Send test notification via specified provider with optional direct config."""
    data = request.get_json(silent=True) or {}
    provider = data.get("provider", "webhook")
    recipient = data.get("recipient")
    custom_cfg = data.get("custom_cfg") or data.get("config")
    _outbox_manager.set_connection(get_db())
    result = _outbox_manager.send_test_notification(provider, recipient=recipient, custom_cfg=custom_cfg)
    write_audit_log(get_db(), "analyst", "test_notification", "notifications", provider, result)
    return jsonify(result)


# ---------------------------------------------------------------------------
# Reports APIs (Phase 8)
# ---------------------------------------------------------------------------

@app.route("/api/reports/types")
def api_reports_types():
    """Return available report types and formats."""
    return jsonify({
        "report_types": REPORT_TYPES,
        "formats": ["html", "json", "csv"],
        "email_available": bool(
            _outbox_manager.get_provider("email")
            and _outbox_manager.get_provider("email").is_configured
        ),
        "max_attachment_mb": MAX_ATTACHMENT_BYTES // (1024 * 1024),
    })


def _dashboard_base_url() -> str | None:
    """Only an explicitly configured public URL is embedded in emails."""
    candidate = (os.getenv("NETGUARD_DASHBOARD_URL") or "").strip()
    if candidate.lower().startswith(("http://", "https://")) and not any(
        ch in candidate for ch in "\r\n\t \"'<>"
    ):
        return candidate.rstrip("/")
    return None


@app.route("/api/reports/email", methods=["POST"])
def api_reports_email():
    """Generate a report and queue it for email delivery.

    The report is rendered into an application-owned artifact directory and only
    a bounded reference is stored on the outbox row. Delivery happens
    asynchronously through the durable outbox worker, so a slow or unavailable
    SMTP server never blocks the HTTP request.
    """
    data = request.get_json(silent=True) or {}

    report_type = str(data.get("type") or data.get("report_type") or "daily").lower()
    fmt = str(data.get("format") or data.get("fmt") or "html").lower()
    case_id = data.get("case_id")

    if report_type not in REPORT_TYPES:
        return jsonify({"error": f"Unknown report type '{report_type}'"}), 400
    if fmt not in SUPPORTED_FORMATS:
        return jsonify({
            "error": f"Unsupported format '{fmt}'. Supported: {', '.join(SUPPORTED_FORMATS)}"
        }), 400

    try:
        hours = int(data.get("hours") or 24)
    except (TypeError, ValueError):
        return jsonify({"error": "hours must be an integer"}), 400
    if not 1 <= hours <= 8760:
        return jsonify({"error": "hours must be between 1 and 8760"}), 400

    parsed = parse_all_recipients(
        data.get("to"), data.get("cc"), data.get("bcc")
    )
    if parsed["errors"]:
        return jsonify({
            "error": parsed["errors"][0],
            "invalid": parsed["invalid"],
        }), 400
    if parsed["invalid"]:
        return jsonify({
            "error": "One or more recipient addresses are invalid",
            "invalid": parsed["invalid"],
        }), 400

    email_provider = _outbox_manager.get_provider("email")
    if email_provider is None or not email_provider.is_configured:
        return jsonify({
            "error": (
                "Email notifications are not configured. Set the SMTP host and "
                "sender address in Notification settings before emailing reports."
            )
        }), 400
    if getattr(email_provider, "auth_required_but_missing", False):
        return jsonify({
            "error": (
                "SMTP username is configured but no password is stored. "
                "Add the password in Notification settings."
            )
        }), 400

    db = get_db()
    _outbox_manager.set_connection(db)

    generator = ReportGenerator(db)
    try:
        artifact = generate_artifact(generator, report_type, hours, fmt, case_id)
    except ReportTooLargeError as exc:
        return jsonify({"error": str(exc), "code": "attachment_too_large"}), 413
    except ReportDeliveryError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Report generation for email failed")
        return jsonify({"error": f"Report generation failed: {exc}"}), 500

    dashboard_url = _dashboard_base_url()
    generated_at = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    recipient_count = len(parsed["to"]) + len(parsed["cc"]) + len(parsed["bcc"])

    rendered = render_report_email(
        report_title=REPORT_TYPES.get(report_type, "NetGuard IDS Report"),
        report_type=report_type,
        fmt=fmt,
        filename=artifact.filename,
        hours=hours,
        recipient_count=recipient_count,
        dashboard_base_url=dashboard_url,
        generated_at=generated_at,
    )

    payload = build_report_payload(
        artifact,
        report_title=REPORT_TYPES.get(report_type, "NetGuard IDS Report"),
        report_type=report_type,
        fmt=fmt,
        hours=hours,
        generated_at=generated_at,
    )

    try:
        job_count = _outbox_manager.enqueue_report_email(
            artifact,
            report_payload=payload,
            subject=rendered.subject,
            text_body=rendered.text,
            html_body=rendered.html,
            to=", ".join(parsed["to"]),
            cc=", ".join(parsed["cc"]),
            bcc=", ".join(parsed["bcc"]),
            severity="medium",
        )
    except Exception as exc:
        logger.exception("Failed to queue report email")
        return jsonify({"error": f"Failed to queue report email: {exc}"}), 500

    write_audit_log(
        db, "analyst", "email_report", "reports", report_type,
        {
            "format": fmt,
            "hours": hours,
            "recipients": recipient_count,
            "attachment_bytes": artifact.size_bytes,
            "attachment_sha256": artifact.sha256,
            "queued_jobs": job_count,
        },
    )

    try:
        prune_artifacts()
    except Exception:
        pass

    return jsonify({
        "status": "queued",
        "queued_jobs": job_count,
        "report": {
            "type": report_type,
            "format": fmt,
            "hours": hours,
            "filename": artifact.filename,
            "size_bytes": artifact.size_bytes,
            "sha256": artifact.sha256,
        },
        "recipients": {
            "to": parsed["to"],
            "cc": parsed["cc"],
            "bcc_count": len(parsed["bcc"]),
            "total": recipient_count,
        },
    }), 202


@app.route("/api/reports/outbox")
def api_reports_outbox():
    """Return recent report-delivery jobs and their status."""
    _outbox_manager.set_connection(get_db())
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute(
            "SELECT id, recipient, subject, status, retry_count, max_retries, "
            "sent_at, error_message, created_at FROM notification_outbox "
            "WHERE rule_name = 'REPORT' ORDER BY created_at DESC LIMIT 25"
        )
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
    except Exception as exc:
        return jsonify({"error": f"Unable to read report outbox: {exc}"}), 500

    for r in rows:
        for key in ("created_at", "sent_at"):
            if r.get(key):
                r[f"{key}_str"] = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(r[key])
                )
    return jsonify({"jobs": rows, "stats": _outbox_manager.get_outbox_stats()})


@app.route("/api/reports/generate")
def api_reports_generate():
    """Generate and download security reports."""
    report_type = request.args.get("type", request.args.get("report_type", "daily"))
    fmt = request.args.get("format", request.args.get("fmt", "html"))
    hours = int(request.args.get("hours", 24))
    case_id = request.args.get("case_id")

    generator = ReportGenerator(get_db())
    mime, filename, content = generator.generate(report_type=report_type, hours=hours, fmt=fmt, case_id=case_id)
    write_audit_log(get_db(), "analyst", "generate_report", "reports", report_type, {"format": fmt, "hours": hours})
    return Response(
        content,
        mimetype=mime,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ---------------------------------------------------------------------------
# System Telemetry & Audit APIs (Phase 10)
# ---------------------------------------------------------------------------

@app.route("/api/system/metrics")
def api_system_metrics():
    """Return host capabilities, cgroup limits, parallel profiles, and storage stats."""
    caps = get_system_capabilities()
    profile = select_performance_profile(profile_name=os.getenv("IDS_PERF_PROFILE", "auto"))
    db = get_db()

    db_size = 0
    if os.path.exists(config.SQLITE_PATH):
        try:
            db_size = os.path.getsize(config.SQLITE_PATH)
        except Exception:
            pass

    flow_count = 0
    alert_count = 0
    from storage.db import _sqlite_lock
    try:
        with _sqlite_lock:
            cur = db.cursor()
            cur.execute("SELECT COUNT(*) FROM network_flows")
            flow_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM alerts")
            alert_count = cur.fetchone()[0]
            cur.close()
    except Exception:
        pass

    uptime_s = time.time() - _app_start_time

    return jsonify({
        "uptime_seconds": int(uptime_s),
        "uptime_str": time.strftime("%H:%M:%S", time.gmtime(uptime_s)),
        "capabilities": caps if isinstance(caps, dict) else {
            "physical_cores": getattr(caps, "physical_cores", None),
            "effective_cpu_quota": getattr(caps, "effective_cpu_quota", None),
            "available_ram_mb": getattr(caps, "available_ram_mb", None),
            "load_avg_1m": getattr(caps, "load_avg_1m", None),
        },
        "performance_profile": profile if isinstance(profile, dict) else {
            "name": getattr(profile, "name", "auto"),
            "workers": getattr(profile, "worker_count", 1),
            "batch_size": getattr(profile, "batch_size", 32),
        },
        "storage": {
            "db_backend": config.DB_BACKEND,
            "sqlite_path": config.SQLITE_PATH,
            "db_size_bytes": db_size,
            "db_size_mb": round(db_size / (1024 * 1024), 2),
            "flow_count": flow_count,
            "alert_count": alert_count,
        }
    })


@app.route("/api/audit-log")
def api_audit_log():
    """Return immutable audit log trail."""
    db = get_db()
    limit = min(int(request.args.get("limit", 100)), 500)
    from storage.db import _sqlite_lock
    with _sqlite_lock:
        cur = db.cursor()
        db_exec(cur, "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
    for r in rows:
        r["time_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.get("timestamp", 0)))
        if r.get("details_json"):
            try:
                r["details"] = json.loads(r["details_json"])
            except Exception:
                pass
    return jsonify(rows)


if __name__ == "__main__":
    app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=config.DASHBOARD_DEBUG,
    )
