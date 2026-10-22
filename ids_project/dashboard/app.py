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

# Allow imports from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, jsonify, render_template, request, Response, stream_with_context
import config
from storage.db import (
    get_connection, init_db,
    read_recent_alerts, read_alerts_range, read_all_devices,
    read_recent_observations, count_alerts_by_hour,
    count_alerts_by_day, read_alerts_for_date,
    write_feedback, read_feedback, feedback_stats
)
from analysis.aggregator import run_analysis, compute_threat_level

logger = logging.getLogger(__name__)
app = Flask(__name__)

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
    """Look up vendor from MAC OUI prefix (first 3 bytes)."""
    if not mac:
        return "Unknown"
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
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
    return _db_conn


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
    return render_template("index.html")


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

    return jsonify({
        "threat_level": threat_level,
        "alert_count_1h": len(alerts),
        "rule_breakdown": rule_counts,
        "severity_breakdown": sev_counts,
        "active_rules_count": 19,
        "server_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "geo_cache_size": len(_GEO_CACHE),
    })


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
        "BLOCKLIST": "rgba(59, 130, 246, 0.8)",
        "TCP_FLAG_ANOMALY": "rgba(234, 179, 8, 0.8)",
        "PORT_SCAN": "rgba(245, 158, 11, 0.8)",
        "UDP_SCAN": "rgba(251, 146, 60, 0.8)",
        "UDP_FLOOD": "rgba(225, 29, 72, 0.8)",
        "TCP_STEALTH_SCAN": "rgba(217, 70, 239, 0.8)",
        "SYN_FLOOD": "rgba(239, 68, 68, 0.8)",
        "DISTRIBUTED_SYN_FLOOD": "rgba(185, 28, 28, 0.8)",
        "ICMP_SWEEP": "rgba(14, 165, 233, 0.8)",
        "ICMP_FLOOD": "rgba(244, 63, 94, 0.8)",
        "ARP_SPOOF": "rgba(168, 85, 247, 0.8)",
        "PAYLOAD_HIT": "rgba(236, 72, 153, 0.8)",
        "DNS_ANOMALY": "rgba(6, 182, 212, 0.8)",
        "BRUTE_FORCE": "rgba(249, 115, 22, 0.8)",
        "SLOW_PORT_SCAN": "rgba(217, 119, 6, 0.8)",
        "DATA_EXFIL": "rgba(192, 38, 211, 0.8)",
        "TLS_ANOMALY": "rgba(99, 102, 241, 0.8)",
        "CLEAR_HTTP_ON_TLS_PORT": "rgba(139, 92, 246, 0.8)",
        "TCP_ZERO_WINDOW": "rgba(220, 38, 38, 0.8)",
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


if __name__ == "__main__":
    app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=config.DASHBOARD_DEBUG,
    )
