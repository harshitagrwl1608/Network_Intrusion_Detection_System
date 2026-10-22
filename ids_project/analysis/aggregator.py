"""
analysis/aggregator.py
-----------------------
Reads recent alerts from the DB and produces:
  1. Higher-level observations (e.g. "most active attacker", "unusual hours")
  2. Plain-English messages for each observation
  3. A threat level summary (clear / low / high)

Runs on a configurable interval from main.py.
"""

import time
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Hours considered "normal" — activity outside this window is flagged
NORMAL_HOURS_START = 8   # 08:00
NORMAL_HOURS_END = 23    # 23:00

# How many alerts from the same IP before it's "most active"
MOST_ACTIVE_MIN_ALERTS = 3

# Number of repeated BLOCKLIST hits from same IP before escalating
REPEATED_BLOCKLIST_THRESHOLD = 3


# ---------------------------------------------------------------------------
# Plain-language templates
# ---------------------------------------------------------------------------

TEMPLATES = {
    "PORT_SCAN": (
        "⚠️  A device at {src_ip} probed multiple network services in a rapid burst — "
        "this pattern typically indicates network reconnaissance or port scanning."
    ),
    "UDP_SCAN": (
        "⚠️  A device at {src_ip} probed multiple UDP ports or hosts in a short window — "
        "this pattern indicates UDP reconnaissance or service sweeps."
    ),
    "TCP_STEALTH_SCAN": (
        "⚠️  A device at {src_ip} sent stealth TCP probes (FIN, NULL, or Xmas scans) — "
        "these scans attempt to evade standard connection logging to map open ports."
    ),
    "SLOW_PORT_SCAN": (
        "🕵️  Low-and-slow port scan detected from {src_ip} spanning multiple minutes — "
        "probes are spaced out to evade rapid sliding-window rate limiters."
    ),
    "SYN_FLOOD": (
        "🔴  A device at {src_ip} sent an unusually high volume of connection requests — "
        "this pattern typically indicates a denial-of-service (SYN flood) attempt."
    ),
    "DISTRIBUTED_SYN_FLOOD": (
        "🚨  Distributed SYN Flood detected targeting {dst_ip} across numerous source addresses — "
        "this indicates a coordinated DDoS assault."
    ),
    "UDP_FLOOD": (
        "🔴  A device at {src_ip} initiated a high-volume UDP packet flood toward {dst_ip} — "
        "this pattern indicates a denial-of-service (UDP flood) attempt."
    ),
    "ICMP_SWEEP": (
        "🔍  A device at {src_ip} sent ICMP echo requests across multiple hosts — "
        "this pattern indicates an active network host discovery sweep."
    ),
    "ICMP_FLOOD": (
        "🔴  A device at {src_ip} generated a rapid flood of ICMP echo packets targeting {dst_ip} — "
        "typical of an ICMP ping flood DoS attack."
    ),
    "TCP_FLAG_ANOMALY": (
        "⚠️  A device at {src_ip} sent malformed TCP packets with illegal flag combinations (e.g., SYN+FIN) — "
        "frequently used for OS fingerprinting or firewall evasion."
    ),
    "TCP_ZERO_WINDOW": (
        "🔴  A burst of TCP Zero-Window advertisements was sent by {src_ip} to {dst_ip} — "
        "indicative of a Sockstress / resource-exhaustion DoS attack."
    ),
    "ARP_SPOOF": (
        "🔴  The network address {src_ip} suddenly changed its hardware MAC identity — "
        "this is a classic sign of ARP spoofing, where a rogue device impersonates another."
    ),
    "BLOCKLIST": (
        "⚠️  A device at {src_ip} attempted to contact {dst_ip}, "
        "which is listed on known-malicious threat intelligence feeds."
    ),
    "PAYLOAD_HIT": (
        "🚨  Malicious payload detected from {src_ip} — "
        "an attack signature (SQL injection, command injection, webshell, or credential leak) was found in "
        "unencrypted traffic."
    ),
    "DNS_ANOMALY": (
        "🔍  A device at {src_ip} sent a suspicious DNS query — "
        "the domain name exhibits high entropy or tunneling characteristics, hallmark of "
        "malware using Domain Generation Algorithms (DGA) or covert DNS data tunneling."
    ),
    "BRUTE_FORCE": (
        "🔐  Repeated authentication connection attempts from {src_ip} to service port {dst_port} — "
        "potential credential brute-force attack."
    ),
    "DATA_EXFIL": (
        "🚨  High-volume outbound data transfer detected from {src_ip} to external destination {dst_ip} — "
        "possible data exfiltration or database dump."
    ),
    "TLS_ANOMALY": (
        "🔒  TLS handshake anomaly detected from {src_ip} — "
        "Server Name Indication (SNI) contained a literal IP or suspicious dynamic proxy/tunnel domain."
    ),
    "CLEAR_HTTP_ON_TLS_PORT": (
        "⚠️  Plaintext HTTP traffic detected on TLS port ({dst_port}) from {src_ip} — "
        "indicates proxy bypass, unencrypted C2 communication, or misconfigured SSL."
    ),
    "MOST_ACTIVE": (
        "📊  The most active suspicious device in the last hour is {src_ip} "
        "with {count} flagged events."
    ),
    "UNUSUAL_HOURS": (
        "🌙  Suspicious activity from {src_ip} was detected at {hour}:00, "
        "outside normal operating hours — this may warrant a closer look."
    ),
    "REPEATED_BLOCKLIST": (
        "🔴  {src_ip} has repeatedly attempted to reach known-malicious addresses ({count} times) — "
        "this device may be infected with malware."
    ),
    "NEW_DEVICE": (
        "📱  A new device at {ip} (MAC: {mac}{vendor_str}) was detected on your network "
        "for the first time — verify if this is an authorized host."
    ),
    "ALL_CLEAR": (
        "✅  No suspicious activity detected in the last 60 minutes. "
        "Your network appears to be operating normally."
    ),
}


def _format(template_key: str, **kwargs) -> str:
    return TEMPLATES[template_key].format(**kwargs)


# ---------------------------------------------------------------------------
# Threat level
# ---------------------------------------------------------------------------

def compute_threat_level(alerts: list[dict]) -> str:
    """
    Returns 'clear', 'low', or 'high' based on recent alerts.
    """
    if not alerts:
        return "clear"
    high_severity = [a for a in alerts if a.get("severity") == "high"]
    if len(high_severity) >= 3:
        return "high"
    return "low"


# ---------------------------------------------------------------------------
# Observation generators
# ---------------------------------------------------------------------------

def _obs_most_active(alerts: list[dict]) -> list[dict]:
    """Which source IP generated the most alerts?"""
    counts: dict[str, int] = {}
    for a in alerts:
        ip = a.get("src_ip")
        if ip:
            counts[ip] = counts.get(ip, 0) + 1

    if not counts:
        return []
    top_ip = max(counts, key=counts.get)
    if counts[top_ip] >= MOST_ACTIVE_MIN_ALERTS:
        return [{
            "message": _format("MOST_ACTIVE", src_ip=top_ip, count=counts[top_ip]),
            "rule_name": "MOST_ACTIVE",
        }]
    return []


def _obs_unusual_hours(alerts: list[dict]) -> list[dict]:
    """Flag any alerts outside normal hours."""
    seen = set()
    results = []
    for a in alerts:
        ts = a.get("timestamp", 0)
        dt = datetime.fromtimestamp(ts)
        hour = dt.hour
        ip = a.get("src_ip", "unknown")
        key = (ip, hour)
        if key not in seen and not (NORMAL_HOURS_START <= hour < NORMAL_HOURS_END):
            seen.add(key)
            results.append({
                "message": _format("UNUSUAL_HOURS", src_ip=ip, hour=hour),
                "rule_name": "UNUSUAL_HOURS",
            })
    return results


def _obs_repeated_blocklist(alerts: list[dict]) -> list[dict]:
    """Flag IPs that hit the blocklist repeatedly."""
    bl_alerts = [a for a in alerts if a.get("rule_name") == "BLOCKLIST"]
    counts: dict[str, int] = {}
    for a in bl_alerts:
        ip = a.get("src_ip")
        if ip:
            counts[ip] = counts.get(ip, 0) + 1

    results = []
    for ip, count in counts.items():
        if count >= REPEATED_BLOCKLIST_THRESHOLD:
            results.append({
                "message": _format("REPEATED_BLOCKLIST", src_ip=ip, count=count),
                "rule_name": "REPEATED_BLOCKLIST",
            })
    return results


def _obs_per_alert_type(alerts: list[dict]) -> list[dict]:
    """One plain-language observation per unique (rule_name, src_ip) pair."""
    seen = set()
    results = []
    for a in alerts:
        rule = a.get("rule_name")
        src = a.get("src_ip", "unknown")
        dst = a.get("dst_ip", "unknown")
        key = (rule, src)
        if key in seen or rule not in TEMPLATES:
            continue
        seen.add(key)
        if rule == "BLOCKLIST" and "Received traffic from" in a.get("detail", ""):
            msg = (
                f"⚠️  Received incoming traffic from {src}, which is "
                f"listed on known-malicious threat intelligence feeds."
            )
        else:
            msg = _format(
                rule,
                src_ip=src,
                dst_ip=dst,
                dst_port=a.get("dst_port") or "—",
                count=1,
            )
        results.append({
            "message": msg,
            "rule_name": rule,
        })
    return results


def _obs_new_devices(db_conn, minutes: int = 60) -> list[dict]:
    """Flag any devices seen for the first time within the recent window."""
    from storage.db import read_all_devices
    now = time.time()
    cutoff = now - (minutes * 60)
    try:
        devices = read_all_devices(db_conn)
    except Exception as e:
        logger.error(f"Failed to read devices for observation: {e}")
        return []

    results = []
    for d in devices:
        first = d.get("first_seen") or 0
        if first >= cutoff:
            vendor = d.get("vendor")
            vendor_str = f", Vendor: {vendor}" if vendor else ""
            results.append({
                "message": _format("NEW_DEVICE", ip=d.get("ip", "unknown"), mac=d.get("mac", "unknown"), vendor_str=vendor_str),
                "rule_name": "NEW_DEVICE",
            })
    return results


# ---------------------------------------------------------------------------
# Main aggregation entry point
# ---------------------------------------------------------------------------

def run_analysis(db_conn) -> dict:
    """
    Read recent alerts, compute observations and threat level.
    Writes new observations to the DB.
    Returns a summary dict for use by the dashboard API.
    """
    from storage.db import read_recent_alerts, write_observation, read_recent_observations

    alerts = read_recent_alerts(db_conn, minutes=60)
    threat_level = compute_threat_level(alerts)

    observations = []

    if not alerts:
        observations.append({
            "message": TEMPLATES["ALL_CLEAR"],
            "rule_name": "ALL_CLEAR",
        })
    else:
        observations += _obs_per_alert_type(alerts)
        observations += _obs_most_active(alerts)
        observations += _obs_unusual_hours(alerts)
        observations += _obs_repeated_blocklist(alerts)
    
    # Check for newly discovered devices
    observations += _obs_new_devices(db_conn, minutes=60)

    # ── Deduplication: only write observations we haven't written recently ──
    # Fetch the last 50 observations (covers all rules written in the last
    # few analysis cycles) and build a set of recently-seen messages.
    try:
        recent_obs = read_recent_observations(db_conn, limit=50)
        recent_messages = {o["message"] for o in recent_obs}
    except Exception:
        recent_messages = set()

    # Persist NEW observations only
    for obs in observations:
        if obs["message"] in recent_messages:
            continue  # already written in a recent cycle — skip
        try:
            write_observation(db_conn, obs["message"], obs.get("rule_name"))
        except Exception as e:
            logger.error(f"Failed to write observation: {e}")

    logger.info(
        f"Analysis complete: {len(alerts)} alerts → "
        f"{len(observations)} observations, threat={threat_level}"
    )

    return {
        "threat_level": threat_level,
        "alert_count": len(alerts),
        "observations": observations,
        "timestamp": time.time(),
    }
