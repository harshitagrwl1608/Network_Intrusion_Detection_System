"""
reports/generator.py
--------------------
Automated report generation for NetGuard IDS.
Supports Daily, Weekly, Monthly, Incident, PCAP, Device, Feedback, and Anomaly reports
in HTML, JSON, and CSV formats.
"""

import os
import sys
import time
import json
import csv
import io
import html
import logging
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config

logger = logging.getLogger(__name__)

# Formats that are genuinely produced by this generator. ``pdf`` was previously
# accepted but silently returned HTML with an ``.html`` extension; it is no
# longer advertised or accepted.
SUPPORTED_FORMATS = ("html", "json", "csv")

# Severities usable as CSS class suffixes. Anything else collapses to "medium"
# so untrusted input cannot inject markup into a class attribute.
_SAFE_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

REPORT_TYPES = {
    "daily": "Daily Network Security Report (24h)",
    "weekly": "Weekly Security Summary (7d)",
    "monthly": "Monthly Traffic & Threat Report (30d)",
    "incident": "Incident Investigation Report",
    "pcap": "PCAP Analysis & Forensic Replay Report",
    "device": "Network Device Inventory & Activity Report",
    "feedback": "Analyst Feedback & False-Positive Audit Report",
    "rule_performance": "Detection Rule Performance & Cost Report",
    "anomaly": "Statistical Traffic Anomaly Report",
}


def _esc(value: Any) -> str:
    """HTML-escape a value before interpolation. ``None`` becomes an em dash."""
    if value is None or value == "":
        return "—"
    return html.escape(str(value), quote=True)


def _safe_sev(value: Any) -> str:
    """Constrain a severity to a known token for safe CSS class use."""
    token = str(value or "medium").strip().lower()
    return token if token in _SAFE_SEVERITIES else "medium"


def _csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection in CSV exports.

    Excel/LibreOffice will execute cells beginning with ``=``, ``+``, ``-``,
    ``@``, tab or carriage return. Prefixing with an apostrophe keeps the value
    readable while preventing formula evaluation.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        return value
    if value[:1] in ("=", "+", "-", "@", "\t", "\r", "\n"):
        return "'" + value
    return value


class ReportGenerator:
    """Generates structured, professional executive and technical reports."""

    def __init__(self, conn=None):
        self._conn = conn

    def set_connection(self, conn):
        self._conn = conn

    def generate(self, report_type: str = "daily", hours: int = 24,
                 fmt: str = "html", case_id: str | None = None) -> tuple[str, str, str | bytes]:
        """
        Generate report of the requested type and format.
        Returns: (mime_type, filename, content)
        """
        report_type = report_type.lower()
        if report_type not in REPORT_TYPES:
            report_type = "daily"
        fmt = fmt.lower()
        if fmt not in SUPPORTED_FORMATS:
            fmt = "html"

        now = time.time()
        start_time = now - (hours * 3600)
        report_data = self._collect_data(report_type, start_time, now, case_id)

        timestamp_str = time.strftime("%Y%m%d_%H%M%S", time.localtime(now))
        base_name = f"netguard_{report_type}_report_{timestamp_str}"

        if fmt == "json":
            content = json.dumps(report_data, indent=2, default=str)
            return "application/json", f"{base_name}.json", content

        elif fmt == "csv":
            content = self._render_csv(report_data)
            return "text/csv", f"{base_name}.csv", content

        else:
            content = self._render_html(report_data)
            return "text/html", f"{base_name}.html", content

    def _collect_data(self, report_type: str, start_time: float, end_time: float,
                      case_id: str | None = None) -> dict[str, Any]:
        """Gather verified database metrics for the reporting window."""
        res = {
            "report_title": REPORT_TYPES.get(report_type, "Network Security Report"),
            "report_type": report_type,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time)),
            "end_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time)),
            "time_window_hours": round((end_time - start_time) / 3600, 1),
            "engine_version": "NetGuard IDS v2.0-RC1",
            "stats": {},
            "rule_breakdown": {},
            "severity_breakdown": {},
            "top_talkers": [],
            "recent_alerts": [],
            "cases": [],
            "devices": [],
            "feedback_summary": {},
            "anomalies": [],
        }

        if not self._conn:
            return res

        cur = self._conn.cursor()

        # 1. Alert counts and breakdown
        cur.execute(
            """
            SELECT COUNT(*),
                   SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END)
            FROM alerts WHERE timestamp >= ? AND timestamp <= ?
            """,
            (start_time, end_time)
        )
        total_a, crit_a, high_a, med_a, low_a = cur.fetchone()
        res["stats"]["total_alerts"] = total_a or 0
        res["severity_breakdown"] = {
            "critical": crit_a or 0,
            "high": high_a or 0,
            "medium": med_a or 0,
            "low": low_a or 0,
        }

        # Rule breakdown
        cur.execute(
            "SELECT rule_name, COUNT(*) as cnt FROM alerts WHERE timestamp >= ? AND timestamp <= ? "
            "GROUP BY rule_name ORDER BY cnt DESC",
            (start_time, end_time)
        )
        res["rule_breakdown"] = {r[0]: r[1] for r in cur.fetchall()}

        # Top source talkers
        cur.execute(
            "SELECT src_ip, COUNT(*) as cnt FROM alerts WHERE timestamp >= ? AND timestamp <= ? "
            "AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY cnt DESC LIMIT 10",
            (start_time, end_time)
        )
        res["top_talkers"] = [{"ip": r[0], "alert_count": r[1]} for r in cur.fetchall()]

        # Recent sample alerts
        cur.execute(
            "SELECT id, timestamp, rule_name, severity, src_ip, dst_ip, dst_port, protocol, detail "
            "FROM alerts WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC LIMIT 50",
            (start_time, end_time)
        )
        res["recent_alerts"] = [dict(r) for r in cur.fetchall()]

        # Cases summary
        cur.execute("SELECT case_id, title, severity, status, assignee, created_at FROM cases ORDER BY created_at DESC LIMIT 10")
        res["cases"] = [dict(r) for r in cur.fetchall()]

        # Devices count
        cur.execute("SELECT COUNT(*) FROM seen_devices")
        res["stats"]["devices_seen"] = cur.fetchone()[0]

        # Active flows count
        try:
            cur.execute("SELECT COUNT(*) FROM network_flows WHERE last_seen >= ?", (start_time,))
            res["stats"]["active_flows"] = cur.fetchone()[0]
        except Exception:
            res["stats"]["active_flows"] = 0

        # Feedback stats
        try:
            from storage.db import feedback_stats
            res["feedback_summary"] = feedback_stats(self._conn)
        except Exception:
            res["feedback_summary"] = {}

        # Anomalies
        try:
            cur.execute("SELECT * FROM traffic_anomalies WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT 20", (start_time,))
            res["anomalies"] = [dict(r) for r in cur.fetchall()]
        except Exception:
            res["anomalies"] = []

        cur.close()
        return res

    def _render_csv(self, data: dict[str, Any]) -> str:
        """Render report findings to CSV format."""
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["# NetGuard IDS Security Report Export"])
        writer.writerow(["Title", _csv_safe(data.get("report_title"))])
        writer.writerow(["Generated At", _csv_safe(data.get("generated_at"))])
        writer.writerow(["Window Start", _csv_safe(data.get("start_time"))])
        writer.writerow(["Window End", _csv_safe(data.get("end_time"))])
        writer.writerow(["Total Alerts", data.get("stats", {}).get("total_alerts", 0)])
        writer.writerow([])

        writer.writerow(["--- Rule Breakdown ---"])
        writer.writerow(["Rule Name", "Alert Count"])
        for r_name, count in data.get("rule_breakdown", {}).items():
            writer.writerow([_csv_safe(r_name), count])
        writer.writerow([])

        writer.writerow(["--- Alerts Log ---"])
        writer.writerow(["ID", "Timestamp", "Rule", "Severity", "Source IP", "Destination IP", "Port", "Protocol", "Detail"])
        for a in data.get("recent_alerts", []):
            writer.writerow([
                _csv_safe(a.get("id")),
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a.get("timestamp", 0) or 0)),
                _csv_safe(a.get("rule_name")),
                _csv_safe(a.get("severity")),
                _csv_safe(a.get("src_ip")),
                _csv_safe(a.get("dst_ip")),
                _csv_safe(a.get("dst_port")),
                _csv_safe(a.get("protocol")),
                _csv_safe(a.get("detail")),
            ])

        return output.getvalue()

    def _render_html(self, data: dict[str, Any]) -> str:
        """Render standalone executive HTML report."""
        stats = data.get("stats", {})
        sev = data.get("severity_breakdown", {})
        rules = data.get("rule_breakdown", {})
        alerts = data.get("recent_alerts", [])
        anomalies = data.get("anomalies", [])

        rule_rows = "".join(
            f"<tr><td><code>{_esc(r)}</code></td><td><strong>{_esc(c)}</strong></td></tr>"
            for r, c in rules.items()
        ) or "<tr><td colspan='2' style='color:#64748b'>No alerts recorded in this period.</td></tr>"

        alert_rows = "".join(
            f"<tr>"
            f"<td>{_esc(time.strftime('%H:%M:%S', time.localtime(a.get('timestamp', 0) or 0)))}</td>"
            f"<td><span class='badge'>{_esc(a.get('rule_name'))}</span></td>"
            f"<td class='sev-{_safe_sev(a.get('severity'))}'>{_esc(_safe_sev(a.get('severity')).upper())}</td>"
            f"<td><code>{_esc(a.get('src_ip'))}</code></td>"
            f"<td><code>{_esc(a.get('dst_ip'))}:{_esc(a.get('dst_port'))}</code></td>"
            f"<td>{_esc(a.get('detail'))}</td>"
            f"</tr>"
            for a in alerts[:50]
        ) or "<tr><td colspan='6' style='color:#64748b;text-align:center'>No alerts in selected window.</td></tr>"

        anomaly_rows = "".join(
            f"<tr>"
            f"<td>{_esc(time.strftime('%H:%M:%S', time.localtime(m.get('timestamp', 0) or 0)))}</td>"
            f"<td>{_esc(m.get('metric_name'))}</td>"
            f"<td>{_esc(m.get('observed_value'))} (exp: {_esc(m.get('expected_value'))})</td>"
            f"<td>{_esc(m.get('deviation_score'))}x MAD</td>"
            f"<td>{_esc(m.get('explanation'))}</td>"
            f"</tr>"
            for m in anomalies[:10]
        ) or "<tr><td colspan='5' style='color:#64748b;text-align:center'>No baseline anomalies detected.</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{_esc(data.get('report_title'))} — NetGuard IDS</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0b101e; color: #e2e8f0; margin: 0; padding: 40px 20px; line-height: 1.5;
    }}
    .container {{ max-width: 1000px; margin: 0 auto; }}
    .header {{ border-bottom: 2px solid #1e293b; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; }}
    h1 {{ font-size: 1.8rem; margin: 0 0 8px 0; color: #f8fafc; }}
    .meta {{ font-size: 0.85rem; color: #94a3b8; }}
    .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 30px; }}
    .kpi-card {{ background: #151e32; border: 1px solid #273553; border-radius: 8px; padding: 16px; }}
    .kpi-val {{ font-size: 1.8rem; font-weight: 700; color: #38bdf8; }}
    .kpi-lbl {{ font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 30px; font-size: 0.85rem; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #1e293b; text-align: left; }}
    th {{ background: #131c31; color: #94a3b8; font-weight: 600; }}
    code {{ font-family: monospace; color: #93c5fd; }}
    .badge {{ background: #1e293b; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; }}
    .sev-critical {{ color: #ef4444; font-weight: bold; }}
    .sev-high {{ color: #f97316; font-weight: bold; }}
    .sev-medium {{ color: #facc15; }}
    .sev-low {{ color: #34d399; }}
    .section-title {{ font-size: 1.15rem; margin: 24px 0 12px 0; color: #cbd5e1; border-bottom: 1px solid #1e293b; padding-bottom: 6px; }}
    .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #1e293b; font-size: 0.75rem; color: #64748b; text-align: center; }}
    @media print {{
      body {{ background: #fff; color: #000; padding: 20px; }}
      .kpi-card {{ border: 1px solid #ccc; background: #f8fafc; }}
      .kpi-val {{ color: #0284c7; }}
      th {{ background: #f1f5f9; color: #333; }}
      td, th {{ border-bottom: 1px solid #e2e8f0; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>{_esc(data.get('report_title'))}</h1>
        <div class="meta">Window: {_esc(data.get('start_time'))} to {_esc(data.get('end_time'))} ({_esc(data.get('time_window_hours'))}h)</div>
      </div>
      <div style="text-align: right">
        <div style="font-weight: 700; color: #6366f1">NetGuard IDS</div>
        <div class="meta">Generated: {_esc(data.get('generated_at'))}</div>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="kpi-card"><div class="kpi-val">{_esc(stats.get('total_alerts', 0))}</div><div class="kpi-lbl">Total Alerts</div></div>
      <div class="kpi-card"><div class="kpi-val" style="color: #ef4444">{_esc((sev.get('critical', 0) or 0) + (sev.get('high', 0) or 0))}</div><div class="kpi-lbl">Critical & High</div></div>
      <div class="kpi-card"><div class="kpi-val">{_esc(stats.get('active_flows', 0))}</div><div class="kpi-lbl">Active Flows</div></div>
      <div class="kpi-card"><div class="kpi-val">{_esc(stats.get('devices_seen', 0))}</div><div class="kpi-lbl">Devices Seen</div></div>
    </div>

    <div class="section-title">Detection Rule Breakdown</div>
    <table>
      <thead><tr><th>Rule Name</th><th>Alert Count</th></tr></thead>
      <tbody>{rule_rows}</tbody>
    </table>

    <div class="section-title">Recent Critical & High Detections</div>
    <table>
      <thead><tr><th>Time</th><th>Rule</th><th>Severity</th><th>Source</th><th>Destination</th><th>Narrative</th></tr></thead>
      <tbody>{alert_rows}</tbody>
    </table>

    <div class="section-title">Statistical Traffic Anomalies</div>
    <table>
      <thead><tr><th>Time</th><th>Metric</th><th>Observed vs Expected</th><th>Deviation</th><th>Explanation</th></tr></thead>
      <tbody>{anomaly_rows}</tbody>
    </table>

    <div class="footer">
      Generated automatically by NetGuard IDS reporting engine. Figures derived from local telemetry and ground-truth SQLite databases.
    </div>
  </div>
</body>
</html>"""
