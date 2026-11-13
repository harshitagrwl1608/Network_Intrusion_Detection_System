"""
notifications/email_render.py
-----------------------------
Professional HTML + plain-text rendering for NetGuard IDS notification emails.

Everything derived from network telemetry (IPs, ports, DNS names, HTTP paths,
rule names, alert narratives, case titles, analyst-supplied text) is treated as
untrusted and is HTML-escaped before interpolation. No field is ever inserted as
markup, and links are only emitted when a validated ``http(s)`` base URL is
configured.

The renderer never invents data: absent fields are omitted rather than filled
with placeholder values.
"""

from __future__ import annotations

import html
import json
import time
from dataclasses import dataclass, field
from typing import Any

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SEVERITY_STYLE = {
    "critical": {"color": "#b91c1c", "bg": "#fef2f2", "border": "#fca5a5", "label": "CRITICAL"},
    "high": {"color": "#c2410c", "bg": "#fff7ed", "border": "#fdba74", "label": "HIGH"},
    "medium": {"color": "#a16207", "bg": "#fefce8", "border": "#fde047", "label": "MEDIUM"},
    "low": {"color": "#047857", "bg": "#ecfdf5", "border": "#6ee7b7", "label": "LOW"},
    "info": {"color": "#1d4ed8", "bg": "#eff6ff", "border": "#93c5fd", "label": "INFO"},
}

# Guidance keyed by rule category. Presented explicitly as suggestions, never as
# evidence, and never as a certainty claim.
CATEGORY_GUIDANCE = {
    "Threat Intel": [
        "Correlate the remote endpoint with your threat-intelligence feed.",
        "Check whether other internal hosts contacted the same address.",
        "If the connection succeeded, isolate the host and review egress logs.",
    ],
    "Reconnaissance": [
        "Identify the scanning host and confirm whether it is an authorised scanner.",
        "Review firewall and host logs for follow-up exploitation attempts.",
    ],
    "Denial of Service": [
        "Verify service availability for the targeted host.",
        "Check upstream link saturation and apply rate limiting if sustained.",
    ],
    "Layer 2 & Protocol": [
        "Confirm the observed MAC mapping against the known-good ARP table.",
        "Inspect switch CAM/ARP tables for duplicate or conflicting bindings.",
    ],
    "Application & DPI": [
        "Inspect the full request/response context in the Traffic Explorer.",
        "Check application logs for the same timestamp and source.",
        "Treat payload matches as indicators requiring corroboration, not proof.",
    ],
    "Covert Channels": [
        "Validate the endpoint against approved egress policy.",
        "Consider blocking the destination pending triage.",
    ],
}

DEFAULT_GUIDANCE = [
    "Open the alert in the dashboard and review the full evidence record.",
    "Corroborate with endpoint, firewall, or application logs.",
    "Classify the alert as true or false positive to improve tuning.",
]


@dataclass
class RenderedEmail:
    """A fully rendered email body pair plus the subject line."""

    subject: str
    text: str
    html: str
    metadata: dict = field(default_factory=dict)


def _esc(value: Any) -> str:
    """HTML-escape any value; ``None`` renders as an em dash."""
    if value is None or value == "":
        return "—"
    return html.escape(str(value), quote=True)


def _plain(value: Any) -> str:
    if value is None or value == "":
        return "-"
    return str(value)


def _fmt_ts(ts: Any) -> str:
    try:
        epoch = float(ts)
    except (TypeError, ValueError):
        return "—"
    if epoch <= 0:
        return "—"
    # Show both local and UTC so geographically distributed recipients agree.
    local = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(epoch))
    utc = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(epoch))
    return f"{local} ({utc})" if utc not in local else local


def _parse_evidence(raw: Any) -> dict:
    """Best-effort parse of ``evidence_json`` into a dict without trusting it."""
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8", "replace")
        except Exception:
            return {}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            return {}
    return {}


def _safe_base_url(base_url: str | None) -> str | None:
    """Return a usable dashboard base URL or ``None``.

    Only absolute http/https URLs are accepted. This prevents ``javascript:`` or
    relative values from becoming a link in an email client.
    """
    if not base_url:
        return None
    candidate = str(base_url).strip()
    lowered = candidate.lower()
    if not (lowered.startswith("http://") or lowered.startswith("https://")):
        return None
    if any(ch in candidate for ch in "\r\n\t \"'<>"):
        return None
    return candidate.rstrip("/")


def _extract_protocol_metadata(alert: dict[str, Any], evidence: dict) -> list[tuple[str, Any]]:
    """Collect optional DNS/HTTP/TLS metadata that is actually present."""
    rows: list[tuple[str, Any]] = []

    dns_query = alert.get("dns_query") or evidence.get("dns_query") or evidence.get("query")
    if dns_query:
        rows.append(("DNS query", dns_query))

    http_method = alert.get("http_method") or evidence.get("http_method") or evidence.get("method")
    if http_method:
        rows.append(("HTTP method", http_method))

    http_host = alert.get("http_host") or evidence.get("http_host") or evidence.get("host")
    if http_host:
        rows.append(("HTTP host", http_host))

    http_uri = alert.get("http_uri") or evidence.get("http_uri") or evidence.get("uri") or evidence.get("path")
    if http_uri:
        rows.append(("HTTP URI", http_uri))

    tls_sni = alert.get("tls_sni") or evidence.get("tls_sni") or evidence.get("sni")
    if tls_sni:
        rows.append(("TLS SNI", tls_sni))

    user_agent = evidence.get("user_agent")
    if user_agent:
        rows.append(("User agent", user_agent))

    signature = evidence.get("signature") or evidence.get("matched_signature")
    if signature:
        rows.append(("DPI signature", signature))

    return rows


def _category_guidance(rule_name: str) -> list[str]:
    try:
        from engine.rule_metadata import RULE_METADATA

        meta = RULE_METADATA.get(str(rule_name or "").upper(), {})
        category = meta.get("category")
    except Exception:
        category = None
    return CATEGORY_GUIDANCE.get(category or "", DEFAULT_GUIDANCE)


def build_subject(alert: dict[str, Any]) -> str:
    """Build a deterministic, header-safe subject line."""
    severity = str(alert.get("severity") or "medium").upper()
    rule_name = str(alert.get("rule_name") or "ALERT").upper()
    dst_ip = str(alert.get("dst_ip") or "").strip()

    if dst_ip:
        headline = f"{rule_name} on {dst_ip}"
    else:
        headline = rule_name

    detail = str(alert.get("detail") or "").strip()
    if detail:
        # Keep the subject readable; long narratives belong in the body.
        short = detail.split("\n")[0].strip()
        if len(short) > 80:
            short = short[:77].rstrip() + "…"
        headline = f"{headline} — {short}" if short else headline

    # Defensive: strip anything that could break a header.
    subject = f"[NetGuard IDS] {severity} — {headline}"
    return subject.replace("\r", " ").replace("\n", " ")[:250]


def render_alert_email(alert: dict[str, Any], *,
                       alert_id: int | None = None,
                       case_id: str | None = None,
                       confidence_score: float | None = None,
                       dashboard_base_url: str | None = None) -> RenderedEmail:
    """Render a professional multi-part alert email.

    The HTML part uses table-based layout and inline styles for wide email-client
    compatibility. There are no images, tracking pixels, or remote resources.
    """
    severity = str(alert.get("severity") or "medium").lower()
    style = SEVERITY_STYLE.get(severity, SEVERITY_STYLE["medium"])

    rule_name = alert.get("rule_name") or "ALERT"
    rule_version = alert.get("rule_version")
    confidence = alert.get("confidence") or "heuristic"
    src_ip = alert.get("src_ip")
    src_port = alert.get("src_port")
    dst_ip = alert.get("dst_ip")
    dst_port = alert.get("dst_port")
    protocol = alert.get("protocol")
    detail = alert.get("detail") or ""
    timestamp = alert.get("timestamp")
    flow_id = alert.get("flow_id")
    resolved_alert_id = alert_id if alert_id is not None else alert.get("id")
    resolved_case_id = case_id or alert.get("assigned_case_id") or alert.get("case_id")

    evidence = _parse_evidence(alert.get("evidence_json"))
    protocol_rows = _extract_protocol_metadata(alert, evidence)
    guidance = _category_guidance(str(rule_name))

    base_url = _safe_base_url(dashboard_base_url)
    dashboard_link = None
    if base_url:
        dashboard_link = f"{base_url}/#alerts"
        if resolved_alert_id is not None:
            try:
                dashboard_link = f"{base_url}/?alert={int(resolved_alert_id)}"
            except (TypeError, ValueError):
                dashboard_link = f"{base_url}/#alerts"

    subject = build_subject(alert)

    # ------------------------------------------------------------------
    # Shared field rows (label, escaped HTML value, plain value)
    # ------------------------------------------------------------------
    endpoint_html = (
        f"<code>{_esc(src_ip)}</code>{':' + _esc(src_port) if src_port not in (None, '') else ''}"
        f" &rarr; "
        f"<code>{_esc(dst_ip)}</code>{':' + _esc(dst_port) if dst_port not in (None, '') else ''}"
    )
    endpoint_plain = (
        f"{_plain(src_ip)}{':' + _plain(src_port) if src_port not in (None, '') else ''}"
        f" -> "
        f"{_plain(dst_ip)}{':' + _plain(dst_port) if dst_port not in (None, '') else ''}"
    )

    def row(label: str, value_html: str, value_plain: str) -> str:
        return (
            f"<tr>"
            f"<td style=\"padding:8px 14px;border-bottom:1px solid #e5e7eb;"
            f"font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#6b7280;"
            f"white-space:nowrap;vertical-align:top;width:34%;\">{_esc(label)}</td>"
            f"<td style=\"padding:8px 14px;border-bottom:1px solid #e5e7eb;"
            f"font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#111827;"
            f"word-break:break-word;\">{value_html}</td>"
            f"</tr>"
        )

    detail_rows = [
        row("Rule", _esc(rule_name), _plain(rule_name)),
    ]
    if rule_version not in (None, ""):
        detail_rows.append(row("Rule version", _esc(rule_version), _plain(rule_version)))
    detail_rows.append(row("Severity", _esc(style["label"]), style["label"]))
    detail_rows.append(
        row("Confidence", _esc(confidence), _plain(confidence))
    )
    if confidence_score is not None:
        try:
            score = float(confidence_score)
            detail_rows.append(row("Heuristic score", _esc(f"{score:.2f}"), f"{score:.2f}"))
        except (TypeError, ValueError):
            pass
    detail_rows.append(row("Endpoints", endpoint_html, endpoint_plain))
    if protocol not in (None, ""):
        detail_rows.append(row("Protocol", _esc(protocol), _plain(protocol)))
    detail_rows.append(row("Detected at", _esc(_fmt_ts(timestamp)), _fmt_ts(timestamp)))
    if resolved_alert_id is not None:
        detail_rows.append(row("Alert ID", _esc(resolved_alert_id), _plain(resolved_alert_id)))
    if flow_id:
        detail_rows.append(row("Flow ID", f"<code>{_esc(flow_id)}</code>", _plain(flow_id)))
    if resolved_case_id:
        detail_rows.append(row("Case ID", _esc(resolved_case_id), _plain(resolved_case_id)))
    for label, value in protocol_rows:
        detail_rows.append(row(label, _esc(value), _plain(value)))

    guidance_html = "".join(
        f"<li style=\"margin:0 0 6px 0;\">{_esc(item)}</li>" for item in guidance
    )
    guidance_text = "\n".join(f"  {i + 1}. {item}" for i, item in enumerate(guidance))

    link_html = ""
    link_text = ""
    if dashboard_link:
        link_html = (
            f"<p style=\"margin:18px 0 0 0;\">"
            f"<a href=\"{_esc(dashboard_link)}\" "
            f"style=\"background:#1d4ed8;color:#ffffff;text-decoration:none;"
            f"padding:10px 18px;border-radius:6px;font-family:Arial,Helvetica,sans-serif;"
            f"font-size:13px;font-weight:bold;display:inline-block;\">"
            f"Open in NetGuard dashboard</a></p>"
        )
        link_text = f"\nDashboard: {dashboard_link}\n"

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_esc(subject)}</title>
</head>
<body style="margin:0;padding:0;background:#f3f4f6;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:24px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
               style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden;">
          <tr>
            <td style="background:#0f172a;padding:18px 22px;">
              <div style="font-family:Arial,Helvetica,sans-serif;font-size:16px;font-weight:bold;color:#ffffff;letter-spacing:0.3px;">
                NetGuard IDS
              </div>
              <div style="font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#94a3b8;margin-top:3px;">
                Network intrusion detection alert
              </div>
            </td>
          </tr>
          <tr>
            <td style="background:{style['bg']};border-bottom:1px solid {style['border']};padding:16px 22px;">
              <div style="font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:bold;
                          color:{style['color']};letter-spacing:1px;">
                {_esc(style['label'])} SEVERITY
              </div>
              <div style="font-family:Arial,Helvetica,sans-serif;font-size:18px;font-weight:bold;
                          color:#111827;margin-top:6px;">
                {_esc(rule_name)}
              </div>
            </td>
          </tr>
          <tr>
            <td style="padding:18px 22px;">
              <div style="font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:bold;
                          color:#374151;text-transform:uppercase;letter-spacing:0.6px;margin-bottom:8px;">
                Detection narrative
              </div>
              <div style="font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#1f2937;
                          line-height:1.6;background:#f9fafb;border-left:3px solid {style['color']};
                          padding:12px 14px;border-radius:4px;">
                {_esc(detail) if detail else '—'}
              </div>
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
                     style="margin-top:18px;border:1px solid #e5e7eb;border-radius:6px;border-collapse:separate;">
                {''.join(detail_rows)}
              </table>
              <div style="font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:bold;
                          color:#374151;text-transform:uppercase;letter-spacing:0.6px;margin:20px 0 8px 0;">
                Suggested next steps
              </div>
              <div style="font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#6b7280;margin-bottom:8px;">
                Guidance only — not evidence. Confidence reflects heuristic weight, not verified certainty.
              </div>
              <ul style="margin:0;padding-left:20px;font-family:Arial,Helvetica,sans-serif;
                         font-size:13px;color:#1f2937;line-height:1.6;">
                {guidance_html}
              </ul>
              {link_html}
            </td>
          </tr>
          <tr>
            <td style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 22px;
                       font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#6b7280;line-height:1.5;">
              Generated automatically by NetGuard IDS. Payload contents are never included in
              notification email. Credentials and tokens are redacted before storage.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    text_lines = [
        "NETGUARD IDS ALERT",
        "=" * 60,
        f"Severity   : {style['label']}",
        f"Rule       : {_plain(rule_name)}",
    ]
    if rule_version not in (None, ""):
        text_lines.append(f"Rule ver.  : {_plain(rule_version)}")
    text_lines += [
        f"Confidence : {_plain(confidence)} (heuristic weight, not verified certainty)",
        f"Endpoints  : {endpoint_plain}",
    ]
    if protocol not in (None, ""):
        text_lines.append(f"Protocol   : {_plain(protocol)}")
    text_lines.append(f"Detected   : {_fmt_ts(timestamp)}")
    if resolved_alert_id is not None:
        text_lines.append(f"Alert ID   : {_plain(resolved_alert_id)}")
    if flow_id:
        text_lines.append(f"Flow ID    : {_plain(flow_id)}")
    if resolved_case_id:
        text_lines.append(f"Case ID    : {_plain(resolved_case_id)}")
    for label, value in protocol_rows:
        text_lines.append(f"{label + ':':<11}: {_plain(value)}")

    text_lines += [
        "",
        "DETECTION NARRATIVE",
        "-" * 60,
        _plain(detail) if detail else "-",
        "",
        "SUGGESTED NEXT STEPS (guidance only, not evidence)",
        "-" * 60,
        guidance_text,
    ]
    if link_text:
        text_lines.append(link_text)
    text_lines += [
        "",
        "Generated automatically by NetGuard IDS.",
        "Payload contents are never included in notification email.",
    ]

    return RenderedEmail(
        subject=subject,
        text="\n".join(text_lines),
        html=html_body,
        metadata={
            "rule_name": str(rule_name),
            "severity": severity,
            "alert_id": resolved_alert_id,
            "flow_id": flow_id,
            "case_id": resolved_case_id,
        },
    )


def render_report_email(*, report_title: str, report_type: str, fmt: str,
                        filename: str, hours: int, recipient_count: int,
                        dashboard_base_url: str | None = None,
                        generated_at: str | None = None,
                        summary_rows: list[tuple[str, Any]] | None = None,
                        delivery_note: str | None = None) -> RenderedEmail:
    """Render the covering email that accompanies a generated report attachment."""
    title = str(report_title or "NetGuard IDS Report")
    subject = f"[NetGuard IDS] Report — {title}"
    subject = subject.replace("\r", " ").replace("\n", " ")[:250]

    stamp = generated_at or time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    base_url = _safe_base_url(dashboard_base_url)
    link_url = f"{base_url}/#reports" if base_url else None

    rows = [
        ("Report type", report_type),
        ("Format", str(fmt).upper()),
        ("Time window", f"Last {hours} hours"),
        ("Attachment", filename),
        ("Generated", stamp),
        ("Recipients", recipient_count),
    ]
    if summary_rows:
        rows.extend([(str(k), v) for k, v in summary_rows])

    rows_html = "".join(
        f"<tr>"
        f"<td style=\"padding:8px 14px;border-bottom:1px solid #e5e7eb;font-family:Arial,Helvetica,sans-serif;"
        f"font-size:12px;color:#6b7280;white-space:nowrap;width:34%;\">{_esc(k)}</td>"
        f"<td style=\"padding:8px 14px;border-bottom:1px solid #e5e7eb;font-family:Arial,Helvetica,sans-serif;"
        f"font-size:13px;color:#111827;word-break:break-word;\">{_esc(v)}</td>"
        f"</tr>"
        for k, v in rows
    )

    link_html = ""
    if link_url:
        link_html = (
            f"<p style=\"margin:18px 0 0 0;\">"
            f"<a href=\"{_esc(link_url)}\" style=\"background:#1d4ed8;color:#ffffff;"
            f"text-decoration:none;padding:10px 18px;border-radius:6px;"
            f"font-family:Arial,Helvetica,sans-serif;font-size:13px;font-weight:bold;"
            f"display:inline-block;\">Open the Reports workspace</a></p>"
        )

    note_html = ""
    note_text = ""
    if delivery_note:
        note_html = (
            f"<div style=\"font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#92400e;"
            f"background:#fffbeb;border:1px solid #fde68a;border-radius:6px;padding:10px 12px;"
            f"margin-top:16px;\">{_esc(delivery_note)}</div>"
        )
        note_text = f"\nNote: {delivery_note}\n"

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(subject)}</title></head>
<body style="margin:0;padding:0;background:#f3f4f6;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:24px 12px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
             style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden;">
        <tr><td style="background:#0f172a;padding:18px 22px;">
          <div style="font-family:Arial,Helvetica,sans-serif;font-size:16px;font-weight:bold;color:#ffffff;">NetGuard IDS</div>
          <div style="font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#94a3b8;margin-top:3px;">Security report delivery</div>
        </td></tr>
        <tr><td style="padding:20px 22px;">
          <div style="font-family:Arial,Helvetica,sans-serif;font-size:18px;font-weight:bold;color:#111827;margin-bottom:12px;">
            {_esc(title)}
          </div>
          <div style="font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#374151;line-height:1.6;">
            The requested report has been generated and is attached to this message
            as <strong>{_esc(filename)}</strong>.
          </div>
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
                 style="margin-top:16px;border:1px solid #e5e7eb;border-radius:6px;border-collapse:separate;">
            {rows_html}
          </table>
          {note_html}
          {link_html}
        </td></tr>
        <tr><td style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 22px;
                       font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#6b7280;line-height:1.5;">
          Generated automatically by NetGuard IDS. Figures are derived from local telemetry.
          Treat report contents as internal and confidential.
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    text_lines = [
        "NETGUARD IDS — SECURITY REPORT",
        "=" * 60,
        f"Report: {title}",
        "",
    ]
    text_lines += [f"{k + ':':<14}: {_plain(v)}" for k, v in rows]
    text_lines += [
        "",
        f"The report is attached to this message as {filename}.",
    ]
    if note_text:
        text_lines.append(note_text)
    if link_url:
        text_lines.append(f"\nDashboard: {link_url}")
    text_lines += ["", "Generated automatically by NetGuard IDS."]

    return RenderedEmail(
        subject=subject,
        text="\n".join(text_lines),
        html=html_body,
        metadata={
            "report_title": title,
            "report_type": report_type,
            "format": fmt,
            "filename": filename,
        },
    )
