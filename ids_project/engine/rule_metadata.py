"""
engine/rule_metadata.py
-----------------------
Authoritative registry of metadata for all 23 NetGuard IDS detection rules.
Used by the dashboard API, UI filters, reporting pipelines, and testing suites.
"""

from typing import Any

RULE_METADATA: dict[str, dict[str, Any]] = {
    "BLOCKLIST": {
        "name": "BLOCKLIST",
        "category": "Threat Intel",
        "description": "Matches connection endpoints against known C2 and malicious IP blocklists (Feodo Tracker).",
        "default_severity": "critical",
        "default_confidence": "high",
        "color": "#3b82f6",
        "bg_color": "rgba(59, 130, 246, 0.15)",
        "border_color": "rgba(59, 130, 246, 0.35)",
    },
    "TCP_FLAG_ANOMALY": {
        "name": "TCP_FLAG_ANOMALY",
        "category": "Layer 2 & Protocol",
        "description": "Detects malformed or contradictory TCP flags (SYN+FIN, SYN+RST, NULL, all flags) used in evasion.",
        "default_severity": "high",
        "default_confidence": "high",
        "color": "#eab308",
        "bg_color": "rgba(234, 179, 8, 0.15)",
        "border_color": "rgba(234, 179, 8, 0.35)",
    },
    "PORT_SCAN": {
        "name": "PORT_SCAN",
        "category": "Reconnaissance",
        "description": "Detects horizontal and vertical TCP port scanning across destination hosts and ports.",
        "default_severity": "medium",
        "default_confidence": "medium",
        "color": "#f59e0b",
        "bg_color": "rgba(245, 158, 11, 0.15)",
        "border_color": "rgba(245, 158, 11, 0.35)",
    },
    "UDP_SCAN": {
        "name": "UDP_SCAN",
        "category": "Reconnaissance",
        "description": "Detects horizontal and vertical UDP reconnaissance probes against open service ports.",
        "default_severity": "medium",
        "default_confidence": "medium",
        "color": "#fb923c",
        "bg_color": "rgba(251, 146, 60, 0.15)",
        "border_color": "rgba(251, 146, 60, 0.35)",
    },
    "UDP_FLOOD": {
        "name": "UDP_FLOOD",
        "category": "Denial of Service",
        "description": "Detects volumetric UDP packet bursts and floods with QUIC/web port awareness.",
        "default_severity": "high",
        "default_confidence": "medium",
        "color": "#e11d48",
        "bg_color": "rgba(225, 29, 72, 0.15)",
        "border_color": "rgba(225, 29, 72, 0.35)",
    },
    "TCP_STEALTH_SCAN": {
        "name": "TCP_STEALTH_SCAN",
        "category": "Reconnaissance",
        "description": "Detects FIN, NULL, and Xmas (FIN+PSH+URG) stealth scans bypassing SYN logging.",
        "default_severity": "medium",
        "default_confidence": "high",
        "color": "#d946ef",
        "bg_color": "rgba(217, 70, 239, 0.15)",
        "border_color": "rgba(217, 70, 239, 0.35)",
    },
    "SYN_FLOOD": {
        "name": "SYN_FLOOD",
        "category": "Denial of Service",
        "description": "Detects TCP SYN and RST volumetric floods exhausting connection state tables.",
        "default_severity": "high",
        "default_confidence": "high",
        "color": "#ef4444",
        "bg_color": "rgba(239, 68, 68, 0.15)",
        "border_color": "rgba(239, 68, 68, 0.35)",
    },
    "DISTRIBUTED_SYN_FLOOD": {
        "name": "DISTRIBUTED_SYN_FLOOD",
        "category": "Denial of Service",
        "description": "Detects multi-source coordinated DDoS SYN floods targeting a single victim host.",
        "default_severity": "critical",
        "default_confidence": "high",
        "color": "#b91c1c",
        "bg_color": "rgba(185, 28, 28, 0.2)",
        "border_color": "rgba(185, 28, 28, 0.35)",
    },
    "ICMP_SWEEP": {
        "name": "ICMP_SWEEP",
        "category": "Reconnaissance",
        "description": "Detects ICMP echo request sweeps across multiple subnet hosts for host discovery.",
        "default_severity": "low",
        "default_confidence": "medium",
        "color": "#0ea5e9",
        "bg_color": "rgba(14, 165, 233, 0.15)",
        "border_color": "rgba(14, 165, 233, 0.35)",
    },
    "ICMP_FLOOD": {
        "name": "ICMP_FLOOD",
        "category": "Denial of Service",
        "description": "Detects high-frequency ICMP echo bursts intended to saturate bandwidth and CPU.",
        "default_severity": "medium",
        "default_confidence": "high",
        "color": "#f43f5e",
        "bg_color": "rgba(244, 63, 94, 0.15)",
        "border_color": "rgba(244, 63, 94, 0.35)",
    },
    "ARP_SPOOF": {
        "name": "ARP_SPOOF",
        "category": "Layer 2 & Protocol",
        "description": "Detects conflicting IP-to-MAC address mappings indicating ARP cache poisoning or MITM attacks.",
        "default_severity": "high",
        "default_confidence": "high",
        "color": "#a855f7",
        "bg_color": "rgba(168, 85, 247, 0.15)",
        "border_color": "rgba(168, 85, 247, 0.35)",
    },
    "PAYLOAD_HIT": {
        "name": "PAYLOAD_HIT",
        "category": "Application & DPI",
        "description": "Deep packet inspection for 18 threat signatures including SQLi, XSS, Command Injection, Log4Shell, and Webshells.",
        "default_severity": "high",
        "default_confidence": "high",
        "color": "#ec4899",
        "bg_color": "rgba(236, 72, 153, 0.15)",
        "border_color": "rgba(236, 72, 153, 0.35)",
    },
    "DNS_ANOMALY": {
        "name": "DNS_ANOMALY",
        "category": "Application & DPI",
        "description": "Detects high-entropy DGA domains, excessive label lengths, frequency bursts, and covert DNS tunneling.",
        "default_severity": "high",
        "default_confidence": "medium",
        "color": "#06b6d4",
        "bg_color": "rgba(6, 182, 212, 0.15)",
        "border_color": "rgba(6, 182, 212, 0.35)",
    },
    "BRUTE_FORCE": {
        "name": "BRUTE_FORCE",
        "category": "Application & DPI",
        "description": "Detects rapid connection attempts against authentication ports (SSH, RDP, SMB, MySQL, FTP).",
        "default_severity": "high",
        "default_confidence": "medium",
        "color": "#f97316",
        "bg_color": "rgba(249, 115, 22, 0.15)",
        "border_color": "rgba(249, 115, 22, 0.35)",
    },
    "SLOW_PORT_SCAN": {
        "name": "SLOW_PORT_SCAN",
        "category": "Reconnaissance",
        "description": "Detects low-and-slow vertical and horizontal scans designed to evade fast sliding-window detectors.",
        "default_severity": "medium",
        "default_confidence": "medium",
        "color": "#d97706",
        "bg_color": "rgba(217, 119, 6, 0.15)",
        "border_color": "rgba(217, 119, 6, 0.35)",
    },
    "DATA_EXFIL": {
        "name": "DATA_EXFIL",
        "category": "Application & DPI",
        "description": "Detects anomalous outbound data transfer volumes and unauthorized archive/database dumps.",
        "default_severity": "high",
        "default_confidence": "medium",
        "color": "#c026d3",
        "bg_color": "rgba(192, 38, 211, 0.15)",
        "border_color": "rgba(192, 38, 211, 0.35)",
    },
    "TLS_ANOMALY": {
        "name": "TLS_ANOMALY",
        "category": "Covert Channels",
        "description": "Detects direct-IP SNI violations and suspicious dynamic reverse-proxy tunnels in TLS handshakes.",
        "default_severity": "medium",
        "default_confidence": "high",
        "color": "#6366f1",
        "bg_color": "rgba(99, 102, 241, 0.15)",
        "border_color": "rgba(99, 102, 241, 0.35)",
    },
    "CLEAR_HTTP_ON_TLS_PORT": {
        "name": "CLEAR_HTTP_ON_TLS_PORT",
        "category": "Covert Channels",
        "description": "Detects cleartext HTTP request commands on encrypted TLS ports 443 and 8443.",
        "default_severity": "high",
        "default_confidence": "high",
        "color": "#8b5cf6",
        "bg_color": "rgba(139, 92, 246, 0.15)",
        "border_color": "rgba(139, 92, 246, 0.35)",
    },
    "TCP_ZERO_WINDOW": {
        "name": "TCP_ZERO_WINDOW",
        "category": "Denial of Service",
        "description": "Detects Sockstress zero-window advertisements causing persist-timer resource starvation.",
        "default_severity": "medium",
        "default_confidence": "high",
        "color": "#dc2626",
        "bg_color": "rgba(220, 38, 38, 0.15)",
        "border_color": "rgba(220, 38, 38, 0.35)",
    },
    "NON_DNS_TRAFFIC_ON_DNS_PORT": {
        "name": "NON_DNS_TRAFFIC_ON_DNS_PORT",
        "category": "Covert Channels",
        "description": "Detects interactive command shells, cleartext HTTP, or non-DNS payloads on port 53.",
        "default_severity": "critical",
        "default_confidence": "high",
        "color": "#14b8a6",
        "bg_color": "rgba(20, 184, 166, 0.15)",
        "border_color": "rgba(20, 184, 166, 0.35)",
    },
    "ICMP_TUNNEL": {
        "name": "ICMP_TUNNEL",
        "category": "Covert Channels",
        "description": "Detects high-entropy, oversized ICMP payloads, Ptunnel, and reverse shells inside ICMP Echo packets.",
        "default_severity": "high",
        "default_confidence": "high",
        "color": "#10b981",
        "bg_color": "rgba(16, 185, 129, 0.15)",
        "border_color": "rgba(16, 185, 129, 0.35)",
    },
    "IP_FRAGMENT_ANOMALY": {
        "name": "IP_FRAGMENT_ANOMALY",
        "category": "Layer 2 & Protocol",
        "description": "Detects Teardrop overlapping fragment crash attacks and tiny fragment firewall evasion.",
        "default_severity": "critical",
        "default_confidence": "high",
        "color": "#84cc16",
        "bg_color": "rgba(132, 204, 22, 0.15)",
        "border_color": "rgba(132, 204, 22, 0.35)",
    },
    "IRC_C2_BEACONING": {
        "name": "IRC_C2_BEACONING",
        "category": "Covert Channels",
        "description": "Detects periodic beaconing and botnet C2 control commands on IRC ports.",
        "default_severity": "high",
        "default_confidence": "high",
        "color": "#a21caf",
        "bg_color": "rgba(162, 28, 175, 0.15)",
        "border_color": "rgba(162, 28, 175, 0.35)",
    },
}

CATEGORIES = [
    "Threat Intel",
    "Reconnaissance",
    "Denial of Service",
    "Layer 2 & Protocol",
    "Application & DPI",
    "Covert Channels",
]


def get_rule_metadata_inventory(engine=None) -> list[dict[str, Any]]:
    """
    Return authoritative list of metadata dicts for all rules currently registered
    in the RuleEngine instance (or creates a temporary RuleEngine if None).
    """
    if engine is None:
        try:
            import config
            from engine.rules import RuleEngine
            engine = RuleEngine(None, set(), config)
        except Exception:
            engine = None

    inventory = []
    if engine and hasattr(engine, "rules"):
        for rule in engine.rules:
            name = getattr(rule, "name", "UNKNOWN")
            ver = getattr(rule, "rule_version", getattr(rule, "version", "1.0"))
            meta = RULE_METADATA.get(name, {
                "name": name,
                "category": "General",
                "description": f"Detection rule {name}",
                "default_severity": "medium",
                "default_confidence": "medium",
                "color": "#64748b",
                "bg_color": "rgba(100, 116, 139, 0.15)",
                "border_color": "rgba(100, 116, 139, 0.35)",
            }).copy()
            meta["rule_version"] = ver
            meta["class_name"] = rule.__class__.__name__
            meta["rule_name"] = name

            # Discover protocol routing
            protos = []
            if hasattr(engine, "_rules_by_proto"):
                for p, p_rules in engine._rules_by_proto.items():
                    if rule in p_rules:
                        protos.append(p)
            meta["protocols"] = protos
            inventory.append(meta)
    else:
        # Fallback to static dictionary entries
        for name, meta in RULE_METADATA.items():
            item = meta.copy()
            item["rule_version"] = "1.0"
            item["class_name"] = name
            item["rule_name"] = name
            item["protocols"] = []
            inventory.append(item)

    return inventory

