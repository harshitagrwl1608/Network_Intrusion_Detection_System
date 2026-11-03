"""
engine/rules.py
---------------
All detection rules + the RuleEngine orchestrator.

Rules are stateful and maintain short-term sliding-window memory.
Each rule's check() method receives a normalised packet record dict and
returns an alert dict (or None).  Multiple rules may fire on the same
packet — the engine never exits early.

Alert schema (§5.2 of roadmap):
  rule_name        str   — rule identifier
  rule_version     str   — "major.minor" for tracking changes
  event_timestamp  float — from packet capture (preserved through sniffer)
  src_ip, dst_ip   str
  src_port, dst_port int
  protocol         str
  severity         str   — "high" | "medium" | "low"
  confidence       str   — "high" | "heuristic" | "low"
  detail           str   — human-readable summary
  evidence         dict  — structured, JSON-serialisable facts
  window_start     float — start of the detection window (stateful rules)
  window_end       float — end of the detection window (stateful rules)

RuleEngine execution order (all rules run; no early exit):
  1.  BlocklistRule          — known-malicious IP lookup
  2.  TcpFlagAnomalyRule     — malformed or suspicious TCP flag combinations
  3.  PortScanRule           — vertical + horizontal TCP scan
  4.  UdpScanRule            — vertical + horizontal UDP scan
  5.  UdpFloodRule           — UDP packet-rate flood
  6.  TcpStealthScanRule     — FIN/NULL/Xmas vertical TCP scan
  7.  SynFloodRule           — SYN burst + RST flood rate per source/destination
  8.  DistributedSynFloodRule — SYN burst per destination across many sources
  9.  IcmpSweepRule          — ICMP echo target sweep by source
 10.  IcmpFloodRule          — ICMP echo-request flood
 11.  ArpSpoofRule           — persistent IP→MAC mapping change
 12.  PayloadRule (v1.18)    — bounded TCP stream DPI + regex signatures (all matches)
     Signatures:
       SQL_INJECTION        — UNION/SELECT, BENCHMARK, LOAD_FILE, INTO OUTFILE, quote-OR bypass
       XSS                  — script/event handlers + SVG/img/iframe/body bypass vectors
       CREDENTIAL_LEAK      — password=, Basic auth, Bearer (min 24 chars), X-API-Key
       CMD_INJECTION        — /bin/sh, reverse shells, interpreter one-liners (python/perl/ruby)
       PATH_TRAVERSAL       — ../ sequences, /etc/passwd, /proc/self, Windows paths
       SSRF                 — file/dict/gopher schemes, cloud metadata IPs, IPv6 internal
       LOG4SHELL            — ${jndi:} + nested lower/upper/:-: obfuscation variants
       XXE                  — <!ENTITY SYSTEM/PUBLIC> declarations
       SSTI                 — Jinja2 introspection/arithmetic, Freemarker ?new(), Spring EL
       SHELLSHOCK           — bash function export CVE-2014-6271 patterns
       DESERIALIZATION      — Java (0xaced), PHP, Python pickle gadget markers
       HEADER_INJECTION     — CRLF-encoded Set-Cookie/Location injection
       SCANNER_PROBE        — sqlmap/nikto/gobuster/zgrab/ZmEu/hydra/medusa User-Agents
       SENSITIVE_FILE_PROBE — .env/.git/.htpasswd/phpinfo/server-status/backup.sql probes
       REVERSE_SHELL_CRADLE — curl|sh, wget|sh, PowerShell cradles, socat exec shells
       HTTP_METHOD_TAMPERING — TRACE/TRACK/DEBUG/WebDAV methods
       WEBSHELL_INJECTION   — PHP/JSP/ASP/Python web shell execution markers
 13.  DnsRule (v1.16)       — Shannon entropy + length + frequency + subdomain exfil
                              + hex/base64/base32 DNS tunnel chunk detection
                              mDNS (port 5353) and LLMNR (port 5355) are explicitly exempt.
 14.  BruteForceRule        — repeated auth-port SYNs per (src,dst,port); covers SSH,
                              RDP, VNC, MySQL, Redis, Elasticsearch, Tomcat/8080/8443
 15.  SlowPortScanRule      — low-and-slow vertical/horizontal TCP scan (120s window)
 16.  DataExfiltrationRule  — outbound payload-volume threshold
 17.  TlsAnomalyRule        — TLS ClientHello/SNI anomalies
 18.  CleartextHttpOnTlsPortRule — repeated cleartext HTTP on a TLS service port
 19.  TcpZeroWindowRule     — repeated TCP zero-window advertisements

MITRE ATT&CK identifiers are not currently part of the alert schema or rule
configuration. Do not infer a technique mapping from the rule name alone.

False Positive Mitigations:
  - PortScanRule: ignores hosts whose SOURCE port is a well-known service
    (servers replying to clients, not scanners).
  - PortScanRule: only counts SYN packets (new connection attempts).
  - PortScanRule: severity scales with scan breadth (medium at threshold, high at 2× threshold).
  - SynFloodRule: only fires on service destination ports (≤ 49151) for SYN floods.
  - SynFloodRule: RST flood checks aggregate all RSTs from src→dst; fires on very high rates.
  - Configurable TRUSTED_HOSTS whitelist for TCP/UDP scans, SYN-flood rules,
    and ICMP sweeps.
  - Configurable WELL_KNOWN_SERVICE_PORTS set.
  - DnsRule: whitelists common high-entropy-but-legit CDN patterns (entropy check only).
  - DnsRule: mDNS (5353) and LLMNR (5355) traffic explicitly excluded.
  - DnsRule: subdomain exfiltration requires ≥ distinct_subdomain_threshold unique
    subdomains under one parent domain in a short window; repeated same subdomain not counted.
  - DnsRule: base64/base32 chunks require mixed case + digits (excludes plain words/UUIDs).
  - SSTI: requires introspection object access or arithmetic operator (excludes ${VAR} shell env).
  - CREDENTIAL_LEAK: Bearer token minimum 24 chars (excludes short benign tokens).
  - BruteForceRule: only fires on known authentication ports; tunable thresholds per-port.
  - SlowPortScanRule: longer window (default 120s) and higher port threshold to avoid FPs
    from normal slow browsing patterns.
  - Stateful rules protect their mutable state with a per-rule lock (§3.8).

Thread safety:
  Each stateful rule guards its mutable history/table/stream state with a
  per-rule threading.Lock or threading.RLock so the capture thread (check)
  and GC thread (prune_stale) cannot race.
"""

import json
import hashlib
import math
import os
import re
import threading
import time
import ipaddress
import logging
from urllib.parse import unquote_to_bytes
from collections import defaultdict, Counter, deque, OrderedDict

logger = logging.getLogger(__name__)


def _positive_setting(value, default: int, setting_name: str) -> int:
    """Parse a positive integer rule setting, falling back to its safe default."""
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        parsed = 0
    if parsed <= 0:
        logger.warning("%s must be a positive integer; using default %d", setting_name, default)
        return default
    return parsed


def _nonnegative_setting(value, default: int, setting_name: str) -> int:
    """Parse a non-negative integer setting, preserving zero as an opt-out."""
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        parsed = -1
    if parsed < 0:
        logger.warning("%s must be a non-negative integer; using default %d", setting_name, default)
        return default
    return parsed


def _positive_float_setting(value, default: float, setting_name: str) -> float:
    """Parse a finite positive float rule setting, falling back when invalid."""
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        parsed = 0.0
    if not math.isfinite(parsed) or parsed <= 0:
        logger.warning("%s must be a finite positive number; using default %s", setting_name, default)
        return default
    return parsed


def _nonnegative_float_setting(value, default: float, setting_name: str) -> float:
    """Parse a finite non-negative float, preserving zero as an opt-out."""
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        parsed = -1.0
    if not math.isfinite(parsed) or parsed < 0:
        logger.warning("%s must be a finite non-negative number; using default %s", setting_name, default)
        return default
    return parsed


def _normalize_port(port: Any) -> int | None:
    """Safely parse a port number to int if valid (0-65535), otherwise None."""
    if port is None:
        return None
    try:
        parsed = int(port)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if 0 <= parsed <= 65535 else None


def _finite_record_timestamp(record: dict, prefer_event_timestamp: bool = True) -> float | None:
    """Return the selected finite packet timestamp, or None for invalid telemetry."""
    raw = None
    if prefer_event_timestamp:
        raw = record.get("event_timestamp")
    if raw is None:
        raw = record.get("timestamp")
    if raw is None:
        raw = time.time()
    try:
        parsed = float(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if math.isfinite(parsed) else None


def _is_initial_syn(record: dict) -> bool:
    """Classify a new TCP SYN consistently when derived metadata is absent."""
    initial_syn = record.get("initial_syn")
    if initial_syn is not None:
        return bool(initial_syn)
    flags = record.get("tcp_flags")
    if flags is not None:
        try:
            parsed_flags = int(flags)
        except (TypeError, ValueError, OverflowError):
            return False
        return bool(parsed_flags & 0x02) and not bool(parsed_flags & 0x10)
    # Preserve compatibility with legacy records that expose only syn_flag.
    return bool(record.get("syn_flag"))

# ---------------------------------------------------------------------------
# Ports that servers legitimately respond FROM — if a host's SOURCE port
# is in this set, it is a server replying to clients, NOT a scanner.
# ---------------------------------------------------------------------------
WELL_KNOWN_SERVICE_PORTS = {
    53,    # DNS
    80,    # HTTP
    443,   # HTTPS
    8080,  # HTTP-alt
    8443,  # HTTPS-alt
    67, 68, # DHCP
    123,   # NTP
    25, 587, 465,  # SMTP
    110, 995,      # POP3
    143, 993,      # IMAP
    21, 22,        # FTP, SSH
    3306, 5432,    # MySQL, PostgreSQL
}

# Trusted hosts/IPs that should never be flagged by scan, SYN-flood, or ICMP rules.
# Add your gateway, DNS server, trusted CDN IPs here.
TRUSTED_HOSTS: set = set()  # populated from config by RuleEngine
_TRUSTED_NETWORKS_CACHE_LOCK = threading.Lock()
_TRUSTED_NETWORKS_CACHE_STATE: tuple[frozenset[str] | None, tuple] = (None, ())


def _trusted_networks(entries: frozenset[str]) -> tuple:
    """Compile configured CIDRs once, refreshing when the trusted set changes."""
    global _TRUSTED_NETWORKS_CACHE_STATE
    cached_key, networks = _TRUSTED_NETWORKS_CACHE_STATE
    if entries == cached_key:
        return networks
    with _TRUSTED_NETWORKS_CACHE_LOCK:
        cached_key, networks = _TRUSTED_NETWORKS_CACHE_STATE
        if entries != cached_key:
            compiled = []
            for entry in entries:
                try:
                    compiled.append(ipaddress.ip_network(entry, strict=False))
                except (TypeError, ValueError):
                    continue
            networks = tuple(compiled)
            _TRUSTED_NETWORKS_CACHE_STATE = (entries, networks)
    return networks


def _is_trusted(ip: str) -> bool:
    """Return True if ip matches any trusted host or CIDR range."""
    if not TRUSTED_HOSTS:
        return False
    try:
        if ip in TRUSTED_HOSTS:
            return True
    except TypeError:
        return False
    entries = frozenset(TRUSTED_HOSTS)
    try:
        address = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return False
    return any(address in network for network in _trusted_networks(entries))


_INTERNAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
)


def _is_internal(ip: str) -> bool:
    """Return True if ip is an RFC-1918, loopback, or link-local private address."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _INTERNAL_NETWORKS)
    except ValueError:
        return False


# =============================================================================
# Rule 1: Blocklist Match
# =============================================================================

class BlocklistRule:
    name = "BLOCKLIST"
    rule_version = "1.1"

    def __init__(self, blocklist):
        """
        Accept either a BlocklistData namedtuple (preferred) or a plain set
        (backwards-compatible with older callers that pass a raw set).
        """
        from engine.blocklist import BlocklistData
        if isinstance(blocklist, BlocklistData):
            self._exact = blocklist.exact
            self._networks = blocklist.networks
        else:
            # Legacy: plain set of IP strings — no CIDR support
            self._exact = set(blocklist)
            self._networks = []

    def _in_blocklist(self, ip: str) -> bool:
        """Check exact set then CIDR networks.
        Normalises the observed IP before exact matching so that
        equivalent IPv6 spellings (e.g. ::1 vs ::0:1) resolve correctly.
        """
        try:
            canon = str(ipaddress.ip_address(ip))
        except ValueError:
            canon = ip  # not a valid IP — try raw string
        if canon in self._exact:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._networks)
        except ValueError:
            return False

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP":
            return None
        src = record.get("src_ip")
        dst = record.get("dst_ip")

        bad_ip = None
        direction = ""
        if dst and self._in_blocklist(dst):
            bad_ip = dst
            direction = "contact"
        elif src and self._in_blocklist(src):
            bad_ip = src
            direction = "receive"

        if bad_ip:
            detail_msg = (
                f"{src} attempted to contact known-malicious IP {bad_ip}"
                if direction == "contact"
                else f"Received traffic from known-malicious IP {bad_ip}"
            )
            return {
                "rule_name": self.name,
                "rule_version": self.rule_version,
                "src_ip": src,
                "dst_ip": dst,
                "src_port": record.get("src_port"),
                "dst_port": record.get("dst_port"),
                "protocol": record.get("protocol"),
                "severity": "high",
                "confidence": "high",
                "detail": detail_msg,
                "evidence": {
                    "bad_ip": bad_ip,
                    "direction": direction,
                },
                "window_start": None,
                "window_end": None,
            }
        return None


# =============================================================================
# Rule 2: Port Scan Detection  (§3.2 — vertical + horizontal)
# =============================================================================

class PortScanRule:
    name = "PORT_SCAN"
    rule_version = "1.12"

    def __init__(self, threshold: int = 15, window: int = 10, protocol: str = "TCP",
                 max_states: int = 10_000):
        self.threshold = _positive_setting(threshold, 15, "PORT_SCAN_THRESHOLD")
        self.window = _positive_setting(window, 10, "TIME_WINDOW")
        self.protocol = protocol
        self.max_states = _positive_setting(
            max_states, 10_000, "PORT_SCAN_MAX_STATES")
        # Retain enough distinct targets to preserve both the alert threshold
        # and the existing high-severity (2x threshold) boundary.
        self._max_evidence = max(2, self.threshold * 2)
        self._lock = threading.RLock()

        # Vertical scan: (src_ip, dst_ip) → ordered dst_port → last timestamp.
        # Ordered maps let us expire old unique targets from the front instead
        # of rebuilding a list and set for every packet in a large scan.
        self._vert: OrderedDict[tuple, OrderedDict] = OrderedDict()

        # Horizontal scan: (src_ip, dst_port) → ordered dst_ip → last timestamp.
        self._horiz: OrderedDict[tuple, OrderedDict] = OrderedDict()

        # Per-key last alert time (cooldown to prevent alert storms).
        # State is kept after firing so the count can grow to 2× threshold.
        self._vert_fired:  OrderedDict[tuple, float] = OrderedDict()
        self._horiz_fired: OrderedDict[tuple, float] = OrderedDict()
        self._vert_saturated: set[tuple] = set()
        self._horiz_saturated: set[tuple] = set()
        # Re-fire cooldown = one full window (avoids alerting every packet once over threshold)
        self._alert_cooldown: float = float(self.window)

    def prune_stale(self, now: float):
        cutoff = now - self.window
        with self._lock:
            for d in (self._vert, self._horiz):
                for key, history in list(d.items()):
                    while history:
                        oldest_time = next(iter(history.values()))
                        if cutoff <= oldest_time <= now:
                            break
                        history.popitem(last=False)
                    if not history:
                        del d[key]
                        if d is self._vert:
                            self._vert_saturated.discard(key)
                        else:
                            self._horiz_saturated.discard(key)
                    elif len(history) < self._max_evidence:
                        if d is self._vert:
                            self._vert_saturated.discard(key)
                        else:
                            self._horiz_saturated.discard(key)
            # Evict stale cooldown entries
            for fired in (self._vert_fired, self._horiz_fired):
                for key in list(fired):
                    if fired[key] < cutoff:
                        del fired[key]

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP":
            return None

        src = record.get("src_ip", "")
        if _is_trusted(src):
            return None

        protocol = record.get("protocol", "")
        if protocol != self.protocol:
            return None

        # UDP has no handshake to distinguish a server reply from a probe, so
        # keep its service-source exemptions. For TCP, the initial-SYN check
        # below already rejects normal SYN-ACK replies; a source-port-only
        # exemption lets scanners evade detection by selecting a service port.
        src_port = _normalize_port(record.get("src_port"))
        if (self.protocol != "TCP" and src_port is not None
                and src_port in WELL_KNOWN_SERVICE_PORTS):
            return None

        # TCP scans count initial SYNs only. UDP has no handshake, so the
        # separate UdpScanRule counts datagrams and relies on distinct targets.
        if self.protocol == "TCP" and not _is_initial_syn(record):
            return None

        dst_ip = record.get("dst_ip", "")
        dst_port = _normalize_port(record.get("dst_port"))
        if dst_port is None:
            return None

        now = _finite_record_timestamp(record, prefer_event_timestamp=False)
        if now is None:
            return None
        vkey = (src, dst_ip)
        hkey = (src, dst_port)

        with self._lock:
            vertical = self._vert.get(vkey)
            horizontal = self._horiz.get(hkey)
            if (vertical and now < next(reversed(vertical.values()))) or \
               (horizontal and now < next(reversed(horizontal.values()))):
                return None  # don't let late events skew an active window
            # Always update BOTH vertical and horizontal histories first,
            # then check thresholds. This ensures a packet contributes to
            # both scan dimensions even when one threshold fires. (P2 §4)
            if vkey not in self._vert and len(self._vert) >= self.max_states:
                evicted = next(iter(self._vert))
                self._vert.pop(evicted)
                self._vert_saturated.discard(evicted)
                self._vert_fired.pop(evicted, None)
            if hkey not in self._horiz and len(self._horiz) >= self.max_states:
                evicted = next(iter(self._horiz))
                self._horiz.pop(evicted)
                self._horiz_saturated.discard(evicted)
                self._horiz_fired.pop(evicted, None)

            # --- Vertical history update ---
            # Each port contributes once; a repeat refreshes its window time.
            if vertical is None:
                vertical = OrderedDict()
                self._vert[vkey] = vertical
            cutoff = now - self.window
            while vertical and next(iter(vertical.values())) < cutoff:
                vertical.popitem(last=False)
            if len(vertical) < self._max_evidence:
                self._vert_saturated.discard(vkey)
            vertical[dst_port] = now
            vertical.move_to_end(dst_port)
            self._vert.move_to_end(vkey)
            if len(vertical) > self._max_evidence:
                vertical.popitem(last=False)
                self._vert_saturated.add(vkey)
            distinct_ports = len(vertical)

            # --- Horizontal history update ---
            # The same bounded sliding-window operation applies across hosts.
            if horizontal is None:
                horizontal = OrderedDict()
                self._horiz[hkey] = horizontal
            while horizontal and next(iter(horizontal.values())) < cutoff:
                horizontal.popitem(last=False)
            if len(horizontal) < self._max_evidence:
                self._horiz_saturated.discard(hkey)
            horizontal[dst_ip] = now
            horizontal.move_to_end(dst_ip)
            self._horiz.move_to_end(hkey)
            if len(horizontal) > self._max_evidence:
                horizontal.popitem(last=False)
                self._horiz_saturated.add(hkey)
            distinct_hosts = len(horizontal)

            vert_fired  = distinct_ports >= self.threshold
            horiz_fired = distinct_hosts >= self.threshold

            if vert_fired:
                window_start = next(iter(vertical.values()))
                # Severity scales with breadth: medium at threshold, high at 2×
                vert_severity = "high" if distinct_ports >= self.threshold * 2 else "medium"
                last_vert_alert = self._vert_fired.get(vkey)
                if last_vert_alert is not None and now - last_vert_alert < self._alert_cooldown:
                    # Within cooldown: suppress, but keep state for growing count
                    pass  # fall through to return None
                else:
                    if vkey not in self._vert_fired and len(self._vert_fired) >= self.max_states:
                        self._vert_fired.popitem(last=False)
                    self._vert_fired[vkey] = now
                    self._vert_fired.move_to_end(vkey)
                    logger.debug(
                        f"{self.name} (vertical) fired: {src}→{dst_ip} "
                        f"{distinct_ports} ports [{vert_severity}]"
                    )
                    return {
                        "rule_name": self.name,
                        "rule_version": self.rule_version,
                        "src_ip": src,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "severity": vert_severity,
                        "confidence": "heuristic",
                        "detail": (
                            f"{src} sent {'SYN' if self.protocol == 'TCP' else 'UDP probes'} "
                            f"to {'at least ' if vkey in self._vert_saturated else ''}"
                            f"{distinct_ports} distinct ports on {dst_ip} in {self.window}s "
                            f"— possible vertical {self.protocol} port scan"
                        ),
                        "evidence": {
                            "scan_type": "vertical",
                            "transport": self.protocol,
                            "distinct_ports": distinct_ports,
                            "distinct_ports_saturated": vkey in self._vert_saturated,
                            "target_host": dst_ip,
                            "window_s": self.window,
                            "threshold": self.threshold,
                        },
                        "window_start": window_start,
                        "window_end": now,
                    }

            if horiz_fired:
                window_start = next(iter(horizontal.values()))
                # Severity scales with breadth: medium at threshold, high at 2×
                horiz_severity = "high" if distinct_hosts >= self.threshold * 2 else "medium"
                last_horiz_alert = self._horiz_fired.get(hkey)
                if last_horiz_alert is not None and now - last_horiz_alert < self._alert_cooldown:
                    pass
                else:
                    if hkey not in self._horiz_fired and len(self._horiz_fired) >= self.max_states:
                        self._horiz_fired.popitem(last=False)
                    self._horiz_fired[hkey] = now
                    self._horiz_fired.move_to_end(hkey)
                    logger.debug(
                        f"{self.name} (horizontal) fired: {src} port {dst_port} "
                        f"→ {distinct_hosts} hosts [{horiz_severity}]"
                    )
                    return {
                        "rule_name": self.name,
                        "rule_version": self.rule_version,
                        "src_ip": src,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "severity": horiz_severity,
                        "confidence": "heuristic",
                        "detail": (
                            f"{src} sent {'SYN' if self.protocol == 'TCP' else 'UDP probes'} "
                            f"to port {dst_port} on {'at least ' if hkey in self._horiz_saturated else ''}"
                            f"{distinct_hosts} distinct hosts in "
                            f"{self.window}s — possible horizontal {self.protocol} port scan"
                        ),
                        "evidence": {
                            "scan_type": "horizontal",
                            "transport": self.protocol,
                            "distinct_hosts": distinct_hosts,
                            "distinct_hosts_saturated": hkey in self._horiz_saturated,
                            "scanned_port": dst_port,
                            "window_s": self.window,
                            "threshold": self.threshold,
                        },
                        "window_start": window_start,
                        "window_end": now,
                    }

        return None


class UdpScanRule(PortScanRule):
    """UDP scan detector sharing the TCP scanner's vertical/horizontal logic."""

    name = "UDP_SCAN"
    rule_version = "1.3"

    def __init__(self, threshold: int = 15, window: int = 10,
                 max_states: int = 10_000):
        super().__init__(threshold, window, protocol="UDP", max_states=max_states)


class UdpFloodRule:
    """
    Detect high-rate UDP packet bursts directed at a single destination host.

    Differentiates between multi-port UDP port scans (tracked by UdpScanRule)
    and single-target UDP volumetric floods.

    Exemptions:
    - DNS responses from servers (src_port == 53).
    - DHCP responses (src_port in (67, 68)).
    - NTP server responses (src_port == 123).
    - Configured TRUSTED_HOSTS.
    """

    name = "UDP_FLOOD"
    rule_version = "1.6"
    ALERT_COOLDOWN_S: float = 60.0
    _EXEMPT_SRC_PORTS: set[int] = {53, 67, 68, 123}

    def __init__(self, threshold: int = 50, window: int = 5,
                 max_flows: int = 4096, cooldown: float = 60.0,
                 web_threshold: int = 500):
        self.threshold = _positive_setting(
            threshold, 50, "UDP_FLOOD_THRESHOLD")
        self.web_threshold = max(self.threshold, _positive_setting(
            web_threshold, 500, "UDP_FLOOD_WEB_THRESHOLD"))
        self.window = _positive_setting(window, 5, "UDP_FLOOD_WINDOW")
        self.max_flows = _positive_setting(max_flows, 4096, "UDP_FLOOD_MAX_FLOWS")
        self.cooldown = _nonnegative_float_setting(
            cooldown, 60.0, "UDP_FLOOD_COOLDOWN")
        self._lock = threading.RLock()
        # (src_ip, dst_ip) → list of timestamps
        self._history: OrderedDict[tuple, list[float]] = OrderedDict()
        # (src_ip, dst_ip) → last_alert_time
        self._cooldown: OrderedDict[tuple, float] = OrderedDict()

    def prune_stale(self, now: float):
        cutoff = now - self.window
        cutoff_cd = now - self.cooldown
        with self._lock:
            for key in list(self._history):
                active = [t for t in self._history[key] if cutoff <= t <= now]
                if active:
                    self._history[key] = active
                else:
                    del self._history[key]
            for key in list(self._cooldown):
                if self._cooldown[key] < cutoff_cd:
                    del self._cooldown[key]

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP" or record.get("protocol") != "UDP":
            return None

        src = record.get("src_ip", "")
        dst = record.get("dst_ip", "")
        if not src or not dst or _is_trusted(src):
            return None
        # This rule detects floods directed at a host. Discovery and service
        # traffic to multicast groups (and limited broadcast) is not targeted
        # host traffic and can otherwise accumulate into false flood alerts.
        try:
            dst_addr = ipaddress.ip_address(dst)
        except (TypeError, ValueError):
            return None
        if dst_addr.is_multicast or (
                dst_addr.version == 4 and int(dst_addr) == 0xFFFFFFFF):
            return None

        src_port = _normalize_port(record.get("src_port"))
        if src_port in self._EXEMPT_SRC_PORTS:
            return None
        dst_port = _normalize_port(record.get("dst_port"))
        effective_threshold = (
            self.web_threshold if (src_port == 443 or dst_port == 443) else self.threshold
        )

        now = _finite_record_timestamp(record)
        if now is None:
            return None
        key = (src, dst)

        with self._lock:
            last_alert = self._cooldown.get(key)
            if last_alert is not None and now - last_alert < self.cooldown:
                self._cooldown.move_to_end(key)
                return None

            if key not in self._history and len(self._history) >= self.max_flows:
                self._history.popitem(last=False)

            history = self._history.get(key, [])
            if history and now < history[-1]:
                return None
            history = [t for t in history if 0 <= now - t <= self.window]
            history.append(now)
            self._history[key] = history
            self._history.move_to_end(key)

            if len(history) < effective_threshold:
                return None

            if key not in self._cooldown and len(self._cooldown) >= self.max_flows:
                self._cooldown.popitem(last=False)
            self._cooldown.pop(key, None)
            self._cooldown[key] = now
            self._cooldown.move_to_end(key)
            window_start = history[0]
            count = len(history)
            self._history.pop(key, None)

            logger.debug(f"{self.name} fired: {src} -> {dst} ({count} pkts in {self.window}s)")
            return {
                "rule_name": self.name,
                "rule_version": self.rule_version,
                "src_ip": src,
                "dst_ip": dst,
                "src_port": src_port,
                "dst_port": record.get("dst_port"),
                "protocol": "UDP",
                "severity": "medium",
                "confidence": "heuristic",
                "detail": (
                    f"{src} sent {count} UDP packets to {dst} in {self.window}s "
                    "— possible targeted UDP flood (packet-rate signal; review source context)"
                ),
                "evidence": {
                    "classification": "UDP_PACKET_RATE_THRESHOLD",
                    "packet_count": count,
                    "target_host": dst,
                    "target_port": record.get("dst_port"),
                    "window_s": self.window,
                    "threshold": effective_threshold,
                },
                "window_start": window_start,
                "window_end": now,
            }


class TcpStealthScanRule:
    """Detect vertical FIN, NULL, and Xmas TCP probes."""

    name = "TCP_STEALTH_SCAN"
    rule_version = "1.5"
    _FIN, _SYN, _RST, _PSH, _ACK, _URG, _ECE, _CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
    _XMAS_FLAGS = _FIN | _PSH | _URG
    _DISALLOWED_FLAGS = _SYN | _RST | _ACK | _ECE | _CWR

    def __init__(self, threshold: int = 15, window: int = 10,
                 max_states: int = 10_000):
        self.threshold = _positive_setting(
            threshold, 15, "TCP_STEALTH_SCAN_THRESHOLD")
        self.window = _positive_setting(window, 10, "TIME_WINDOW")
        self.max_states = _positive_setting(
            max_states, 10_000, "TCP_STEALTH_SCAN_MAX_STATES")
        self._lock = threading.RLock()
        self._probes: dict[tuple, list[tuple[float, int, str]]] = {}
        self._fired: OrderedDict[tuple, float] = OrderedDict()
        self._alert_cooldown = float(self.window)

    @classmethod
    def _probe_type(cls, flags: int) -> str | None:
        if flags & cls._DISALLOWED_FLAGS:
            return None
        if flags == 0:
            return "NULL"
        if flags == cls._FIN:
            return "FIN"
        if flags == cls._XMAS_FLAGS:
            return "XMAS"
        return None

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP" or record.get("protocol") != "TCP":
            return None
        src, dst = record.get("src_ip", ""), record.get("dst_ip", "")
        if not src or not dst or _is_trusted(src):
            return None
        src_port, dst_port = record.get("src_port"), record.get("dst_port")
        flags = record.get("tcp_flags")
        if dst_port is None or flags is None:
            return None
        try:
            flags = int(flags)
            dst_port = int(dst_port)
        except (TypeError, ValueError, OverflowError):
            return None
        if not 0 <= dst_port <= 65535:
            return None
        probe_type = self._probe_type(flags)
        if probe_type is None:
            return None

        now = _finite_record_timestamp(record)
        if now is None:
            return None
        key = (src, dst)
        cutoff = now - self.window
        with self._lock:
            history = self._probes.get(key, [])
            if history and now < max(ts for ts, _, _ in history):
                return None
            active = [(ts, port, kind) for ts, port, kind in history
                      if cutoff <= ts <= now and port != dst_port]
            active.append((now, dst_port, probe_type))
            if key not in self._probes and len(self._probes) >= self.max_states:
                self._probes.pop(next(iter(self._probes)))
            self._probes.pop(key, None)
            self._probes[key] = active
            distinct_ports = len({port for _, port, _ in active})
            if distinct_ports < self.threshold:
                return None

            last_fired = self._fired.get(key)
            if last_fired is not None and now - last_fired < self._alert_cooldown:
                # A long scan is one continuing event; don't emit an alert for
                # every threshold-sized batch from the same source/target.
                self._probes.pop(key, None)
                self._fired.move_to_end(key)
                return None

            if key not in self._fired and len(self._fired) >= self.max_states:
                self._fired.popitem(last=False)
            self._fired[key] = now
            self._fired.move_to_end(key)

            kinds = sorted({kind for _, _, kind in active})
            window_start = min(ts for ts, _, _ in active)
            self._probes.pop(key, None)
            return {
                "rule_name": self.name,
                "rule_version": self.rule_version,
                "src_ip": src,
                "dst_ip": dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "TCP",
                "severity": "high",
                "confidence": "heuristic",
                "detail": (
                    f"{src} sent {distinct_ports} distinct TCP {', '.join(kinds)} probes "
                    f"to {dst} in {self.window}s — possible TCP stealth port scan"
                ),
                "evidence": {
                    "scan_type": "stealth_vertical",
                    "probe_types": kinds,
                    "distinct_ports": distinct_ports,
                    "target_host": dst,
                    "window_s": self.window,
                    "threshold": self.threshold,
                },
                "window_start": window_start,
                "window_end": now,
            }

    def prune_stale(self, now: float):
        cutoff = now - self.window
        with self._lock:
            for key in list(self._probes):
                active = [(ts, port, kind) for ts, port, kind in self._probes[key]
                          if cutoff <= ts <= now]
                if active:
                    self._probes[key] = active
                else:
                    del self._probes[key]
            for key, fired_at in list(self._fired.items()):
                if fired_at <= cutoff or fired_at > now:
                    del self._fired[key]


# =============================================================================
# Rule: TCP Flag Anomaly & Malformed Packet Detection
# =============================================================================

class TcpFlagAnomalyRule:
    """
    Detect malformed TCP packets and unusual flag combinations that need state context.

    In the TCP state machine (RFC 9293):
      - SYN and FIN cannot be set simultaneously (SYN_FIN: 0x03).
      - SYN and RST cannot be set simultaneously (SYN_RST: 0x06).
      - All control flags set simultaneously (ALL_FLAGS / Kamikaze: 0x3F).
      - PSH set without ACK or SYN (PSH_WITHOUT_ACK: 0x08), treated as
        unusual because this packet-only rule cannot establish TCP state.
      - URG set without ACK (URG_WITHOUT_ACK: 0x20), also treated as unusual
        without connection-state context.

    Conflicting control flags can indicate malformed traffic or scan evasion.
    The ACK-missing patterns remain lower-confidence heuristics because this
    rule does not track connection state.
    Stateful cooldown prevents alert storms if an attacker sends a flood.
    """

    name = "TCP_FLAG_ANOMALY"
    rule_version = "1.5"
    ALERT_COOLDOWN_S = 60.0

    def __init__(self, cooldown: float = 60.0, max_states: int = 5000):
        self.cooldown = _nonnegative_float_setting(
            cooldown, 60.0, "TCP_FLAG_ANOMALY_COOLDOWN")
        self.max_states = _positive_setting(
            max_states, 5000, "TCP_FLAG_ANOMALY_MAX_STATES")
        self._lock = threading.RLock()
        # (src_ip, anomaly_type) → last_alert_timestamp
        self._cooldown: OrderedDict[tuple, float] = OrderedDict()

    def prune_stale(self, now: float):
        cutoff = now - self.cooldown
        with self._lock:
            for key in list(self._cooldown):
                if self._cooldown[key] < cutoff:
                    del self._cooldown[key]

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP" or record.get("protocol") != "TCP":
            return None

        src = record.get("src_ip", "")
        if not src or _is_trusted(src):
            return None

        flags = record.get("tcp_flags")
        if flags is None:
            return None
        try:
            flags = int(flags)
        except (TypeError, ValueError, OverflowError):
            return None
        # TCP reserves nine flag bits (including NS); values outside that
        # range are malformed telemetry and cannot support a reliable verdict.
        if not 0 <= flags <= 0x1FF:
            return None

        # Standard TCP flags
        _FIN = 0x01
        _SYN = 0x02
        _RST = 0x04
        _PSH = 0x08
        _ACK = 0x10
        _URG = 0x20

        anomaly_type = None
        severity = "medium"
        confidence = "high"
        classification = "malformed"
        desc = ""

        # Ignore Xmas probes (_FIN | _PSH | _URG = 0x29) and pure FIN probes — handled by TcpStealthScanRule
        if (flags & (_FIN | _PSH | _URG)) == (_FIN | _PSH | _URG) and not (flags & (_SYN | _RST | _ACK)):
            return None

        # 1. All control flags set (SYN+FIN+RST+PSH+ACK+URG = 0x3F)
        if (flags & 0x3F) == 0x3F:
            anomaly_type = "ALL_FLAGS"
            severity = "high"
            desc = "All 6 standard TCP control flags set simultaneously (Kamikaze/Xmas probe)"
        # 2. SYN + FIN (0x03)
        elif (flags & (_SYN | _FIN)) == (_SYN | _FIN):
            anomaly_type = "SYN_FIN"
            severity = "high"
            desc = "SYN+FIN flags set simultaneously (illegal connection open/close request)"
        # 3. SYN + RST (0x06)
        elif (flags & (_SYN | _RST)) == (_SYN | _RST):
            anomaly_type = "SYN_RST"
            severity = "high"
            desc = "SYN+RST flags set simultaneously (illegal connection open/abort request)"
        # 4. PSH without ACK or SYN
        elif (flags & _PSH) and not (flags & (_ACK | _SYN)):
            anomaly_type = "PSH_WITHOUT_ACK"
            confidence = "heuristic"
            classification = "unusual"
            severity = "medium"
            desc = "PSH flag set without ACK or SYN; connection state is unavailable"
        # 5. URG without ACK
        elif (flags & _URG) and not (flags & _ACK):
            anomaly_type = "URG_WITHOUT_ACK"
            confidence = "heuristic"
            classification = "unusual"
            severity = "medium"
            desc = "URG flag set without ACK; connection state is unavailable"

        if not anomaly_type:
            return None

        now = _finite_record_timestamp(record)
        if now is None:
            return None
        key = (src, anomaly_type)

        with self._lock:
            last = self._cooldown.get(key)
            if last is not None and now - last < self.cooldown:
                self._cooldown.move_to_end(key)
                return None

            if key not in self._cooldown and len(self._cooldown) >= self.max_states:
                self._cooldown.popitem(last=False)
            self._cooldown[key] = now
            self._cooldown.move_to_end(key)

        dst = record.get("dst_ip", "")
        dst_port = record.get("dst_port")
        src_port = record.get("src_port")

        logger.debug(f"{self.name} fired: {src}→{dst}:{dst_port} {anomaly_type} (flags=0x{flags:02x})")

        return {
            "rule_name": self.name,
            "rule_version": self.rule_version,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": "TCP",
            "severity": severity,
            "confidence": confidence,
            "detail": (
                f"{src} sent {classification} TCP flags to {dst}:{dst_port} "
                f"(0x{flags:02x}) — {desc}"
            ),
            "evidence": {
                "anomaly_type": anomaly_type,
                "classification": classification,
                "tcp_flags": flags,
                "flags_hex": f"0x{flags:02x}",
                "description": desc,
                "note": "Illegal TCP flag combinations are commonly used for OS fingerprinting, firewall evasion, or malformed packet attacks.",
            },
            "window_start": None,
            "window_end": None,
        }


# =============================================================================
# Rule 3: SYN Burst / Connection-Rate Abuse  (§3.3 — label clarified)
# =============================================================================

class SynFloodRule:
    """Detect SYN/RST floods while excluding normal closed-port RST replies."""

    name = "SYN_FLOOD"
    rule_version = "1.11"
    ALERT_COOLDOWN_S = 60.0

    def __init__(self, threshold: int = 100, window: int = 10,
                 max_flows: int = 8192,
                 rst_threshold: int = 100, rst_window: int = 10,
                 max_rst_flows: int = 4096,
                 rst_response_grace: float = 5.0,
                 max_syn_contexts: int = 32768):
        self.threshold = _positive_setting(threshold, 100, "SYN_FLOOD_THRESHOLD")
        self.window = _positive_setting(window, 10, "TIME_WINDOW")
        self.max_flows = _positive_setting(
            max_flows, 8192, "SYN_FLOOD_MAX_FLOWS")
        # RST flood parameters: RSTs from one src to one dst (any port)
        self.rst_threshold = _positive_setting(
            rst_threshold, 100, "RST_FLOOD_THRESHOLD")
        self.rst_window = _positive_setting(
            rst_window, 10, "RST_FLOOD_WINDOW")
        self.max_rst_flows = _positive_setting(
            max_rst_flows, 4096, "SYN_FLOOD_MAX_RST_FLOWS")
        self.rst_response_grace = _nonnegative_float_setting(
            rst_response_grace, 5.0, "RST_RESPONSE_GRACE_SECONDS")
        self.max_syn_contexts = _positive_setting(
            max_syn_contexts, 32768, "SYN_FLOOD_MAX_SYN_CONTEXTS")
        self._lock = threading.RLock()
        # (src_ip, dst_ip, dst_port) → list of SYN timestamps
        self._history: dict[tuple, list] = defaultdict(list)
        # (src_ip, dst_ip) → list of RST timestamps
        self._rst_history: dict[tuple, list] = defaultdict(list)
        # Per-target cooldowns keep sustained floods from emitting one alert
        # for every threshold-sized packet group.
        self._syn_cooldown: dict[tuple, float] = {}
        self._rst_cooldown: dict[tuple, float] = {}
        # Suppress retransmitted/capture-duplicated copies of the same TCP RST
        # segment; one identical segment cannot tear down a flow more than once.
        self._rst_seen: OrderedDict[tuple, float] = OrderedDict()
        # Recent initiator 4-tuples → (initial SYN time, saw SYN-ACK). A
        # reverse-direction RST without a SYN-ACK is normally the response to
        # a closed-port probe, not an outbound reset flood.
        self._syn_contexts: OrderedDict[tuple, tuple[float, bool]] = OrderedDict()

    def prune_stale(self, now: float):
        cutoff_syn = now - self.window
        cutoff_rst = now - self.rst_window
        with self._lock:
            for key in list(self._history):
                active = [t for t in self._history[key] if cutoff_syn <= t <= now]
                if active:
                    self._history[key] = active
                else:
                    del self._history[key]
            for key in list(self._rst_history):
                active = [t for t in self._rst_history[key] if cutoff_rst <= t <= now]
                if active:
                    self._rst_history[key] = active
                else:
                    del self._rst_history[key]
            syn_cooldown_cutoff = now - self.ALERT_COOLDOWN_S
            for key, last_alert in list(self._syn_cooldown.items()):
                if last_alert < syn_cooldown_cutoff or last_alert > now:
                    del self._syn_cooldown[key]
            for key, last_alert in list(self._rst_cooldown.items()):
                if last_alert < syn_cooldown_cutoff or last_alert > now:
                    del self._rst_cooldown[key]
            rst_seen_cutoff = now - self.rst_window
            for key, seen_at in list(self._rst_seen.items()):
                if seen_at < rst_seen_cutoff or seen_at > now:
                    del self._rst_seen[key]
            syn_cutoff = now - self.rst_response_grace
            for key, (syn_time, _saw_syn_ack) in list(self._syn_contexts.items()):
                if syn_time < syn_cutoff:
                    del self._syn_contexts[key]

    def check(self, record: dict) -> dict | None:
        if record.get("protocol") != "TCP":
            return None

        src = record.get("src_ip", "")
        dst = record.get("dst_ip", "")
        src_port = _normalize_port(record.get("src_port"))
        dst_port = _normalize_port(record.get("dst_port"))

        if _is_trusted(src):
            return None

        now = _finite_record_timestamp(record, prefer_event_timestamp=False)
        if now is None:
            return None
        try:
            tcp_flags = int(record.get("tcp_flags") or 0)
        except (TypeError, ValueError, OverflowError):
            tcp_flags = 0
        _RST = 0x04
        _SYN = 0x02
        _ACK = 0x10

        is_rst = bool(tcp_flags & _RST) and not bool(tcp_flags & _SYN)
        is_initial_syn = _is_initial_syn(record)

        # Keep bounded handshake context so a target's immediate RST response
        # to a closed-port SYN scan is not mislabeled as an RST flood.
        if is_initial_syn and src and dst and src_port is not None and dst_port is not None:
            flow_key = (src, src_port, dst, dst_port)
            with self._lock:
                self._syn_contexts[flow_key] = (now, False)
                self._syn_contexts.move_to_end(flow_key)
                while len(self._syn_contexts) > self.max_syn_contexts:
                    self._syn_contexts.popitem(last=False)
        elif (tcp_flags & (_SYN | _ACK)) == (_SYN | _ACK) and src and dst \
                and src_port is not None and dst_port is not None:
            # SYN-ACK is in the reverse direction of the initiating SYN.
            flow_key = (dst, dst_port, src, src_port)
            with self._lock:
                context = self._syn_contexts.get(flow_key)
                if context and 0 <= now - context[0] <= self.rst_response_grace:
                    self._syn_contexts[flow_key] = (context[0], True)
                    self._syn_contexts.move_to_end(flow_key)

        # ── RST Flood detection ───────────────────────────────────────────────
        # RSTs from one source to one destination (any port) at high rate.
        # RST floods are used to tear down TCP connections en masse.
        if is_rst and dst:
            if src_port is not None and dst_port is not None:
                # A closed service commonly answers a scan SYN with RST|ACK.
                # Suppress only a matching reverse tuple when no SYN-ACK was
                # observed; established-flow resets remain eligible.
                syn_key = (dst, dst_port, src, src_port)
                with self._lock:
                    syn_context = self._syn_contexts.get(syn_key)
                if syn_context:
                    syn_time, saw_syn_ack = syn_context
                    if (not saw_syn_ack and
                            0 <= now - syn_time <= self.rst_response_grace):
                        return None
                tcp_seq = record.get("tcp_seq")
                tcp_ack = record.get("tcp_ack")
                if tcp_seq is not None or tcp_ack is not None:
                    try:
                        segment_key = (
                            src, src_port, dst, dst_port,
                            int(tcp_seq or 0) & 0xFFFFFFFF,
                            int(tcp_ack or 0) & 0xFFFFFFFF,
                        )
                    except (TypeError, ValueError, OverflowError):
                        segment_key = None  # malformed metadata cannot identify a retransmission
                    if segment_key is not None:
                        with self._lock:
                            seen_at = self._rst_seen.get(segment_key)
                            if seen_at is not None and now >= seen_at \
                                    and now - seen_at <= self.rst_window:
                                return None
                            if seen_at is not None and now < seen_at:
                                return None
                            if seen_at is None and len(self._rst_seen) >= self.max_rst_flows * 32:
                                self._rst_seen.popitem(last=False)
                            self._rst_seen[segment_key] = now
                            self._rst_seen.move_to_end(segment_key)
            rkey = (src, dst)
            with self._lock:
                if rkey not in self._rst_history and len(self._rst_history) >= self.max_rst_flows:
                    evicted = next(iter(self._rst_history))
                    self._rst_history.pop(evicted)
                    self._rst_cooldown.pop(evicted, None)
                rst_hist = self._rst_history.get(rkey, [])
                if not (rst_hist and now < rst_hist[-1]):
                    rst_hist = [t for t in rst_hist if 0 <= now - t <= self.rst_window]
                    rst_hist.append(now)
                    rst_count = len(rst_hist)
                    rst_window_start = rst_hist[0]
                    if rst_count >= self.rst_threshold:
                        rst_hist = rst_hist[-self.rst_threshold:]
                    self._rst_history.pop(rkey, None)
                    self._rst_history[rkey] = rst_hist
                    if rst_count >= self.rst_threshold:
                        last_alert = self._rst_cooldown.get(rkey)
                        if (last_alert is not None
                                and now - last_alert < self.ALERT_COOLDOWN_S):
                            return None
                        if (rkey not in self._rst_cooldown
                                and len(self._rst_cooldown) >= self.max_rst_flows):
                            self._rst_cooldown.pop(next(iter(self._rst_cooldown)))
                        self._rst_cooldown.pop(rkey, None)
                        self._rst_cooldown[rkey] = now
                        logger.debug(f"SYN_FLOOD (RST) fired: {src} → {dst} ({rst_count} RSTs)")
                        return {
                            "rule_name": self.name,
                            "rule_version": self.rule_version,
                            "src_ip": src,
                            "dst_ip": dst,
                            "src_port": record.get("src_port"),
                            "dst_port": dst_port,
                            "protocol": "TCP",
                            "severity": "high",
                            "confidence": "heuristic",
                            "detail": (
                                f"{src} sent {rst_count} RST packets to {dst} "
                                f"in {self.rst_window}s — possible RST flood / connection teardown attack"
                            ),
                            "evidence": {
                                "flood_type": "RST",
                                "rst_count": rst_count,
                                "window_s": self.rst_window,
                                "threshold": self.rst_threshold,
                                "note": "RST flood can exhaust connection tables or disrupt existing sessions.",
                            },
                            "window_start": rst_window_start,
                            "window_end": now,
                        }
            return None  # RST processed — don't also check SYN path

        # ── SYN Flood detection ───────────────────────────────────────────────
        # Only count initial SYN (SYN=1, ACK=0); skip SYN-ACK server responses
        if not _is_initial_syn(record):
            return None

        # SYN floods target services; skip ephemeral dst ports (IANA: 49152-65535)
        if dst_port is not None and dst_port > 49151:
            return None

        key = (src, dst, dst_port)

        with self._lock:
            if key not in self._history and len(self._history) >= self.max_flows:
                evicted = next(iter(self._history))
                self._history.pop(evicted)
                self._syn_cooldown.pop(evicted, None)
            history = self._history.get(key, [])
            if history and now < history[-1]:
                return None  # ignore reordered events; they cannot be in this window
            history = [t for t in history if 0 <= now - t <= self.window]
            history.append(now)
            count = len(history)
            window_start = history[0]
            if count >= self.threshold:
                history = history[-self.threshold:]
            self._history.pop(key, None)
            self._history[key] = history
            if count >= self.threshold:
                last_alert = self._syn_cooldown.get(key)
                if (last_alert is not None
                        and now - last_alert < self.ALERT_COOLDOWN_S):
                    return None
                if (key not in self._syn_cooldown
                        and len(self._syn_cooldown) >= self.max_flows):
                    self._syn_cooldown.pop(next(iter(self._syn_cooldown)))
                self._syn_cooldown.pop(key, None)
                self._syn_cooldown[key] = now
            else:
                return None

        if count >= self.threshold:
            logger.debug(f"SYN_FLOOD fired: {src} → {dst}:{dst_port} ({count} SYNs)")
            return {
                "rule_name": self.name,
                "rule_version": self.rule_version,
                "src_ip": src,
                "dst_ip": dst,
                "src_port": record.get("src_port"),
                "dst_port": dst_port,
                "protocol": record.get("protocol", "TCP"),
                # Confidence is heuristic: we count SYNs but do not verify
                # handshake outcomes or confirmed service impact (§3.3).
                "severity": "high",
                "confidence": "heuristic",
                "detail": (
                    f"{src} sent {count} SYN packets to {dst}:{dst_port} "
                    f"in {self.window}s — possible SYN burst / flood"
                ),
                "evidence": {
                    "flood_type": "SYN",
                    "syn_count": count,
                    "window_s": self.window,
                    "threshold": self.threshold,
                    "note": (
                        "SYN count only; handshake completion "
                        "not tracked in current schema"
                    ),
                },
                "window_start": window_start,
                "window_end": now,
            }
        return None


class DistributedSynFloodRule:
    """Detect high-volume initial-SYN bursts to one service from many sources."""

    name = "DISTRIBUTED_SYN_FLOOD"
    rule_version = "1.7"
    ALERT_COOLDOWN_S = 60.0

    def __init__(self, threshold: int = 500, min_sources: int = 20,
                 window: int = 10, max_targets: int = 2048):
        self.threshold = _positive_setting(
            threshold, 500, "DISTRIBUTED_SYN_FLOOD_THRESHOLD")
        self.min_sources = _positive_setting(
            min_sources, 20, "DISTRIBUTED_SYN_FLOOD_MIN_SOURCES")
        self.window = _positive_setting(window, 10, "TIME_WINDOW")
        self.max_targets = _positive_setting(
            max_targets, 2048, "DISTRIBUTED_SYN_FLOOD_MAX_TARGETS")
        self._lock = threading.RLock()
        # (dst_ip, dst_port) → (last threshold packet times, recent source map).
        # Packet count is exact as a threshold predicate: if the newest
        # `threshold` events fit in the window, the window contains at least
        # that many events; if they do not, no older event can restore it.
        # Keeping the most recently active `min_sources` sources is enough to
        # decide the distinct-source predicate without retaining every packet.
        self._history: dict[tuple, tuple[deque[float], dict[str, float]]] = {}
        self._cooldown: dict[tuple, float] = {}

    def prune_stale(self, now: float):
        cutoff = now - self.window
        with self._lock:
            for key in list(self._history):
                packet_times, sources = self._history[key]
                packet_times = deque(ts for ts in packet_times if cutoff <= ts <= now)
                sources = {src: ts for src, ts in sources.items()
                           if cutoff <= ts <= now}
                if packet_times:
                    self._history.pop(key, None)
                    self._history[key] = (packet_times, sources)
                else:
                    del self._history[key]
            cooldown_cutoff = now - self.ALERT_COOLDOWN_S
            for key, last_alert in list(self._cooldown.items()):
                if last_alert < cooldown_cutoff or last_alert > now:
                    del self._cooldown[key]

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP" or record.get("protocol") != "TCP":
            return None
        if not _is_initial_syn(record):
            return None

        src, dst = record.get("src_ip"), record.get("dst_ip")
        dst_port = _normalize_port(record.get("dst_port"))
        if not src or not dst or dst_port is None or not 1 <= dst_port <= 49151:
            return None
        if _is_trusted(src):
            return None

        now = _finite_record_timestamp(record)
        if now is None:
            return None
        key = (dst, dst_port)
        with self._lock:
            state = self._history.get(key)
            if state is None:
                if len(self._history) >= self.max_targets:
                    evicted = next(iter(self._history))
                    self._history.pop(evicted)
                    self._cooldown.pop(evicted, None)
                packet_times, sources = deque(), {}
            else:
                packet_times, sources = state
            if packet_times and now < packet_times[-1]:
                return None
            packet_times = deque(ts for ts in packet_times
                                 if 0 <= now - ts <= self.window)
            sources = {host: ts for host, ts in sources.items()
                       if 0 <= now - ts <= self.window}
            packet_times.append(now)
            if len(packet_times) > self.threshold:
                packet_times.popleft()
            sources.pop(src, None)
            sources[src] = now
            if len(sources) > self.min_sources:
                sources.pop(next(iter(sources)))
            source_count = len(sources)
            if len(packet_times) < self.threshold or source_count < self.min_sources:
                self._history.pop(key, None)
                self._history[key] = (packet_times, sources)
                return None
            window_start = packet_times[0]
            packet_count = len(packet_times)
            last_alert = self._cooldown.get(key)
            if (last_alert is not None
                    and now - last_alert < self.ALERT_COOLDOWN_S):
                self._history.pop(key, None)
                self._history[key] = (packet_times, sources)
                return None
            self._cooldown[key] = now
            self._history.pop(key, None)
            self._history[key] = (packet_times, sources)

        return {
            "rule_name": self.name,
            "rule_version": self.rule_version,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": record.get("src_port"),
            "dst_port": dst_port,
            "protocol": "TCP",
            "severity": "high",
            "confidence": "heuristic",
            "detail": (
                f"at least {packet_count} initial SYNs from at least {source_count} sources targeted "
                f"{dst}:{dst_port} in {self.window}s — possible distributed SYN flood"
            ),
            "evidence": {
                "syn_count": packet_count,
                "distinct_sources": source_count,
                "counts_are_lower_bounds": True,
                "window_s": self.window,
                "threshold": self.threshold,
                "min_sources": self.min_sources,
                "note": (
                    "Counts are threshold-capped lower bounds; initial SYNs only, "
                    "handshake outcomes are not tracked."
                ),
            },
            "window_start": window_start,
            "window_end": now,
        }


# =============================================================================
# Rule 4: ICMP Echo Sweep Detection
# =============================================================================

class IcmpSweepRule:
    """Detect a source probing distinct IPv4/IPv6 destinations with echo requests."""

    name = "ICMP_SWEEP"
    rule_version = "1.5"

    def __init__(self, threshold: int = 12, window: int = 10,
                 max_sources: int = 4096):
        self.threshold = _positive_setting(threshold, 12, "ICMP_SWEEP_THRESHOLD")
        self.window = _positive_setting(window, 10, "TIME_WINDOW")
        self.max_sources = _positive_setting(
            max_sources, 4096, "ICMP_SWEEP_MAX_SOURCES")
        self._lock = threading.RLock()
        self._history: dict[str, list[tuple[float, str]]] = defaultdict(list)
        self._fired: dict[str, float] = {}

    def prune_stale(self, now: float):
        cutoff = now - self.window
        with self._lock:
            for src in list(self._history):
                active = [(ts, dst) for ts, dst in self._history[src]
                          if cutoff <= ts <= now]
                if active:
                    self._history[src] = active
                else:
                    del self._history[src]
            for src, fired_at in list(self._fired.items()):
                if now - fired_at >= self.window or fired_at > now:
                    del self._fired[src]

    def check(self, record: dict) -> dict | None:
        protocol = record.get("protocol")
        if record.get("type") != "IP" or protocol not in {"ICMP", "ICMPV6"}:
            return None
        expected_type = 128 if protocol == "ICMPV6" else 8
        try:
            raw_type = record.get("icmp_type")
            icmp_type = int(raw_type) if raw_type is not None else None
            raw_code = record.get("icmp_code", 0)
            icmp_code = int(raw_code) if raw_code is not None else 0
        except (TypeError, ValueError, OverflowError):
            return None
        if icmp_type != expected_type or icmp_code != 0:
            return None  # count echo requests, never replies or control messages

        src, dst = record.get("src_ip"), record.get("dst_ip")
        if not src or not dst or src == dst or _is_trusted(src):
            return None

        now = _finite_record_timestamp(record)
        if now is None:
            return None
        with self._lock:
            # PCAPs are expected to be ordered; reject a late/reordered event
            # instead of letting it erase newer window state.
            history = self._history.get(src, [])
            if history and now < max(ts for ts, _ in history):
                return None
            history = [(ts, host) for ts, host in history
                       if 0 <= now - ts <= self.window and host != dst]
            history.append((now, dst))
            self._history.pop(src, None)
            if len(self._history) >= self.max_sources:
                self._history.pop(next(iter(self._history)))
            self._history[src] = history
            targets = sorted({host for _, host in history})
            if len(targets) < self.threshold:
                return None
            last_alert = self._fired.get(src)
            self._history.pop(src, None)
            if last_alert is not None and now - last_alert < self.window:
                return None
            if src not in self._fired and len(self._fired) >= self.max_sources:
                self._fired.pop(next(iter(self._fired)))
            self._fired[src] = now
            window_start = min(ts for ts, _ in history)

        return {
            "rule_name": self.name,
            "rule_version": self.rule_version,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": None,
            "dst_port": None,
            "protocol": protocol,
            "severity": "medium",
            "confidence": "heuristic",
            "detail": (
                f"{src} sent ICMP echo requests to {len(targets)} distinct hosts "
                f"in {self.window}s — possible host-discovery sweep"
            ),
            "evidence": {
                "icmp_type": expected_type,
                "icmp_code": 0,
                "distinct_targets": len(targets),
                "targets": targets[:50],
                "window_s": self.window,
                "threshold": self.threshold,
            },
            "window_start": window_start,
            "window_end": now,
        }


# =============================================================================
# Rule: ICMP Targeted Flood Detection
# =============================================================================

class IcmpFloodRule:
    """
    Detect high-rate ICMP Echo requests (ping flood) directed at a single destination.

    Differentiates between host sweeps (one source probing many hosts, tracked by
    IcmpSweepRule) and targeted ping floods (high volume directed at a single target).

    Supports both IPv4 ICMP Echo Requests (type 8) and IPv6 ICMPv6 Echo Requests (type 128).
    Ignores ICMP Echo Replies (types 0 and 129).
    Stateful cooldown prevents alert storms during an extended flood.
    """

    name = "ICMP_FLOOD"
    rule_version = "1.6"
    ALERT_COOLDOWN_S: float = 60.0

    def __init__(self, threshold: int = 50, window: int = 5,
                 max_flows: int = 4096, cooldown: float = 60.0):
        self.threshold = _positive_setting(
            threshold, 50, "ICMP_FLOOD_THRESHOLD")
        self.window = _positive_setting(window, 5, "ICMP_FLOOD_WINDOW")
        self.max_flows = _positive_setting(max_flows, 4096, "ICMP_FLOOD_MAX_FLOWS")
        self.cooldown = _nonnegative_float_setting(
            cooldown, 60.0, "ICMP_FLOOD_COOLDOWN")
        self._lock = threading.RLock()
        # (src_ip, dst_ip) → list of timestamps
        self._history: dict[tuple, list[float]] = {}
        # (src_ip, dst_ip) → last_alert_time
        self._cooldown: OrderedDict[tuple, float] = OrderedDict()

    def prune_stale(self, now: float):
        cutoff = now - self.window
        cutoff_cd = now - self.cooldown
        with self._lock:
            for key in list(self._history):
                active = [t for t in self._history[key] if cutoff <= t <= now]
                if active:
                    self._history[key] = active
                else:
                    del self._history[key]
            for key in list(self._cooldown):
                if self._cooldown[key] < cutoff_cd:
                    del self._cooldown[key]

    def check(self, record: dict) -> dict | None:
        proto = record.get("protocol", "")
        if proto not in ("ICMP", "ICMPV6"):
            return None

        # Only count Echo Requests: IPv4 type 8, IPv6 type 128
        expected_type = 128 if proto == "ICMPV6" else 8
        try:
            raw_type = record.get("icmp_type")
            icmp_type = int(raw_type) if raw_type is not None else None
            raw_code = record.get("icmp_code", 0)
            icmp_code = int(raw_code) if raw_code is not None else 0
        except (TypeError, ValueError, OverflowError):
            return None
        if icmp_type != expected_type or icmp_code != 0:
            return None

        src = record.get("src_ip", "")
        dst = record.get("dst_ip", "")
        if not src or not dst or _is_trusted(src):
            return None

        now = _finite_record_timestamp(record)
        if now is None:
            return None
        key = (src, dst)

        with self._lock:
            # Check cooldown
            last_alert = self._cooldown.get(key)
            if last_alert is not None and now - last_alert < self.cooldown:
                self._cooldown.move_to_end(key)
                return None

            if key not in self._history and len(self._history) >= self.max_flows:
                self._history.pop(next(iter(self._history)))

            history = self._history.get(key, [])
            if history and now < history[-1]:
                return None  # reject out-of-order timestamps
            history = [t for t in history if 0 <= now - t <= self.window]
            history.append(now)
            self._history.pop(key, None)
            self._history[key] = history

            count = len(history)
            window_start = history[0]

            if count < self.threshold:
                return None

            # Threshold reached: set cooldown and reset history for next burst
            if key not in self._cooldown and len(self._cooldown) >= self.max_flows:
                self._cooldown.popitem(last=False)
            self._cooldown.pop(key, None)
            self._cooldown[key] = now
            self._cooldown.move_to_end(key)
            self._history.pop(key, None)

        logger.debug(f"{self.name} fired: {src}→{dst} ({count} echo requests in {self.window}s)")

        return {
            "rule_name": self.name,
            "rule_version": self.rule_version,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": None,
            "dst_port": None,
            "protocol": proto,
            "severity": "medium",
            "confidence": "heuristic",
            "detail": (
                f"{src} sent {count} ICMP echo requests to {dst} "
                f"in {self.window}s — possible targeted ICMP echo flood "
                "(rate-threshold signal; review source context)"
            ),
            "evidence": {
                "classification": "ICMP_ECHO_RATE_THRESHOLD",
                "icmp_type": expected_type,
                "packet_count": count,
                "target_host": dst,
                "window_s": self.window,
                "threshold": self.threshold,
                "note": "High rate of ICMP echo requests to a single destination can exhaust bandwidth or stack processing capacity.",
            },
            "window_start": window_start,
            "window_end": now,
        }


# Rule 5: ARP Spoofing Detection
# =============================================================================
class ArpSpoofRule:
    name = "ARP_SPOOF"
    rule_version = "1.6"

    # Per-IP cooldown: once an alert fires for a given IP, suppress repeats
    # for this many seconds to avoid alert storms. Set to 0 to disable.
    ALERT_COOLDOWN_S: float = 120.0

    def __init__(self, table_path: str, max_entries: int = 65_536,
                 max_cooldowns: int = 10_000):
        self.table_path = table_path
        self.max_entries = _positive_setting(
            max_entries, 65_536, "ARP_MAX_ENTRIES")
        self.max_cooldowns = _positive_setting(
            max_cooldowns, 10_000, "ARP_MAX_COOLDOWNS")
        self._lock = threading.RLock()
        self._table: dict[str, str] = {}    # ip → mac
        self._cooldown: dict[str, float] = {}  # ip → last_alert_time
        self._dirty = False
        self._load()

        import atexit
        self._saver_thread = threading.Thread(
            target=self._periodic_save, daemon=True
        )
        self._saver_thread.start()
        atexit.register(self.flush)

    def flush(self):
        """Force write to disk if dirty."""
        with self._lock:
            if self._dirty:
                self._save()
                self._dirty = False

    def _periodic_save(self):
        while True:
            time.sleep(60)
            self.flush()

    def _load(self):
        try:
            with open(self.table_path) as f:
                loaded = json.load(f)
            if not isinstance(loaded, dict):
                raise ValueError("ARP table must be a JSON object")
            cleaned = {}
            for ip, mac in loaded.items():
                normalized = self._normalize_observation(ip, mac)
                if normalized:
                    cleaned[normalized[0]] = normalized[1]
            if len(cleaned) > self.max_entries:
                cleaned = dict(list(cleaned.items())[-self.max_entries:])
            with self._lock:
                self._table = cleaned
                self._dirty = cleaned != loaded
            logger.info(f"ARP table loaded: {len(self._table)} entries")
        except FileNotFoundError:
            logger.info("No ARP table found — starting fresh")
            self._table = {}
        except (OSError, ValueError, TypeError) as exc:
            logger.warning(f"Could not read ARP table '{self.table_path}': {exc}")
            self._table = {}

    @staticmethod
    def _normalize_observation(ip: str, mac: str) -> tuple[str, str] | None:
        """Accept only usable IPv4-to-unicast-MAC ARP identity claims."""
        try:
            address = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            return None
        if (address.version != 4 or address.is_unspecified
                or address.is_multicast or int(address) == 0xFFFFFFFF):
            return None
        if not isinstance(mac, str):
            return None
        parts = mac.replace("-", ":").split(":")
        if (len(parts) != 6
                or any(re.fullmatch(r"[0-9a-fA-F]{2}", part) is None for part in parts)):
            return None
        try:
            raw_mac = bytes(int(part, 16) for part in parts)
        except ValueError:
            return None
        if raw_mac[0] & 1 or not any(raw_mac):
            return None  # multicast/broadcast and all-zero source MACs are invalid
        canonical_mac = ":".join(f"{octet:02x}" for octet in raw_mac)
        return str(address), canonical_mac

    def _save(self):
        # os.path.dirname returns '' for bare filenames (e.g. 'arp_table.json');
        # makedirs('') would raise an error on some platforms.
        d = os.path.dirname(self.table_path) or "."
        os.makedirs(d, exist_ok=True)
        tmp = self.table_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self._table, f, indent=2)
        os.replace(tmp, self.table_path)

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "ARP":
            return None

        normalized = self._normalize_observation(
            record.get("src_ip"), record.get("src_mac")
        )
        if normalized is None:
            return None
        ip, mac = normalized

        with self._lock:
            known_mac = self._table.get(ip)
            if known_mac is None:
                if len(self._table) >= self.max_entries:
                    return None  # preserve learned mappings instead of evicting them
                self._table[ip] = mac
                self._dirty = True
                return None

            if known_mac != mac:
                try:
                    now_t = float(record.get("timestamp", time.time()))
                except (TypeError, ValueError, OverflowError):
                    now_t = time.time()
                if not math.isfinite(now_t):
                    now_t = time.time()
                if ip in self._cooldown:
                    if now_t - self._cooldown[ip] < self.ALERT_COOLDOWN_S:
                        return None  # suppress — already alerted recently
                if len(self._cooldown) >= self.max_cooldowns:
                    cutoff = now_t - self.ALERT_COOLDOWN_S
                    self._cooldown = {
                        key: ts for key, ts in self._cooldown.items() if ts > cutoff
                    }
                    if len(self._cooldown) >= self.max_cooldowns:
                        self._cooldown.pop(next(iter(self._cooldown)))
                self._cooldown[ip] = now_t

                logger.debug(f"ARP_SPOOF fired: {ip} was {known_mac}, now {mac}")
                return {
                    "rule_name": self.name,
                    "rule_version": self.rule_version,
                    "src_ip": ip,
                    "dst_ip": record.get("dst_ip"),
                    "src_port": None,
                    "dst_port": None,
                    "protocol": "ARP",
                    "severity": "medium",
                    "confidence": "heuristic",
                    "detail": (
                        f"IP {ip} changed its observed MAC from {known_mac} "
                        f"to {mac} — possible ARP spoofing or a legitimate host change"
                    ),
                    "evidence": {
                        "classification": "ARP_IDENTITY_CHANGE",
                        "ip": ip,
                        "previous_mac": known_mac,
                        "new_mac": mac,
                        "cooldown_s": self.ALERT_COOLDOWN_S,
                    },
                    "window_start": None,
                    "window_end": None,
                }
        return None


# =============================================================================
# Rule 5: Deep Packet Inspection (DPI) — Payload Signature Matching  (§3.4)
# =============================================================================

# Signatures: (label, compiled_regex, confidence_note)
_PAYLOAD_SIGNATURES: list[tuple[str, re.Pattern, str]] = [
    # SQL Injection — extended with Suricata ET SQL signatures and timing/file attacks
    # Covers UNION/SELECT, time-based blind (SLEEP/BENCHMARK/WAITFOR), stacked queries,
    # file read/write (LOAD_FILE/INTO OUTFILE), quote-based OR bypass, and xp_cmdshell.
    (
        "SQL_INJECTION",
        re.compile(
            rb"(?i)(union\s+(?:all\s+)?select|select\s+(?:\*|null|@@version|user\s*\()|drop\s+table|drop\s+database"
            rb"|insert\s+into|update\s+\w+\s+set"
            rb"|or\s+[\x27\x22]?\s*[\w]+\s*=\s*[\x27\x22]?\s*[\w]"
            rb"|or\s+1\s*=\s*1|or\s+\x27\w+\x27\s*=\s*\x27\w+\x27"
            # A bounded sample may start or end inside a binary/application
            # value. Only accept a MySQL comment after a SQL-like value or
            # whitespace; exclude assignment values such as `bgColor=#` and
            # punctuation in binary data while retaining line-ending comments.
            rb"|--.{0,2}(?:\r?\n|$)|(?:(?<=[\w'\")\]])|(?<=\s))#[ \t]*(?:\r?\n|$)"
            rb"|sleep\s*\(\s*\d+|benchmark\s*\(\s*\d+|waitfor\s+delay\s+\x27"
            rb"|exec\s+(?:xp_cmdshell|sp_executesql)|xp_cmdshell"
            rb"|load_file\s*\(|into\s+(?:outfile|dumpfile)\s+[\x27\x22]"
            rb"|cast\s*\(.*?as\s+(?:char|varchar)|convert\s*\(.*?using"
            rb"|information_schema|sys\.tables|pg_sleep)",
            re.MULTILINE,
        ),
        "heuristic",
    ),
    # XSS — extended with Suricata ET WEB_CLIENT bypass vectors
    # Covers inline script, javascript: URI, event handlers, DOM sinks,
    # SVG/img/iframe/body/input tag injection (common WAF bypass vectors).
    (
        "XSS",
        re.compile(
            rb"(?i)(<script[\s>]|javascript:\s*(?:void|alert|eval|document)|onerror\s*=|onload\s*="
            rb"|alert\s*\(|document\.cookie"
            rb"|document\.write\s*\([^)]{0,200}(?:location(?:\.[\w]+|\[[^\]]+\])"
            rb"|document\.URL|window\.name|decodeURIComponent|unescape|atob)"
            rb"|<svg(?:\s[^>]*)?\s+on\w+\s*=|<svg/on\w+="
            rb"|<img[^>]+src\s*=\s*[\x27\x22]?x[\x27\x22]?[^>]+onerror\s*="
            rb"|<iframe[^>]+src\s*=\s*[\x27\x22]?javascript:"
            rb"|<body[^>]+on(?:load|error|focus|blur)\s*="
            rb"|<input[^>]+on(?:focus|blur|change|keyup)\s*="
            rb"|<object[^>]+data\s*=\s*[\x27\x22]?javascript:"
            rb"|<details[^>]+on(?:toggle)\s*="
            rb"|expression\s*\([^)]{0,100}\))"
        ),
        "heuristic",
    ),
    # Plaintext credential leak — tightened bearer token minimum length to reduce
    # false positives on short benign tokens; added X-API-Key, private_key, client_secret.
    # Suricata ET POLICY uses similar length anchors for credential patterns.
    (
        "CREDENTIAL_LEAK",
        re.compile(
            rb"(?i)(password=(?!\*{3,})[^&\r\n]{1,128}|passwd=(?!\*{3,})[^&\r\n]{1,64}"
            rb"|\bpwd=[^&\r\n]{4,64}|client_secret=[^&\r\n]{8,}"
            rb"|private_key=[^&\r\n]{16,}|api_key=[^&\r\n]{16,}|secret=[^&\r\n]{16,}"
            rb"|X-API-Key:\s*[A-Za-z0-9\-._~+/]{16,}"
            rb"|Authorization:\s*Basic\s+[A-Za-z0-9+/=]{12,}"
            rb"|Bearer\s+[A-Za-z0-9\-._~+/]{24,}=*)"
        ),
        "heuristic",
    ),
    # Shell / command injection payloads — extended with interpreter one-liners
    # and common privilege escalation patterns (Suricata ET EXPLOIT).
    (
        "CMD_INJECTION",
        re.compile(
            rb"(?i)(/bin/sh|/bin/bash|/etc/passwd|/etc/shadow|cmd\.exe|powershell\.exe"
            # A bare command-substitution delimiter is common in quoted mail,
            # logs and templates. Require a recognizable command inside it so
            # arbitrary delimited prose does not become a shell alert.
            rb"|\$\(\s*(?:/(?:[\w.-]+/)*[\w.-]+|(?:id|whoami|uname|cat|curl|wget|nc|netcat|bash|sh|cmd|powershell|python\d?|perl|ruby|node|php|chmod|chown|sudo|touch|rm|echo|sleep|ping)\b)[^)]{0,100}\)"
            rb"|`\s*(?:/(?:[\w.-]+/)*[\w.-]+|(?:id|whoami|uname|cat|curl|wget|nc|netcat|bash|sh|cmd|powershell|python\d?|perl|ruby|node|php|chmod|chown|sudo|touch|rm|echo|sleep|ping)\b)[^`]{0,100}`"
            # Reverse-shell patterns
            rb"|bash\s+-i\s+>&\s*/dev/tcp/|/dev/tcp/"
            rb"|nc\s+-(?:e|c)\s+/bin"
            # Interpreter one-liner code execution (python, perl, ruby, node, php)
            rb"|python\d?\s+-c\s+[\x27\x22]"
            rb"|perl\s+-e\s+[\x27\x22]"
            rb"|ruby\s+-e\s+[\x27\x22]"
            rb"|node\s+-e\s+[\x27\x22]"
            rb"|php\s+-r\s+[\x27\x22]"
            # Privilege escalation / living off the land
            rb"|chmod\s+[0-7]{3,4}\s+/(?:bin|tmp|usr|etc)/"
            rb"|chown\s+root"
            rb"|sudo\s+-l\b"
            rb"|/usr/bin/python3?\s+-c)",
        ),
        "heuristic",
    ),
    # Path traversal — extended with double-encoding, overlong UTF-8, Windows paths,
    # and bypass variants seen in Suricata ET WEB_SERVER path traversal rules.
    (
        "PATH_TRAVERSAL",
        re.compile(
            rb"(?i)(\.\.[\\/]\.\.[\\/]|\.\.%2[fF]|%2[eE]%2[eE]%2[fF]"
            # NOTE: %252e%252e (double URL-encoded) handled by multi-pass URL decoder
            # URL-encoded backslash traversal: ..%5c..%5c (Windows)
            rb"|\.\.%5[cC]|%2[eE]%2[eE]%5[cC]"
            # Overlong UTF-8 encoding: %c0%ae = '.', %c1%9c = '\'
            rb"|%c0%[aA][eE]%c0%[aA][eE]|%c1%9[cC]"
            # Fullwidth slash bypass: \uFF0F (HTML entity / URL %ef%bc%8f)
            rb"|%[eE][fF]%[bB][cC]%8[fF]"
            # Nginx/Tomcat specific: /..;/ bypass
            rb"|/\.\.;/"
            # Classic targets
            rb"|/etc/passwd|/etc/shadow|/etc/hosts|/proc/self"
            # Windows system targets
            rb"|win\.ini|boot\.ini|system\.ini"
            rb"|/windows/system32|c(?::|%3[aA])[\\/]windows[\\/]"
            rb"|c(?::|%3[aA])[\\/](?:boot\.ini|win\.ini|inetpub))",
            re.MULTILINE,
        ),
        "heuristic",
    ),
    # Server-Side Request Forgery — extended with cloud metadata IPs, IPv6 internal
    # addresses, and additional dangerous schemes (Suricata ET SCAN / ET WEB_SERVER).
    # Covers AWS (169.254.169.254), GCP (metadata.google), Azure (169.254.169.254),
    # Alibaba Cloud (100.100.100.200), and IPv6 loopback/link-local/ULA ranges.
    (
        "SSRF",
        re.compile(
            # Non-HTTP schemes are SSRF candidates when supplied as a
            # server-side fetch/URL value. A literal file:// in SMTP content,
            # documentation or a message body is not enough to establish SSRF.
            rb"(?i)(?:(?:\b(?:url|uri|dest|target|callback|webhook|proxy|redirect|fetch|path)\s*[:=]\s*|[?&][\w.-]{1,32}=)"
            rb"(?:file|dict|gopher|sftp|tftp|ldap|ldaps)://"
            rb"|ftp://127\.|ftp://0\."
            rb"|http://127\.|http://0\.0\.0\.0|http://0:"
            rb"|http://169\.254\.169\.254|http://metadata\.google"
            rb"|http://100\.100\.100\.200"
            rb"|http://\[::1\]|http://\[0::|http://\[::ffff:"
            rb"|http://\[fe80:|http://\[fc|http://\[fd"
            rb"|url=(?:file|dict|gopher|ldap|ftp|http)://(?:127|0|169\.254|10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.))"
        ),
        "heuristic",
    ),
    # Log4Shell / Log4j JNDI injection — extended with obfuscated nested lookup variants
    # as documented in CVE-2021-44228 bypasses (lower/upper/:-: nesting).
    # Suricata ET EXPLOIT rules cover these specific obfuscation chains.
    (
        "LOG4SHELL",
        re.compile(
            rb"(?i)(\$\{jndi:"
            rb"|\$\{\$\{lower:j\}|\$\{\$\{upper:j\}"
            rb"|\$\{\$\{::-j\}\$\{::-n\}\$\{::-d\}\$\{::-i\}:"
            rb"|j\$\{::-n\}di:|j\$\{lower:n\}di:|\$\{j\$\{:\:-n\}di:"
            rb"|\$\{\$\{env:NaN}:|-j\}ndi:|\$\{jn\$\{\w*:\}di:"
            rb"|\$\{j\$\{lower:nd\}i:|\$\{::-j\}\$\{::-n\}\$\{::-d\})"
        ),
        "high",
    ),
    # XML External Entity (XXE) injection
    (
        "XXE",
        re.compile(
            rb"(?is)(?:<!ENTITY\s+%?[\w:.-]+\s+(?:SYSTEM|PUBLIC)\s+['\"]"
            rb"|<!DOCTYPE\s+[\w:.-]+\s*\[[\s\S]{0,512}?"
            rb"<!ENTITY\s+%?[\w:.-]+\s+(?:SYSTEM|PUBLIC)\s+['\"]"
            rb"|<!DOCTYPE\s+[\w:.-]+\s+SYSTEM\s+['\"]"
            rb"(?:file|ftp|gopher|dict|jar|netdoc|expect|php):[^'\"]+['\"]"
            rb"|<!DOCTYPE\s+[\w:.-]+\s+PUBLIC\s+['\"][^'\"]+['\"]\s+['\"]"
            rb"(?:file|ftp|gopher|dict|jar|netdoc|expect|php):[^'\"]+['\"]"
            rb"|<!DOCTYPE\s+[\w:.-]+\s+SYSTEM\s+['\"]"
            rb"https?://(?!(?:www\.)?w3\.org/TR/)[^'\"]+['\"]"
            rb"|<!DOCTYPE\s+[\w:.-]+\s+PUBLIC\s+['\"][^'\"]+['\"]\s+['\"]"
            rb"https?://(?!(?:www\.)?w3\.org/TR/)[^'\"]+['\"])"
        ),
        "high",
    ),
    # Server-Side Template Injection (SSTI) — tightened to require dangerous expression
    # indicators inside the template delimiters, reducing false positives from legitimate
    # ${PORT}, ${variable} shell environment substitution in POST bodies and config payloads.
    # Suricata ET WEB_SERVER SSTI rules anchor on class/config/process access patterns.
    # Matches:
    #   {{ __class__|config|request|self }} — Jinja2 object access (introspection)
    #   {{ 7*7 }} / {{ 7**7 }}             — arithmetic probe (canary detection)
    #   {% import os %} / {% for %}         — Jinja2 code execution blocks
    #   ${Runtime.exec('id')}              — Spring/Groovy EL RCE (CVE-2022-22963)
    #   ${"fr"+"eemarker"?...}             — Freemarker string built-ins or ?new()
    #   #{T(java.lang.Runtime)}            — Thymeleaf Spring EL RCE
    (
        "SSTI",
        re.compile(
            # Jinja2/Twig: {{ with object introspection or arithmetic operator
            rb"(?s)(\{\{[^{}]{0,120}(?:__class__|__mro__|__subclasses__|config|request\.)"
            rb"|\{\{\s*[0-9]+\s*[*+\-/]\s*[0-9]+\s*\}\}"
            # Jinja2 block: {% import|from|set|for|if — only code-exec blocks
            rb"|\{%[-\s]*(?:import|from|set\s+\w|for\s+\w|if\s+[^%]{0,80}%\})"
            # Spring/Thymeleaf EL: #{T( — Runtime access
            rb"|#\{T\s*\(\s*java\.lang"
            # Spring/Groovy/Freemarker ${...}: dangerous method calls
            # Catches: ${Runtime.exec(...)}, ${\"a\".class.forName(...)},
            # ${\"a\"?new()}, Freemarker ?eval, ProcessBuilder invocations
            rb"|\$\{[^}]{0,120}(?:Runtime\.exec|ProcessBuilder|getRuntime|\?new\(|\?eval|execute\s*\(|class\.forName))"
        ),
        "heuristic",
    ),
    # Shellshock (CVE-2014-6271 / 6278) — bash function export header
    (
        "SHELLSHOCK",
        re.compile(
            rb"\(\s*\)\s*\{\s*[^}]*;\s*\}\s*;|\(\s*\)\s*\{\s*[^}]+\}\s*;",
        ),
        "high",
    ),
    # Java/Python deserialization gadget markers
    (
        "DESERIALIZATION",
        re.compile(
            rb"(?s)(\xac\xed\x00\x05|rO0AB|O:8:\"stdClass\"|a:\d+:\{|"
            rb"java\.lang\.Runtime|ProcessBuilder|java\.io\.ObjectInputStream|"
            rb"pickle\.loads|__reduce__|__class__\.mro|"
            # Spring4Shell (CVE-2022-22965): class.module.classLoader gadget
            rb"class\.module\.classLoader|class\.classLoader\.urls|"
            # Commons Collections / ysoserial gadget chain markers
            rb"CommonsCollections\d|org\.apache\.commons\.collections\.Transformer|"
            rb"InvokerTransformer|ConstantTransformer|ChainedTransformer|"
            # ysoserial well-known JNDI/RMI gadget types
            rb"URLDNS|JRMPClient|Groovy[123]|Spring[12]|Hibernate[12]|"
            # Kryo / Java serialization wrappers seen in middleware exploits
            rb"com\.esotericsoftware\.kryo|SnakeYaml.*!!|"
            # PHP Magento/Laravel gadget deserialization
            rb"O:\d+:\"(?:Illuminate|Magento|Symfony|Laravel)|"
            # Python: arbitrary pickle execution
            rb"cposix\ngetenv|cos\nsystem|csubprocess)"
        ),
        "high",
    ),
    # HTTP Response Splitting / Header Injection — CRLF injection and header spoofing.
    # Suricata ET WEB rules: ET WEB_CLIENT 2000071 (CRLF injection) etc.
    # NOTE: Patterns are chained with explicit | inside a single group to avoid
    # the double-pipe (||) empty-match bug from string concatenation.
    (
        "HEADER_INJECTION",
        re.compile(
            # A raw CRLF must occur inside an HTTP request target before an
            # injected security-sensitive header.  Matching every ordinary
            # CRLF-prefixed Content-Type line incorrectly flags normal JSON
            # and form requests.
            rb"(?im)(?:^[A-Z]{3,10}\s+\S*[?&][^=\s\r\n]+=[^\s\r\n]*\r\n[ \t]*(?:Set-Cookie|Location|Content-Type):\s*"
            # URL-encoded CRLF injection (%0d%0a) — common bypass
            rb"|%0[dD]%0[aA][ \t]*[\w-]+:"
            # Host header SSRF: attacker sends request with internal IP as Host
            # to exploit reverse-proxy misconfiguration (no ^anchor issue in MULTILINE)
            rb"|^Host:[ \t]*(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|\[(?:::1?|0::|fe80:[0-9a-fA-F:]*|f[cd][0-9a-fA-F]{2}:[0-9a-fA-F:]*)\])"
            # X-Forwarded-For spoofing to loopback / metadata IPs for auth bypass
            rb"|X-Forwarded-For:[ \t]*(?:127\.0\.0\.1|::1|169\.254\.169\.254|0\.0\.0\.0)"
            # X-Original-URL / X-Rewrite-URL path override (nginx/Squid WAF bypass)
            rb"|X-(?:Original|Rewrite)-URL:[ \t]*/(?:admin|etc|proc|windows|system32)[^\r\n]{0,100})",
            re.MULTILINE,
        ),
        "heuristic",
    ),
    # Automated web reconnaissance / vulnerability scanner probe — extended with
    # zgrab (internet scanner), ZmEu (legacy PHP scanner), and automated headless
    # client patterns common in CTF enumeration (Suricata ET SCAN rules).
    (
        "SCANNER_PROBE",
        re.compile(
            rb"(?i)(User-Agent:\s*[^\r\n]*\b(sqlmap|nikto|gobuster|dirbuster|dirsearch|wfuzz|ffuf|nuclei|masscan|wpscan|acunetix|nessus|openvas|arachni|zgrab|zmeu|hydra|medusa|burpsuite|havij|pangolin)\b"
            rb"|Mozilla/5\.00\s*\(Nikto|nmap\s+scripting\s+engine"
            rb"|User-Agent:\s*ZmEu|User-Agent:\s*\w+/\d+\.\d+\s+zgrab"
            rb"|X-Scanner:|X-Scan-Memo:)"
        ),
        "high",
    ),
    # Sensitive configuration, credential, or VCS repository file probe — extended
    # with .htpasswd/.htaccess, phpinfo.php, /proc/self/environ, .DS_Store,
    # /crossdomain.xml, /server-status (Suricata ET WEB_SERVER rules).
    (
        "SENSITIVE_FILE_PROBE",
        re.compile(
            rb"(?i)(GET|POST|HEAD|OPTIONS)\s+[^\r\n]*?(?:/|\b)"
            rb"(\.env(\.[\w-]+)?|\.git/(config|HEAD|COMMIT_EDITMSG)|\.svn/(?:entries|wc\.db)"
            rb"|id_rsa|id_ed25519|id_dsa|\.ssh/known_hosts|\.ssh/authorized_keys"
            rb"|\.aws/(credentials|config)|\.gcloud/credentials\.db"
            rb"|wp-config\.php|configuration\.php|config\.php|settings\.php"
            rb"|web\.config|appsettings\.json|application\.properties|application\.yaml"
            rb"|\.htpasswd|\.htaccess"
            rb"|phpinfo\.php"
            rb"|/proc/self/environ|/proc/self/cmdline"
            rb"|\.DS_Store|crossdomain\.xml|clientaccesspolicy\.xml"
            rb"|/server-status|/server-info"
            rb"|backup\.(sql|zip|tar\.gz|tgz|gz)|dump\.sql|db\.sql)\b"
        ),
        "high",
    ),
    # Remote download cradle or interactive socket redirection — extended with
    # socat reverse shell (very common alternative to netcat) and improved
    # PowerShell base64-encoded command execution patterns.
    (
        "REVERSE_SHELL_CRADLE",
        re.compile(
            rb"(?i)(curl\s+[^\r\n|]+?\|\s*(ba)?sh|wget\s+[^\r\n|]+?\|\s*(ba)?sh|"
            rb"powershell(\.exe)?\s+-(?:enc(?:oded(?:command)?)?|nop|w(?:indow)?\s+h(?:idden)?|downloadstring|iex)|"
            rb"iex\s*\(\s*(new-object\s+net\.webclient|iwr|invoke-webrequest)|"
            rb"0<&196;exec\s*196<>/dev/tcp/|mkfifo\s+/tmp/[\w.-]+;\s*cat\s+/tmp/|"
            # socat reverse shell: socat TCP:attacker:4444 EXEC:/bin/bash
            rb"socat\s+(?:tcp(?:4|6)?|ssl):[\w.\[\]:-]+:\d+\s+exec:|socat\s+[^;\r\n]{0,80}exec:/bin(?:/ba)?sh|"
            # Python/PHP socket cradles
            rb"import\s+socket\s*,\s*(?:os|subprocess)|fsockopen\s*\([^)]{0,80}(?:exec|shell_exec)\s*\()"
        ),
        "high",
    ),
    # HTTP Method Tampering, Cross-Site Tracing (XST), and WebDAV method probing
    (
        "HTTP_METHOD_TAMPERING",
        re.compile(
            rb"(?i)(?:^|\r\n)\s*(TRACE|TRACK|DEBUG|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|SEARCH)\s+/[^\r\n]*\s+HTTP/[0-9.]+|Translate:\s*f\b"
            # CONNECT to internal IPs (proxy abuse for internal SSRF tunneling)
            rb"|(?:^|\r\n)\s*CONNECT\s+(?:localhost|127\.0\.0\.1|192\.168\.|10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.)"
            # DELETE/PATCH on management paths.  Generic REST user endpoints
            # are common application traffic and do not by themselves imply
            # method tampering.
            rb"|(?:^|\r\n)\s*(?:DELETE|PATCH)\s+/(?:admin|api/(?:v[0-9]+/)?(?:admin|config)|config|actuator|manage)(?=[/?\s])[^\r\n]*\s+HTTP/",
        ),
        "high",
    ),
    # Malicious web shell upload / code execution injection markers —
    # extended with JSP scriptlet execution, Python os.popen/subprocess, and
    # ASP Server.CreateObject patterns (Suricata ET WEB_SERVER webshell rules).
    (
        "WEBSHELL_INJECTION",
        re.compile(
            rb"(?i)(<\?php\s+(eval|assert|system|passthru|shell_exec|exec|popen)\b|"
            rb"\b(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_POST|\$_GET|\$_REQUEST|\$_COOKIE)\b|"
            rb"\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\b|"
            rb"\bpreg_replace\s*\(\s*['\"]/.*?/e['\"]\s*,|"
            rb"\bRuntime\.getRuntime\(\)\.exec\s*\(|"
            # JSP scriptlet code execution
            rb"<%[=@]?\s*(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder|request\.getParameter)|"
            # Python web shell markers: os.popen, subprocess.call with user input
            rb"(?:os\.popen|os\.system|subprocess\.(?:call|Popen|check_output))\s*\(\s*(?:request|\$|_GET|_POST)|"
            # ASP classic web shell: Server.CreateObject("WScript.Shell")
            rb"Server\.CreateObject\s*\(\s*[\x27\x22](?:WScript\.Shell|Scripting\.FileSystemObject)|"
            # Generic base64-encoded cmd execution markers
            rb"(?:fromCharCode|atob)\s*\([^)]{10,}\)\s*\))"
        ),
        "high",
    ),
]

# Only inspect unencrypted application protocols (TLS payload is ciphertext).
# Extended with common exploitation targets from Suricata ET EXPLOIT rules:
#   9000  — PHP-FPM / Phalcon / SonarQube (direct RCE exposure)
#   4848  — GlassFish Admin Console (CVE-2011-0807)
#   8161  — Apache ActiveMQ Web Console (CVE-2023-46604)
#   61616 — ActiveMQ JMX / OpenWire (deserialization RCE)
#   2375  — Docker daemon unprotected API
#   6443  — Kubernetes API server (unencrypted fallback)
#   9090  — Prometheus/Cockpit admin
_DPI_PORTS: set[int] = {
    80, 8080,       # HTTP
    21, 23,         # FTP, Telnet
    25, 587,        # SMTP
    110, 143,       # POP3, IMAP
    3000, 5000, 8000, 8888,   # Common dev/app servers
    3306, 5432,     # MySQL, PostgreSQL
    6379,           # Redis
    27017,          # MongoDB
    9200,           # Elasticsearch
    9000,           # PHP-FPM / SonarQube
    4848,           # GlassFish Admin Console
    8161,           # Apache ActiveMQ Web Console
    61616,          # ActiveMQ OpenWire (deserialization RCE)
    2375,           # Docker daemon API (unprotected)
    6443,           # Kubernetes API
    9090,           # Prometheus / Cockpit
    7547,           # TR-069 (CPE WAN management — Mirai target)
    8291,           # Winbox (MikroTik — routerOS exploits)
}


def _multi_unquote(data: bytes, max_passes: int = 3) -> bytes:
    """Iteratively percent-decode *data* up to *max_passes* times or until fixed point."""
    current = data
    for _ in range(max_passes):
        if b"%" not in current:
            break
        try:
            next_decoded = unquote_to_bytes(current)
        except Exception:
            break
        if next_decoded == current:
            break
        current = next_decoded
    return current


class PayloadRule:
    name = "PAYLOAD_HIT"
    rule_version = "1.19"

    def __init__(self, max_bytes: int = 512, enabled: bool = True,
                 stream_timeout: int = 30, max_streams: int = 2048,
                 alert_cooldown: float = 60.0):
        self.max_bytes = _positive_setting(max_bytes, 512, "PAYLOAD_MAX_BYTES")
        self.enabled   = enabled
        self.stream_timeout = _positive_setting(
            stream_timeout, 30, "PAYLOAD_STREAM_TIMEOUT")
        self.max_streams = _positive_setting(
            max_streams, 2048, "PAYLOAD_MAX_STREAMS")
        self.alert_cooldown = _nonnegative_float_setting(
            alert_cooldown, 60.0, "PAYLOAD_ALERT_COOLDOWN_S")
        self._stream_lock = threading.RLock()
        # Directional 4-tuples keep client requests and server responses apart.
        # Each value is (next expected sequence, bounded bytes, last event time,
        # queued out-of-order segments, and initial SYN sequence when observed).
        self._streams: dict[tuple, tuple[int, bytes, float, dict[int, bytes], int | None]] = {}
        # STARTTLS can switch an otherwise cleartext SMTP/IMAP flow to TLS on
        # the same service port. Remember that transition so ciphertext and
        # certificate bytes never enter the payload signatures.
        self._tls_flows: OrderedDict[tuple, float] = OrderedDict()
        # Per directional TCP flow and signature, suppress duplicate packet
        # matches while allowing a newly observed signature to alert at once.
        self._alerted: OrderedDict[tuple, float] = OrderedDict()
        self._max_alert_states = max(1024, self.max_streams * 32)

    def prune_stale(self, now: float):
        cutoff = now - self.stream_timeout
        with self._stream_lock:
            for key in list(self._streams):
                if self._streams[key][2] < cutoff or self._streams[key][2] > now:
                    del self._streams[key]
            for key, last_seen in list(self._tls_flows.items()):
                if last_seen < cutoff or last_seen > now:
                    del self._tls_flows[key]
            alert_cutoff = now - self.alert_cooldown
            for key in list(self._alerted):
                if self._alerted[key] < alert_cutoff:
                    del self._alerted[key]

    @staticmethod
    def _tls_flow_key(record: dict) -> tuple | None:
        src, dst = record.get("src_ip"), record.get("dst_ip")
        src_port, dst_port = record.get("src_port"), record.get("dst_port")
        if not src or not dst or src_port is None or dst_port is None:
            return None
        try:
            endpoints = sorted(((src, int(src_port)), (dst, int(dst_port))))
        except (TypeError, ValueError, OverflowError):
            return None
        return endpoints[0], endpoints[1]

    @staticmethod
    def _looks_like_tls_record(payload: bytes) -> bool:
        """Recognize a TLS record header without treating arbitrary binary as TLS."""
        if len(payload) < 5 or payload[0] not in (0x14, 0x15, 0x16, 0x17):
            return False
        if payload[1] != 0x03 or payload[2] > 0x04:
            return False
        record_len = int.from_bytes(payload[3:5], "big")
        return 0 < record_len <= 18_432

    def _update_stream(self, record: dict, payload: bytes) -> bytes | None:
        """Return a bounded contiguous TCP sample, resetting across sequence gaps."""
        if record.get("protocol") != "TCP":
            return None
        seq = record.get("tcp_payload_seq")
        if seq is None:
            return None
        src, dst = record.get("src_ip"), record.get("dst_ip")
        sport, dport = record.get("src_port"), record.get("dst_port")
        if not src or not dst or sport is None or dport is None:
            return None
        now = _finite_record_timestamp(record)
        if now is None:
            return None
        key = (src, sport, dst, dport)
        try:
            seq = int(seq) & 0xFFFFFFFF
        except (TypeError, ValueError, OverflowError):
            # Stream reconstruction is unavailable without a valid sequence
            # number; check() still inspects this packet's payload directly.
            return None
        try:
            flags = int(record.get("tcp_flags") or 0)
        except (TypeError, ValueError, OverflowError):
            flags = 0
        is_initial_syn = bool(record.get("initial_syn")) or bool(
            flags & 0x02 and not flags & 0x10
        )
        syn_seq = None
        if is_initial_syn:
            try:
                syn_seq = int(record.get("tcp_seq")) & 0xFFFFFFFF
            except (TypeError, ValueError, OverflowError):
                # tcp_payload_seq is ISN+1 for a SYN, so it still identifies
                # the connection if the separate TCP sequence field is absent.
                syn_seq = (seq - 1) & 0xFFFFFFFF

        with self._stream_lock:
            state = self._streams.get(key)
            if state is None or now - state[2] > self.stream_timeout:
                if key not in self._streams and len(self._streams) >= self.max_streams:
                    self._streams.pop(next(iter(self._streams)))
                next_seq = (seq + len(payload)) & 0xFFFFFFFF
                sample = payload[-self.max_bytes:]
                pending: dict[int, bytes] = {}
                initial_seq = syn_seq if is_initial_syn else None
            else:
                expected, previous, last_seen, pending, initial_seq = state
                if now < last_seen:
                    return None  # late segments cannot alter the contiguous stream
                if is_initial_syn and syn_seq != initial_seq:
                    # A new SYN starts a new sequence space even if the 4-tuple
                    # is reused and the new sequence happens to be near the old one.
                    sample = payload[-self.max_bytes:]
                    next_seq = (seq + len(payload)) & 0xFFFFFFFF
                    pending = {}
                    initial_seq = syn_seq
                else:
                    # Signed modular distance handles ordinary 32-bit sequence wrap.
                    delta = ((seq - expected + (1 << 31)) % (1 << 32)) - (1 << 31)
                    if delta == 0:
                        sample = (previous + payload)[-self.max_bytes:]
                        next_seq = (expected + len(payload)) & 0xFFFFFFFF
                    elif delta > 0:
                        # Hold a modest amount of reordering without joining across
                        # a gap. Bound both the ahead distance and queued bytes.
                        queued = sum(len(part) for part in pending.values())
                        if (delta <= self.max_bytes and len(pending) < 8
                                and queued + len(payload) <= self.max_bytes):
                            pending.setdefault(seq, payload)
                        sample = previous
                        next_seq = expected
                    else:
                        overlap = -delta
                        if overlap >= len(payload):
                            sample = previous  # retransmission of bytes already inspected
                            next_seq = expected
                        else:
                            sample = (previous + payload[overlap:])[-self.max_bytes:]
                            next_seq = (expected + len(payload) - overlap) & 0xFFFFFFFF

                # A previously queued segment can now extend the contiguous
                # stream. Prefer the closest extending segment and discard
                # fully covered retransmissions.
                while pending:
                    candidates = []
                    covered = []
                    for pending_seq, part in pending.items():
                        distance = ((pending_seq - next_seq + (1 << 31)) % (1 << 32)) - (1 << 31)
                        if distance <= 0:
                            overlap = -distance
                            if overlap >= len(part):
                                covered.append(pending_seq)
                            else:
                                candidates.append((distance, pending_seq, part))
                    # A longer in-order segment may cover a segment that was
                    # previously queued out of order. Drop it now so stale
                    # bytes do not consume the bounded reordering budget.
                    for pending_seq in covered:
                        pending.pop(pending_seq, None)
                    if not candidates:
                        if covered:
                            continue
                        break
                    distance, pending_seq, part = max(candidates, key=lambda item: item[0])
                    pending.pop(pending_seq, None)
                    overlap = -distance
                    sample = (sample + part[overlap:])[-self.max_bytes:]
                    next_seq = (next_seq + len(part) - overlap) & 0xFFFFFFFF
            # Refresh insertion order so capacity eviction removes the least
            # recently active flow, not merely the oldest-created one.
            self._streams.pop(key, None)
            self._streams[key] = (next_seq, sample, now, pending, initial_seq)
            if flags & 0x05:  # FIN or RST closes this directional flow
                self._streams.pop(key, None)
            return sample

    def check(self, record: dict) -> dict | None:
        """
        Returns an alert if ANY signature matches.
        Evidence lists ALL matches found in the inspected sample (§3.4).
        """
        if not self.enabled:
            return None
        if record.get("type") != "IP":
            return None

        payload: bytes = record.get("payload", b"")
        dst_port = _normalize_port(record.get("dst_port")) or 0
        src_port = _normalize_port(record.get("src_port")) or 0

        # A reused TCP 4-tuple starts a new connection. Clear any STARTTLS
        # suppression state first so an earlier connection cannot hide new
        # plaintext traffic on the same endpoints.
        if record.get("protocol") == "TCP" and record.get("initial_syn"):
            flow_key = self._tls_flow_key(record)
            if flow_key is not None:
                with self._stream_lock:
                    self._tls_flows.pop(flow_key, None)

        # Direction decision (P1 §3.4 direction fix):
        # - Both dst and src NOT in DPI_PORTS → not a plaintext app port, skip.
        # - src_port IS a known service port AND dst_port is NOT → this looks
        #   like a server responding to a client (e.g. HTTP server replying);
        #   we do not want to flag the server's response as an attack.
        # - Otherwise (dst_port IS a service port) → treat as client→server;
        #   inspect it.
        if dst_port not in _DPI_PORTS and src_port not in _DPI_PORTS:
            return None
        if src_port in _DPI_PORTS and dst_port not in _DPI_PORTS:
            # Server responding to a client — skip inspection
            return None

        if record.get("protocol") == "TCP" and payload:
            now = _finite_record_timestamp(record)
            flow_key = self._tls_flow_key(record)
            if flow_key is not None:
                with self._stream_lock:
                    if flow_key in self._tls_flows:
                        last_seen = self._tls_flows[flow_key]
                        if now is not None and (
                            last_seen < now - self.stream_timeout or last_seen > now
                        ):
                            del self._tls_flows[flow_key]
                        else:
                            if now is not None:
                                self._tls_flows[flow_key] = now
                                self._tls_flows.move_to_end(flow_key)
                            return None
                    if self._looks_like_tls_record(payload):
                        if now is not None:
                            self._tls_flows[flow_key] = now
                            self._tls_flows.move_to_end(flow_key)
                            while len(self._tls_flows) > self.max_streams:
                                self._tls_flows.popitem(last=False)
                        # Discard any cleartext reassembly buffer at the
                        # protocol transition so later ciphertext cannot join it.
                        self._streams.pop(
                            (record.get("src_ip"), src_port,
                             record.get("dst_ip"), dst_port), None)
                        self._streams.pop(
                            (record.get("dst_ip"), dst_port,
                             record.get("src_ip"), src_port), None)
                        return None

        packet_sample = payload[: self.max_bytes]
        try:
            captured_payload_len = int(record.get("payload_len", len(payload)))
        except (TypeError, ValueError, OverflowError):
            captured_payload_len = len(payload)
        packet_truncated = (
            len(packet_sample) >= self.max_bytes
            or len(payload) > len(packet_sample)
            or captured_payload_len > len(packet_sample)
        )
        try:
            tcp_flags = int(record.get("tcp_flags") or 0)
        except (TypeError, ValueError, OverflowError):
            tcp_flags = 0
        is_initial_syn = bool(record.get("initial_syn")) or bool(
            tcp_flags & 0x02 and not tcp_flags & 0x10
        )
        stream_sample = (
            self._update_stream(record, payload)
            if payload or (record.get("protocol") == "TCP" and is_initial_syn)
            else None
        )
        if not payload:
            return None
        base_samples: list[tuple[bytes, str, bool]] = [
            (packet_sample, "packet", packet_truncated)
        ]
        if stream_sample and stream_sample != packet_sample:
            base_samples.append((
                stream_sample, "tcp_stream", len(stream_sample) >= self.max_bytes
            ))

        samples: list[tuple[bytes, str, bool]] = list(base_samples)
        seen_representations: set[bytes] = {s[0] for s in samples}

        # Inspect single- and multi-pass URL-decoded views as well as form-encoded views.
        for sample, source, truncated in base_samples:
            if b"%" in sample:
                decoded = unquote_to_bytes(sample)
                if decoded not in seen_representations:
                    samples.append((decoded, "percent_decoded", truncated))
                    seen_representations.add(decoded)

                multi_dec = _multi_unquote(sample, max_passes=3)
                if multi_dec not in seen_representations:
                    samples.append((multi_dec, "multi_pass_decoded", truncated))
                    seen_representations.add(multi_dec)

            if b"+" in sample:
                # Decode raw form '+' as space before percent escapes so an
                # encoded literal %2B remains a plus sign.
                form_decoded = unquote_to_bytes(sample.replace(b"+", b" "))
                if form_decoded not in seen_representations:
                    samples.append((form_decoded, "form_decoded", truncated))
                    seen_representations.add(form_decoded)

                multi_form = _multi_unquote(sample.replace(b"+", b" "), max_passes=3)
                if multi_form not in seen_representations:
                    samples.append((multi_form, "multi_pass_decoded", truncated))
                    seen_representations.add(multi_form)

        # Deobfuscation and evasion normalization passes:
        # - Stripping and normalizing null bytes (%00 or \x00)
        # - Collapsing inline SQL comments (/*...*/) to spaces
        for sample, source, truncated in list(samples):
            if b"\x00" in sample:
                null_stripped = sample.replace(b"\x00", b"")
                if null_stripped not in seen_representations:
                    samples.append((null_stripped, "null_byte_stripped", truncated))
                    seen_representations.add(null_stripped)
                null_spaced = sample.replace(b"\x00", b" ")
                if null_spaced not in seen_representations:
                    samples.append((null_spaced, "null_byte_normalized", truncated))
                    seen_representations.add(null_spaced)

            if b"/*" in sample and b"*/" in sample:
                comment_normalized = re.sub(rb"/\*.*?\*/", b" ", sample)
                if comment_normalized not in seen_representations:
                    samples.append((comment_normalized, "comment_normalized", truncated))
                    seen_representations.add(comment_normalized)

        # Collect ALL matching signatures (§3.4 — do not return on first match)
        hits: list[dict] = []
        for label, pattern, confidence in _PAYLOAD_SIGNATURES:
            match = None
            for sample, source, truncated in samples:
                for found in pattern.finditer(sample):
                    # A comment marker at the end of a bounded packet/stream
                    # sample may only look complete because inspection stopped
                    # at the cap. Do not call an unfinished SQL comment a hit.
                    if (
                        label == "SQL_INJECTION"
                        and truncated
                        and found.end() == len(sample)
                        and found.group(0).startswith((b"#", b"--"))
                    ):
                        continue
                    match = (found, source)
                    break
                if match is not None:
                    break
            if match:
                m, representation = match
                matched_bytes = m.group(0)[:80]
                try:
                    matched_str = matched_bytes.decode("utf-8", errors="replace")
                except Exception:
                    matched_str = repr(matched_bytes)
                hits.append({"signature": label, "matched": matched_str,
                             "confidence": confidence,
                             "representation": representation})

        if hits and self.alert_cooldown > 0:
            src_ip = record.get("src_ip")
            dst_ip = record.get("dst_ip")
            if src_ip and dst_ip and record.get("dst_port") is not None:
                flow_key = (
                    src_ip, dst_ip, record.get("protocol"), int(record["dst_port"])
                )
                now = _finite_record_timestamp(record)
                if now is not None:
                    cutoff = now - self.alert_cooldown
                    eligible_hits = []
                    with self._stream_lock:
                        for key in list(self._alerted):
                            if self._alerted[key] < cutoff:
                                del self._alerted[key]
                        for hit in hits:
                            # A repeated C2 request may use a fresh client source
                            # port each time. Collapse identical matches by host
                            # pair, transport and service for the cooldown, while retaining
                            # distinct signatures and destination services.
                            key = (flow_key, hit["signature"], hit["matched"])
                            last_alert = self._alerted.get(key)
                            if last_alert is not None and now - last_alert < self.alert_cooldown:
                                # Retain actively suppressed signatures under key
                                # pressure, and do not let late packets erase newer
                                # cooldown evidence.
                                self._alerted.move_to_end(key)
                                continue
                            if key not in self._alerted and len(self._alerted) >= self._max_alert_states:
                                self._alerted.pop(next(iter(self._alerted)))
                            self._alerted[key] = now
                            self._alerted.move_to_end(key)
                            eligible_hits.append(hit)
                    hits = eligible_hits

        if not hits:
            return None

        labels_str = ", ".join(h["signature"] for h in hits)
        logger.debug(
            f"PAYLOAD_HIT [{labels_str}]: "
            f"{record.get('src_ip')} → {record.get('dst_ip')}:{dst_port}"
        )

        # Severity: high if any hit is high-confidence (e.g. LOG4SHELL)
        severity = "high" if any(h["confidence"] == "high" for h in hits) else "medium"
        overall_confidence = "high" if severity == "high" else "heuristic"

        # Don't repeatedly fire on the same signature retained in a stream tail.
        if stream_sample:
            key = (record.get("src_ip"), src_port, record.get("dst_ip"), dst_port)
            with self._stream_lock:
                state = self._streams.get(key)
                if state:
                    self._streams[key] = (state[0], b"", state[2], state[3], state[4])

        return {
            "rule_name": self.name,
            "rule_version": self.rule_version,
            "src_ip": record.get("src_ip"),
            "dst_ip": record.get("dst_ip"),
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": record.get("protocol"),
            "severity": severity,
            "confidence": overall_confidence,
            "detail": (
                f"{record.get('src_ip')} → {record.get('dst_ip')}:{dst_port} "
                f"matched DPI signature(s): {labels_str}"
            ),
            "evidence": {
                "hits": hits,
                "inspected_bytes": max(len(sample) for sample, _, _ in samples),
                "cap_bytes": self.max_bytes,
                "inspection": "packet_and_bounded_tcp_stream",
                "stream_timeout_s": self.stream_timeout,
                "stream_buffer_bytes": self.max_bytes,
                "note": "Only contiguous TCP bytes are inspected; small gaps may be buffered, and TLS is not decrypted.",
            },
            "window_start": None,
            "window_end": None,
        }


# =============================================================================
# Rule 6: DNS Tunneling & DGA Detection  (§3.5 — query frequency added)
# =============================================================================

# Domains whose labels are legitimately high-entropy (CDN, tracking, etc.)
# IMPORTANT: This list should be kept narrow. Broad shared-hosting suffixes
# (e.g. *.github.io, *.cloudfront.net) can also host malicious content, so
# they are NOT included. Add only infrastructure you explicitly trust and own.
# Entropy allowlist: CDN and cloud-infrastructure domains whose high-entropy labels
# are structurally legitimate (hash-based routing, Anycast node IDs, signed tokens).
# Entropy exemption ONLY — length and frequency anomalies are still checked.
# Sources: real PCAP capture analysis (test.pcap / test2.pcap traffic) and
# Suricata ET DNS allowlist practices.
_DGA_WHITELIST_SUFFIXES: tuple[str, ...] = (
    # Cloudflare CDN (both primary and CDN-chain suffix seen in CNAME records)
    ".cloudflare.com", ".cloudflare.net", ".cloudflareinsights.com",
    # Akamai (seen in Spotify CDN CNAME chains: edgesuite.net, akamaiedge.net)
    ".akamai.net", ".akamaiedge.net", ".akamaized.net",
    ".edgesuite.net", ".edgekey.net",
    # Google CDN and APIs
    ".cdn.ampproject.org", ".googleapis.com", ".googleusercontent.com",
    ".gstatic.com", ".google.com", ".googlevideo.com", ".doubleclick.net",
    # AWS and Azure
    ".amazonaws.com", ".azurefd.net", ".azure.com",
    # Fastly CDN
    ".fastly.net", ".fastlylb.net",
    # Render.com CDN (seen in real PCAP: api.render.com.cdn.cloudflare.net)
    ".render.com",
    # Spotify CDN (seen in real PCAP CNAME chains)
    ".spotifycdn.com", ".scdn.co",
    # Facebook CDN
    ".fbcdn.net",
    # NOTE: github.io, cloudfront.net, s3.amazonaws.com are intentionally
    # NOT included — shared-hosting providers can host both legit and abusive
    # content under the same suffix. Add specific domains via config instead.
)


def _shannon_entropy(s: str) -> float:
    """Return Shannon entropy in bits/character for string s."""
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# Common multi-label public suffixes that use country-code TLDs. This is a
# bounded heuristic list rather than a complete Public Suffix List; unknown
# suffixes fall back to the final two labels to avoid grouping unrelated sites.
_COMMON_MULTI_LABEL_CC_SUFFIXES = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "sch.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz", "school.nz",
    "co.in", "firm.in", "net.in", "org.in", "gen.in", "ind.in",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "ac.kr",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    "com.mx", "org.mx", "gob.mx", "edu.mx",
    "co.za", "com.za", "net.za", "org.za", "gov.za",
    "com.ar", "net.ar", "org.ar", "gov.ar", "edu.ar",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
    "co.id", "web.id", "or.id", "ac.id", "go.id",
    "com.ua", "net.ua", "org.ua", "gov.ua",
})


class DnsRule:
    name = "DNS_ANOMALY"
    rule_version = "1.19"

    # Alert dedup cooldown — class-level default; overridable via __init__
    ALERT_COOLDOWN_S = 60
    # DNS clients commonly retry an unanswered transaction after a short wait.
    # Such retries retain the same ID and question and should not inflate the
    # repeated-query heuristic; a new transaction ID remains a fresh query.
    RETRANSMISSION_DEDUP_S = 2.0

    def __init__(
        self,
        entropy_threshold: float = 3.8,
        max_query_len: int = 60,
        freq_threshold: int = 20,
        freq_window: int = 60,
        max_frequency_keys: int = 10_000,
        max_seen_keys: int = 10_000,
        subdomain_threshold: int = 20,
        subdomain_window: int = 60,
    ):
        self.entropy_threshold = _positive_float_setting(
            entropy_threshold, 3.8, "DNS_ENTROPY_THRESHOLD")
        self.max_query_len = _positive_setting(
            max_query_len, 60, "DNS_QUERY_MAX_LEN")
        # Frequency detection parameters — wired from config via RuleEngine (P1)
        self._freq_threshold = _nonnegative_setting(
            freq_threshold, 20, "DNS_FREQ_THRESHOLD")
        self._freq_window = _positive_setting(
            freq_window, 60, "DNS_FREQ_WINDOW")
        self._max_frequency_keys = _positive_setting(
            max_frequency_keys, 10_000, "DNS_MAX_FREQUENCY_KEYS")
        self._max_seen_keys = _positive_setting(
            max_seen_keys, 10_000, "DNS_MAX_SEEN_KEYS")
        # Subdomain exfiltration parameters
        self._subdomain_threshold = _nonnegative_setting(
            subdomain_threshold, 20, "DNS_SUBDOMAIN_THRESHOLD")
        self._subdomain_window = _positive_setting(
            subdomain_window, 60, "DNS_SUBDOMAIN_WINDOW")
        self._lock = threading.RLock()

        # (src_ip, parent_domain, anomaly_type) → last_alert_time (dedup)
        self._seen: OrderedDict[tuple, float] = OrderedDict()

        # (src_ip, parent_domain) → bounded [timestamps] (query frequency)
        self._freq: dict[tuple, list] = defaultdict(list)

        # (src_ip, parent_domain) → [(timestamp, subdomain)] (subdomain exfil)
        self._subdomain_freq: dict[tuple, list] = {}
        self._seen_queries: OrderedDict[tuple, float] = OrderedDict()
        self._max_seen_queries = max(1024, min(50_000, self._max_frequency_keys * 4))

    def _parent_domain(self, domain: str) -> str:
        """
        Return a stable grouping key for the domain.

        Using only the last two labels (e.g. 'example.com') works for most
        gTLDs but breaks for common multi-label public suffixes like 'co.uk':
        'one.example.co.uk' and 'two.other.co.uk' would both collapse to
        'co.uk', aggregating unrelated activity.

        Three-label grouping is limited to a maintained set of common
        country-code suffixes. Guessing from label length misclassified
        ordinary registrations such as ``foo.io`` as a public suffix and
        split their subdomain history across unrelated parent keys. Unknown
        suffixes fall back to the last two labels. A complete Public Suffix
        List remains more accurate but would add a dependency.
        """
        labels = domain.rstrip(".").split(".")
        if (len(labels) >= 3
                and ".".join(labels[-2:]).lower() in _COMMON_MULTI_LABEL_CC_SUFFIXES):
            return ".".join(labels[-3:])
        return ".".join(labels[-2:]) if len(labels) >= 2 else domain

    def _prune_seen(self, now: float):
        cutoff = now - 120
        for key, seen_at in list(self._seen.items()):
            if seen_at <= cutoff:
                del self._seen[key]

    def prune_stale(self, now: float):
        cutoff_freq = now - self._freq_window
        cutoff_sd = now - self._subdomain_window
        with self._lock:
            for key in list(self._freq):
                active = [t for t in self._freq[key] if cutoff_freq <= t <= now]
                if active:
                    self._freq[key] = active
                else:
                    del self._freq[key]
            for key in list(self._subdomain_freq):
                active = [(t, s) for t, s in self._subdomain_freq[key] if cutoff_sd <= t <= now]
                if active:
                    self._subdomain_freq[key] = active
                else:
                    del self._subdomain_freq[key]
            retry_cutoff = now - self.RETRANSMISSION_DEDUP_S
            for key, timestamp in list(self._seen_queries.items()):
                if timestamp < retry_cutoff or timestamp > now:
                    del self._seen_queries[key]
            if len(self._seen) > 5000:
                self._prune_seen(now)

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP":
            return None
        dst_port = _normalize_port(record.get("dst_port"))
        src_port = _normalize_port(record.get("src_port"))
        # Exclude mDNS (port 5353) and LLMNR (port 5355): both are legitimate
        # link-local service discovery protocols and are not DNS resolvers.
        # Real-world traffic (Chromecast, Apple Bonjour) heavily uses these.
        if dst_port in (5353, 5355) or src_port in (5353, 5355):
            return None
        if dst_port != 53 and src_port != 53:
            return None

        domain: str | None = record.get("dns_query")
        if not domain:
            return None

        # DNS labels are case-insensitive; canonicalize before deriving the
        # frequency and dedup keys so mixed-case queries still aggregate.
        domain = domain.rstrip(".").lower()
        src = record.get("src_ip", "unknown")
        now = _finite_record_timestamp(record, prefer_event_timestamp=False)
        has_valid_time = now is not None

        # --- Allowlist: applied only to entropy check, NOT to length/frequency ---
        # Broad suffix allowlisting should not suppress other anomaly signals.
        # A high-entropy domain under a CDN suffix is excused from entropy only;
        # an unusually LONG or REPEATED query under that suffix still fires.
        dl = domain.lower()
        entropy_exempt = any(dl.endswith(w) for w in _DGA_WHITELIST_SUFFIXES)

        labels = domain.split(".")
        # SRV service-discovery names such as _ldap._tcp.<site>._sites.dc
        # are descriptive by design and can exceed ordinary hostname lengths.
        service_discovery = (
            record.get("dns_qtype") == 33
            and any(label.startswith("_") for label in labels)
        )
        parent = self._parent_domain(domain)
        parent_label_count = len(parent.split(".")) if parent else 0
        registrable_index = max(0, len(labels) - parent_label_count)
        # Track the entire prefix before the registrable domain. DNS tunnel
        # chunks can sit below a stable prefix (for example,
        # host.<encoded-chunk>.example.com), not only in the leftmost label.
        subdomain = ".".join(labels[:registrable_index])
        # Include every label through the registrable domain. This catches
        # randomized nested labels and DGA-like second-level domains without
        # measuring public-suffix labels such as "co" or "uk".
        entropy_labels = labels[:registrable_index + 1]
        entropy_candidates = [
            (label, _shannon_entropy(label))
            for label in entropy_labels if len(label) >= 8
        ]
        entropy_label, entropy = max(
            entropy_candidates, key=lambda item: item[1],
            default=(subdomain, _shannon_entropy(subdomain)),
        )
        # Total QNAME length includes every dot and the registered domain,
        # which makes ordinary multi-label hostnames exceed modest settings.
        # Tunneling data is carried in labels, so measure the longest label.
        longest_label = max(labels, key=len, default="")
        too_long = len(longest_label) > self.max_query_len and not service_discovery
        # Require at least one relevant label of length >= 8 to limit FPs.
        # Also skip entropy checks for explicitly allowlisted CDN suffixes.
        high_ent = (
            not entropy_exempt
            and bool(entropy_candidates)
            and entropy >= self.entropy_threshold
        )

        # Check for encoded chunk tunneling — hex and base64/base32 variants.
        # Hex chunks (e.g. iodine TXT challenge, custom C2): [0-9a-f]{24,}
        # Base64 URL-safe chunks (dnscat2, iodine over base64): [A-Za-z0-9+/=-]{20,}
        # Base32 chunks (iodine default): [A-Z2-7]{20,} (all-uppercase, restricted charset)
        # All three require both letters and digits to exclude plain words/numbers.
        hex_chunks = []
        b64_chunks = []
        if not entropy_exempt:
            for lbl in entropy_labels:
                # Pure hex chunks (≥24 chars, mixed digits+hex-letters)
                if len(lbl) >= 24 and re.fullmatch(r"[0-9a-f]{24,}", lbl):
                    if any(c.isdigit() for c in lbl) and any(c in "abcdef" for c in lbl):
                        hex_chunks.append(lbl)
                # Base64/base32 chunks: ≥20 chars, alphanumeric+padding chars,
                # must contain both digits and uppercase letters, no hyphens
                # (hyphens distinguish UUIDs and legitimate hostnames).
                elif (len(lbl) >= 20 and "-" not in lbl
                        and re.fullmatch(r"[A-Za-z0-9+/=]{20,}", lbl)
                        and any(c.isdigit() for c in lbl)
                        and any(c.isupper() for c in lbl)
                        and any(c.islower() for c in lbl)):
                    b64_chunks.append(lbl)
                # Base32 chunks (iodine): uppercase letters + digits 2-7 only
                elif (len(lbl) >= 20 and "-" not in lbl
                        and re.fullmatch(r"[A-Z2-7]{20,}", lbl)
                        and any(c.isdigit() for c in lbl)
                        and lbl.isupper()):
                    b64_chunks.append(lbl)
        has_hex_chunk = bool(hex_chunks)
        has_b64_chunk = bool(b64_chunks)
        hex_chunk_label = hex_chunks[0] if hex_chunks else (b64_chunks[0] if b64_chunks else "")
        has_encoded_chunk = has_hex_chunk or has_b64_chunk

        # ── Query frequency: count repeated queries to same parent domain ──
        # Keep only the threshold-sized rolling tail: once the threshold is
        # reached, larger exact counts do not change the detection decision.
        # This bounds a single hot domain even when queries arrive at line rate.
        # A disabled frequency rule must not allocate or retain per-domain state.
        query_count = 0
        freq_window_start = None
        query_count_saturated = False
        if has_valid_time and self._freq_threshold > 0:
            query_identity = None
            try:
                dns_id = int(record["dns_id"])
                qtype = int(record["dns_qtype"])
                query_src_port = int(record["src_port"])
                query_dst_port = int(record["dst_port"])
                if (0 <= dns_id <= 65535 and 0 <= qtype <= 65535
                        and 1 <= query_src_port <= 65535
                        and 1 <= query_dst_port <= 65535
                        and record.get("dst_ip")):
                    query_identity = (
                        str(src), str(record["dst_ip"]), query_src_port,
                        query_dst_port, dns_id, qtype, domain,
                    )
            except (KeyError, TypeError, ValueError, OverflowError):
                query_identity = None
            is_retransmission = False
            with self._lock:
                fkey = (src, parent)
                history = self._freq.get(fkey, [])
                if history and now < history[-1]:
                    return None  # ignore late observations instead of corrupting the window
                history = [
                    t for t in history if 0 <= now - t <= self._freq_window
                ]
                # Reject out-of-order records before they mutate retry state;
                # otherwise a dropped event could suppress a later valid query.
                if query_identity is not None:
                    first_seen = self._seen_queries.get(query_identity)
                    if (first_seen is not None
                            and 0 <= now - first_seen <= self.RETRANSMISSION_DEDUP_S):
                        is_retransmission = True
                        self._seen_queries.move_to_end(query_identity)
                    else:
                        self._seen_queries[query_identity] = now
                        self._seen_queries.move_to_end(query_identity)
                        while len(self._seen_queries) > self._max_seen_queries:
                            self._seen_queries.popitem(last=False)
                if not is_retransmission:
                    if fkey not in self._freq and len(self._freq) >= self._max_frequency_keys:
                        self._freq.pop(next(iter(self._freq)))
                    if len(history) >= self._freq_threshold:
                        query_count_saturated = True
                        history = history[-(self._freq_threshold - 1):] if self._freq_threshold > 1 else []
                    history.append(now)
                    self._freq.pop(fkey, None)
                    self._freq[fkey] = history
                query_count = len(history)
                freq_window_start = history[0] if history else None

        high_freq = query_count >= self._freq_threshold > 0

        # ── Subdomain exfiltration: many distinct subdomains under one parent ──
        # DNS tunneling via data-in-subdomains uses a large number of unique
        # subdomains (e.g. aGVsbG8=.evil.com, d29ybGQ=.evil.com). Legitimate
        # services use a small finite set of subdomains.
        high_subdomain = False
        subdomain_count = 0
        subdomain_count_saturated = False
        subdomain_window_start = None
        if has_valid_time and self._subdomain_threshold > 0:
            with self._lock:
                sdkey = (src, parent)
                if sdkey not in self._subdomain_freq and len(self._subdomain_freq) >= self._max_frequency_keys:
                    self._subdomain_freq.pop(next(iter(self._subdomain_freq)))
                # Store (timestamp, subdomain_label) pairs
                sd_history = self._subdomain_freq.get(sdkey, [])
                if not (sd_history and now < sd_history[-1][0]):
                    sd_history = [
                        (t, s) for t, s in sd_history
                        if 0 <= now - t <= self._subdomain_window
                        and s != subdomain  # don't double-count same subdomain
                    ]
                    sd_history.append((now, subdomain))
                    if len(sd_history) >= self._subdomain_threshold:
                        subdomain_count_saturated = True
                        sd_history = sd_history[-self._subdomain_threshold:]
                    self._subdomain_freq.pop(sdkey, None)
                    self._subdomain_freq[sdkey] = sd_history
                    subdomain_count = len({s for _, s in sd_history})
                    if sd_history:
                        subdomain_window_start = sd_history[0][0]
                    high_subdomain = subdomain_count >= self._subdomain_threshold

        if not (high_ent or too_long or high_freq or high_subdomain or has_encoded_chunk):
            return None

        if high_subdomain:
            sub_type = "DNS_EXFIL"
        elif has_encoded_chunk and not (high_ent or too_long):
            sub_type = "DNS_TUNNEL"
        elif high_freq and not (high_ent or too_long):
            sub_type = "DNS_FREQ"
        elif high_ent:
            sub_type = "DNS_DGA"
        else:
            sub_type = "DNS_TUNNEL"

        # Deduplicate by parent and anomaly class. Randomized query labels under
        # one domain otherwise evade per-QNAME cooldowns and can flood alerts.
        alert_key = (src, parent, sub_type)
        if has_valid_time:
            with self._lock:
                last_alert = self._seen.get(alert_key)
                if last_alert is not None and now - last_alert < self.ALERT_COOLDOWN_S:
                    self._seen.move_to_end(alert_key)
                    return None
                if alert_key not in self._seen and len(self._seen) >= self._max_seen_keys:
                    self._seen.popitem(last=False)
                self._seen.pop(alert_key, None)
                self._seen[alert_key] = now
                self._seen.move_to_end(alert_key)

        reason = []
        if high_ent:
            reason.append(
                f"entropy={entropy:.2f} for label '{entropy_label}' "
                f"(≥{self.entropy_threshold})"
            )
        if too_long:
            reason.append(
                f"label_length={len(longest_label)} for '{longest_label}' "
                f"(>{self.max_query_len})"
            )
        if has_encoded_chunk:
            chunk_kind = "base64" if has_b64_chunk and not has_hex_chunk else "hex"
            reason.append(
                f"{chunk_kind}_encoded_chunk='{hex_chunk_label}' "
                f"(len={len(hex_chunk_label)} ≥ {'20' if has_b64_chunk and not has_hex_chunk else '24'})"
            )
        if high_freq:
            reason.append(
                f"query_count={query_count} to '{parent}' "
                f"in {self._freq_window}s (≥{self._freq_threshold})"
            )
        if high_subdomain:
            reason.append(
                f"distinct_subdomains={subdomain_count} under '{parent}' "
                f"in {self._subdomain_window}s (≥{self._subdomain_threshold})"
            )

        logger.debug(f"{sub_type} fired: {src} queried '{domain}' [{', '.join(reason)}]")
        # DNS_EXFIL and encoded chunk tunnels are high severity — covert channels
        severity = "high" if (high_ent or too_long or high_subdomain or has_encoded_chunk) else "medium"
        return {
            "rule_name": self.name,
            "rule_version": self.rule_version,
            "src_ip": src,
            "dst_ip": record.get("dst_ip"),
            "src_port": record.get("src_port"),
            "dst_port": 53,
            "protocol": record.get("protocol", "UDP"),
            "severity": severity,
            "confidence": "heuristic",
            "detail": (
                f"{src} queried suspicious domain '{domain}' "
                f"[{', '.join(reason)}] — possible {sub_type}"
            ),
            "evidence": {
                "domain": domain,
                "subdomain": subdomain,
                "longest_label": longest_label,
                "longest_label_length": len(longest_label),
                "max_label_length": self.max_query_len,
                "entropy_label": entropy_label,
                "parent_domain": parent,
                "entropy": round(entropy, 3),
                "sub_type": sub_type,
                "hex_encoded_chunk": hex_chunk_label if has_encoded_chunk else None,
                "chunk_encoding": ("base64" if has_b64_chunk and not has_hex_chunk else "hex") if has_encoded_chunk else None,
                "query_count_in_window": query_count,
                "query_count_saturated": query_count_saturated,
                "freq_window_s": self._freq_window,
                "freq_threshold": self._freq_threshold,
                "distinct_subdomains": subdomain_count,
                "distinct_subdomains_saturated": subdomain_count_saturated,
                "subdomain_threshold": self._subdomain_threshold,
                "subdomain_window_s": self._subdomain_window,
            },
            "window_start": (
                subdomain_window_start if high_subdomain
                else (freq_window_start if high_freq else None)
            ),
            "window_end": now if has_valid_time and (high_freq or high_subdomain) else None,
        }


# =============================================================================
# Rule 11: Brute Force Detection  (auth port repeated connection attempts)
# =============================================================================

# Ports commonly targeted by brute-force credential attacks.
# Only connections to THESE destination ports are counted by BruteForceRule.
# NOTE: Port 8080/8443 are intentionally excluded despite being admin panels;
# they serve legitimate web traffic and the existing test suite guards against
# false positives on these ports. A dedicated admin-panel rule is the correct
# approach for Tomcat Manager brute-force detection.
_BRUTE_FORCE_AUTH_PORTS: frozenset = frozenset({
    22,    # SSH
    23,    # Telnet
    21,    # FTP
    25,    # SMTP AUTH
    110,   # POP3
    143,   # IMAP
    389,   # LDAP
    445,   # SMB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    27017, # MongoDB
    11211, # Memcached
    2181,  # ZooKeeper
    9300,  # Elasticsearch cluster transport
})


class BruteForceRule:
    """
    Detect repeated authentication attempts from a single source to a single
    auth-port destination, indicative of credential brute-forcing.

    Detection logic:
      - Counts initial SYN packets (new connection attempts) to known auth ports.
      - Suppresses matching SYN retransmissions when the TCP tuple and sequence
        number are available; records without sequence metadata remain countable.
      - Fires when a source makes >= threshold SYN attempts to the same (dst, port)
        pair within the window.
      - Only fires on known authentication ports (see _BRUTE_FORCE_AUTH_PORTS).
      - Trusted sources are exempted; TCP SYN direction distinguishes new
        attempts from ordinary SYN-ACK replies.

    False Positive Mitigations:
      - Only auth ports are counted (not arbitrary services).
      - Trusted sources (TRUSTED_HOSTS) are exempted.
      - Alert cooldown prevents alert storms from the same (src, dst, port) triple.
      - Configurable threshold and window via config / RuleEngine wiring.
    """

    name = "BRUTE_FORCE"
    rule_version = "1.9"

    # Per-(src, dst, port) cooldown after firing. Prevents re-alerting for the
    # same ongoing brute-force burst; renewed bursts after the cooldown will fire.
    ALERT_COOLDOWN_S: float = 60.0

    def __init__(self, threshold: int = 20, window: int = 60,
                 max_states: int = 8192, extra_ports=()):
        self.threshold = max(2, _positive_setting(
            threshold, 20, "BRUTE_FORCE_THRESHOLD"))
        self.window = _positive_setting(window, 60, "BRUTE_FORCE_WINDOW")
        self.max_states = _positive_setting(
            max_states, 8192, "BRUTE_FORCE_MAX_STATES")
        valid_extra_ports = set()
        invalid_extra_port = False
        try:
            extra_port_values = iter(extra_ports)
        except TypeError:
            extra_port_values = ()
            invalid_extra_port = extra_ports is not None
        for port in extra_port_values:
            try:
                parsed_port = int(port)
            except (TypeError, ValueError, OverflowError):
                invalid_extra_port = True
                continue
            if 1 <= parsed_port <= 65535:
                valid_extra_ports.add(parsed_port)
            else:
                invalid_extra_port = True
        if invalid_extra_port:
            logger.warning("Ignoring invalid BRUTE_FORCE_EXTRA_PORTS entries")
        self.auth_ports = _BRUTE_FORCE_AUTH_PORTS | frozenset(valid_extra_ports)
        self._lock = threading.RLock()
        # (src_ip, dst_ip, dst_port) → list of SYN timestamps
        self._history: OrderedDict[tuple, list] = OrderedDict()
        self._saturated_history: set[tuple] = set()
        # (src_ip, dst_ip, dst_port) → last_alert_time (cooldown)
        self._cooldown: OrderedDict[tuple, float] = OrderedDict()
        # Full SYN identity → first-seen time. Bounded independently because a
        # busy source can touch many auth tuples within one detection window.
        self._seen_syns: OrderedDict[tuple, float] = OrderedDict()
        self._max_seen_syns = max(1024, min(50_000, self.max_states * 4))

    def _evict_history_key(self, key: tuple):
        self._history.pop(key, None)
        self._saturated_history.discard(key)
        self._cooldown.pop(key, None)

    def prune_stale(self, now: float):
        cutoff = now - self.window
        with self._lock:
            for key in list(self._history):
                active = [t for t in self._history[key] if cutoff <= t <= now]
                if active:
                    self._history[key] = active
                    if len(active) < self.threshold:
                        self._saturated_history.discard(key)
                else:
                    del self._history[key]
                    self._saturated_history.discard(key)
            cooldown_cutoff = now - self.ALERT_COOLDOWN_S
            for key, last_alert in list(self._cooldown.items()):
                if last_alert <= cooldown_cutoff:
                    del self._cooldown[key]
            for syn_key, first_seen in list(self._seen_syns.items()):
                if not (cutoff <= first_seen <= now):
                    del self._seen_syns[syn_key]

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP" or record.get("protocol") != "TCP":
            return None

        dst_port = _normalize_port(record.get("dst_port"))
        if dst_port is None or dst_port not in self.auth_ports:
            return None

        # Only count initial SYN (SYN=1, ACK=0) — new connection attempts
        if not _is_initial_syn(record):
            return None

        src = record.get("src_ip", "")
        dst = record.get("dst_ip", "")
        if not src or not dst:
            return None
        if _is_trusted(src):
            return None

        src_port = _normalize_port(record.get("src_port"))
        now = _finite_record_timestamp(record)
        if now is None:
            return None
        key = (src, dst, dst_port)

        syn_identity = None
        if src_port is not None and record.get("tcp_seq") is not None:
            try:
                syn_identity = (
                    src, dst, int(src_port), int(dst_port),
                    int(record["tcp_seq"]) & 0xFFFFFFFF,
                )
            except (TypeError, ValueError, OverflowError):
                # Incomplete or malformed metadata must not discard an attempt.
                syn_identity = None

        with self._lock:
            # Cooldown: if we just fired for this triple, suppress until cooldown expires
            last_alert = self._cooldown.get(key)
            if last_alert is not None and now - last_alert < self.ALERT_COOLDOWN_S:
                # Still update history for accurate counting after cooldown
                pass

            if key not in self._history and len(self._history) >= self.max_states:
                self._evict_history_key(next(iter(self._history)))
            history = self._history.get(key, [])
            if history and now < history[-1]:
                return None  # reject reordered events
            if syn_identity is not None:
                first_seen = self._seen_syns.get(syn_identity)
                if first_seen is not None and 0 <= now - first_seen <= self.window:
                    self._seen_syns.move_to_end(syn_identity)
                    return None
                self._seen_syns[syn_identity] = now
                self._seen_syns.move_to_end(syn_identity)
                while len(self._seen_syns) > self._max_seen_syns:
                    self._seen_syns.popitem(last=False)
            history = [t for t in history if 0 <= now - t <= self.window]
            if len(history) < self.threshold:
                self._saturated_history.discard(key)
            history.append(now)
            if len(history) > self.threshold:
                history = history[-self.threshold:]
                self._saturated_history.add(key)
            self._history.pop(key, None)
            self._history[key] = history
            self._history.move_to_end(key)
            count = len(history)
            count_saturated = key in self._saturated_history
            window_start = history[0]

            if count < self.threshold:
                return None

            # Enforce cooldown AFTER threshold check so we measure alert suppression,
            # not attempt suppression.
            if last_alert is not None and now - last_alert < self.ALERT_COOLDOWN_S:
                return None

            # Record alert time and reset history for the next burst window
            if key not in self._cooldown and len(self._cooldown) >= self.max_states:
                self._cooldown.popitem(last=False)
            self._cooldown.pop(key, None)
            self._cooldown[key] = now
            self._history.pop(key, None)
            self._saturated_history.discard(key)

        logger.debug(
            f"BRUTE_FORCE fired: {src} → {dst}:{dst_port} "
            f"({'at least ' if count_saturated else ''}{count} SYNs in {self.window}s)"
        )
        return {
            "rule_name": self.name,
            "rule_version": self.rule_version,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": "TCP",
            "severity": "medium",
            "confidence": "heuristic",
            "detail": (
                f"{src} made {'at least ' if count_saturated else ''}"
                f"{count} connection attempts to {dst}:{dst_port} "
                f"(auth port) in {self.window}s — possible credential brute-force "
                "(SYN-rate signal; authentication outcome is not observed)"
            ),
            "evidence": {
                "classification": "AUTH_SERVICE_SYN_BURST",
                "attempt_count": count,
                "attempt_count_saturated": count_saturated,
                "auth_port": dst_port,
                "window_s": self.window,
                "threshold": self.threshold,
                "note": (
                    "Counts SYN packets to authentication ports; does not verify "
                    "whether credentials were submitted or accepted."
                ),
            },
            "window_start": window_start,
            "window_end": now,
        }


# =============================================================================
# Rule 12: Slow Port Scan Detection  (low-and-slow evasion variant)
# =============================================================================

class SlowPortScanRule:
    """
    Detect low-and-slow vertical or horizontal TCP port scans that evade the
    standard PortScanRule's short 10-second window by spreading probes over
    a longer time period (default: 120 seconds).

    Attackers deliberately reduce probe rates to avoid threshold-based IDS
    detection. This rule catches such evasion by maintaining a longer sliding
    window with a higher port count threshold.

    Detection logic:
      - Vertical: (src, dst) → distinct dst_ports in the slow window
      - Horizontal: (src, port) → distinct dst_hosts in the slow window
      - Uses a higher threshold than PortScanRule to avoid FPs from normal
        slow browsing (e.g., a browser slowly loading a page with many resources).

    False Positive Mitigations:
      - Only initial SYN packets are counted.
      - Trusted sources are exempted.
      - Only initial SYN packets are counted, so SYN-ACK service replies do
        not need a source-port-only exemption.
      - Default threshold (30 ports) is 2× the PortScanRule threshold to
        compensate for the longer window accumulating incidental activity.
      - Alert cooldown prevents storm after a long burst.
    """

    name = "SLOW_PORT_SCAN"
    rule_version = "1.7"

    def __init__(self, threshold: int = 30, window: int = 120,
                 max_states: int = 5000, cooldown: float | None = None):
        self.threshold = max(2, _positive_setting(
            threshold, 30, "SLOW_PORT_SCAN_THRESHOLD"))
        self.window = _positive_setting(window, 120, "SLOW_PORT_SCAN_WINDOW")
        self.max_states = _positive_setting(
            max_states, 5000, "SLOW_PORT_SCAN_MAX_STATES")
        cooldown_default = float(self.window)
        self.cooldown = _nonnegative_float_setting(
            cooldown_default if cooldown is None else cooldown,
            cooldown_default, "SLOW_PORT_SCAN_COOLDOWN")
        self._lock = threading.RLock()
        # Vertical scan: (src_ip, dst_ip) → [(ts, dst_port)]
        self._vert: dict[tuple, list] = {}
        # Horizontal scan: (src_ip, dst_port) → [(ts, dst_ip)]
        self._horiz: dict[tuple, list] = {}
        # Rate-limit alerts per scanning source and scan direction. The same
        # campaign can cross hundreds of destination keys in one capture.
        self._alert_cooldown: OrderedDict[tuple[str, str], float] = OrderedDict()

    def prune_stale(self, now: float):
        cutoff = now - self.window
        with self._lock:
            for d in (self._vert, self._horiz):
                for key in list(d):
                    active = [e for e in d[key] if cutoff <= e[0] <= now]
                    if active:
                        d[key] = active
                    else:
                        del d[key]
            cooldown_cutoff = now - self.cooldown
            for key in list(self._alert_cooldown):
                if self._alert_cooldown[key] < cooldown_cutoff or self._alert_cooldown[key] > now:
                    del self._alert_cooldown[key]

    def _allow_alert(self, key: tuple[str, str], now: float) -> bool:
        last_alert = self._alert_cooldown.get(key)
        if last_alert is not None and now - last_alert < self.cooldown:
            self._alert_cooldown.move_to_end(key)
            return False
        if key not in self._alert_cooldown and len(self._alert_cooldown) >= self.max_states * 2:
            self._alert_cooldown.popitem(last=False)
        self._alert_cooldown[key] = now
        self._alert_cooldown.move_to_end(key)
        return True

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP" or record.get("protocol") != "TCP":
            return None

        src = record.get("src_ip", "")
        if _is_trusted(src):
            return None

        # Only count initial SYN (SYN=1, ACK=0)
        if not _is_initial_syn(record):
            return None

        dst_ip = record.get("dst_ip", "")
        src_port = _normalize_port(record.get("src_port"))
        dst_port = _normalize_port(record.get("dst_port"))
        if dst_port is None:
            return None

        now = _finite_record_timestamp(record)
        if now is None:
            return None
        vkey = (src, dst_ip)
        hkey = (src, dst_port)

        with self._lock:
            # Reject late events
            if (self._vert.get(vkey) and now < max(t for t, _ in self._vert[vkey])) or \
               (self._horiz.get(hkey) and now < max(t for t, _ in self._horiz[hkey])):
                return None

            # Capacity eviction
            if vkey not in self._vert and len(self._vert) >= self.max_states:
                self._vert.pop(next(iter(self._vert)))
            if hkey not in self._horiz and len(self._horiz) >= self.max_states:
                self._horiz.pop(next(iter(self._horiz)))

            # Vertical history update (deduplicate per port)
            vertical = [(t, p) for t, p in self._vert.get(vkey, [])
                        if 0 <= now - t <= self.window and p != dst_port]
            vertical.append((now, dst_port))
            self._vert.pop(vkey, None)
            self._vert[vkey] = vertical
            distinct_ports = len({p for _, p in vertical})

            # Horizontal history update (deduplicate per host)
            horizontal = [(t, ip) for t, ip in self._horiz.get(hkey, [])
                          if 0 <= now - t <= self.window and ip != dst_ip]
            horizontal.append((now, dst_ip))
            self._horiz.pop(hkey, None)
            self._horiz[hkey] = horizontal
            distinct_hosts = len({ip for _, ip in horizontal})

            vert_fired  = distinct_ports >= self.threshold
            horiz_fired = distinct_hosts >= self.threshold

            if vert_fired:
                window_start = min(t for t, _ in vertical)
                self._vert.pop(vkey, None)
                if self._allow_alert((src, "vertical"), now):
                    logger.debug(
                        f"{self.name} (vertical) fired: {src}→{dst_ip} "
                        f"{distinct_ports} ports over {self.window}s"
                    )
                    return {
                        "rule_name": self.name,
                        "rule_version": self.rule_version,
                        "src_ip": src,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": "TCP",
                        "severity": "medium",
                        "confidence": "heuristic",
                        "detail": (
                            f"{src} sent SYN packets to {distinct_ports} distinct ports on "
                            f"{dst_ip} over {self.window}s — possible low-and-slow vertical TCP scan"
                        ),
                        "evidence": {
                            "scan_type": "slow_vertical",
                            "transport": "TCP",
                            "distinct_ports": distinct_ports,
                            "target_host": dst_ip,
                            "window_s": self.window,
                            "threshold": self.threshold,
                            "note": "Slow scan evasion: probes spread over extended time window.",
                        },
                        "window_start": window_start,
                        "window_end": now,
                    }

            if horiz_fired:
                window_start = min(t for t, _ in horizontal)
                self._horiz.pop(hkey, None)
                if not self._allow_alert((src, "horizontal"), now):
                    return None
                logger.debug(
                    f"{self.name} (horizontal) fired: {src} port {dst_port} "
                    f"→ {distinct_hosts} hosts over {self.window}s"
                )
                return {
                    "rule_name": self.name,
                    "rule_version": self.rule_version,
                    "src_ip": src,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": "TCP",
                    "severity": "medium",
                    "confidence": "heuristic",
                    "detail": (
                        f"{src} sent SYN to port {dst_port} on {distinct_hosts} distinct hosts "
                        f"over {self.window}s — possible low-and-slow horizontal TCP scan"
                    ),
                    "evidence": {
                        "scan_type": "slow_horizontal",
                        "transport": "TCP",
                        "distinct_hosts": distinct_hosts,
                        "scanned_port": dst_port,
                        "window_s": self.window,
                        "threshold": self.threshold,
                        "note": "Slow scan evasion: probes spread over extended time window.",
                    },
                    "window_start": window_start,
                    "window_end": now,
                }

        return None


# =============================================================================
# Rule 14: Outbound Data Exfiltration Detection
# =============================================================================

class DataExfiltrationRule:
    """
    Detects outbound data exfiltration from internal networks to external destinations:
    1. Volumetric: an internal host transmits >= byte_threshold (default 50 KB)
       of payload bytes to an external internet endpoint within a sliding window.
    2. Signature-based: an internal host transmits archive or database dump headers
       (SQLite database, ZIP, 7-Zip, GZIP, TAR) directly to an external endpoint.

    Exemptions:
    - DNS queries (dst_port == 53) are handled by DnsRule.
    - Multicast/broadcast destinations.
    - Internal-to-internal LAN traffic.
    - Configured TRUSTED_HOSTS.
    """
    name = "DATA_EXFIL"
    rule_version = "1.15"
    ALERT_COOLDOWN_S = 60.0
    MAX_TRACKED_FLOWS = 5000
    MAX_TRACKED_FLOW_EVENTS = 1_000_000
    MAX_FRAGMENT_ORPHAN_EVENTS = 10_000
    MAX_TRACKED_PAYLOAD_SEGMENTS = 50_000
    MAX_TRACKED_TCP_CONNECTIONS = 5000
    MAX_TRACKED_SIGNATURE_STREAMS = 5000
    SIGNATURE_PREFIX_BYTES = 512
    COMMON_WEB_PORTS = frozenset({80, 443, 8000, 8080, 8443, 8888})

    # Archive / DB file signatures: (magic_bytes, format_name)
    # Extended with common exfiltration file types (Suricata ET POLICY / ET HUNTING):
    # executables, office documents, PDFs, and additional compressed archives.
    _EXFIL_SIGNATURES: list[tuple[bytes, str]] = [
        (b"SQLite format 3\x00", "SQLite database file dump"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"\x1f\x8b\x08", "GZIP compressed archive"),
        (b"ustar", "TAR archive"),
        # BZip2: very common for credential dump compression
        (b"BZh", "BZip2 compressed archive"),
        # RAR: widely used for exfil packaging
        (b"Rar!\x1a\x07", "RAR archive"),
        # XZ: modern Linux compression (also used for supply-chain attack payloads)
        (b"\xfd7zXZ\x00", "XZ compressed archive"),
        # LZW/Compress: classic Unix .Z files
        (b"\x1f\x9d", "LZW/Compress archive"),
        # Windows PE/EXE/DLL: executable binary exfiltration
        (b"MZ", "Windows PE executable"),
        # MS Office/OLE compound document (Word, Excel, PowerPoint, Outlook .msg)
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "MS Office OLE compound document"),
        # PDF: credential documents, internal reports
        (b"%PDF-", "PDF document"),
    ]

    def __init__(self, byte_threshold: int = 50000, window: int = 30,
                 web_byte_threshold: int = 1_000_000):
        self.byte_threshold = max(1000, _positive_setting(
            byte_threshold, 50_000, "DATA_EXFIL_BYTE_THRESHOLD"))
        self.web_byte_threshold = max(self.byte_threshold, _positive_setting(
            web_byte_threshold, 1_000_000, "DATA_EXFIL_WEB_BYTE_THRESHOLD"))
        self.window = _positive_setting(window, 30, "DATA_EXFIL_WINDOW")
        self._lock = threading.Lock()
        # Key: (src_ip, dst_ip, dst_port, protocol) -> byte history/cooldown.
        # Keep services separate so volume on one port cannot cross-trigger another.
        self._flows: OrderedDict[tuple, deque] = OrderedDict()
        self._flow_event_count = 0
        # Cached sum of each flow deque avoids rescanning every packet on each
        # check; subtract entries as they leave the rolling time window.
        self._flow_totals: dict[tuple, int] = {}
        # A flow can retain the newest threshold-sized byte suffix without
        # changing the threshold decision. Mark when older active bytes were
        # discarded so later evidence is clearly labeled as a lower bound.
        self._flow_saturated: set[tuple] = set()
        self._cooldown: OrderedDict[tuple, float] = OrderedDict()
        # Fragment ID -> resolved service tuple, allowing non-initial IP
        # fragments (which have no transport ports) to join their first fragment.
        self._fragment_ports: OrderedDict[tuple, tuple[int | None, int | None, float]] = OrderedDict()
        # Out-of-order non-initial fragments wait here until the first fragment
        # reveals the service port. Both keys and queued packets are bounded.
        self._fragment_orphans: OrderedDict[tuple, list[tuple[float, int]]] = OrderedDict()
        self._fragment_orphan_count = 0
        # Bounded signatures let the volume counter suppress exact TCP
        # retransmissions and exact IP-fragment duplicates in the time window.
        self._seen_payload_segments: OrderedDict[tuple, float] = OrderedDict()
        # Canonical endpoint pair -> (initial sequence, generation, last seen).
        # A new SYN distinguishes tuple reuse from an exact segment retransmit.
        self._tcp_connection_generations: OrderedDict[tuple, tuple[int, int, float]] = OrderedDict()
        # Bounded directional TCP prefixes allow existing file signatures to
        # be recognized when their leading bytes cross contiguous segments.
        # Each value is (next sequence, prefix bytes, last timestamp).
        self._signature_streams: OrderedDict[tuple, tuple[int, bytes, float]] = OrderedDict()

    @property
    def _flow_event_limit(self) -> int:
        return max(
            1, int(self.MAX_TRACKED_FLOW_EVENTS),
            self.byte_threshold, self.web_byte_threshold,
        )

    def _evict_flow_state(self, key: tuple):
        history = self._flows.pop(key, None)
        if history is not None:
            self._flow_event_count -= len(history)
        self._flow_totals.pop(key, None)
        self._flow_saturated.discard(key)
        self._cooldown.pop(key, None)

    def _tcp_generation(self, record: dict, now: float):
        if record.get("protocol") != "TCP":
            return 0
        try:
            endpoints = tuple(sorted((
                (str(record["src_ip"]), int(record["src_port"])),
                (str(record["dst_ip"]), int(record["dst_port"])),
            )))
        except (KeyError, TypeError, ValueError, OverflowError):
            return 0

        try:
            tcp_flags = int(record.get("tcp_flags") or 0)
            tcp_seq = int(record["tcp_seq"]) & 0xFFFFFFFF
        except (KeyError, TypeError, ValueError, OverflowError):
            tcp_seq = None
            tcp_flags = 0
        initial_syn = bool(tcp_flags & 0x02 and not tcp_flags & 0x10)

        with self._lock:
            current = self._tcp_connection_generations.get(endpoints)
            if initial_syn and tcp_seq is not None:
                if current is None:
                    generation = 1
                    initial_seq = tcp_seq
                    last_seen = now
                elif now < current[2]:
                    # A late SYN must not roll an active tuple back to an
                    # older connection generation.
                    generation = current[1]
                    initial_seq = current[0]
                    last_seen = current[2]
                elif current[0] == tcp_seq:
                    # A repeated SYN with the same initial sequence is a
                    # retransmission of the handshake, not tuple reuse.
                    generation = current[1]
                    initial_seq = current[0]
                    last_seen = max(current[2], now)
                else:
                    generation = current[1] + 1
                    initial_seq = tcp_seq
                    last_seen = now
                self._tcp_connection_generations[endpoints] = (
                    initial_seq, generation, last_seen)
            elif current is not None:
                generation = current[1]
                self._tcp_connection_generations[endpoints] = (current[0], generation, max(current[2], now))
            else:
                generation = 0
            if endpoints in self._tcp_connection_generations:
                self._tcp_connection_generations.move_to_end(endpoints)
            while len(self._tcp_connection_generations) > self.MAX_TRACKED_TCP_CONNECTIONS:
                self._tcp_connection_generations.popitem(last=False)
        return generation

    def prune_stale(self, now: float = None):
        if now is None:
            now = time.time()
        cutoff = now - self.window
        with self._lock:
            for key in list(self._flows):
                dq = self._flows[key]
                expired_events = 0
                while dq and dq[0][0] < cutoff:
                    _, expired_bytes = dq.popleft()
                    self._flow_totals[key] -= expired_bytes
                    expired_events += 1
                self._flow_event_count -= expired_events
                if not dq:
                    del self._flows[key]
                    self._flow_totals.pop(key, None)
                    self._flow_saturated.discard(key)
                else:
                    flow_threshold = (
                        self.web_byte_threshold if key[2] in self.COMMON_WEB_PORTS
                        else self.byte_threshold
                    )
                    if self._flow_totals[key] < flow_threshold:
                        self._flow_saturated.discard(key)
            cooldown_cutoff = now - self.ALERT_COOLDOWN_S
            for key in list(self._cooldown):
                if self._cooldown[key] < cooldown_cutoff:
                    del self._cooldown[key]
            for key, (_, _, timestamp) in list(self._fragment_ports.items()):
                if timestamp < cutoff or timestamp > now:
                    del self._fragment_ports[key]
            for key, events in list(self._fragment_orphans.items()):
                active = [(ts, size) for ts, size in events if cutoff <= ts <= now]
                self._fragment_orphan_count -= len(events) - len(active)
                if active:
                    self._fragment_orphans[key] = active
                else:
                    del self._fragment_orphans[key]
            for key, timestamp in list(self._seen_payload_segments.items()):
                if timestamp < cutoff or timestamp > now:
                    del self._seen_payload_segments[key]
            for key, (_, _, timestamp) in list(self._tcp_connection_generations.items()):
                if timestamp < cutoff or timestamp > now:
                    del self._tcp_connection_generations[key]
            for key, (_, _, timestamp) in list(self._signature_streams.items()):
                if timestamp < cutoff or timestamp > now:
                    del self._signature_streams[key]

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP":
            return None

        src_ip = record.get("src_ip")
        dst_ip = record.get("dst_ip")
        if not src_ip or not dst_ip:
            return None

        # Exfiltration check applies strictly to outbound traffic (internal -> external)
        if not _is_internal(src_ip):
            return None
        if _is_internal(dst_ip):
            return None

        # Exclude all IP multicast ranges, not only the 224/8 subrange, plus
        # the limited IPv4 broadcast address. String-prefix checks omitted
        # IPv4 multicast groups such as 239.0.0.0/8.
        try:
            dst_addr = ipaddress.ip_address(dst_ip)
        except ValueError:
            return None
        if dst_addr.is_multicast or (
                dst_addr.version == 4 and int(dst_addr) == 0xFFFFFFFF):
            return None

        if _is_trusted(src_ip):
            return None

        now = _finite_record_timestamp(record)
        dst_port = record.get("dst_port")
        src_port = record.get("src_port")
        protocol = record.get("protocol")
        try:
            tcp_flags = int(record.get("tcp_flags") or 0)
        except (TypeError, ValueError, OverflowError):
            tcp_flags = 0
        generation_needed = protocol == "TCP" and (
            record.get("tcp_payload_digest") is not None
            or (tcp_flags & 0x02 and not tcp_flags & 0x10)
        )
        tcp_generation = (
            self._tcp_generation(record, now)
            if generation_needed and now is not None else 0
        )

        payload = record.get("payload", b"")
        # IP total length includes network and transport headers, not just
        # transmitted application data. Subtracting a fixed 40 bytes can
        # count TCP options as payload and overcount IPv6 headers entirely.
        # The replay parser caps `payload` for DPI memory bounds, so use its
        # uncapped captured transport-payload length when present. For legacy
        # callers, fall back only to bytes actually supplied, never IP length.
        payload_len = record.get("payload_len")
        if payload_len is None:
            payload_len = len(payload) if isinstance(payload, (bytes, bytearray, memoryview)) else 0
        try:
            bytes_sent = max(0, int(payload_len))
        except (TypeError, ValueError, OverflowError):
            bytes_sent = 0
        if bytes_sent <= 0:
            return None

        fragment_offset = record.get("ip_fragment_offset", 0) or 0
        fragment_id = record.get("ip_fragment_id")
        is_fragmented = bool(
            record.get("ip_fragmented") or fragment_offset
            or record.get("ip_more_fragments")
        ) and fragment_id is not None
        fragment_key = (
            str(src_ip), str(dst_ip), str(protocol), int(fragment_id)
        ) if is_fragmented else None

        # Check for direct archive / database dump signature in outbound payload
        matched_sig = None
        if payload:
            for magic, desc in self._EXFIL_SIGNATURES:
                if payload.startswith(magic) or (magic == b"ustar" and magic in payload[:512]):
                    matched_sig = desc
                    break

        # File signatures are packet-local and do not need event ordering.
        # Preserve that high-confidence coverage when timestamps are malformed,
        # while avoiding mutation of flow, retransmission, and cooldown state.
        if now is None:
            if not matched_sig:
                return None
            detail = (
                f"{src_ip} transmitting {matched_sig} to external host "
                f"{dst_ip}:{dst_port} ({bytes_sent} bytes) — possible sensitive data exfiltration"
            )
            return {
                "rule_name": self.name,
                "rule_version": self.rule_version,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": record.get("src_port"),
                "dst_port": dst_port,
                "protocol": protocol or "TCP",
                "severity": "high",
                "confidence": "high",
                "detail": detail,
                "evidence": {
                    "sub_type": "SIGNATURE_EXFIL",
                    "bytes_transferred": bytes_sent,
                    "byte_count_is_lower_bound": False,
                    "byte_count_basis": "captured_payload_bytes_after_exact_duplicate_suppression",
                    "partial_tcp_overlaps_counted": True,
                    "deduplication": (
                        "exact TCP-segment retransmissions suppressed by connection generation, "
                        "sequence, length and fingerprint; exact IP-fragment retransmissions "
                        "suppressed by fragment identity and fingerprint; partial overlaps are not suppressed"
                    ),
                    "threshold": self.byte_threshold,
                    "base_threshold": self.byte_threshold,
                    "window_s": self.window,
                    "matched_signature": matched_sig,
                },
                "window_start": None,
                "window_end": None,
            }

        with self._lock:
            # Join only sequence-adjacent payloads in the same direction and
            # TCP generation. Gaps and overlaps reset the prefix, avoiding
            # signatures synthesized from unrelated or retransmitted bytes.
            raw_payload = bytes(payload) if isinstance(
                payload, (bytes, bytearray, memoryview)) else b""
            tcp_seq = record.get("tcp_payload_seq")
            if (protocol == "TCP" and raw_payload and len(raw_payload) == bytes_sent
                    and tcp_seq is not None
                    and src_port is not None and dst_port is not None):
                try:
                    seq = int(tcp_seq) & 0xFFFFFFFF
                    stream_key = (
                        str(src_ip), int(src_port), str(dst_ip), int(dst_port),
                        tcp_generation,
                    )
                except (TypeError, ValueError, OverflowError):
                    stream_key = None
                if stream_key is not None:
                    previous = self._signature_streams.get(stream_key)
                    if previous is not None and 0 <= now - previous[2] <= self.window \
                            and seq == previous[0]:
                        prefix = (previous[1] + raw_payload)[
                            :self.SIGNATURE_PREFIX_BYTES]
                    else:
                        prefix = raw_payload[:self.SIGNATURE_PREFIX_BYTES]
                    self._signature_streams[stream_key] = (
                        (seq + len(raw_payload)) & 0xFFFFFFFF, prefix, now)
                    self._signature_streams.move_to_end(stream_key)
                    while len(self._signature_streams) > self.MAX_TRACKED_SIGNATURE_STREAMS:
                        self._signature_streams.popitem(last=False)
                    if not matched_sig:
                        for magic, desc in self._EXFIL_SIGNATURES:
                            if (prefix.startswith(magic)
                                    or (magic == b"ustar"
                                        and magic in prefix[:self.SIGNATURE_PREFIX_BYTES])):
                                matched_sig = desc
                                break

            duplicate_key = None
            tcp_digest = record.get("tcp_payload_digest")
            if (protocol == "TCP" and src_port is not None and dst_port is not None
                    and tcp_seq is not None and tcp_digest is not None):
                try:
                    duplicate_key = (
                        "tcp", str(src_ip), int(src_port), str(dst_ip), int(dst_port),
                        tcp_generation, int(tcp_seq) & 0xFFFFFFFF,
                        bytes_sent, bytes(tcp_digest),
                    )
                except (TypeError, ValueError, OverflowError):
                    duplicate_key = None
            elif (fragment_key is not None and record.get("ip_fragment_data_digest") is not None):
                duplicate_key = (
                    "fragment", fragment_key, int(fragment_offset),
                    int(record.get("ip_fragment_data_len") or 0),
                    bytes(record["ip_fragment_data_digest"]),
                )

            if duplicate_key is not None:
                seen_at = self._seen_payload_segments.get(duplicate_key)
                if seen_at is not None and 0 <= now - seen_at <= self.window:
                    self._seen_payload_segments[duplicate_key] = now
                    self._seen_payload_segments.move_to_end(duplicate_key)
                    return None
                self._seen_payload_segments[duplicate_key] = now
                self._seen_payload_segments.move_to_end(duplicate_key)
                while len(self._seen_payload_segments) > self.MAX_TRACKED_PAYLOAD_SEGMENTS:
                    self._seen_payload_segments.popitem(last=False)

            pending_fragments = []
            if fragment_key is not None:
                if not fragment_offset and dst_port is not None:
                    self._fragment_ports[fragment_key] = (dst_port, src_port, now)
                    self._fragment_ports.move_to_end(fragment_key)
                    while len(self._fragment_ports) > self.MAX_TRACKED_FLOWS:
                        self._fragment_ports.popitem(last=False)
                    pending_fragments = self._fragment_orphans.pop(fragment_key, [])
                    self._fragment_orphan_count -= len(pending_fragments)
                else:
                    resolved = self._fragment_ports.get(fragment_key)
                    if resolved and 0 <= now - resolved[2] <= self.window:
                        dst_port, src_port = resolved[0], resolved[1]
                        self._fragment_ports.move_to_end(fragment_key)
                    else:
                        if self._fragment_orphan_count >= self.MAX_FRAGMENT_ORPHAN_EVENTS:
                            _, expired = self._fragment_orphans.popitem(last=False)
                            self._fragment_orphan_count -= len(expired)
                        if fragment_key not in self._fragment_orphans:
                            if len(self._fragment_orphans) >= self.MAX_TRACKED_FLOWS:
                                _, expired = self._fragment_orphans.popitem(last=False)
                                self._fragment_orphan_count -= len(expired)
                            self._fragment_orphans[fragment_key] = []
                        self._fragment_orphans[fragment_key].append((now, bytes_sent))
                        self._fragment_orphans.move_to_end(fragment_key)
                        self._fragment_orphan_count += 1
                        return None

            # Ignore DNS queries (port 53 is monitored by DnsRule). This is
            # checked after fragment port resolution so every DNS fragment is
            # excluded consistently.
            if dst_port == 53:
                return None

            flow_key = (src_ip, dst_ip, dst_port, protocol)
            effective_threshold = (
                self.web_byte_threshold if dst_port in self.COMMON_WEB_PORTS
                else self.byte_threshold
            )
            last_alert = self._cooldown.get(flow_key, 0.0)
            in_cooldown = (now - last_alert) < self.ALERT_COOLDOWN_S

            if flow_key not in self._flows:
                if len(self._flows) >= self.MAX_TRACKED_FLOWS:
                    self._evict_flow_state(next(iter(self._flows)))
                self._flows[flow_key] = deque()
                self._flow_totals[flow_key] = 0

            dq = self._flows[flow_key]
            self._flows.move_to_end(flow_key)
            total_bytes = self._flow_totals[flow_key]
            cutoff = now - self.window
            out_of_order = bool(dq and now < dq[-1][0])
            if out_of_order and not matched_sig:
                # Preserve chronological ordering so stale records cannot be
                # stranded behind newer deque entries and counted indefinitely.
                return None
            if pending_fragments and not out_of_order:
                active_fragments = [(ts, size) for ts, size in pending_fragments
                                    if cutoff <= ts <= now]
                dq.extend(active_fragments)
                self._flow_event_count += len(active_fragments)
                total_bytes += sum(size for _, size in active_fragments)
                dq = deque(sorted(dq))
                self._flows[flow_key] = dq
            if not out_of_order:
                dq.append((now, bytes_sent))
                self._flow_event_count += 1
                total_bytes += bytes_sent
                expired_events = 0
                while dq and dq[0][0] < cutoff:
                    _, expired_bytes = dq.popleft()
                    total_bytes -= expired_bytes
                    expired_events += 1
                self._flow_event_count -= expired_events
                if total_bytes < effective_threshold:
                    self._flow_saturated.discard(flow_key)
                self._flow_totals[flow_key] = total_bytes

            observed_total = total_bytes
            byte_count_is_lower_bound = flow_key in self._flow_saturated
            # Keeping only the newest threshold bytes is sufficient to answer
            # whether the active window crossed the threshold. Older bytes
            # expire no later than this retained suffix, so this cap cannot
            # hide a threshold crossing. It does make later exact totals
            # unavailable, which is exposed in alert evidence.
            if total_bytes > effective_threshold:
                excess = total_bytes - effective_threshold
                while excess > 0 and dq:
                    event_time, event_bytes = dq[0]
                    if event_bytes <= excess:
                        dq.popleft()
                        self._flow_event_count -= 1
                        total_bytes -= event_bytes
                        excess -= event_bytes
                    else:
                        dq[0] = (event_time, event_bytes - excess)
                        total_bytes -= excess
                        excess = 0
                self._flow_saturated.add(flow_key)
            self._flow_totals[flow_key] = total_bytes
            self._flows.move_to_end(flow_key)
            while (self._flow_event_count > self._flow_event_limit
                   and len(self._flows) > 1):
                evicted = next(iter(self._flows))
                if evicted == flow_key:
                    self._flows.move_to_end(evicted)
                    evicted = next(iter(self._flows))
                self._evict_flow_state(evicted)

            # Trigger condition: volumetric threshold exceeded OR sensitive signature detected
            if (total_bytes >= effective_threshold or matched_sig) and not in_cooldown:
                last_alert = self._cooldown.get(flow_key)
                if last_alert is None and len(self._cooldown) >= self.MAX_TRACKED_FLOWS:
                    self._cooldown.popitem(last=False)
                alert_time = max(now, last_alert if last_alert is not None else now)
                self._cooldown.pop(flow_key, None)
                self._cooldown[flow_key] = alert_time

                if matched_sig:
                    sub_type = "SIGNATURE_EXFIL"
                    detail = (
                        f"{src_ip} transmitting {matched_sig} to external host {dst_ip}:{dst_port} "
                        f"({bytes_sent} bytes) — possible sensitive data exfiltration"
                    )
                else:
                    reported_bytes = (
                        effective_threshold if byte_count_is_lower_bound
                        else observed_total
                    )
                    sub_type = "VOLUMETRIC_EXFIL"
                    detail = (
                        f"{src_ip} transmitted "
                        f"{'at least ' if byte_count_is_lower_bound else ''}"
                        f"{reported_bytes} bytes to external host {dst_ip}:{dst_port} "
                        f"in {self.window}s (≥{effective_threshold}) — possible outbound data exfiltration"
                    )

                logger.debug(f"DATA_EXFIL fired: {detail}")
                return {
                    "rule_name": self.name,
                    "rule_version": self.rule_version,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": record.get("src_port"),
                    "dst_port": dst_port,
                    "protocol": protocol or "TCP",
                    "severity": "high" if matched_sig else "medium",
                    "confidence": "high" if matched_sig else "heuristic",
                    "detail": detail,
                    "evidence": {
                        "sub_type": sub_type,
                        "bytes_transferred": reported_bytes if not matched_sig else bytes_sent,
                        "byte_count_is_lower_bound": (
                            byte_count_is_lower_bound if not matched_sig else False
                        ),
                        "byte_count_basis": "captured_payload_bytes_after_exact_duplicate_suppression",
                        "partial_tcp_overlaps_counted": True,
                        "deduplication": (
                            "exact TCP-segment retransmissions suppressed by connection generation, "
                            "sequence, length and fingerprint; exact IP-fragment retransmissions "
                            "suppressed by fragment identity and fingerprint; partial overlaps are not suppressed"
                        ),
                        "threshold": effective_threshold,
                        "base_threshold": self.byte_threshold,
                        "window_s": self.window,
                        "matched_signature": matched_sig,
                    },
                    "window_start": now if out_of_order else (dq[0][0] if dq else now),
                    "window_end": now,
                }

        return None


# =============================================================================
# Rule 16: TLS Handshake & SNI Anomaly Detection
# =============================================================================

class CleartextHttpOnTlsPortRule:
    """Flag repeated plaintext HTTP requests sent to conventional TLS ports."""

    name = "CLEAR_HTTP_ON_TLS_PORT"
    rule_version = "1.8"
    MAX_REQUEST_LINE_BYTES = 2064
    STREAM_TIMEOUT_S = 30.0
    MAX_SEEN_REQUEST_IDENTITIES = 32_768
    _METHOD_PREFIXES = (b"GET ", b"POST ", b"PUT ", b"DELETE ",
                        b"PATCH ", b"OPTIONS ", b"HEAD ")
    _REQUEST_LINE = re.compile(
        rb"(?i)^(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+[^\r\n]{1,2048}\s+HTTP/1\.[01]\r?\n"
    )

    def __init__(self, cooldown: float = 600.0, window: float = 600.0,
                 min_requests: int = 2, max_states: int = 4096):
        self.cooldown = _nonnegative_float_setting(
            cooldown, 600.0, "CLEAR_HTTP_TLS_COOLDOWN_S")
        self.window = _positive_float_setting(
            window, 600.0, "CLEAR_HTTP_TLS_WINDOW_S")
        self.min_requests = _positive_setting(
            min_requests, 2, "CLEAR_HTTP_TLS_MIN_REQUESTS")
        self.max_states = _positive_setting(
            max_states, 4096, "CLEAR_HTTP_TLS_MAX_STATES")
        self._lock = threading.Lock()
        self._seen: OrderedDict[tuple[str, str, int], float] = OrderedDict()
        self._history: OrderedDict[tuple[str, str, int], list[float]] = OrderedDict()
        self._saturated: set[tuple[str, str, int]] = set()
        # Incomplete request-line prefixes, keyed by directional TCP 4-tuple.
        # State is capped separately from service-level request history.
        self._tcp_prefixes: OrderedDict[
            tuple[str, int, str, int],
            tuple[int, int, bytes, float, dict[int, bytes]],
        ] = OrderedDict()
        # Exact full-segment retransmissions do not count as separate HTTP requests.
        self._seen_requests: OrderedDict[tuple, float] = OrderedDict()

    def _extract_request_line(self, record: dict, payload: bytes, now: float) -> bytes | None:
        match = self._REQUEST_LINE.match(payload)
        if match:
            try:
                direct_key = (str(record["src_ip"]), int(record["src_port"]),
                              str(record["dst_ip"]), int(record["dst_port"]))
            except (KeyError, TypeError, ValueError, OverflowError):
                direct_key = None
            if direct_key is not None:
                with self._lock:
                    state = self._tcp_prefixes.get(direct_key)
                    if state is not None and now >= state[3]:
                        self._tcp_prefixes.pop(direct_key, None)
            return match.group(0).strip()

        try:
            src_port = int(record["src_port"])
            dst_port = int(record["dst_port"])
            seq = int(record["tcp_payload_seq"]) & 0xFFFFFFFF
            src, dst = str(record["src_ip"]), str(record["dst_ip"])
        except (KeyError, TypeError, ValueError, OverflowError):
            return None
        if not 1 <= src_port <= 65535 or dst_port not in (443, 8443):
            return None

        key = (src, src_port, dst, dst_port)
        with self._lock:
            state = self._tcp_prefixes.get(key)
            if state is not None:
                start_seq, expected_seq, prefix, last_seen, pending = state
                if now < last_seen:
                    return None  # late segments cannot replace active prefix state
                if now - last_seen > self.STREAM_TIMEOUT_S:
                    self._tcp_prefixes.pop(key, None)
                    state = None
                elif seq == start_seq and payload == prefix:
                    # An exact retransmission of the partial segment is not a
                    # second request and must not replace its continuation state.
                    self._tcp_prefixes[key] = (
                        start_seq, expected_seq, prefix, now, pending)
                    self._tcp_prefixes.move_to_end(key)
                    return None
                elif seq == expected_seq:
                    combined = prefix + payload
                    next_seq = (seq + len(payload)) & 0xFFFFFFFF
                    pending = dict(pending)
                    while next_seq in pending:
                        next_payload = pending.pop(next_seq)
                        combined += next_payload
                        next_seq = (next_seq + len(next_payload)) & 0xFFFFFFFF
                    match = self._REQUEST_LINE.match(combined)
                    if match:
                        self._tcp_prefixes.pop(key, None)
                        return match.group(0).strip()
                    if (len(combined) <= self.MAX_REQUEST_LINE_BYTES
                            and b"\n" not in combined
                            and any(method.startswith(combined) or combined.startswith(method)
                                    for method in self._METHOD_PREFIXES)):
                        self._tcp_prefixes[key] = (
                            start_seq, next_seq, combined, now, pending)
                        self._tcp_prefixes.move_to_end(key)
                    else:
                        self._tcp_prefixes.pop(key, None)
                    return None
                else:
                    delta = ((seq - expected_seq + (1 << 31)) % (1 << 32)) - (1 << 31)
                    if delta <= 0:
                        self._tcp_prefixes.pop(key, None)
                        state = None
                    else:
                        # Keep a few bounded future segments so capture
                        # reordering does not discard an observed request prefix.
                        buffered_bytes = sum(len(part) for part in pending.values())
                        if (payload and delta <= self.MAX_REQUEST_LINE_BYTES
                                and len(pending) < 4
                                and len(prefix) + buffered_bytes + len(payload)
                                <= self.MAX_REQUEST_LINE_BYTES):
                            pending.setdefault(seq, payload)
                            self._tcp_prefixes[key] = (
                                start_seq, expected_seq, prefix, now, pending)
                            self._tcp_prefixes.move_to_end(key)
                            return None
                        self._tcp_prefixes.pop(key, None)

            # Buffer only plausible partial method/request prefixes, not
            # arbitrary application data from every flow to port 443.
            if (payload and len(payload) <= self.MAX_REQUEST_LINE_BYTES
                    and b"\n" not in payload
                    and any(method.startswith(payload) or payload.startswith(method)
                            for method in self._METHOD_PREFIXES)):
                if key not in self._tcp_prefixes and len(self._tcp_prefixes) >= self.max_states:
                    self._tcp_prefixes.popitem(last=False)
                self._tcp_prefixes[key] = (
                    seq, (seq + len(payload)) & 0xFFFFFFFF, payload, now, {})
                self._tcp_prefixes.move_to_end(key)
        return None

    def prune_stale(self, now: float):
        cutoff = now - self.cooldown
        history_cutoff = now - self.window
        with self._lock:
            stream_cutoff = now - self.STREAM_TIMEOUT_S
            for key, (_, _, _, last_seen, _) in list(self._tcp_prefixes.items()):
                if last_seen < stream_cutoff or last_seen > now:
                    del self._tcp_prefixes[key]
            for key, times in list(self._history.items()):
                active = [ts for ts in times if history_cutoff <= ts <= now]
                if active:
                    self._history[key] = active
                    if len(active) < self.min_requests:
                        self._saturated.discard(key)
                else:
                    del self._history[key]
                    self._saturated.discard(key)
            for key, seen_at in list(self._seen_requests.items()):
                if seen_at < history_cutoff or seen_at > now:
                    del self._seen_requests[key]
            for key, seen_at in list(self._seen.items()):
                if seen_at < cutoff or seen_at > now:
                    del self._seen[key]

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP" or record.get("protocol") != "TCP":
            return None
        src, dst = record.get("src_ip"), record.get("dst_ip")
        dst_port = _normalize_port(record.get("dst_port"))
        src_port = _normalize_port(record.get("src_port"))
        if not src or not dst or dst_port not in (443, 8443) or _is_trusted(src):
            return None
        payload = record.get("payload", b"")
        if not isinstance(payload, bytes):
            return None

        now = _finite_record_timestamp(record)
        if now is None:
            return None
        request_line_bytes = self._extract_request_line(record, payload, now)
        if request_line_bytes is None:
            return None
        key = (src, dst, dst_port)
        with self._lock:
            times = self._history.get(key, [])
            if times and now < times[-1]:
                return None
            # A retransmission repeats the same bytes at the same sequence
            # position. A fresh keep-alive request advances sequence even when
            # its request line is identical, so it remains countable.
            if record.get("tcp_payload_seq") is not None and record.get("src_port") is not None:
                try:
                    seq = int(record["tcp_payload_seq"]) & 0xFFFFFFFF
                    src_port = int(record["src_port"])
                    if 1 <= src_port <= 65535:
                        digest = record.get("tcp_payload_digest")
                        if not isinstance(digest, bytes) or len(digest) != 16:
                            digest = hashlib.blake2s(payload, digest_size=16).digest()
                        identity = (
                            src, src_port, dst, int(dst_port), seq, digest
                        )
                        seen_at = self._seen_requests.get(identity)
                        if seen_at is not None and 0 <= now - seen_at <= self.window:
                            self._seen_requests.move_to_end(identity)
                            return None
                        self._seen_requests[identity] = now
                        self._seen_requests.move_to_end(identity)
                        while len(self._seen_requests) > self.MAX_SEEN_REQUEST_IDENTITIES:
                            self._seen_requests.popitem(last=False)
                except (TypeError, ValueError, OverflowError):
                    # Request counting remains available when TCP metadata is
                    # malformed, but this packet cannot be deduplicated safely.
                    pass
            times = [ts for ts in times if 0 <= now - ts <= self.window]
            if len(times) < self.min_requests:
                self._saturated.discard(key)
            times.append(now)
            if len(times) > self.min_requests:
                times = times[-self.min_requests:]
                self._saturated.add(key)
            if key not in self._history and len(self._history) >= self.max_states:
                evicted, _ = self._history.popitem(last=False)
                self._saturated.discard(evicted)
            self._history[key] = times
            self._history.move_to_end(key)
            if len(times) < self.min_requests:
                return None
            last = self._seen.get(key)
            if last is not None and 0 <= now - last < self.cooldown:
                self._seen.move_to_end(key)
                return None
            if key not in self._seen and len(self._seen) >= self.max_states:
                self._seen.popitem(last=False)
            self._seen[key] = now
            self._seen.move_to_end(key)
            self._history.move_to_end(key)

        request_line = request_line_bytes.decode("ascii", errors="replace")
        return {
            "rule_name": self.name,
            "rule_version": self.rule_version,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": record.get("src_port"),
            "dst_port": dst_port,
            "protocol": "TCP",
            "severity": "medium",
            "confidence": "heuristic",
            "detail": (
                f"{src} sent a cleartext HTTP request to {dst}:{dst_port} "
                "where TLS is normally expected"
            ),
            "evidence": {
                "request_line": request_line,
                "target_port": dst_port,
                "request_count": len(times),
                "request_count_saturated": key in self._saturated,
                "request_threshold": self.min_requests,
                "window_s": self.window,
                "note": "HTTP on a TLS port is unusual but may be intentional in some deployments.",
            },
            "window_start": now,
            "window_end": now,
        }

# Suspicious TLS SNI suffixes indicating dynamic DNS or reverse-proxy tunneling services.
# These are commonly used by attackers to disguise C2 traffic:
#   - ngrok/localtunnel: most common CTF/pentest/malware tunneling
#   - trycloudflare: Cloudflare Quick Tunnels, heavily abused by Cobalt Strike/Sliver C2
#   - bore.pub/zrok: newer open-source tunneling tools
#   - natapp.cn/cpolar.cn/frp.cool: Asia-Pacific APT tunneling infrastructure
# Sources: Suricata ET C2, CISA advisories, Trend Micro APT reports.
_SUSPICIOUS_TLS_SUFFIXES: tuple[str, ...] = (
    # Western tunnel services (most common in red team / commodity malware)
    ".ngrok-free.app", ".ngrok.io", ".ngrok.app",
    ".localtunnel.me", ".loca.lt",
    ".serveo.net", ".portmap.io",
    ".duckdns.org", ".no-ip.biz", ".no-ip.com", ".no-ip.org",
    ".bounceme.net", ".ddns.net", ".redirectme.net",
    # Cloudflare Quick Tunnels (heavily abused for C2 — Cobalt Strike, Sliver, Havoc)
    ".trycloudflare.com",
    # Page hosting tunnels
    ".pagekite.me",
    # Newer open-source tunneling
    ".bore.pub",
    ".zrok.io",
    # Asia-Pacific APT tunneling infrastructure
    ".natapp.cn", ".cpolar.cn", ".frp.cool", ".frps.io",
    ".vip.cpolar.cn", ".vip.cpolar.top",
    # Additional DDNS providers
    ".myddns.rocks", ".3utilities.com", ".wikaba.com",
)


def _extract_tls_sni(payload: bytes) -> str | None:
    """
    Parse SNI only from a complete, length-consistent TLS ClientHello record.
    Returns the decoded hostname if present, or None for incomplete/malformed data.
    """
    if len(payload) < 9 or payload[0] != 0x16 or payload[5] != 0x01:
        return None

    record_end = 5 + int.from_bytes(payload[3:5], "big")
    if record_end > len(payload):
        return None
    handshake_end = 9 + int.from_bytes(payload[6:9], "big")
    if handshake_end > record_end:
        return None

    pos = 43  # record header + handshake header + legacy version + random
    if pos >= handshake_end:
        return None
    session_id_len = payload[pos]
    pos += 1 + session_id_len

    if pos + 2 > handshake_end:
        return None
    cipher_suites_len = int.from_bytes(payload[pos:pos+2], "big")
    if cipher_suites_len < 2 or cipher_suites_len % 2:
        return None
    pos += 2 + cipher_suites_len

    if pos + 1 > handshake_end:
        return None
    compression_len = payload[pos]
    pos += 1 + compression_len

    if pos + 2 > handshake_end:
        return None
    extensions_len = int.from_bytes(payload[pos:pos+2], "big")
    pos += 2
    extensions_end = pos + extensions_len
    if extensions_end != handshake_end:
        return None

    while pos + 4 <= extensions_end:
        ext_type = int.from_bytes(payload[pos:pos+2], "big")
        ext_len = int.from_bytes(payload[pos+2:pos+4], "big")
        pos += 4
        ext_end = pos + ext_len
        if ext_end > extensions_end:
            return None
        if ext_type == 0:  # Server Name Indication (SNI)
            if ext_len < 2:
                return None
            names_end = pos + 2 + int.from_bytes(payload[pos:pos+2], "big")
            if names_end != ext_end:
                return None
            name_pos = pos + 2
            while name_pos + 3 <= names_end:
                name_type = payload[name_pos]
                name_len = int.from_bytes(payload[name_pos+1:name_pos+3], "big")
                name_pos += 3
                if name_pos + name_len > names_end:
                    return None
                if name_type == 0:
                    if name_len == 0:
                        return None
                    try:
                        return payload[name_pos:name_pos+name_len].decode("ascii")
                    except UnicodeDecodeError:
                        return None
                name_pos += name_len
            return None
        pos = ext_end
    if pos != extensions_end:
        return None
    return None


class TlsAnomalyRule:
    """
    Detects TLS handshake anomalies on ports 443, 4443, 8443, 9443, 5223, 8083:
    1. Literal IP in TLS SNI (RFC 6066 violation; common indicator of direct-IP botnet C2).
    2. Dynamic DNS / Reverse-proxy tunneling services in SNI (*.ngrok-free.app, *.trycloudflare.com,
       *.duckdns.org, *.natapp.cn, etc.) used to disguise C2 communication or data exfiltration.
    Port expansion covers: XMPP-SSL (5223), MQTT-TLS (8083), alternative HTTPS C2 (4443, 9443).
    """
    name = "TLS_ANOMALY"
    rule_version = "1.8"
    ALERT_COOLDOWN_S = 60.0
    MAX_TRACKED_FLOWS = 4096
    MAX_CLIENT_HELLO_BYTES = 16_389
    STREAM_TIMEOUT_S = 30.0
    TLS_PORTS = frozenset({443, 4443, 8443, 9443, 5223, 8083})

    def __init__(self, cooldown: float = 60.0, enabled: bool = True):
        self.cooldown = _nonnegative_float_setting(
            cooldown, 60.0, "TLS_COOLDOWN_S")
        self.enabled = bool(enabled)
        self._lock = threading.Lock()
        # Key: (src_ip, dst_ip, anomaly_type) -> float (last alert timestamp)
        self._seen: OrderedDict[tuple, float] = OrderedDict()
        # Directional 4-tuple -> (start seq, next seq, ClientHello prefix,
        # last-seen time, nearby future segments). Independent of alert state.
        self._hello_prefixes: OrderedDict[
            tuple[str, int, str, int],
            tuple[int, int, bytes, float, dict[int, bytes]],
        ] = OrderedDict()

    @classmethod
    def _is_client_hello_prefix(cls, data: bytes) -> bool:
        if not data or data[0] != 0x16:
            return False
        if len(data) == 1:
            return True
        if data[1] != 0x03:
            return False
        if len(data) >= 3 and data[2] > 0x04:
            return False
        if len(data) >= 5:
            record_len = int.from_bytes(data[3:5], "big")
            if not 4 <= record_len <= cls.MAX_CLIENT_HELLO_BYTES - 5:
                return False
        if len(data) >= 6 and data[5] != 0x01:
            return False
        return True

    def _extract_sni(self, record: dict, payload: bytes, now: float) -> str | None:
        sni = _extract_tls_sni(payload)
        try:
            src_port, dst_port = int(record["src_port"]), int(record["dst_port"])
            seq = int(record["tcp_payload_seq"]) & 0xFFFFFFFF
            key = (str(record["src_ip"]), src_port,
                   str(record["dst_ip"]), dst_port)
        except (KeyError, TypeError, ValueError, OverflowError):
            return sni
        if not 1 <= src_port <= 65535 or dst_port not in self.TLS_PORTS:
            return sni

        if sni:
            with self._lock:
                state = self._hello_prefixes.get(key)
                if state is not None and now >= state[3]:
                    self._hello_prefixes.pop(key, None)
            return sni

        if not payload:
            return None
        with self._lock:
            state = self._hello_prefixes.get(key)
            if state is not None:
                start_seq, expected_seq, prefix, last_seen, pending = state
                if now < last_seen:
                    return None
                if now - last_seen > self.STREAM_TIMEOUT_S:
                    self._hello_prefixes.pop(key, None)
                    state = None
                elif seq == start_seq and payload == prefix:
                    self._hello_prefixes[key] = (
                        start_seq, expected_seq, prefix, now, pending)
                    self._hello_prefixes.move_to_end(key)
                    return None
                elif seq == expected_seq:
                    combined = prefix + payload
                    next_seq = (seq + len(payload)) & 0xFFFFFFFF
                    pending = dict(pending)
                    while next_seq in pending:
                        next_payload = pending.pop(next_seq)
                        combined += next_payload
                        next_seq = (next_seq + len(next_payload)) & 0xFFFFFFFF
                    sni = _extract_tls_sni(combined)
                    if sni:
                        self._hello_prefixes.pop(key, None)
                        return sni
                    if (len(combined) <= self.MAX_CLIENT_HELLO_BYTES
                            and self._is_client_hello_prefix(combined)):
                        self._hello_prefixes[key] = (
                            start_seq, next_seq, combined, now, pending)
                        self._hello_prefixes.move_to_end(key)
                    else:
                        self._hello_prefixes.pop(key, None)
                    return None
                else:
                    delta = ((seq - expected_seq + (1 << 31)) % (1 << 32)) - (1 << 31)
                    if delta > 0:
                        pending_bytes = sum(len(part) for part in pending.values())
                        if (delta <= self.MAX_CLIENT_HELLO_BYTES
                                and len(pending) < 4
                                and len(prefix) + pending_bytes + len(payload)
                                <= self.MAX_CLIENT_HELLO_BYTES):
                            pending.setdefault(seq, payload)
                            self._hello_prefixes[key] = (
                                start_seq, expected_seq, prefix, now, pending)
                            self._hello_prefixes.move_to_end(key)
                            return None
                    self._hello_prefixes.pop(key, None)

            if self._is_client_hello_prefix(payload):
                if len(payload) > self.MAX_CLIENT_HELLO_BYTES:
                    return None
                if key not in self._hello_prefixes and len(self._hello_prefixes) >= self.MAX_TRACKED_FLOWS:
                    self._hello_prefixes.popitem(last=False)
                self._hello_prefixes[key] = (
                    seq, (seq + len(payload)) & 0xFFFFFFFF, payload, now, {})
                self._hello_prefixes.move_to_end(key)
        return None

    def prune_stale(self, now: float):
        cutoff = now - self.cooldown
        with self._lock:
            for k in list(self._seen):
                if self._seen[k] < cutoff:
                    del self._seen[k]
            stream_cutoff = now - self.STREAM_TIMEOUT_S
            for key, (_, _, _, last_seen, _) in list(self._hello_prefixes.items()):
                if last_seen < stream_cutoff or last_seen > now:
                    del self._hello_prefixes[key]

    def check(self, record: dict) -> dict | None:
        if not self.enabled:
            return None
        if record.get("type") != "IP" or record.get("protocol") != "TCP":
            return None

        src_ip = record.get("src_ip", "")
        dst_ip = record.get("dst_ip", "")
        dst_port = _normalize_port(record.get("dst_port"))
        if not src_ip or not dst_ip or _is_trusted(src_ip):
            return None

        if dst_port not in self.TLS_PORTS:
            return None

        payload = record.get("tls_payload") or record.get("payload", b"")
        if not isinstance(payload, bytes) or not payload:
            return None

        now = _finite_record_timestamp(record)
        if now is None:
            return None
        sni = self._extract_sni(record, payload, now)
        if not sni:
            return None

        sni_clean = sni.lower().strip()
        anomaly_type = None
        detail = ""

        # Check 1: Literal IP in SNI (RFC 6066 prohibits literal IPs in HostName)
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", sni_clean) or ":" in sni_clean:
            anomaly_type = "DIRECT_IP_SNI"
            detail = (
                f"{src_ip} sent TLS Client Hello to {dst_ip}:{dst_port} with literal IP "
                f"in SNI ('{sni}') — violates RFC 6066, possible C2 beacon"
            )
        # Check 2: Suspicious dynamic DNS / reverse-proxy tunnel in SNI
        elif any(sni_clean.endswith(suffix) for suffix in _SUSPICIOUS_TLS_SUFFIXES):
            anomaly_type = "SUSPICIOUS_TUNNEL_SNI"
            detail = (
                f"{src_ip} sent TLS Client Hello to {dst_ip}:{dst_port} with suspicious "
                f"tunneling domain in SNI ('{sni}') — possible covert C2 channel"
            )

        if not anomaly_type:
            return None

        key = (src_ip, dst_ip, anomaly_type)

        with self._lock:
            last = self._seen.get(key)
            if last is not None and now - last < self.cooldown:
                self._seen.move_to_end(key)
                return None
            if key not in self._seen and len(self._seen) >= self.MAX_TRACKED_FLOWS:
                self._seen.popitem(last=False)
            self._seen[key] = now
            self._seen.move_to_end(key)

        logger.debug(f"{self.name} [{anomaly_type}] fired: {detail}")
        return {
            "rule_name": self.name,
            "rule_version": self.rule_version,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": record.get("src_port"),
            "dst_port": dst_port,
            "protocol": "TCP",
            "severity": "high" if anomaly_type == "DIRECT_IP_SNI" else "medium",
            "confidence": "high" if anomaly_type == "DIRECT_IP_SNI" else "heuristic",
            "detail": detail,
            "evidence": {
                "sni": sni,
                "anomaly_type": anomaly_type,
                "target_port": dst_port,
            },
            "window_start": now,
            "window_end": now,
        }


# =============================================================================
# Rule 17: TCP Zero-Window / Sockstress DoS Detection
# =============================================================================

class TcpZeroWindowRule:
    """
    Detects sustained TCP zero-window advertisements and reports whether the
    sender is the connection initiator, responder, or unknown. The signal can
    indicate Sockstress, but ordinary receiver backpressure is also possible.
    """
    name = "TCP_ZERO_WINDOW"
    rule_version = "1.9"

    def __init__(self, threshold: int = 20, window: int = 10, cooldown: float = 60.0,
                 max_tracked: int = 4096, enabled: bool = True,
                 min_distinct_flows: int = 3):
        self.threshold = _positive_setting(
            threshold, 20, "TCP_ZERO_WINDOW_THRESHOLD")
        self.window = _positive_setting(
            window, 10, "TCP_ZERO_WINDOW_WINDOW")
        self.cooldown = _nonnegative_float_setting(
            cooldown, 60.0, "TCP_ZERO_WINDOW_COOLDOWN")
        self.max_tracked = max(100, _positive_setting(
            max_tracked, 4096, "TCP_ZERO_WINDOW_MAX_TRACKED"))
        self.enabled = bool(enabled)
        self.min_distinct_flows = max(2, _positive_setting(
            min_distinct_flows, 3, "TCP_ZERO_WINDOW_MIN_FLOWS"))
        self._lock = threading.Lock()
        self._handshake_ttl = max(120.0, self.window * 10.0)
        # (canonical connection key) -> (initiator endpoint, SYN timestamp)
        self._initiators: dict[tuple, tuple[tuple[str, int], float]] = {}
        # (src_ip, dst_ip, role) -> deque[(timestamp, destination port, source port)]
        # Only the latest threshold-sized evidence window is needed to decide
        # whether one flow or several distinct flows meet the trigger. Keeping
        # more events per key would let a packet flood grow memory without bound.
        self._history: dict[tuple[str, str, str], deque] = {}
        # Same key as _history -> last alert timestamp
        self._fired: dict[tuple[str, str, str], float] = {}

    @staticmethod
    def _connection_key(src_ip: str, src_port, dst_ip: str, dst_port):
        try:
            source = (str(src_ip), int(src_port))
            destination = (str(dst_ip), int(dst_port))
        except (TypeError, ValueError):
            return None
        return tuple(sorted((source, destination)))

    def prune_stale(self, now: float):
        cutoff = now - self.window
        cooldown_cutoff = now - self.cooldown
        handshake_cutoff = now - self._handshake_ttl
        with self._lock:
            for k in list(self._history):
                dq = self._history[k]
                while dq and dq[0][0] < cutoff:
                    dq.popleft()
                if not dq:
                    del self._history[k]
            for k in list(self._fired):
                if self._fired[k] < cooldown_cutoff:
                    del self._fired[k]
            for key, (_, timestamp) in list(self._initiators.items()):
                if timestamp < handshake_cutoff:
                    del self._initiators[key]

    def check(self, record: dict) -> dict | None:
        if not self.enabled or record.get("type") != "IP" or record.get("protocol") != "TCP":
            return None

        tcp_flags = record.get("tcp_flags")
        if tcp_flags is None:
            return None
        try:
            tcp_flags = int(tcp_flags)
        except (TypeError, ValueError, OverflowError):
            return None
        if tcp_flags & 0x04:  # RST does not advertise receiver capacity.
            return None

        src_ip = record.get("src_ip", "")
        dst_ip = record.get("dst_ip", "")
        src_port = _normalize_port(record.get("src_port"))
        dst_port = _normalize_port(record.get("dst_port"))
        if not src_ip or not dst_ip:
            return None

        now = _finite_record_timestamp(record)
        if now is None:
            return None
        connection_key = self._connection_key(src_ip, src_port, dst_ip, dst_port)

        # Learn direction from the initial SYN so an alert can distinguish
        # client-side zero windows from receiver-side backpressure.
        if tcp_flags & 0x02 and not tcp_flags & 0x10:
            if connection_key is not None:
                initiator_endpoint = (str(src_ip), src_port)
                with self._lock:
                    if (connection_key not in self._initiators
                            and len(self._initiators) >= self.max_tracked):
                        self._initiators.pop(next(iter(self._initiators)))
                    self._initiators[connection_key] = (initiator_endpoint, now)
            return None

        # SYN and SYN-ACK windows are handshake negotiation, not established-
        # flow backpressure. Count only ACK-bearing non-SYN packets, excluding
        # RST above.
        if tcp_flags & 0x02:
            return None
        raw_win = record.get("tcp_window")
        try:
            win_val = int(raw_win) if raw_win is not None else None
        except (TypeError, ValueError, OverflowError):
            win_val = None
        if not (tcp_flags & 0x10) or win_val != 0:
            return None
        if _is_trusted(src_ip):
            return None

        role = "unknown"
        if connection_key is not None:
            with self._lock:
                initiator = self._initiators.get(connection_key)
                if initiator is not None:
                    endpoint, syn_time = initiator
                    if 0 <= now - syn_time <= self._handshake_ttl:
                        advertiser = (str(src_ip), src_port)
                        role = "initiator" if advertiser == endpoint else "responder"
                    elif now - syn_time > self._handshake_ttl:
                        del self._initiators[connection_key]

        key = (src_ip, dst_ip, role)
        cutoff = now - self.window

        with self._lock:
            # Bound total tracked keys to prevent state exhaustion.
            if key not in self._history and len(self._history) >= self.max_tracked:
                evicted = next(iter(self._history))
                self._history.pop(evicted)
                self._fired.pop(evicted, None)

            dq = self._history.get(key)
            if dq is None:
                dq = deque(maxlen=self.threshold)
                self._history[key] = dq
            # Ignore out-of-order records rather than corrupting deque expiry.
            if dq and now < dq[-1][0]:
                return None
            dq.append((now, dst_port, src_port))
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            count = len(dq)
            flow_counts = {}
            for _, flow_dst_port, flow_src_port in dq:
                flow_key = (flow_src_port, flow_dst_port)
                flow_counts[flow_key] = flow_counts.get(flow_key, 0) + 1
            max_flow_count = max(flow_counts.values(), default=0)
            detection_mode = None
            if max_flow_count >= self.threshold:
                detection_mode = "single_flow"
            elif count >= self.threshold and len(flow_counts) >= self.min_distinct_flows:
                detection_mode = "multi_flow"
            if detection_mode is not None:
                last_fired = self._fired.get(key, 0.0)
                if now - last_fired < self.cooldown:
                    return None
                if key not in self._fired and len(self._fired) >= self.max_tracked:
                    self._fired.pop(next(iter(self._fired)))
                self._fired[key] = now
                window_start = dq[0][0]
                detail = (
                    f"{src_ip} sent at least {count} TCP zero-window advertisements to {dst_ip} "
                    f"across {len(flow_counts)} flow(s) in {self.window}s "
                    f"(≥{self.threshold}, max {max_flow_count} on one flow, "
                    f"mode: {detection_mode}, advertiser role: {role}) "
                    "— possible Sockstress or TCP receiver backpressure"
                )
                logger.debug(f"TCP_ZERO_WINDOW fired: {detail}")
                return {
                    "rule_name": self.name,
                    "rule_version": self.rule_version,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": "TCP",
                    "severity": "medium",
                    "confidence": "heuristic",
                    "detail": detail,
                    "evidence": {
                        "zero_window_count": count,
                        "zero_window_count_is_lower_bound": True,
                        "distinct_flow_count": len(flow_counts),
                        "max_flow_count": max_flow_count,
                        "detection_mode": detection_mode,
                        "min_distinct_flows": self.min_distinct_flows,
                        "threshold": self.threshold,
                        "window_s": self.window,
                        "target_port": dst_port,
                        "advertiser_role": role,
                    },
                    "window_start": window_start,
                    "window_end": now,
                }
        return None


# =============================================================================
# Alert Spool & Rule Engine Orchestrator
# =============================================================================

class AlertSpool:
    """
    Durable, bounded local disk spool for alert persistence during database outages.

    Guarantees:
    - Bounded disk usage: capped at max_size alerts (default 5,000).
    - Thread-safe append, drain, count, and clear operations.
    - Preserves alerts on disk when primary database connection or writes fail.
    - Drains spooled alerts into the database upon recovery, maintaining idempotency.
    - Rejects new additions when capacity is reached, enabling explicit backpressure drops.
    """
    def __init__(self, spool_path: str, max_size: int = 5000):
        self.spool_path = spool_path
        self.max_size = max_size
        self._lock = threading.Lock()
        self._count = 0
        self._init_count()

    def _init_count(self):
        """Count existing entries in spool file on startup."""
        if not os.path.exists(self.spool_path):
            self._count = 0
            return
        count = 0
        try:
            with open(self.spool_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        count += 1
            self._count = count
        except Exception as exc:
            logger.warning(f"Error reading spool file {self.spool_path}: {exc}")
            self._count = 0

    @staticmethod
    def _fsync_parent(path: str):
        """Persist directory-entry changes where the platform supports it."""
        directory = os.path.dirname(os.path.abspath(path)) or "."
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        fd = os.open(directory, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def count(self) -> int:
        with self._lock:
            return self._count

    def append(self, alert: dict) -> bool:
        """
        Append an alert to the spool file.
        Returns True if spooled successfully, False if spool is full or unwriteable.
        """
        with self._lock:
            if self._count >= self.max_size:
                return False
            try:
                dirname = os.path.dirname(self.spool_path)
                if dirname:
                    os.makedirs(dirname, exist_ok=True)
                with open(self.spool_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(alert, default=str) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                # Persist directory metadata too when the spool file is new.
                self._fsync_parent(self.spool_path)
                self._count += 1
                return True
            except Exception as exc:
                logger.error(f"Failed to append alert to spool {self.spool_path}: {exc}")
                return False

    def drain(self, write_fn) -> int:
        """
        Attempt to drain all spooled alerts using write_fn(alert).
        If write_fn succeeds for an alert, it is marked as persisted.
        If write_fn fails on an alert, draining halts immediately,
        unpersisted alerts remain in the spool file, and the exception is re-raised.
        Returns the number of alerts successfully recovered and written.
        """
        with self._lock:
            if self._count == 0 or not os.path.exists(self.spool_path):
                return 0

            persisted = 0
            remaining = []
            drain_err = None

            try:
                with open(self.spool_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception as exc:
                logger.error(f"Failed to read spool during drain: {exc}")
                raise

            for line in lines:
                line_s = line.strip()
                if not line_s:
                    continue
                if drain_err is not None:
                    remaining.append(line)
                    continue

                try:
                    alert = json.loads(line_s)
                    write_fn(alert)
                    persisted += 1
                except Exception as exc:
                    drain_err = exc
                    remaining.append(line)

            try:
                if remaining:
                    tmp_path = self.spool_path + ".tmp"
                    with open(tmp_path, "w", encoding="utf-8") as f:
                        f.writelines(remaining)
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(tmp_path, self.spool_path)
                    self._count = len(remaining)
                    self._fsync_parent(self.spool_path)
                else:
                    if os.path.exists(self.spool_path):
                        os.remove(self.spool_path)
                    self._count = 0
                    self._fsync_parent(self.spool_path)
            except Exception as exc:
                logger.error(f"Failed to update spool file after drain: {exc}")
                raise

            if drain_err is not None:
                raise drain_err

            return persisted

    def clear(self):
        with self._lock:
            try:
                if os.path.exists(self.spool_path):
                    os.remove(self.spool_path)
            except Exception:
                pass
            self._count = 0


class RuleEngine:
    """
    Runs all rules against every packet record.
    Writes any resulting alerts to the database asynchronously with local disk spooling.
    Also tracks seen devices for the dashboard device list.

    All rules are run for every packet — no early exit. A packet may
    legitimately trigger multiple independent rules; both alerts are
    valuable and should be persisted.
    """

    def __init__(self, db_conn, blocklist, cfg, event_clock=None):
        from storage.db import write_alert, upsert_device
        import engine.rules as _rules_mod
        import queue

        self._write_alert  = write_alert
        self._upsert_device = upsert_device
        self._event_clock = event_clock

        # Load trusted hosts from config into module-level set
        trusted = getattr(cfg, "TRUSTED_HOSTS", set())
        _rules_mod.TRUSTED_HOSTS.clear()
        _rules_mod.TRUSTED_HOSTS.update(trusted)
        if trusted:
            logger.info(f"Trusted hosts loaded: {trusted}")

        self.rules = [
            BlocklistRule(blocklist),
            TcpFlagAnomalyRule(),
            PortScanRule(cfg.PORT_SCAN_THRESHOLD, cfg.TIME_WINDOW),
            UdpScanRule(
                getattr(cfg, "UDP_SCAN_THRESHOLD", 15), cfg.TIME_WINDOW
            ),
            UdpFloodRule(
                threshold=getattr(cfg, "UDP_FLOOD_THRESHOLD", 50),
                window=getattr(cfg, "UDP_FLOOD_WINDOW", 5),
                web_threshold=getattr(cfg, "UDP_FLOOD_WEB_THRESHOLD", 500),
            ),
            TcpStealthScanRule(
                getattr(cfg, "TCP_STEALTH_SCAN_THRESHOLD", 15), cfg.TIME_WINDOW
            ),
            SynFloodRule(
                cfg.SYN_FLOOD_THRESHOLD, cfg.TIME_WINDOW,
                rst_threshold=getattr(cfg, "RST_FLOOD_THRESHOLD", 100),
                rst_window=getattr(cfg, "TIME_WINDOW", 10),
                rst_response_grace=getattr(cfg, "RST_RESPONSE_GRACE_SECONDS", 5.0),
            ),
            DistributedSynFloodRule(
                getattr(cfg, "DISTRIBUTED_SYN_FLOOD_THRESHOLD", 500),
                getattr(cfg, "DISTRIBUTED_SYN_FLOOD_MIN_SOURCES", 20),
                cfg.TIME_WINDOW,
            ),
            IcmpSweepRule(
                getattr(cfg, "ICMP_SWEEP_THRESHOLD", 12), cfg.TIME_WINDOW
            ),
            IcmpFloodRule(
                threshold=getattr(cfg, "ICMP_FLOOD_THRESHOLD", 50),
                window=getattr(cfg, "ICMP_FLOOD_WINDOW", 5),
            ),
            ArpSpoofRule(cfg.ARP_TABLE_PATH),
            PayloadRule(
                max_bytes=getattr(cfg, "PAYLOAD_MAX_BYTES", 512),
                enabled=getattr(cfg, "PAYLOAD_INSPECTION", True),
                alert_cooldown=getattr(cfg, "PAYLOAD_ALERT_COOLDOWN_S", 60.0),
            ),
            DnsRule(
                entropy_threshold=getattr(cfg, "DNS_ENTROPY_THRESHOLD", 3.8),
                max_query_len=getattr(cfg, "DNS_QUERY_MAX_LEN", 60),
                freq_threshold=getattr(cfg, "DNS_FREQ_THRESHOLD", 20),
                freq_window=getattr(cfg, "DNS_FREQ_WINDOW", 60),
                subdomain_threshold=getattr(cfg, "DNS_SUBDOMAIN_THRESHOLD", 20),
                subdomain_window=getattr(cfg, "DNS_SUBDOMAIN_WINDOW", 60),
            ),
            BruteForceRule(
                threshold=getattr(cfg, "BRUTE_FORCE_THRESHOLD", 20),
                window=getattr(cfg, "BRUTE_FORCE_WINDOW", 60),
                extra_ports=getattr(cfg, "BRUTE_FORCE_EXTRA_PORTS", ()),
            ),
            SlowPortScanRule(
                threshold=getattr(cfg, "SLOW_SCAN_THRESHOLD", 30),
                window=getattr(cfg, "SLOW_SCAN_WINDOW", 120),
                cooldown=getattr(cfg, "SLOW_SCAN_COOLDOWN_S", 120.0),
            ),
            DataExfiltrationRule(
                byte_threshold=getattr(cfg, "DATA_EXFIL_BYTE_THRESHOLD", 50000),
                window=getattr(cfg, "DATA_EXFIL_WINDOW", 30),
                web_byte_threshold=getattr(cfg, "DATA_EXFIL_WEB_BYTE_THRESHOLD", 1000000),
            ),
            TlsAnomalyRule(
                cooldown=getattr(cfg, "TLS_COOLDOWN_S", 60.0),
                enabled=getattr(cfg, "TLS_INSPECTION", True),
            ),
            CleartextHttpOnTlsPortRule(
                cooldown=getattr(cfg, "CLEAR_HTTP_TLS_COOLDOWN_S", 300.0),
                window=getattr(cfg, "CLEAR_HTTP_TLS_WINDOW_S", 300.0),
                min_requests=getattr(cfg, "CLEAR_HTTP_TLS_MIN_REQUESTS", 2),
            ),
            TcpZeroWindowRule(
                threshold=getattr(cfg, "TCP_ZERO_WINDOW_THRESHOLD", 20),
                window=getattr(cfg, "TCP_ZERO_WINDOW_WINDOW", 10),
                cooldown=getattr(cfg, "TCP_ZERO_WINDOW_COOLDOWN", 60.0),
                min_distinct_flows=getattr(cfg, "TCP_ZERO_WINDOW_MIN_FLOWS", 3),
            ),
        ]

        # Bounded alert queue + durable disk spool backup
        alert_q_max = getattr(cfg, "ALERT_QUEUE_MAXSIZE", 1000)
        self._alert_queue: queue.Queue = queue.Queue(maxsize=alert_q_max)

        spool_path = getattr(cfg, "ALERT_SPOOL_PATH", None)
        if not spool_path:
            sqlite_path = getattr(cfg, "SQLITE_PATH", "alerts.db")
            if sqlite_path and sqlite_path != ":memory:":
                spool_path = sqlite_path + ".spool.jsonl"
            else:
                import tempfile
                spool_path = os.path.join(tempfile.gettempdir(), f"netguard_spool_{os.getpid()}_{id(self)}.jsonl")
        spool_max = getattr(cfg, "ALERT_SPOOL_MAX_SIZE", 5000)
        self._spool = AlertSpool(spool_path, max_size=spool_max)

        # Device queue is bounded with deduplication and periodic refresh
        DEVICE_REFRESH_INTERVAL = 300  # 5 minutes
        self._device_refresh_s: float = DEVICE_REFRESH_INTERVAL
        self._device_queue: queue.Queue = queue.Queue(maxsize=1000)
        self._seen_devices: dict = {}
        self._seen_device_lock = threading.Lock()
        self._seen_device_max_keys = 65_536

        self._stats = {
            "alert_writes": 0,
            "device_writes": 0,
            "alerts_dropped": 0,
            "devices_dropped": 0,
            "alerts_spooled": 0,
            "spool_recoveries": 0,
            "shutdown_timeout": False,
        }
        self._stop_event = threading.Event()

        self._alert_writer = threading.Thread(
            target=self._alert_writer_loop, daemon=True, name="alert-writer"
        )
        self._device_writer = threading.Thread(
            target=self._device_writer_loop, daemon=True, name="device-writer"
        )
        self._alert_writer.start()
        self._device_writer.start()

        # GC thread for stateful rules
        self._gc_thread = threading.Thread(
            target=self._gc_loop, daemon=True, name="rule-gc"
        )
        self._gc_thread.start()

        import atexit
        atexit.register(self.flush)

    def prune_stale(self, now: float = None):
        """
        Prune stale stateful rule histories.
        If *now* is not specified, queries self._event_clock() or time.time().
        Enables deterministic testing and on-demand GC without waiting for the
        background GC thread loop.
        """
        if now is None:
            clock = self._event_clock or time.time
            now = clock()
        for rule in self.rules:
            if hasattr(rule, "prune_stale"):
                try:
                    rule.prune_stale(now)
                except Exception as e:
                    logger.error(f"Rule GC error for {rule.name}: {e}")

    def _gc_loop(self):
        """
        Periodically prune stale stateful rule histories.
        clock: uses self._event_clock if provided (e.g. during replay),
        otherwise falls back to time.time.
        """
        while not self._stop_event.is_set():
            time.sleep(10)
            self.prune_stale()

    def _alert_writer_loop(self):
        """
        Drain the alert queue and persist each alert to the DB.

        Reliability & Recovery Architecture:
          - Bounded in-memory queue + durable local disk spool (AlertSpool).
          - Exponential backoff with cap for connection failures (0.5s to 5.0s max).
          - Transient write failures trigger reconnection and retry before falling back
            to durable spooling (never silent drops).
          - When DB connection recovers, spooled alerts are automatically drained and
            persisted before accepting new queue traffic.
          - Idempotent writes via idempotency_key prevent duplicate database rows.
          - Bounded memory and bounded disk usage ensure persistent outages cannot
            cause memory leaks or tight loops.
        """
        import queue as _queue
        from storage.db import get_connection, init_db

        conn = None
        consecutive_failures = 0
        last_connect_time = 0.0

        def _get_backoff():
            return min(5.0, 0.2 * (2 ** min(consecutive_failures, 4)))

        def _try_connect():
            nonlocal conn, consecutive_failures, last_connect_time
            last_connect_time = time.time()
            try:
                c = get_connection()
                init_db(c)
                conn = c
                consecutive_failures = 0
                logger.info("Alert writer: connected to database.")
                return True
            except Exception as exc:
                consecutive_failures += 1
                conn = None
                delay = _get_backoff()
                logger.warning(
                    f"Alert writer: DB connection failed ({exc}). Retrying in {delay:.1f}s..."
                )
                return False

        def _drain_spool():
            nonlocal conn
            if conn is None or self._spool.count() == 0:
                return
            def _write_spooled(spooled_alert):
                self._write_alert(conn, spooled_alert)
                self._stats["alert_writes"] += 1
                self._stats["spool_recoveries"] += 1
            try:
                recovered = self._spool.drain(_write_spooled)
                if recovered > 0:
                    logger.info(f"Alert writer: recovered {recovered} spooled alerts into DB.")
            except Exception as exc:
                logger.warning(f"Alert writer: error draining spool ({exc}).")
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None

        # Initial connection attempt
        _try_connect()
        # Drain any alerts already spooled from earlier runs
        _drain_spool()

        while True:
            # If not connected, check if it's time to retry connection
            if conn is None and not self._stop_event.is_set():
                if time.time() - last_connect_time >= _get_backoff():
                    if _try_connect():
                        _drain_spool()

            try:
                sentinel, data = self._alert_queue.get(timeout=0.1)
                if sentinel == "stop":
                    self._alert_queue.task_done()
                    break

                if conn is not None and self._spool.count() > 0:
                    _drain_spool()

                if conn is not None:
                    # Attempt write with retry
                    write_ok = False
                    for attempt in range(2):
                        try:
                            self._write_alert(conn, data)
                            self._stats["alert_writes"] += 1
                            write_ok = True
                            break
                        except Exception as write_err:
                            logger.warning(
                                f"Alert write transient failure (attempt {attempt+1}/2): {write_err}"
                            )
                            try:
                                conn.close()
                            except Exception:
                                pass
                            conn = None
                            if attempt == 0:
                                if _try_connect():
                                    continue
                            break

                    if not write_ok:
                        # Write failed even after retry/reconnect -> spool to disk
                        spooled = self._spool.append(data)
                        if spooled:
                            self._stats["alerts_spooled"] = self._spool.count()
                            logger.warning(
                                f"Alert write failed after retry — spooled to disk: rule={data.get('rule_name')}"
                            )
                        else:
                            self._stats["alerts_dropped"] += 1
                            logger.error(
                                f"Alert spool saturated/failed — alert dropped: rule={data.get('rule_name')} (drop count: {self._stats['alerts_dropped']})"
                            )
                else:
                    # DB is currently disconnected -> buffer to durable spool
                    spooled = self._spool.append(data)
                    if spooled:
                        self._stats["alerts_spooled"] = self._spool.count()
                        logger.warning(
                            f"DB unavailable — alert spooled to disk: rule={data.get('rule_name')}"
                        )
                    else:
                        self._stats["alerts_dropped"] += 1
                        logger.error(
                            f"DB unavailable & spool saturated — alert dropped: rule={data.get('rule_name')} (drop count: {self._stats['alerts_dropped']})"
                        )

                self._alert_queue.task_done()
            except _queue.Empty:
                if self._stop_event.is_set():
                    break

        # -------------------------------------------------------------
        # Clean Shutdown: Drain queue and attempt final spool drain
        # -------------------------------------------------------------
        while True:
            try:
                sentinel, data = self._alert_queue.get_nowait()
                if sentinel == "alert":
                    if conn is not None:
                        try:
                            self._write_alert(conn, data)
                            self._stats["alert_writes"] += 1
                        except Exception:
                            if self._spool.append(data):
                                self._stats["alerts_spooled"] = self._spool.count()
                            else:
                                self._stats["alerts_dropped"] += 1
                    else:
                        if self._spool.append(data):
                            self._stats["alerts_spooled"] = self._spool.count()
                        else:
                            self._stats["alerts_dropped"] += 1
                self._alert_queue.task_done()
            except _queue.Empty:
                break

        # If DB connection was offline earlier, attempt reconnect to drain spool
        if conn is None:
            _try_connect()

        if conn is not None:
            _drain_spool()
            try:
                conn.close()
            except Exception:
                pass
            conn = None

        self._stats["alerts_spooled"] = self._spool.count()

    def _device_writer_loop(self):
        """Drain the device queue. Drops and connection failures are non-fatal."""
        import queue as _queue
        from storage.db import get_connection

        conn = None
        while not self._stop_event.is_set() or not self._device_queue.empty():
            if conn is None:
                try:
                    conn = get_connection()
                except Exception:
                    conn = None
            try:
                sentinel, data = self._device_queue.get(timeout=0.1)
                if sentinel == "stop":
                    self._device_queue.task_done()
                    break
                if conn is not None:
                    try:
                        self._upsert_device(conn, data["mac"], data["ip"])
                        self._stats["device_writes"] += 1
                    except Exception as e:
                        logger.error(f"Device write error: {e}")
                else:
                    self._stats["devices_dropped"] += 1
                self._device_queue.task_done()
            except _queue.Empty:
                if self._stop_event.is_set():
                    break

        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    def flush(self):
        """
        Signal stop and drain pending writes reliably.
        Waits for alert writes and spooling to complete or until writer thread exits.
        Hard timeout prevents infinite hang.
        """
        self._stop_event.set()

        # Send stop sentinels
        try:
            self._alert_queue.put(("stop", None), timeout=1)
        except Exception:
            pass
        try:
            self._device_queue.put_nowait(("stop", None))
        except Exception:
            pass

        # Wait for the alert writer thread to exit
        self._alert_writer.join(timeout=5)
        if self._alert_writer.is_alive():
            logger.warning(
                f"Alert writer thread still alive after flush timeout. "
                f"Alerts written: {self._stats['alert_writes']}, "
                f"queue depth: {self._alert_queue.qsize()}"
            )
            self._stats["shutdown_timeout"] = True

        self._device_writer.join(timeout=2)
        if self._gc_thread.is_alive():
            self._gc_thread.join(timeout=1)

        # Flush per-rule state (e.g. ARP table to disk)
        for rule in self.rules:
            if hasattr(rule, "flush"):
                try:
                    rule.flush()
                except Exception as e:
                    logger.error(f"Rule flush error: {e}")

        self._stats["alerts_spooled"] = self._spool.count()
        logger.info(
            f"RuleEngine shutdown: alerts={self._stats['alert_writes']}, "
            f"devices={self._stats['device_writes']}, "
            f"alerts_dropped={self._stats['alerts_dropped']}, "
            f"alerts_spooled={self._stats['alerts_spooled']}, "
            f"devices_dropped={self._stats['devices_dropped']}"
        )

    def check(self, record: dict):
        # Device refresh: enqueue device write on first-seen OR after the
        # refresh interval has elapsed so last_seen stays current.
        mac = record.get("src_mac")
        ip  = record.get("src_ip")
        if mac and ip:
            dev_key = (mac, ip)
            now_wall = time.time()
            import queue as _queue
            with self._seen_device_lock:
                last_write = self._seen_devices.get(dev_key, 0.0)
                if now_wall - last_write >= self._device_refresh_s:
                    try:
                        self._device_queue.put_nowait(("device", {"mac": mac, "ip": ip}))
                    except _queue.Full:
                        self._stats["devices_dropped"] += 1
                        logger.warning(f"Device queue full — dropped ({mac}, {ip})")
                    else:
                        # Record only successful enqueue so queue pressure does
                        # not suppress retries for the full refresh interval.
                        if (dev_key not in self._seen_devices
                                and len(self._seen_devices) >= self._seen_device_max_keys):
                            self._seen_devices.pop(next(iter(self._seen_devices)))
                        self._seen_devices.pop(dev_key, None)
                        self._seen_devices[dev_key] = now_wall

        # Run ALL rules — no early exit
        for rule in self.rules:
            try:
                alert = rule.check(record)
                if alert:
                    # Persist only finite event times. A few packet-local
                    # detections intentionally survive malformed timestamps;
                    # use receipt time for those alerts so SQLite and dashboard
                    # consumers never receive NaN or non-numeric time values.
                    alert_timestamp = _finite_record_timestamp(record)
                    alert["timestamp"] = (
                        alert_timestamp if alert_timestamp is not None else time.time()
                    )
                    # Serialise evidence dict to JSON string for DB persistence
                    if "evidence" in alert:
                        alert["evidence_json"] = json.dumps(alert["evidence"], default=str)
                    if "idempotency_key" not in alert:
                        import uuid
                        alert["idempotency_key"] = (
                            f"{alert.get('rule_name')}:{alert.get('src_ip')}:"
                            f"{alert.get('dst_ip')}:{alert.get('dst_port')}:"
                            f"{alert.get('timestamp')}:{uuid.uuid4().hex[:8]}"
                        )
                    import queue as _queue
                    try:
                        self._alert_queue.put_nowait(("alert", alert))
                    except _queue.Full:
                        # Queue saturation backpressure policy:
                        # Spool directly to durable disk storage
                        spooled = self._spool.append(alert)
                        if spooled:
                            self._stats["alerts_spooled"] = self._spool.count()
                            logger.warning(
                                f"Alert queue full ({self._alert_queue.maxsize}) — "
                                f"spooled to disk under backpressure: {alert.get('rule_name')}"
                            )
                        else:
                            self._stats["alerts_dropped"] += 1
                            logger.error(
                                f"Alert queue and spool saturated — alert dropped: "
                                f"{alert.get('rule_name')} (drop count: {self._stats['alerts_dropped']})"
                            )
                    logger.info(
                        f"[ALERT] {alert['rule_name']} v{alert.get('rule_version','?')} "
                        f"— {alert['detail']}"
                    )
            except Exception as e:
                logger.error(f"Rule {rule.name} error: {e}")
