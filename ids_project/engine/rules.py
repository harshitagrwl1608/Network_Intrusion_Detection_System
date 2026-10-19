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

Rule order (cheapest → most expensive):
  1. BlocklistRule     — stateless, O(1)+O(networks) lookup
  2. PortScanRule      — stateful, vertical + horizontal scan tracking
  3. SynFloodRule      — stateful, SYN burst rate per (src,dst,port)
  4. ArpSpoofRule      — stateful, persistent IP→MAC table
  5. PayloadRule       — stateless regex DPI (returns ALL matches)
  6. DnsRule           — stateful Shannon-entropy + query-frequency

False Positive Mitigations:
  - PortScanRule: ignores hosts whose SOURCE port is a well-known service
    (servers replying to clients, not scanners).
  - PortScanRule: only counts SYN packets (new connection attempts).
  - SynFloodRule: only fires on service destination ports (≤ 49151).
  - Configurable TRUSTED_HOSTS whitelist.
  - Configurable WELL_KNOWN_SERVICE_PORTS set.
  - DnsRule: whitelists common high-entropy-but-legit CDN patterns.
  - All stateful rules: per-rule threading.Lock (§3.8).

Thread safety:
  Every stateful rule guards its mutable _history/_table/_seen with a
  threading.RLock so the capture thread (check) and GC thread
  (prune_stale) cannot race.
"""

import json
import math
import os
import re
import threading
import time
import ipaddress
import logging
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)

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

# Trusted hosts/IPs that should never be flagged by port-scan or SYN-flood.
# Add your gateway, DNS server, trusted CDN IPs here.
TRUSTED_HOSTS: set = set()  # populated from config by RuleEngine

def _is_trusted(ip: str) -> bool:
    """Return True if ip matches any trusted host or CIDR range."""
    if ip in TRUSTED_HOSTS:
        return True
    for entry in TRUSTED_HOSTS:
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            pass
    return False


def _is_internal(ip: str) -> bool:
    """Return True if ip is an RFC-1918 / link-local private address."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_link_local
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
    rule_version = "1.2"

    def __init__(self, threshold: int = 15, window: int = 10):
        self.threshold = threshold
        self.window = window
        self._lock = threading.RLock()

        # Vertical scan: (src_ip, dst_ip) → [(ts, dst_port)]
        # A single src probing many ports on one host.
        self._vert: dict[tuple, list] = defaultdict(list)

        # Horizontal scan: (src_ip, dst_port) → [(ts, dst_ip)]
        # A single src probing the same port across many hosts.
        self._horiz: dict[tuple, list] = defaultdict(list)

    def prune_stale(self, now: float):
        cutoff = now - self.window
        with self._lock:
            for d in (self._vert, self._horiz):
                stale = [k for k, v in d.items()
                         if not [e for e in v if e[0] > cutoff]]
                for k in stale:
                    del d[k]
                for k in list(d):
                    if k in d:
                        d[k] = [e for e in d[k] if e[0] > cutoff]

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP":
            return None

        src = record.get("src_ip", "")
        if _is_trusted(src):
            return None

        # Skip server-side responses (DNS/HTTP/etc. replying to many clients)
        src_port = record.get("src_port")
        if src_port and src_port in WELL_KNOWN_SERVICE_PORTS:
            return None

        # Explicitly restrict to TCP only. UDP probes are not counted as scan
        # attempts by this rule (that would need a separate UDP-scan rule).
        protocol = record.get("protocol", "")
        if protocol != "TCP":
            return None

        # Only count initial SYN (SYN=1, ACK=0) — pure new connection attempts.
        # SYN-ACK packets (SYN=1, ACK=1) are server responses and must not count.
        if "initial_syn" in record:
            if not record.get("initial_syn"):
                return None
        else:
            if not record.get("syn_flag"):
                return None

        dst_ip = record.get("dst_ip", "")
        dst_port = record.get("dst_port")
        if dst_port is None:
            return None

        now = record.get("timestamp", time.time())

        with self._lock:
            # Always update BOTH vertical and horizontal histories first,
            # then check thresholds. This ensures a packet contributes to
            # both scan dimensions even when one threshold fires. (P2 §4)

            # --- Vertical history update ---
            vkey = (src, dst_ip)
            self._vert[vkey] = [(t, p) for t, p in self._vert[vkey]
                                if now - t <= self.window]
            self._vert[vkey].append((now, dst_port))
            distinct_ports = len({p for _, p in self._vert[vkey]})

            # --- Horizontal history update ---
            hkey = (src, dst_port)
            self._horiz[hkey] = [(t, ip) for t, ip in self._horiz[hkey]
                                  if now - t <= self.window]
            self._horiz[hkey].append((now, dst_ip))
            distinct_hosts = len({ip for _, ip in self._horiz[hkey]})

            vert_fired  = distinct_ports >= self.threshold
            horiz_fired = distinct_hosts >= self.threshold

            if vert_fired:
                window_start = now - self.window
                self._vert[vkey] = []  # reset to prevent alert storm
                logger.debug(
                    f"PORT_SCAN (vertical) fired: {src}→{dst_ip} "
                    f"{distinct_ports} ports"
                )
                return {
                    "rule_name": self.name,
                    "rule_version": self.rule_version,
                    "src_ip": src,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "severity": "high",
                    "confidence": "heuristic",
                    "detail": (
                        f"{src} sent SYN to {distinct_ports} distinct ports "
                        f"on {dst_ip} in {self.window}s — possible vertical port scan"
                    ),
                    "evidence": {
                        "scan_type": "vertical",
                        "distinct_ports": distinct_ports,
                        "target_host": dst_ip,
                        "window_s": self.window,
                        "threshold": self.threshold,
                    },
                    "window_start": window_start,
                    "window_end": now,
                }

            if horiz_fired:
                window_start = now - self.window
                self._horiz[hkey] = []
                logger.debug(
                    f"PORT_SCAN (horizontal) fired: {src} port {dst_port} "
                    f"→ {distinct_hosts} hosts"
                )
                return {
                    "rule_name": self.name,
                    "rule_version": self.rule_version,
                    "src_ip": src,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "severity": "high",
                    "confidence": "heuristic",
                    "detail": (
                        f"{src} sent SYN to port {dst_port} on "
                        f"{distinct_hosts} distinct hosts in {self.window}s "
                        f"— possible horizontal port scan"
                    ),
                    "evidence": {
                        "scan_type": "horizontal",
                        "distinct_hosts": distinct_hosts,
                        "scanned_port": dst_port,
                        "window_s": self.window,
                        "threshold": self.threshold,
                    },
                    "window_start": window_start,
                    "window_end": now,
                }

        return None


# =============================================================================
# Rule 3: SYN Burst / Connection-Rate Abuse  (§3.3 — label clarified)
# =============================================================================

class SynFloodRule:
    name = "SYN_FLOOD"
    rule_version = "1.1"

    def __init__(self, threshold: int = 100, window: int = 10):
        self.threshold = threshold
        self.window = window
        self._lock = threading.RLock()
        # (src_ip, dst_ip, dst_port) → list of SYN timestamps
        self._history: dict[tuple, list] = defaultdict(list)

    def prune_stale(self, now: float):
        cutoff = now - self.window
        with self._lock:
            stale_keys = []
            for key, history in self._history.items():
                self._history[key] = [t for t in history if t > cutoff]
                if not self._history[key]:
                    stale_keys.append(key)
            for key in stale_keys:
                del self._history[key]

    def check(self, record: dict) -> dict | None:
        if record.get("protocol") != "TCP":
            return None
        # Only count initial SYN (SYN=1, ACK=0); skip SYN-ACK server responses
        if "initial_syn" in record:
            if not record.get("initial_syn"):
                return None
        else:
            if not record.get("syn_flag"):
                return None

        src = record.get("src_ip", "")
        dst = record.get("dst_ip", "")
        dst_port = record.get("dst_port")

        if _is_trusted(src):
            return None

        # SYN floods target services; skip ephemeral dst ports (IANA: 49152-65535)
        if dst_port and dst_port > 49151:
            return None

        now = record.get("timestamp", time.time())
        key = (src, dst, dst_port)

        with self._lock:
            self._history[key] = [
                t for t in self._history[key] if now - t <= self.window
            ]
            self._history[key].append(now)
            count = len(self._history[key])

        if count >= self.threshold:
            with self._lock:
                self._history[key] = []
            window_start = now - self.window
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


# =============================================================================
# Rule 4: ARP Spoofing Detection
# =============================================================================

class ArpSpoofRule:
    name = "ARP_SPOOF"
    rule_version = "1.2"

    # Per-IP cooldown: once an alert fires for a given IP, suppress repeats
    # for this many seconds to avoid alert storms. Set to 0 to disable.
    ALERT_COOLDOWN_S: float = 120.0

    def __init__(self, table_path: str):
        self.table_path = table_path
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
                with self._lock:
                    self._table = json.load(f)
            logger.info(f"ARP table loaded: {len(self._table)} entries")
        except FileNotFoundError:
            logger.info("No ARP table found — starting fresh")
            self._table = {}

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

        ip = record.get("src_ip")
        mac = record.get("src_mac")
        if not ip or not mac:
            return None

        with self._lock:
            known_mac = self._table.get(ip)
            if known_mac is None:
                self._table[ip] = mac
                self._dirty = True
                return None

            if known_mac != mac:
                now_t = record.get("timestamp", time.time())
                if ip in self._cooldown:
                    if now_t - self._cooldown[ip] < self.ALERT_COOLDOWN_S:
                        return None  # suppress — already alerted recently
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
                    "severity": "high",
                    "confidence": "high",
                    "detail": (
                        f"IP {ip} previously answered as {known_mac}, "
                        f"now claims to be {mac} — possible ARP spoofing"
                    ),
                    "evidence": {
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
    # SQL Injection
    (
        "SQL_INJECTION",
        re.compile(
            rb"(?i)(union\s+select|select\s+\*|drop\s+table|insert\s+into"
            rb"|or\s+1=1|--\s*$|sleep\s*\(|waitfor\s+delay|exec\s+xp_cmdshell)",
            re.MULTILINE,
        ),
        "heuristic",
    ),
    # XSS
    (
        "XSS",
        re.compile(
            rb"(?i)(<script[\s>]|javascript:|onerror\s*=|onload\s*=|alert\s*\()"
        ),
        "heuristic",
    ),
    # Plaintext credential leak
    (
        "CREDENTIAL_LEAK",
        re.compile(
            rb"(?i)(password=|passwd=|pass=|pwd=|token=|api_key=|secret="
            rb"|Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8}"
            rb"|Bearer\s+[A-Za-z0-9\-._~+/]+=*)"
        ),
        "heuristic",
    ),
    # Shell / command injection payloads
    (
        "CMD_INJECTION",
        re.compile(
            rb"(?i)(/bin/sh|/bin/bash|/etc/passwd|cmd\.exe|powershell\.exe"
            rb"|\$\(|`[^`]+`"
            # Reverse-shell patterns: raw 'bash -i >& /dev/tcp/' AND
            # standalone '/dev/tcp/' (covers URL-encoded forms: bash+-i+>%26+/dev/tcp/)
            rb"|bash\s+-i\s+>&\s*/dev/tcp/|/dev/tcp/"
            rb"|nc\s+-e\s+/bin)"
        ),
        "heuristic",
    ),
    # Path traversal
    (
        "PATH_TRAVERSAL",
        re.compile(
            rb"(?i)(\.\.[\\/]\.\.[\\/]|\.\.%2[fF]|%2[eE]%2[eE]%2[fF]"
            rb"|/etc/passwd|/etc/shadow|/proc/self)"
        ),
        "heuristic",
    ),
    # Server-Side Request Forgery
    (
        "SSRF",
        re.compile(
            rb"(?i)(file://|dict://|gopher://|ldap://|ftp://127\.|http://127\."
            rb"|http://169\.254\.169\.254|http://\[::1\])"
        ),
        "heuristic",
    ),
    # Log4Shell / Log4j JNDI injection
    (
        "LOG4SHELL",
        re.compile(
            rb"(?i)(\$\{jndi:|j\$\{:|j\$\{lower:|j\$\{::-j\}ndi:)"
        ),
        "high",
    ),
]

# Only inspect unencrypted application protocols (TLS payload is ciphertext)
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
}


class PayloadRule:
    name = "PAYLOAD_HIT"
    rule_version = "1.2"

    def __init__(self, max_bytes: int = 512, enabled: bool = True):
        self.max_bytes = max_bytes
        self.enabled   = enabled

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
        if not payload:
            return None

        dst_port = record.get("dst_port") or 0
        src_port = record.get("src_port") or 0

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

        sample = payload[: self.max_bytes]

        # Collect ALL matching signatures (§3.4 — do not return on first match)
        hits: list[dict] = []
        for label, pattern, confidence in _PAYLOAD_SIGNATURES:
            m = pattern.search(sample)
            if m:
                matched_bytes = m.group(0)[:80]
                try:
                    matched_str = matched_bytes.decode("utf-8", errors="replace")
                except Exception:
                    matched_str = repr(matched_bytes)
                hits.append({"signature": label, "matched": matched_str,
                             "confidence": confidence})

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
                "inspected_bytes": len(sample),
                "cap_bytes": self.max_bytes,
                "note": "Packet-level inspection only; no stream reassembly",
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
_DGA_WHITELIST_SUFFIXES: tuple[str, ...] = (
    ".cloudflare.com", ".akamai.net", ".akamaiedge.net",
    ".cdn.ampproject.org", ".amazonaws.com", ".fastly.net",
    ".google.com", ".googleapis.com", ".gstatic.com",
    ".doubleclick.net", ".googlevideo.com", ".fbcdn.net",
    ".azure.com", ".azurefd.net",
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


class DnsRule:
    name = "DNS_ANOMALY"
    rule_version = "1.3"

    # Alert dedup cooldown — class-level default; overridable via __init__
    ALERT_COOLDOWN_S = 60

    def __init__(
        self,
        entropy_threshold: float = 3.8,
        max_query_len: int = 60,
        freq_threshold: int = 20,
        freq_window: int = 60,
    ):
        self.entropy_threshold = entropy_threshold
        self.max_query_len     = max_query_len
        # Frequency detection parameters — wired from config via RuleEngine (P1)
        self._freq_threshold   = freq_threshold
        self._freq_window      = freq_window
        self._lock = threading.RLock()

        # (src_ip, domain) → last_alert_time  (alert dedup)
        self._seen: dict[tuple, float] = {}

        # (src_ip, parent_domain) → [timestamps]  (query frequency)
        self._freq: dict[tuple, list] = defaultdict(list)

    def _parent_domain(self, domain: str) -> str:
        """
        Return a stable grouping key for the domain.

        Using only the last two labels (e.g. 'example.com') works for most
        gTLDs but breaks for multi-label public suffixes like 'co.uk':
        'one.example.co.uk' and 'two.other.co.uk' would both collapse to
        'co.uk', aggregating unrelated activity.

        For now we use a deliberately limited heuristic: if the TLD-1 label
        looks like a country-code + second-level pair (len <= 3, all alpha),
        take the last THREE labels.  This handles co.uk, com.au, org.in etc.
        A full Public Suffix List library (tldextract) would be more correct
        and should be introduced when the project adds a dependency manager.
        """
        labels = domain.rstrip(".").split(".")
        if len(labels) >= 3:
            tld   = labels[-1]   # e.g. 'uk'
            tld_1 = labels[-2]   # e.g. 'co'
            if len(tld) <= 3 and len(tld_1) <= 3 and tld_1.isalpha():
                # Likely a multi-label TLD (co.uk, com.au, org.in ...)
                return ".".join(labels[-3:])
        return ".".join(labels[-2:]) if len(labels) >= 2 else domain

    def _prune_seen(self, now: float):
        cutoff = now - 120
        self._seen = {k: v for k, v in self._seen.items() if v > cutoff}

    def prune_stale(self, now: float):
        cutoff = now - self._freq_window
        with self._lock:
            stale = [k for k, v in self._freq.items()
                     if not [t for t in v if t > cutoff]]
            for k in stale:
                del self._freq[k]
            for k in list(self._freq):
                if k in self._freq:
                    self._freq[k] = [t for t in self._freq[k] if t > cutoff]
            if len(self._seen) > 5000:
                self._prune_seen(now)

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP":
            return None
        if record.get("dst_port") != 53 and record.get("src_port") != 53:
            return None

        domain: str | None = record.get("dns_query")
        if not domain:
            return None

        domain = domain.rstrip(".")
        src = record.get("src_ip", "unknown")
        now = record.get("timestamp", time.time())

        # --- Allowlist: applied only to entropy check, NOT to length/frequency ---
        # Broad suffix allowlisting should not suppress other anomaly signals.
        # A high-entropy domain under a CDN suffix is excused from entropy only;
        # an unusually LONG or REPEATED query under that suffix still fires.
        dl = domain.lower()
        entropy_exempt = any(dl.endswith(w) for w in _DGA_WHITELIST_SUFFIXES)

        labels = domain.split(".")
        subdomain = labels[0] if labels else domain
        parent = self._parent_domain(domain)

        entropy  = _shannon_entropy(subdomain)
        too_long = len(domain) > self.max_query_len
        # Require label length >= 8 to avoid FPs on short words.
        # Also skip entropy check when domain is on the CDN allowlist.
        high_ent = (
            not entropy_exempt
            and len(subdomain) >= 8
            and entropy >= self.entropy_threshold
        )

        # ── Query frequency: count repeated queries to same parent domain ──
        # freq_threshold=0 disables frequency detection entirely
        with self._lock:
            fkey = (src, parent)
            self._freq[fkey] = [
                t for t in self._freq[fkey] if now - t <= self._freq_window
            ]
            self._freq[fkey].append(now)
            query_count = len(self._freq[fkey])

        high_freq = (
            self._freq_threshold > 0
            and query_count >= self._freq_threshold
        )

        if not (high_ent or too_long or high_freq):
            return None

        # Alert dedup — suppress re-alerting on same (src, domain) within cooldown
        alert_key = (src, domain)
        with self._lock:
            last_alert = self._seen.get(alert_key, 0)
            if now - last_alert < self.ALERT_COOLDOWN_S:
                return None
            self._seen[alert_key] = now

        reason = []
        if high_ent:
            reason.append(f"entropy={entropy:.2f} (≥{self.entropy_threshold})")
        if too_long:
            reason.append(f"length={len(domain)} chars (>{self.max_query_len})")
        if high_freq:
            reason.append(
                f"query_count={query_count} to '{parent}' "
                f"in {self._freq_window}s (≥{self._freq_threshold})"
            )

        sub_type = "DNS_FREQ" if high_freq and not (high_ent or too_long) \
                   else ("DNS_DGA" if high_ent else "DNS_TUNNEL")

        logger.debug(f"{sub_type} fired: {src} queried '{domain}' [{', '.join(reason)}]")
        return {
            "rule_name": self.name,
            "rule_version": self.rule_version,
            "src_ip": src,
            "dst_ip": record.get("dst_ip"),
            "src_port": record.get("src_port"),
            "dst_port": 53,
            "protocol": "UDP",
            "severity": "medium" if high_freq and not (high_ent or too_long) else "high",
            "confidence": "heuristic",
            "detail": (
                f"{src} queried suspicious domain '{domain}' "
                f"[{', '.join(reason)}] — possible {sub_type}"
            ),
            "evidence": {
                "domain": domain,
                "subdomain": subdomain,
                "parent_domain": parent,
                "entropy": round(entropy, 3),
                "sub_type": sub_type,
                "query_count_in_window": query_count,
                "freq_window_s": self._freq_window,
                "freq_threshold": self._freq_threshold,
            },
            "window_start": now - self._freq_window if high_freq else None,
            "window_end": now if high_freq else None,
        }


# =============================================================================
# Rule Engine Orchestrator
# =============================================================================

class RuleEngine:
    """
    Runs all rules against every packet record.
    Writes any resulting alerts to the database asynchronously.
    Also tracks seen devices for the dashboard device list.

    All rules are run for every packet — no early exit.  A packet may
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
            PortScanRule(cfg.PORT_SCAN_THRESHOLD, cfg.TIME_WINDOW),
            SynFloodRule(cfg.SYN_FLOOD_THRESHOLD, cfg.TIME_WINDOW),
            ArpSpoofRule(cfg.ARP_TABLE_PATH),
            PayloadRule(
                max_bytes=getattr(cfg, "PAYLOAD_MAX_BYTES", 512),
                enabled=getattr(cfg, "PAYLOAD_INSPECTION", True),
            ),
            DnsRule(
                entropy_threshold=getattr(cfg, "DNS_ENTROPY_THRESHOLD", 3.8),
                max_query_len=getattr(cfg, "DNS_QUERY_MAX_LEN", 60),
                # Wire frequency config from environment (P1 — was hard-coded)
                freq_threshold=getattr(cfg, "DNS_FREQ_THRESHOLD", 20),
                freq_window=getattr(cfg, "DNS_FREQ_WINDOW", 60),
            ),
        ]

        # Alert queue is unbounded (never drops); device queue is bounded + dedup.
        # DEVICE_REFRESH_INTERVAL: seconds between re-writing the same (mac, ip)
        # to the DB to update last_seen. Set to 0 to disable refresh (lifetime dedup).
        DEVICE_REFRESH_INTERVAL = 300  # 5 minutes
        self._device_refresh_s: float = DEVICE_REFRESH_INTERVAL
        self._alert_queue: queue.Queue = queue.Queue()
        self._device_queue: queue.Queue = queue.Queue(maxsize=1000)
        # Dict instead of set: tracks (mac,ip) -> wall-clock time of last DB write
        # so the same device can refresh its last_seen periodically.
        self._seen_devices: dict = {}
        self._stats = {
            "alert_writes": 0,
            "device_writes": 0,
            "alerts_dropped": 0,
            "devices_dropped": 0,
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

    def _gc_loop(self):
        """
        Periodically prune stale stateful rule histories.
        clock: uses self._event_clock if provided (e.g. during replay),
        otherwise falls back to time.time.
        """
        clock = self._event_clock or time.time
        while not self._stop_event.is_set():
            time.sleep(10)
            now = clock()
            for rule in self.rules:
                if hasattr(rule, "prune_stale"):
                    try:
                        rule.prune_stale(now)
                    except Exception as e:
                        logger.error(f"Rule GC error for {rule.name}: {e}")

    def _alert_writer_loop(self):
        """
        Drain the alert queue and persist each alert to the DB.

        Connection handling:
          - If the initial connection fails, retries up to 5 times with
            exponential back-off (1 s, 2 s, 4 s, 8 s, 16 s).
          - After the retry budget is exhausted, the thread continues to drain
            the queue but counts every alert as a drop (alerts_dropped).
          - Transient write errors on a live connection increment alerts_dropped
            and log the failure; the alert is NOT silently discarded silently.
          - On shutdown, the stop sentinel is consumed and the loop exits cleanly.
        """
        import queue as _queue
        from storage.db import get_connection, init_db

        conn = None
        _MAX_RETRIES = 5
        for attempt in range(_MAX_RETRIES):
            try:
                conn = get_connection()
                break
            except Exception as exc:
                delay = 2 ** attempt
                logger.error(
                    f"Alert writer: DB connection attempt {attempt+1}/{_MAX_RETRIES} "
                    f"failed: {exc}. Retrying in {delay}s..."
                )
                time.sleep(delay)

        if conn is None:
            logger.error(
                "Alert writer: exhausted DB connection retries. "
                "All queued alerts will be counted as dropped."
            )

        while True:
            try:
                sentinel, data = self._alert_queue.get(timeout=1)
                if sentinel == "stop":
                    self._alert_queue.task_done()
                    break
                if conn is not None:
                    try:
                        self._write_alert(conn, data)
                        self._stats["alert_writes"] += 1
                    except Exception as e:
                        self._stats["alerts_dropped"] += 1
                        logger.error(
                            f"Alert write FAILED (alert dropped, drop count: "
                            f"{self._stats['alerts_dropped']}): {e} | "
                            f"rule={data.get('rule_name','?')}"
                        )
                else:
                    self._stats["alerts_dropped"] += 1
                    logger.error(
                        f"Alert dropped (no DB connection): "
                        f"rule={data.get('rule_name','?')} — "
                        f"drop count: {self._stats['alerts_dropped']}"
                    )
                self._alert_queue.task_done()
            except _queue.Empty:
                if self._stop_event.is_set():
                    break

    def _device_writer_loop(self):
        """Drain the device queue. Drops are counted but non-fatal."""
        import queue as _queue
        from storage.db import get_connection
        conn = get_connection()
        while True:
            try:
                sentinel, data = self._device_queue.get(timeout=1)
                if sentinel == "stop":
                    self._device_queue.task_done()
                    break
                try:
                    self._upsert_device(conn, data["mac"], data["ip"])
                    self._stats["device_writes"] += 1
                except Exception as e:
                    logger.error(f"Device write error: {e}")
                self._device_queue.task_done()
            except _queue.Empty:
                if self._stop_event.is_set():
                    break

    def flush(self):
        """
        Signal stop and drain pending writes reliably.
        Waits for ALL alert writes to complete or until the writer thread exits.
        Hard timeout of 10 s prevents infinite hang.
        """
        self._stop_event.set()

        # Send stop sentinels
        self._alert_queue.put(("stop", None))
        try:
            self._device_queue.put_nowait(("stop", None))
        except Exception:
            pass

        # Wait for the alert writer thread to exit
        self._alert_writer.join(timeout=10)
        if self._alert_writer.is_alive():
            logger.warning(
                f"Alert writer thread still alive after flush timeout. "
                f"Alerts written: {self._stats['alert_writes']}, "
                f"queue depth: {self._alert_queue.qsize()}"
            )
            self._stats["shutdown_timeout"] = True

        self._device_writer.join(timeout=3)

        # Flush per-rule state (e.g. ARP table to disk)
        for rule in self.rules:
            if hasattr(rule, "flush"):
                try:
                    rule.flush()
                except Exception as e:
                    logger.error(f"Rule flush error: {e}")

        logger.info(
            f"RuleEngine shutdown: alerts={self._stats['alert_writes']}, "
            f"devices={self._stats['device_writes']}, "
            f"alerts_dropped={self._stats['alerts_dropped']}, "
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
            last_write = self._seen_devices.get(dev_key, 0.0)
            if now_wall - last_write >= self._device_refresh_s:
                self._seen_devices[dev_key] = now_wall
                import queue as _queue
                try:
                    self._device_queue.put_nowait(("device", {"mac": mac, "ip": ip}))
                except _queue.Full:
                    self._stats["devices_dropped"] += 1
                    logger.warning(f"Device queue full — dropped ({mac}, {ip})")

        # Run ALL rules — no early exit
        for rule in self.rules:
            try:
                alert = rule.check(record)
                if alert:
                    # Stamp with event_timestamp from the packet record
                    alert["timestamp"] = record.get(
                        "event_timestamp",
                        record.get("timestamp", time.time()),
                    )
                    # Serialise evidence dict to JSON string for DB persistence
                    if "evidence" in alert:
                        alert["evidence_json"] = json.dumps(alert["evidence"])
                    # Alerts go to the dedicated, never-dropping alert queue
                    self._alert_queue.put(("alert", alert))
                    logger.info(
                        f"[ALERT] {alert['rule_name']} v{alert.get('rule_version','?')} "
                        f"— {alert['detail']}"
                    )
            except Exception as e:
                logger.error(f"Rule {rule.name} error: {e}")
