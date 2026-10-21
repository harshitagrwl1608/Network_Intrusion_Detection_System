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
                freq_threshold=getattr(cfg, "DNS_FREQ_THRESHOLD", 20),
                freq_window=getattr(cfg, "DNS_FREQ_WINDOW", 60),
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
