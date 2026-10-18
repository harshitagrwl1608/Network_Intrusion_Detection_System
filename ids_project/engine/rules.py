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
        """Check exact set then CIDR networks."""
        if ip in self._exact:
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

        # Only count SYN packets (new connection attempts); skip ACK/PSH traffic
        protocol = record.get("protocol", "")
        if protocol == "TCP" and not record.get("syn_flag"):
            return None

        dst_ip = record.get("dst_ip", "")
        dst_port = record.get("dst_port")
        if dst_port is None:
            return None

        now = record.get("timestamp", time.time())

        with self._lock:
            # --- Vertical scan check ---
            vkey = (src, dst_ip)
            self._vert[vkey] = [(t, p) for t, p in self._vert[vkey]
                                if now - t <= self.window]
            self._vert[vkey].append((now, dst_port))
            distinct_ports = len({p for _, p in self._vert[vkey]})

            if distinct_ports >= self.threshold:
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

            # --- Horizontal scan check ---
            hkey = (src, dst_port)
            self._horiz[hkey] = [(t, ip) for t, ip in self._horiz[hkey]
                                  if now - t <= self.window]
            self._horiz[hkey].append((now, dst_ip))
            distinct_hosts = len({ip for _, ip in self._horiz[hkey]})

            if distinct_hosts >= self.threshold:
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
    rule_version = "1.1"

    def __init__(self, table_path: str):
        self.table_path = table_path
        self._lock = threading.RLock()
        self._table: dict[str, str] = {}  # ip → mac
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
        os.makedirs(os.path.dirname(self.table_path), exist_ok=True)
        with open(self.table_path, "w") as f:
            json.dump(self._table, f, indent=2)

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
            rb"|\$\(|`[^`]+`|bash\s+-i\s+>&\s*/dev/tcp/|nc\s+-e\s+/bin)"
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

        # Only inspect on plaintext ports; skip if this appears to be
        # a server-direction response (src_port in DPI_PORTS) — the
        # matching response to a benign client request should not be flagged
        # as an attack originating from the server.
        if dst_port not in _DPI_PORTS and src_port not in _DPI_PORTS:
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
_DGA_WHITELIST_SUFFIXES: tuple[str, ...] = (
    ".cloudflare.com", ".akamai.net", ".akamaiedge.net",
    ".cdn.ampproject.org", ".amazonaws.com", ".fastly.net",
    ".google.com", ".googleapis.com", ".gstatic.com",
    ".doubleclick.net", ".googlevideo.com", ".fbcdn.net",
    ".azure.com", ".azurefd.net", ".cloudfront.net",
    ".github.io", ".s3.amazonaws.com",
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
    rule_version = "1.2"

    # Alert dedup: don't re-alert on the same (src, domain) within this window
    ALERT_COOLDOWN_S = 60

    # Query-frequency detection: alert if a src queries the same
    # parent domain more than FREQ_THRESHOLD times in FREQ_WINDOW seconds
    FREQ_THRESHOLD = 20
    FREQ_WINDOW = 60

    def __init__(self, entropy_threshold: float = 3.8, max_query_len: int = 60):
        self.entropy_threshold = entropy_threshold
        self.max_query_len     = max_query_len
        self._lock = threading.RLock()

        # (src_ip, domain) → last_alert_time  (alert dedup)
        self._seen: dict[tuple, float] = {}

        # (src_ip, parent_domain) → [timestamps]  (query frequency)
        self._freq: dict[tuple, list] = defaultdict(list)

    def _parent_domain(self, domain: str) -> str:
        """Return the registrable parent domain (last two labels)."""
        labels = domain.rstrip(".").split(".")
        return ".".join(labels[-2:]) if len(labels) >= 2 else domain

    def _prune_seen(self, now: float):
        cutoff = now - 120
        self._seen = {k: v for k, v in self._seen.items() if v > cutoff}

    def prune_stale(self, now: float):
        cutoff = now - self.FREQ_WINDOW
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

        # Whitelist known-legit high-entropy CDN / cloud domains
        dl = domain.lower()
        if any(dl.endswith(w) for w in _DGA_WHITELIST_SUFFIXES):
            return None

        labels = domain.split(".")
        subdomain = labels[0] if labels else domain
        parent = self._parent_domain(domain)

        entropy  = _shannon_entropy(subdomain)
        too_long = len(domain) > self.max_query_len
        # Require label length >= 8 to avoid FPs on short words
        high_ent = len(subdomain) >= 8 and entropy >= self.entropy_threshold

        # ── Query frequency: count repeated queries to same parent domain ──
        with self._lock:
            fkey = (src, parent)
            self._freq[fkey] = [
                t for t in self._freq[fkey] if now - t <= self.FREQ_WINDOW
            ]
            self._freq[fkey].append(now)
            query_count = len(self._freq[fkey])

        high_freq = query_count >= self.FREQ_THRESHOLD

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
                f"in {self.FREQ_WINDOW}s (≥{self.FREQ_THRESHOLD})"
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
                "freq_window_s": self.FREQ_WINDOW,
                "freq_threshold": self.FREQ_THRESHOLD,
            },
            "window_start": now - self.FREQ_WINDOW if high_freq else None,
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

    def __init__(self, db_conn, blocklist, cfg):
        from storage.db import write_alert, upsert_device
        import engine.rules as _rules_mod
        import queue

        self._write_alert  = write_alert
        self._upsert_device = upsert_device

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
            ),
        ]

        # Bounded async writer queue with explicit stop sentinel
        self._write_queue: queue.Queue = queue.Queue(maxsize=2000)
        self._stop_event = threading.Event()
        self._writer_thread = threading.Thread(
            target=self._db_writer_loop, daemon=True, name="db-writer"
        )
        self._writer_thread.start()

        # GC thread for stateful rules
        self._gc_thread = threading.Thread(
            target=self._gc_loop, daemon=True, name="rule-gc"
        )
        self._gc_thread.start()

        import atexit
        atexit.register(self.flush)

    def _gc_loop(self):
        while not self._stop_event.is_set():
            time.sleep(10)
            now = time.time()
            for rule in self.rules:
                if hasattr(rule, "prune_stale"):
                    try:
                        rule.prune_stale(now)
                    except Exception as e:
                        logger.error(f"Rule GC error for {rule.name}: {e}")

    def _db_writer_loop(self):
        import queue as _queue
        from storage.db import get_connection
        conn = get_connection()
        while True:
            try:
                task, data = self._write_queue.get(timeout=1)
                if task == "stop":
                    self._write_queue.task_done()
                    break
                if task == "alert":
                    self._write_alert(conn, data)
                elif task == "device":
                    self._upsert_device(conn, data["mac"], data["ip"])
                self._write_queue.task_done()
            except _queue.Empty:
                if self._stop_event.is_set():
                    break
            except Exception as e:
                logger.error(f"DB writer error: {e}")
                try:
                    self._write_queue.task_done()
                except Exception:
                    pass

    def _enqueue(self, task: str, data):
        """Put work onto the bounded queue; drop and log if full."""
        import queue as _queue
        try:
            self._write_queue.put_nowait((task, data))
        except _queue.Full:
            logger.warning(f"Write queue full — dropping {task} entry")

    def flush(self):
        """Signal stop, wait for pending writes to drain."""
        self._stop_event.set()
        try:
            self._write_queue.put_nowait(("stop", None))
        except Exception:
            pass
        self._writer_thread.join(timeout=5)
        for rule in self.rules:
            if hasattr(rule, "flush"):
                try:
                    rule.flush()
                except Exception as e:
                    logger.error(f"Rule flush error: {e}")

    def check(self, record: dict):
        # Track seen device
        mac = record.get("src_mac")
        ip  = record.get("src_ip")
        if mac and ip:
            self._enqueue("device", {"mac": mac, "ip": ip})

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
                    # Serialise evidence dict to JSON string for DB persistence (§3.7)
                    if "evidence" in alert:
                        alert["evidence_json"] = json.dumps(alert["evidence"])
                    self._enqueue("alert", alert)
                    logger.info(
                        f"[ALERT] {alert['rule_name']} v{alert.get('rule_version','?')} "
                        f"— {alert['detail']}"
                    )
            except Exception as e:
                logger.error(f"Rule {rule.name} error: {e}")
