"""
engine/rules.py
---------------
All 6 detection rules + the RuleEngine orchestrator.

Rules are stateful and maintain short-term sliding-window memory.
Each rule's check() method receives a normalised packet record dict and
returns an alert dict (or None).

Rule order (simplest → most complex):
  1. BlocklistRule    — stateless, O(1) set lookup
  2. PortScanRule     — stateful, tracks distinct DESTINATION ports per src_ip
  3. SynFloodRule     — stateful, tracks SYN count per src_ip
  4. ArpSpoofRule     — stateful, persistent IP→MAC table
  5. PayloadRule      — stateless regex DPI (SQL injection, XSS, credentials)
  6. DnsRule          — stateful Shannon-entropy DGA / DNS-tunneling detection

False Positive Mitigations (2025-10):
  - PortScanRule: ignores hosts whose SOURCE port is a well-known service
    (53/DNS, 80/HTTP, 443/HTTPS, etc.) — prevents DNS servers replying to
    many clients from being flagged as scanners.
  - PortScanRule: only counts SYN packets (new connection attempts), not
    every packet — response traffic is filtered out.
  - PortScanRule: only counts ephemeral destination ports (dst_port >= 1024
    in response direction skipped; only scans TO low ports 1-1023 OR
    SYN to any port count).
  - Configurable TRUSTED_HOSTS whitelist to exempt known-good IPs/names.
  - Configurable WELL_KNOWN_SERVICE_PORTS set for source-port exemption.
  - DnsRule: whitelists common high-entropy-but-legit TLDs / CDN patterns.
"""

import json
import math
import os
import re
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
    # Check CIDR membership for any entries that look like networks
    for entry in TRUSTED_HOSTS:
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            pass
    return False


# =============================================================================
# Rule 1: Blocklist Match
# =============================================================================

class BlocklistRule:
    name = "BLOCKLIST"

    def __init__(self, blocklist: set):
        self.blocklist = blocklist

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP":
            return None
        src = record.get("src_ip")
        dst = record.get("dst_ip")
        
        bad_ip = None
        direction = ""
        if dst and dst in self.blocklist:
            bad_ip = dst
            direction = "contact"
        elif src and src in self.blocklist:
            bad_ip = src
            direction = "receive traffic from"

        if bad_ip:
            detail_msg = (
                f"{src} attempted to contact known-malicious IP {bad_ip}"
                if direction == "contact"
                else f"Received traffic from known-malicious IP {bad_ip}"
            )
            return {
                "rule_name": self.name,
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": record.get("dst_port"),
                "detail": detail_msg,
                "severity": "high",
            }
        return None


# =============================================================================
# Rule 2: Port Scan Detection
# =============================================================================

class PortScanRule:
    name = "PORT_SCAN"

    def __init__(self, threshold: int = 15, window: int = 10):
        self.threshold = threshold
        self.window = window
        # src_ip -> list of (timestamp, dst_port)
        self._history: dict[str, list] = defaultdict(list)

    def prune_stale(self, now: float):
        cutoff = now - self.window
        stale_srcs = []
        for src, history in self._history.items():
            self._history[src] = [(t, p) for t, p in history if t > cutoff]
            if not self._history[src]:
                stale_srcs.append(src)
        for src in stale_srcs:
            del self._history[src]

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP":
            return None

        # ── False Positive Filter 1: skip trusted hosts ──
        src = record.get("src_ip", "")
        if _is_trusted(src):
            return None

        # ── False Positive Filter 2: skip server-side response traffic ──
        # If the SOURCE port is a well-known service port, this host is a
        # *server replying to clients*, not a scanner probing many ports.
        # Example: reliance.reliance:53 (DNS) → client:46295, client:48643 ...
        # Without this filter, the DNS server looks like it's "scanning" clients.
        protocol = record.get("protocol", "")
        src_port = record.get("src_port")  # set by text-log parser when available
        if src_port and src_port in WELL_KNOWN_SERVICE_PORTS:
            return None

        # ── False Positive Filter 3: only count SYN (new connection) packets ──
        # A port scan sends SYN packets to probe ports. Normal response traffic
        # (ACK, PSH, etc.) from legitimate services should not be counted.
        # Exception: UDP and ICMP are stateless — count all of them.
        if protocol == "TCP" and not record.get("syn_flag"):
            return None

        dst_port = record.get("dst_port")
        if dst_port is None:
            return None

        now = record["timestamp"]

        # Purge entries outside the time window
        self._history[src] = [
            (t, p) for t, p in self._history[src] if now - t <= self.window
        ]
        self._history[src].append((now, dst_port))

        distinct_ports = len({p for _, p in self._history[src]})
        if distinct_ports >= self.threshold:
            self._history[src] = []  # reset to prevent alert storm
            logger.debug(f"PORT_SCAN fired: {src} → {distinct_ports} ports")
            return {
                "rule_name": self.name,
                "src_ip": src,
                "dst_ip": record.get("dst_ip"),
                "dst_port": dst_port,
                "detail": (
                    f"{src} sent SYN to {distinct_ports} distinct ports "
                    f"in {self.window}s — possible port scan"
                ),
                "severity": "high",
                "evidence": {
                    "distinct_ports": distinct_ports,
                    "window_s": self.window,
                    "threshold": self.threshold,
                },
            }
        return None


# =============================================================================
# Rule 3: SYN Flood / Connection-Rate Abuse
# =============================================================================

class SynFloodRule:
    name = "SYN_FLOOD"

    def __init__(self, threshold: int = 100, window: int = 10):
        self.threshold = threshold
        self.window = window
        # (src_ip, dst_ip, dst_port) -> list of SYN timestamps
        self._history: dict[tuple, list] = defaultdict(list)

    def prune_stale(self, now: float):
        cutoff = now - self.window
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

        # ── False Positive Filter: skip trusted hosts ──
        if _is_trusted(src):
            return None

        # ── False Positive Filter: only count floods TO service ports ──
        # A SYN flood targets a service (dst_port 80, 443, etc.).
        # Random ephemeral destination ports suggest legitimate client traffic.
        if dst_port and dst_port > 49151:  # skip ephemeral dest ports (IANA: 49152-65535)
            return None

        now = record["timestamp"]
        key = (src, dst, dst_port)

        self._history[key] = [
            t for t in self._history[key] if now - t <= self.window
        ]
        self._history[key].append(now)

        count = len(self._history[key])
        if count >= self.threshold:
            self._history[key] = []
            logger.debug(f"SYN_FLOOD fired: {src} -> {dst}:{dst_port} ({count} SYNs)")
            return {
                "rule_name": self.name,
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": dst_port,
                "detail": (
                    f"{src} sent {count} SYN packets to {dst}:{dst_port} "
                    f"in {self.window}s — possible SYN flood"
                ),
                "severity": "high",
                "evidence": {
                    "syn_count": count,
                    "window_s": self.window,
                    "threshold": self.threshold,
                },
            }
        return None


# =============================================================================
# Rule 4: ARP Spoofing Detection
# =============================================================================

class ArpSpoofRule:
    name = "ARP_SPOOF"

    def __init__(self, table_path: str):
        self.table_path = table_path
        self._table: dict[str, str] = {}  # ip -> mac
        self._dirty = False
        self._load()
        
        import threading
        import atexit
        self._saver_thread = threading.Thread(target=self._periodic_save, daemon=True)
        self._saver_thread.start()
        atexit.register(self.flush)

    def flush(self):
        """Force write to disk if dirty."""
        if self._dirty:
            self._save()
            self._dirty = False

    def _periodic_save(self):
        import time
        while True:
            time.sleep(60)
            self.flush()

    def _load(self):
        try:
            with open(self.table_path) as f:
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

        known_mac = self._table.get(ip)
        if known_mac is None:
            # First time we see this IP — record it
            self._table[ip] = mac
            self._dirty = True
            return None

        if known_mac != mac:
            logger.debug(f"ARP_SPOOF fired: {ip} was {known_mac}, now claims {mac}")
            return {
                "rule_name": self.name,
                "src_ip": ip,
                "dst_ip": record.get("dst_ip"),
                "dst_port": None,
                "detail": (
                    f"IP {ip} previously answered as {known_mac}, "
                    f"now claims to be {mac} — possible ARP spoofing"
                ),
                "severity": "high",
            }
        return None


# =============================================================================
# Rule 5: Deep Packet Inspection (DPI) — Payload Signature Matching
# =============================================================================

# Signatures: (label, compiled_regex)
_PAYLOAD_SIGNATURES: list[tuple[str, re.Pattern]] = [
    # SQL Injection
    ("SQL_INJECTION",  re.compile(rb"(?i)(union\s+select|select\s+\*|drop\s+table|insert\s+into|or\s+1=1|--\s*$)", re.MULTILINE)),
    # XSS
    ("XSS",            re.compile(rb"(?i)(<script[\s>]|javascript:|onerror\s*=|onload\s*=|alert\s*\()") ),
    # Plaintext credential leak
    ("CREDENTIAL_LEAK",re.compile(rb"(?i)(password=|passwd=|pass=|pwd=|Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8})") ),
    # Shell / command injection payloads
    ("CMD_INJECTION",  re.compile(rb"(?i)(/bin/sh|/bin/bash|/etc/passwd|cmd\.exe|powershell\.exe|\$\(|`[^`]+`)") ),
]

# Only inspect unencrypted application protocols (TLS payload is ciphertext)
_DPI_PORTS: set[int] = {80, 8080, 21, 23, 25, 110, 143, 3000, 5000, 8000, 8888}


class PayloadRule:
    name = "PAYLOAD_HIT"

    def __init__(self, max_bytes: int = 512, enabled: bool = True):
        self.max_bytes = max_bytes
        self.enabled   = enabled

    def check(self, record: dict) -> dict | None:
        if not self.enabled:
            return None
        if record.get("type") != "IP":
            return None

        payload: bytes = record.get("payload", b"")
        if not payload:
            return None

        # Only inspect plaintext ports
        dst_port = record.get("dst_port") or 0
        src_port = record.get("src_port") or 0
        if dst_port not in _DPI_PORTS and src_port not in _DPI_PORTS:
            return None

        # Truncate to cap CPU usage
        sample = payload[: self.max_bytes]

        for label, pattern in _PAYLOAD_SIGNATURES:
            m = pattern.search(sample)
            if m:
                matched_bytes = m.group(0)[:80]  # keep evidence short
                try:
                    matched_str = matched_bytes.decode("utf-8", errors="replace")
                except Exception:
                    matched_str = repr(matched_bytes)
                logger.debug(f"PAYLOAD_HIT [{label}]: {record.get('src_ip')} → {record.get('dst_ip')}:{dst_port}")
                return {
                    "rule_name": self.name,
                    "src_ip": record.get("src_ip"),
                    "dst_ip": record.get("dst_ip"),
                    "dst_port": dst_port,
                    "detail": (
                        f"{record.get('src_ip')} → {record.get('dst_ip')}:{dst_port} "
                        f"contains {label} pattern: '{matched_str}'"
                    ),
                    "severity": "high",
                    "evidence": {"signature": label, "matched": matched_str},
                }
        return None


# =============================================================================
# Rule 6: DNS Tunneling & DGA Detection — Shannon Entropy
# =============================================================================

# Domains whose labels are legitimately high-entropy (CDN, tracking, etc.)
_DGA_WHITELIST_SUFFIXES: tuple[str, ...] = (
    ".cloudflare.com", ".akamai.net", ".akamaiedge.net",
    ".cdn.ampproject.org", ".amazonaws.com", ".fastly.net",
    ".google.com", ".googleapis.com", ".gstatic.com",
    ".doubleclick.net", ".googlevideo.com", ".fbcdn.net",
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

    def __init__(self, entropy_threshold: float = 3.5, max_query_len: int = 50):
        self.entropy_threshold = entropy_threshold
        self.max_query_len     = max_query_len
        # per-src_ip dedup: (src_ip, domain) → last_alert_time
        # prevents re-alerting on same domain within 60s
        self._seen: dict[tuple, float] = {}

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP":
            return None
        if record.get("dst_port") != 53 and record.get("src_port") != 53:
            return None

        domain: str | None = record.get("dns_query")
        if not domain:
            return None

        # Strip trailing dot (FQDN)
        domain = domain.rstrip(".")
        src = record.get("src_ip", "unknown")

        # Whitelist legitimate high-entropy CDN / cloud domains
        dl = domain.lower()
        if any(dl.endswith(w) for w in _DGA_WHITELIST_SUFFIXES):
            return None

        # Extract the leftmost label (the randomly generated part in DGA)
        labels = domain.split(".")
        subdomain = labels[0] if labels else domain

        entropy  = _shannon_entropy(subdomain)
        too_long = len(domain) > self.max_query_len
        # Require label length >= 8 for entropy checks to avoid false positives on short words
        high_ent = len(subdomain) >= 8 and entropy >= self.entropy_threshold

        if not (high_ent or too_long):
            return None

        # Deduplicate — don't fire on the same (src, domain) within 60s
        key = (src, domain)
        now = record.get("timestamp", time.time())
        if now - self._seen.get(key, 0) < 60:
            return None
        self._seen[key] = now
        # Prune old entries to prevent unbounded growth
        if len(self._seen) > 5000:
            cutoff = now - 120
            self._seen = {k: v for k, v in self._seen.items() if v > cutoff}

        reason = []
        if high_ent:
            reason.append(f"entropy={entropy:.2f} (≥{self.entropy_threshold})")
        if too_long:
            reason.append(f"length={len(domain)} chars (>{self.max_query_len})")

        sub_type = "DNS_DGA" if high_ent else "DNS_TUNNEL"
        logger.debug(f"{sub_type} fired: {src} queried '{domain}' [{', '.join(reason)}]")
        return {
            "rule_name": self.name,
            "src_ip": src,
            "dst_ip": record.get("dst_ip"),
            "dst_port": 53,
            "detail": (
                f"{src} queried suspicious domain '{domain}' "
                f"[{', '.join(reason)}] — possible DGA/DNS-tunneling"
            ),
            "severity": "high",
            "evidence": {
                "domain": domain,
                "subdomain": subdomain,
                "entropy": round(entropy, 3),
                "sub_type": sub_type,
            },
        }


# =============================================================================
# Rule Engine Orchestrator
# =============================================================================

class RuleEngine:
    """
    Runs all rules against every packet record.
    Writes any resulting alerts to the database asynchronously.
    Also tracks seen devices for the dashboard device list.
    """

    def __init__(self, db_conn, blocklist_set: set, cfg):
        from storage.db import write_alert, upsert_device
        import engine.rules as _rules_mod
        import queue
        import threading
        
        self._write_alert = write_alert
        self._upsert_device = upsert_device

        # Load trusted hosts from config into module-level set (used by FP filters)
        trusted = getattr(cfg, "TRUSTED_HOSTS", set())
        _rules_mod.TRUSTED_HOSTS.clear()
        _rules_mod.TRUSTED_HOSTS.update(trusted)
        if trusted:
            logger.info(f"Trusted hosts loaded: {trusted}")

        self.rules = [
            BlocklistRule(blocklist_set),
            PortScanRule(cfg.PORT_SCAN_THRESHOLD, cfg.TIME_WINDOW),
            SynFloodRule(cfg.SYN_FLOOD_THRESHOLD, cfg.TIME_WINDOW),
            ArpSpoofRule(cfg.ARP_TABLE_PATH),
            PayloadRule(
                max_bytes=getattr(cfg, "PAYLOAD_MAX_BYTES", 512),
                enabled=getattr(cfg, "PAYLOAD_INSPECTION", True),
            ),
            DnsRule(
                entropy_threshold=getattr(cfg, "DNS_ENTROPY_THRESHOLD", 3.5),
                max_query_len=getattr(cfg, "DNS_QUERY_MAX_LEN", 50),
            ),
        ]
        
        # Async writer setup
        self._write_queue = queue.Queue()
        self._writer_thread = threading.Thread(target=self._db_writer_loop, daemon=True)
        self._writer_thread.start()

        # GC thread setup for stateful rules
        self._gc_thread = threading.Thread(target=self._gc_loop, daemon=True)
        self._gc_thread.start()

        import atexit
        atexit.register(self.flush)

    def _gc_loop(self):
        import time
        while True:
            time.sleep(10) # Prune every 10 seconds
            now = time.time()
            for rule in self.rules:
                if hasattr(rule, 'prune_stale'):
                    try:
                        rule.prune_stale(now)
                    except Exception as e:
                        logger.error(f"Rule GC error for {rule.name}: {e}")

    def _db_writer_loop(self):
        from storage.db import get_connection
        conn = get_connection()
        while True:
            try:
                task, data = self._write_queue.get()
                if task == 'alert':
                    self._write_alert(conn, data)
                elif task == 'device':
                    self._upsert_device(conn, data['mac'], data['ip'])
                self._write_queue.task_done()
            except Exception as e:
                logger.error(f"DB writer error: {e}")
                self._write_queue.task_done()

    def flush(self):
        """Wait for pending writes in the queue to finish processing and flush rules."""
        self._write_queue.join()
        for rule in self.rules:
            if hasattr(rule, 'flush'):
                try:
                    rule.flush()
                except Exception as e:
                    logger.error(f"Rule flush error: {e}")

    def check(self, record: dict):
        # Track device
        mac = record.get("src_mac")
        ip = record.get("src_ip")
        if mac and ip:
            self._write_queue.put(('device', {'mac': mac, 'ip': ip}))

        # Run all rules
        for rule in self.rules:
            try:
                alert = rule.check(record)
                if alert:
                    alert["timestamp"] = record.get("timestamp", time.time())
                    self._write_queue.put(('alert', alert))
                    logger.info(f"[ALERT] {alert['rule_name']} — {alert['detail']}")
            except Exception as e:
                logger.error(f"Rule {rule.name} error: {e}")

