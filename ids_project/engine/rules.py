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
  2. PortScanRule      — stateful, vertical + horizontal TCP scan tracking
  3. UdpScanRule       — stateful, vertical + horizontal UDP scan tracking
  4. TcpStealthScanRule — stateful FIN/NULL/Xmas vertical TCP scan tracking
  5. SynFloodRule      — stateful, SYN burst rate per (src,dst,port)
  6. DistributedSynFloodRule — SYN burst per destination across many sources
  7. IcmpSweepRule     — stateful, ICMP echo target sweep by source
  8. ArpSpoofRule      — stateful, persistent IP→MAC table
  9. PayloadRule       — bounded TCP stream DPI + regex signatures (all matches)
 10. DnsRule           — stateful Shannon-entropy + query-frequency

False Positive Mitigations:
  - PortScanRule: ignores hosts whose SOURCE port is a well-known service
    (servers replying to clients, not scanners).
  - PortScanRule: only counts SYN packets (new connection attempts).
  - SynFloodRule: only fires on service destination ports (≤ 49151).
  - Configurable TRUSTED_HOSTS whitelist for TCP/UDP scans, SYN-flood rules,
    and ICMP sweeps.
  - Configurable WELL_KNOWN_SERVICE_PORTS set.
  - DnsRule: whitelists common high-entropy-but-legit CDN patterns.
  - All stateful rules: per-rule threading.Lock (§3.8).

Thread safety:
  Every stateful rule guards its mutable history/table/stream state with a
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
from urllib.parse import unquote_to_bytes
from collections import defaultdict, Counter, deque

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

# Trusted hosts/IPs that should never be flagged by scan, SYN-flood, or ICMP rules.
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
    rule_version = "1.3"

    def __init__(self, threshold: int = 15, window: int = 10, protocol: str = "TCP",
                 max_states: int = 10_000):
        self.threshold = threshold
        self.window = window
        self.protocol = protocol
        self.max_states = max(1, int(max_states))
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
                for key in list(d):
                    active = [e for e in d[key] if cutoff <= e[0] <= now]
                    if active:
                        d[key] = active
                    else:
                        del d[key]

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

        protocol = record.get("protocol", "")
        if protocol != self.protocol:
            return None

        # TCP scans count initial SYNs only. UDP has no handshake, so the
        # separate UdpScanRule counts datagrams and relies on distinct targets.
        if self.protocol == "TCP":
            if "initial_syn" in record:
                if not record.get("initial_syn"):
                    return None
            elif not record.get("syn_flag"):
                return None

        dst_ip = record.get("dst_ip", "")
        dst_port = record.get("dst_port")
        if dst_port is None:
            return None

        now = record.get("timestamp", time.time())
        vkey = (src, dst_ip)
        hkey = (src, dst_port)

        with self._lock:
            if (self._vert.get(vkey) and now < max(t for t, _ in self._vert[vkey])) or \
               (self._horiz.get(hkey) and now < max(t for t, _ in self._horiz[hkey])):
                return None  # don't let late events skew an active window
            # Always update BOTH vertical and horizontal histories first,
            # then check thresholds. This ensures a packet contributes to
            # both scan dimensions even when one threshold fires. (P2 §4)
            if vkey not in self._vert and len(self._vert) >= self.max_states:
                self._vert.pop(next(iter(self._vert)))
            if hkey not in self._horiz and len(self._horiz) >= self.max_states:
                self._horiz.pop(next(iter(self._horiz)))

            # --- Vertical history update ---
            # A scan is defined by distinct targets, so retain only the latest
            # observation per port. Repeated connections to one service must
            # refresh its window membership without growing state per packet.
            vertical = [(t, p) for t, p in self._vert.get(vkey, [])
                        if 0 <= now - t <= self.window and p != dst_port]
            vertical.append((now, dst_port))
            self._vert.pop(vkey, None)
            self._vert[vkey] = vertical
            distinct_ports = len({p for _, p in vertical})

            # --- Horizontal history update ---
            # Likewise, repeated probes to one host do not add scan evidence.
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
                self._vert.pop(vkey, None)  # reset to prevent alert storm
                logger.debug(
                    f"{self.name} (vertical) fired: {src}→{dst_ip} "
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
                        f"{src} sent {'SYN' if self.protocol == 'TCP' else 'UDP probes'} "
                        f"to {distinct_ports} distinct ports on {dst_ip} in {self.window}s "
                        f"— possible vertical {self.protocol} port scan"
                    ),
                    "evidence": {
                        "scan_type": "vertical",
                        "transport": self.protocol,
                        "distinct_ports": distinct_ports,
                        "target_host": dst_ip,
                        "window_s": self.window,
                        "threshold": self.threshold,
                    },
                    "window_start": window_start,
                    "window_end": now,
                }

            if horiz_fired:
                window_start = min(t for t, _ in horizontal)
                self._horiz.pop(hkey, None)
                logger.debug(
                    f"{self.name} (horizontal) fired: {src} port {dst_port} "
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
                        f"{src} sent {'SYN' if self.protocol == 'TCP' else 'UDP probes'} "
                        f"to port {dst_port} on {distinct_hosts} distinct hosts in "
                        f"{self.window}s — possible horizontal {self.protocol} port scan"
                    ),
                    "evidence": {
                        "scan_type": "horizontal",
                        "transport": self.protocol,
                        "distinct_hosts": distinct_hosts,
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
    rule_version = "1.1"

    def __init__(self, threshold: int = 15, window: int = 10,
                 max_states: int = 10_000):
        super().__init__(threshold, window, protocol="UDP", max_states=max_states)


class TcpStealthScanRule:
    """Detect vertical FIN, NULL, and Xmas TCP probes."""

    name = "TCP_STEALTH_SCAN"
    rule_version = "1.0"
    _FIN, _SYN, _RST, _PSH, _ACK, _URG, _ECE, _CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
    _XMAS_FLAGS = _FIN | _PSH | _URG
    _DISALLOWED_FLAGS = _SYN | _RST | _ACK | _ECE | _CWR

    def __init__(self, threshold: int = 15, window: int = 10,
                 max_states: int = 10_000):
        self.threshold = max(1, int(threshold))
        self.window = max(1, int(window))
        self.max_states = max(1, int(max_states))
        self._lock = threading.RLock()
        self._probes: dict[tuple, list[tuple[float, int, str]]] = {}

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
        if src_port in WELL_KNOWN_SERVICE_PORTS or dst_port is None or flags is None:
            return None
        probe_type = self._probe_type(int(flags))
        if probe_type is None:
            return None

        now = float(record.get("event_timestamp", record.get("timestamp", time.time())))
        key = (src, dst)
        cutoff = now - self.window
        with self._lock:
            history = self._probes.get(key, [])
            if history and now < max(ts for ts, _, _ in history):
                return None
            active = [(ts, port, kind) for ts, port, kind in history
                      if cutoff <= ts <= now and port != int(dst_port)]
            active.append((now, int(dst_port), probe_type))
            if key not in self._probes and len(self._probes) >= self.max_states:
                self._probes.pop(next(iter(self._probes)))
            self._probes.pop(key, None)
            self._probes[key] = active
            distinct_ports = len({port for _, port, _ in active})
            if distinct_ports < self.threshold:
                return None

            kinds = sorted({kind for _, _, kind in active})
            window_start = min(ts for ts, _, _ in active)
            self._probes.pop(key, None)
            return {
                "rule_name": self.name,
                "rule_version": self.rule_version,
                "src_ip": src,
                "dst_ip": dst,
                "src_port": src_port,
                "dst_port": int(dst_port),
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


# =============================================================================
# Rule 3: SYN Burst / Connection-Rate Abuse  (§3.3 — label clarified)
# =============================================================================

class SynFloodRule:
    name = "SYN_FLOOD"
    rule_version = "1.2"

    def __init__(self, threshold: int = 100, window: int = 10,
                 max_flows: int = 8192):
        self.threshold = threshold
        self.window = window
        self.max_flows = max(1, int(max_flows))
        self._lock = threading.RLock()
        # (src_ip, dst_ip, dst_port) → list of SYN timestamps
        self._history: dict[tuple, list] = defaultdict(list)

    def prune_stale(self, now: float):
        cutoff = now - self.window
        with self._lock:
            for key in list(self._history):
                active = [t for t in self._history[key] if cutoff <= t <= now]
                if active:
                    self._history[key] = active
                else:
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
            if key not in self._history and len(self._history) >= self.max_flows:
                self._history.pop(next(iter(self._history)))
            history = self._history.get(key, [])
            if history and now < history[-1]:
                return None  # ignore reordered events; they cannot be in this window
            history = [t for t in history if 0 <= now - t <= self.window]
            history.append(now)
            self._history.pop(key, None)
            self._history[key] = history
            count = len(history)
            window_start = history[0]

        if count >= self.threshold:
            with self._lock:
                self._history.pop(key, None)
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


class DistributedSynFloodRule:
    """Detect high-volume initial-SYN bursts to one service from many sources."""

    name = "DISTRIBUTED_SYN_FLOOD"
    rule_version = "1.1"

    def __init__(self, threshold: int = 500, min_sources: int = 20,
                 window: int = 10, max_targets: int = 2048):
        self.threshold = max(1, int(threshold))
        self.min_sources = max(1, int(min_sources))
        self.window = max(1, int(window))
        self.max_targets = max(1, int(max_targets))
        self._lock = threading.RLock()
        # (dst_ip, dst_port) → (last threshold packet times, recent source map).
        # Packet count is exact as a threshold predicate: if the newest
        # `threshold` events fit in the window, the window contains at least
        # that many events; if they do not, no older event can restore it.
        # Keeping the most recently active `min_sources` sources is enough to
        # decide the distinct-source predicate without retaining every packet.
        self._history: dict[tuple, tuple[deque[float], dict[str, float]]] = {}

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

    def check(self, record: dict) -> dict | None:
        if record.get("type") != "IP" or record.get("protocol") != "TCP":
            return None
        if "initial_syn" in record:
            if not record.get("initial_syn"):
                return None
        elif not record.get("syn_flag"):
            return None

        src, dst, dst_port = record.get("src_ip"), record.get("dst_ip"), record.get("dst_port")
        if not src or not dst or not isinstance(dst_port, int) or not 1 <= dst_port <= 49151:
            return None
        if _is_trusted(src):
            return None

        now = float(record.get("event_timestamp", record.get("timestamp", time.time())))
        key = (dst, dst_port)
        with self._lock:
            state = self._history.get(key)
            if state is None:
                if len(self._history) >= self.max_targets:
                    self._history.pop(next(iter(self._history)))
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
            self._history.pop(key, None)

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
    rule_version = "1.1"

    def __init__(self, threshold: int = 12, window: int = 10,
                 max_sources: int = 4096):
        self.threshold = max(1, int(threshold))
        self.window = max(1, int(window))
        self.max_sources = max(1, int(max_sources))
        self._lock = threading.RLock()
        self._history: dict[str, list[tuple[float, str]]] = defaultdict(list)

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

    def check(self, record: dict) -> dict | None:
        protocol = record.get("protocol")
        if record.get("type") != "IP" or protocol not in {"ICMP", "ICMPV6"}:
            return None
        expected_type = 128 if protocol == "ICMPV6" else 8
        if record.get("icmp_type") != expected_type or record.get("icmp_code", 0) != 0:
            return None  # count echo requests, never replies or control messages

        src, dst = record.get("src_ip"), record.get("dst_ip")
        if not src or not dst or src == dst or _is_trusted(src):
            return None

        now = float(record.get("event_timestamp", record.get("timestamp", time.time())))
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
            window_start = min(ts for ts, _ in history)
            self._history.pop(src, None)  # one alert per completed burst

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


# Rule 5: ARP Spoofing Detection
# =============================================================================
class ArpSpoofRule:
    name = "ARP_SPOOF"
    rule_version = "1.3"

    # Per-IP cooldown: once an alert fires for a given IP, suppress repeats
    # for this many seconds to avoid alert storms. Set to 0 to disable.
    ALERT_COOLDOWN_S: float = 120.0

    def __init__(self, table_path: str, max_entries: int = 65_536,
                 max_cooldowns: int = 10_000):
        self.table_path = table_path
        self.max_entries = max(1, int(max_entries))
        self.max_cooldowns = max(1, int(max_cooldowns))
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
                now_t = record.get("timestamp", time.time())
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
    rule_version = "1.4"

    def __init__(self, max_bytes: int = 512, enabled: bool = True,
                 stream_timeout: int = 30, max_streams: int = 2048):
        self.max_bytes = max(1, int(max_bytes))
        self.enabled   = enabled
        self.stream_timeout = max(1, int(stream_timeout))
        self.max_streams = max(1, int(max_streams))
        self._stream_lock = threading.RLock()
        # Directional 4-tuples keep client requests and server responses apart.
        # Each value is (next expected sequence, bounded bytes, last event time,
        # a small bounded set of out-of-order segments).
        self._streams: dict[tuple, tuple[int, bytes, float, dict[int, bytes]]] = {}

    def prune_stale(self, now: float):
        cutoff = now - self.stream_timeout
        with self._stream_lock:
            for key in list(self._streams):
                if self._streams[key][2] < cutoff or self._streams[key][2] > now:
                    del self._streams[key]

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
        now = float(record.get("event_timestamp", record.get("timestamp", time.time())))
        key = (src, sport, dst, dport)
        seq = int(seq) & 0xFFFFFFFF

        with self._stream_lock:
            state = self._streams.get(key)
            if state is None or now - state[2] > self.stream_timeout:
                if key not in self._streams and len(self._streams) >= self.max_streams:
                    self._streams.pop(next(iter(self._streams)))
                next_seq = (seq + len(payload)) & 0xFFFFFFFF
                sample = payload[-self.max_bytes:]
                pending: dict[int, bytes] = {}
            else:
                expected, previous, last_seen, pending = state
                if now < last_seen:
                    return None  # late segments cannot alter the contiguous stream
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
            self._streams[key] = (next_seq, sample, now, pending)
            flags = int(record.get("tcp_flags") or 0)
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

        packet_sample = payload[: self.max_bytes]
        stream_sample = self._update_stream(record, payload)
        samples: list[tuple[bytes, str]] = [(packet_sample, "packet")]
        if stream_sample and stream_sample != packet_sample:
            samples.append((stream_sample, "tcp_stream"))
        # Inspect common single-encoded URL payloads as well as the raw bytes.
        # '+' is a space in form-encoded values; retain the raw view too.
        for sample, source in list(samples):
            decoded = unquote_to_bytes(sample) if b"%" in sample else sample
            if b"%" in sample:
                if decoded != sample:
                    samples.append((decoded, "percent_decoded"))
            if b"+" in sample:
                # Decode raw form '+' as space before percent escapes so an
                # encoded literal %2B remains a plus sign.
                form_decoded = unquote_to_bytes(sample.replace(b"+", b" "))
                if form_decoded != decoded:
                    samples.append((form_decoded, "form_decoded"))

        # Collect ALL matching signatures (§3.4 — do not return on first match)
        hits: list[dict] = []
        for label, pattern, confidence in _PAYLOAD_SIGNATURES:
            match = None
            for sample, source in samples:
                found = pattern.search(sample)
                if found is not None:
                    match = (found, source)
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
                    self._streams[key] = (state[0], b"", state[2], state[3])

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
                "inspected_bytes": max(len(sample) for sample, _ in samples),
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
    rule_version = "1.6"

    # Alert dedup cooldown — class-level default; overridable via __init__
    ALERT_COOLDOWN_S = 60

    def __init__(
        self,
        entropy_threshold: float = 3.8,
        max_query_len: int = 60,
        freq_threshold: int = 20,
        freq_window: int = 60,
        max_frequency_keys: int = 10_000,
        max_seen_keys: int = 10_000,
    ):
        self.entropy_threshold = entropy_threshold
        self.max_query_len     = max_query_len
        # Frequency detection parameters — wired from config via RuleEngine (P1)
        self._freq_threshold   = freq_threshold
        self._freq_window      = freq_window
        self._max_frequency_keys = max(1, int(max_frequency_keys))
        self._max_seen_keys = max(1, int(max_seen_keys))
        self._lock = threading.RLock()

        # (src_ip, parent_domain, anomaly_type) → last_alert_time (dedup)
        self._seen: dict[tuple, float] = {}

        # (src_ip, parent_domain) → bounded [timestamps] (query frequency)
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
            for key in list(self._freq):
                active = [t for t in self._freq[key] if cutoff <= t <= now]
                if active:
                    self._freq[key] = active
                else:
                    del self._freq[key]
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

        # DNS labels are case-insensitive; canonicalize before deriving the
        # frequency and dedup keys so mixed-case queries still aggregate.
        domain = domain.rstrip(".").lower()
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
        parent_label_count = len(parent.split(".")) if parent else 0
        registrable_index = max(0, len(labels) - parent_label_count)
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
        too_long = len(domain) > self.max_query_len
        # Require at least one relevant label of length >= 8 to limit FPs.
        # Also skip entropy checks for explicitly allowlisted CDN suffixes.
        high_ent = (
            not entropy_exempt
            and bool(entropy_candidates)
            and entropy >= self.entropy_threshold
        )

        # ── Query frequency: count repeated queries to same parent domain ──
        # Keep only the threshold-sized rolling tail: once the threshold is
        # reached, larger exact counts do not change the detection decision.
        # This bounds a single hot domain even when queries arrive at line rate.
        # A disabled frequency rule must not allocate or retain per-domain state.
        query_count = 0
        freq_window_start = None
        query_count_saturated = False
        if self._freq_threshold > 0:
            with self._lock:
                fkey = (src, parent)
                if fkey not in self._freq and len(self._freq) >= self._max_frequency_keys:
                    self._freq.pop(next(iter(self._freq)))
                history = self._freq.get(fkey, [])
                if history and now < history[-1]:
                    return None  # ignore late observations instead of corrupting the window
                history = [
                    t for t in history if 0 <= now - t <= self._freq_window
                ]
                if len(history) >= self._freq_threshold:
                    query_count_saturated = True
                    history = history[-(self._freq_threshold - 1):] if self._freq_threshold > 1 else []
                history.append(now)
                self._freq.pop(fkey, None)
                self._freq[fkey] = history
                query_count = len(history)
                freq_window_start = history[0]

        high_freq = query_count >= self._freq_threshold > 0

        if not (high_ent or too_long or high_freq):
            return None

        sub_type = "DNS_FREQ" if high_freq and not (high_ent or too_long) \
                   else ("DNS_DGA" if high_ent else "DNS_TUNNEL")

        # Deduplicate by parent and anomaly class. Randomized query labels under
        # one domain otherwise evade per-QNAME cooldowns and can flood alerts.
        alert_key = (src, parent, sub_type)
        with self._lock:
            last_alert = self._seen.get(alert_key)
            if last_alert is not None and now - last_alert < self.ALERT_COOLDOWN_S:
                return None
            if alert_key not in self._seen and len(self._seen) >= self._max_seen_keys:
                self._seen.pop(next(iter(self._seen)))
            self._seen.pop(alert_key, None)
            self._seen[alert_key] = now

        reason = []
        if high_ent:
            reason.append(
                f"entropy={entropy:.2f} for label '{entropy_label}' "
                f"(≥{self.entropy_threshold})"
            )
        if too_long:
            reason.append(f"length={len(domain)} chars (>{self.max_query_len})")
        if high_freq:
            reason.append(
                f"query_count={query_count} to '{parent}' "
                f"in {self._freq_window}s (≥{self._freq_threshold})"
            )

        logger.debug(f"{sub_type} fired: {src} queried '{domain}' [{', '.join(reason)}]")
        return {
            "rule_name": self.name,
            "rule_version": self.rule_version,
            "src_ip": src,
            "dst_ip": record.get("dst_ip"),
            "src_port": record.get("src_port"),
            "dst_port": 53,
            "protocol": record.get("protocol", "UDP"),
            "severity": "medium" if high_freq and not (high_ent or too_long) else "high",
            "confidence": "heuristic",
            "detail": (
                f"{src} queried suspicious domain '{domain}' "
                f"[{', '.join(reason)}] — possible {sub_type}"
            ),
            "evidence": {
                "domain": domain,
                "subdomain": subdomain,
                "entropy_label": entropy_label,
                "parent_domain": parent,
                "entropy": round(entropy, 3),
                "sub_type": sub_type,
                "query_count_in_window": query_count,
                "query_count_saturated": query_count_saturated,
                "freq_window_s": self._freq_window,
                "freq_threshold": self._freq_threshold,
            },
            "window_start": freq_window_start if high_freq else None,
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
            UdpScanRule(
                getattr(cfg, "UDP_SCAN_THRESHOLD", 15), cfg.TIME_WINDOW
            ),
            TcpStealthScanRule(
                getattr(cfg, "TCP_STEALTH_SCAN_THRESHOLD", 15), cfg.TIME_WINDOW
            ),
            SynFloodRule(cfg.SYN_FLOOD_THRESHOLD, cfg.TIME_WINDOW),
            DistributedSynFloodRule(
                getattr(cfg, "DISTRIBUTED_SYN_FLOOD_THRESHOLD", 500),
                getattr(cfg, "DISTRIBUTED_SYN_FLOOD_MIN_SOURCES", 20),
                cfg.TIME_WINDOW,
            ),
            IcmpSweepRule(
                getattr(cfg, "ICMP_SWEEP_THRESHOLD", 12), cfg.TIME_WINDOW
            ),
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
