"""
capture/sniffer.py
------------------
Packet capture and field extraction.
Uses Scapy to sniff on the chosen interface.

Extracted fields per packet (normalized event schema):
  type               -- "IP" | "ARP"
  event_timestamp    -- capture/packet timestamp (pkt.time for PCAP replay;
                        time.time() for live sniff). Use this for sliding-window
                        rules so that PCAP replay is deterministic.
  processing_timestamp -- wall-clock time when _extract() ran (always time.time()).
  src_ip, dst_ip, src_mac
  dst_port, src_port
  protocol           -- "TCP" | "UDP" | "ICMP" | "ARP" | str(proto_num)
  syn_flag           -- bool, True only for TCP SYN packets
  icmp_type, icmp_code -- int, present only for ICMP packets
  ip_len             -- total IP packet length in bytes (for volume tracking)
  payload            -- bytes, capped at PAYLOAD_MAX_BYTES (for DPI rule)
  dns_query          -- str FQDN (for DNS anomaly rule, UDP port 53 queries only)

For ARP packets: type=ARP, src_ip, src_mac, dst_ip are set; port/flag fields are None/False.

Fields are None when the protocol does not provide them.
Rules must fail safely when expected optional fields are absent.

Requires: sudo / CAP_NET_RAW capability for live sniff.
"""

import time
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

logger = logging.getLogger(__name__)

try:
    from scapy.all import sniff, IP, TCP, UDP, ARP, Ether, ICMP, DNS, DNSQR, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.error("Scapy not installed. Run: pip install scapy")

# Maximum payload bytes forwarded to DPI rule (tune via config)
try:
    import config as _cfg
    _PAYLOAD_MAX_BYTES = getattr(_cfg, "PAYLOAD_MAX_BYTES", 512)
except Exception:
    _PAYLOAD_MAX_BYTES = 512


def _extract(pkt, capture_ts: float | None = None) -> dict | None:
    """
    Extract a normalised record dict from a raw Scapy packet.

    Args:
        pkt:        Raw Scapy packet.
        capture_ts: Override for event_timestamp (use pkt.time during PCAP
                    replay so that sliding-window rules are deterministic).
                    If None, pkt.time is used when available, otherwise
                    falls back to current wall-clock time.
    """
    now = time.time()  # processing wall-clock time — always real time

    # Resolve event timestamp: explicit override → pkt.time → wall clock
    if capture_ts is not None:
        event_ts = float(capture_ts)
    else:
        try:
            event_ts = float(pkt.time)
        except Exception:
            event_ts = now

    record = {
        "event_timestamp": event_ts,
        "processing_timestamp": now,
        # Legacy alias so existing rules that read record["timestamp"] still work
        "timestamp": event_ts,
    }

    # --- ARP packet ---
    if ARP in pkt:
        record.update({
            "type": "ARP",
            "src_ip": pkt[ARP].psrc,
            "src_mac": pkt[ARP].hwsrc,
            "dst_ip": pkt[ARP].pdst,
            "dst_port": None,
            "src_port": None,
            "protocol": "ARP",
            "syn_flag": False,
            "initial_syn": False,
            "icmp_type": None,
            "icmp_code": None,
            "ip_len": None,
            "payload": b"",
            "dns_query": None,
        })
        return record

    # --- IP packet ---
    if IP in pkt:
        proto_num = pkt[IP].proto
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto = proto_map.get(proto_num, str(proto_num))

        dst_port    = None
        src_port    = None
        syn_flag    = False
        initial_syn = False
        payload     = b""
        dns_query   = None
        icmp_type   = None
        icmp_code   = None
        ip_len      = pkt[IP].len  # total IP packet length in bytes

        if TCP in pkt:
            dst_port = pkt[TCP].dport
            src_port = pkt[TCP].sport
            flags = pkt[TCP].flags
            syn_flag = bool(flags & 0x02)  # SYN bit
            initial_syn = bool(flags & 0x02) and not bool(flags & 0x10)  # SYN set, ACK clear
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)[: _PAYLOAD_MAX_BYTES]
        elif UDP in pkt:
            dst_port = pkt[UDP].dport
            src_port = pkt[UDP].sport
            # --- DNS query extraction (for DnsRule) ---
            if DNS in pkt and pkt[DNS].qr == 0:  # qr=0 means query
                try:
                    if pkt[DNS].qd is not None:
                        dns_query = pkt[DNS].qd.qname.decode("utf-8", errors="replace")
                except Exception:
                    dns_query = None
        elif ICMP in pkt:
            icmp_type = pkt[ICMP].type
            icmp_code = pkt[ICMP].code
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)[: _PAYLOAD_MAX_BYTES]

        record.update({
            "type": "IP",
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "src_mac": pkt[Ether].src if Ether in pkt else None,
            "dst_port": dst_port,
            "src_port": src_port,
            "protocol": proto,
            "syn_flag": syn_flag,
            "initial_syn": initial_syn,
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "ip_len": ip_len,
            "payload": payload,
            "dns_query": dns_query,
        })
        return record

    return None  # ignore non-IP, non-ARP packets


def start_sniff(interface: str, rule_engine, packet_filter: str = "ip or arp"):
    """
    Start live packet capture on `interface`.
    Hands each packet to rule_engine.check() after extraction.

    For live sniff, pkt.time is used as event_timestamp (Scapy sets this
    from the kernel timestamp at capture time, which is accurate).

    Args:
        interface:     Network interface name (e.g. "eth0", "wlan0")
        rule_engine:   RuleEngine instance with a .check(record) method
        packet_filter: BPF filter string (default captures IP and ARP)
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not installed")

    logger.info(f"Starting capture on interface '{interface}' (filter: '{packet_filter}')")
    logger.info("Press Ctrl+C to stop.")

    def _handle(pkt):
        try:
            # capture_ts=None → _extract() uses pkt.time (kernel timestamp)
            record = _extract(pkt, capture_ts=None)
            if record:
                rule_engine.check(record)
        except Exception as e:
            logger.error(f"Packet handling error: {e}")

    sniff(
        iface=interface,
        prn=_handle,
        filter=packet_filter,
        store=False,       # don't buffer packets in memory
    )


def _parse_tcpdump_endpoint(ep: str):
    common_ports = {
        'https': 443, 'http': 80, 'domain': 53, 'ssh': 22,
        'ntp': 123, 'ftp': 21, 'telnet': 23, 'smtp': 25, 'dns': 53
    }
    parts = ep.rsplit('.', 1)
    if len(parts) == 2:
        host, port_str = parts[0], parts[1]
        port = int(port_str) if port_str.isdigit() else common_ports.get(port_str.lower())
        return host, port
    return ep, None


def _replay_text_log(log_path: str, rule_engine):
    """
    Parses an ASCII tcpdump output log and feeds records to the rule engine.

    Supported timestamp formats:
      - HH:MM:SS.frac             (tcpdump -nn)
      - YYYY-MM-DD HH:MM:SS.frac  (tcpdump -tttt -nn)  ← documented in README
      - HH:MM:SS                  (no fractional seconds)

    Reports skipped lines and warns if zero records parsed.
    """
    import re
    from datetime import datetime, date

    logger.info(f"Detected ASCII tcpdump text log: {log_path}")
    processed  = 0
    skipped    = 0
    today      = date.today()

    # Regex that matches both full-date and time-only prefixes
    TS_RE = re.compile(
        r'^'
        r'(?P<ts>(?:\d{4}-\d{2}-\d{2}\s+)?\d{2}:\d{2}:\d{2}(?:\.\d+)?)'
        r'\s+'
    )

    def _parse_ts(ts_str: str) -> float:
        """Return a POSIX timestamp from the matched timestamp string."""
        ts_str = ts_str.strip()
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%H:%M:%S.%f",
            "%H:%M:%S",
        ):
            try:
                if fmt.startswith("%H"):
                    dt = datetime.strptime(f"{today} {ts_str}", f"%Y-%m-%d {fmt}")
                else:
                    dt = datetime.strptime(ts_str, fmt)
                return dt.timestamp()
            except ValueError:
                continue
        return time.time()

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue

            ts_m = TS_RE.match(line)
            if not ts_m:
                skipped += 1
                continue
            ts_str = ts_m.group("ts")
            rest_of_line = line[ts_m.end():]

            ts = _parse_ts(ts_str)

            # --- ARP lines ---
            if rest_of_line.startswith("ARP"):
                m_reply = re.search(
                    r'Reply\s+([^\s]+)\s+is-at\s+([0-9a-fA-F:]+)',
                    rest_of_line,
                )
                if m_reply:
                    ip, mac = m_reply.groups()
                    record = {
                        "type": "ARP",
                        "src_ip":  ip,
                        "src_mac": mac,
                        "dst_ip":  None,
                        "dst_port": None,
                        "protocol": "ARP",
                        "syn_flag": False,
                        "initial_syn": False,
                        "timestamp": ts,
                        "event_timestamp": ts,
                        "processing_timestamp": time.time(),
                    }
                    rule_engine.check(record)
                    processed += 1
                else:
                    skipped += 1
                continue

            # --- IP / IP6 lines ---
            m = re.match(
                r'(IP[6]?)\s+([^>]+)\s+>\s+([^:]+):\s*(.*)',
                rest_of_line,
            )
            if not m:
                skipped += 1
                continue

            proto_name, src_ep, dst_ep, detail = m.groups()
            src_host, src_port = _parse_tcpdump_endpoint(src_ep.strip())
            dst_host, dst_port = _parse_tcpdump_endpoint(dst_ep.strip())

            # SYN-only flag: [S] is initial SYN; [S.] is SYN-ACK (server response)
            is_syn_ack  = bool(re.search(r'Flags\s+\[S\.', detail))
            is_any_syn  = bool(re.search(r'Flags\s+\[S',  detail))
            initial_syn = is_any_syn and not is_syn_ack
            syn_flag    = is_any_syn

            protocol = "TCP" if "Flags" in detail else (
                "UDP" if "UDP" in rest_of_line else proto_name
            )

            record = {
                "type":        "IP",
                "src_ip":      src_host,
                "dst_ip":      dst_host,
                "src_mac":     None,
                "src_port":    src_port,
                "dst_port":    dst_port,
                "protocol":    protocol,
                "syn_flag":    syn_flag,
                "initial_syn": initial_syn,
                "timestamp":   ts,
                "event_timestamp": ts,
                "processing_timestamp": time.time(),
                "payload":     b"",
                "dns_query":   None,
            }
            rule_engine.check(record)
            processed += 1

    if skipped:
        logger.warning(f"Text log replay: {skipped} lines could not be parsed (skipped)")
    if processed == 0:
        logger.error("Text log replay: zero records were successfully parsed.")
    logger.info(f"Replay complete: {processed} text log entries processed ({skipped} skipped)")


def replay_pcap(pcap_path: str, rule_engine):
    """
    Replay a saved .pcap or tcpdump text file through the rule engine.
    Automatically detects whether file is binary PCAP or ASCII tcpdump log.
    """
    # Check if the file is an ASCII text log or binary PCAP
    try:
        with open(pcap_path, "rb") as f:
            header = f.read(4)
        # Standard libpcap magic numbers (0xa1b2c3d4, 0xd4c3b2a1, or pcapng 0x0a0d0d0a)
        is_binary_pcap = header in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
                                   b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
                                   b"\x0a\x0d\x0d\x0a")
    except Exception as e:
        logger.error(f"Cannot read file {pcap_path}: {e}")
        return

    if not is_binary_pcap:
        # File is ASCII text (e.g. created with `tcpdump > file.pcap` or `tcpdump > file.log`)
        _replay_text_log(pcap_path, rule_engine)
        return

    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not installed")

    from scapy.all import rdpcap
    logger.info(f"Replaying binary pcap: {pcap_path}")
    packets = rdpcap(pcap_path)
    processed = 0
    for pkt in packets:
        # Pass pkt.time explicitly so that sliding-window rules use the
        # original capture timestamps, making replay deterministic.
        try:
            capture_ts = float(pkt.time)
        except Exception:
            capture_ts = None
        record = _extract(pkt, capture_ts=capture_ts)
        if record:
            rule_engine.check(record)
            processed += 1
    logger.info(f"Replay complete: {processed}/{len(packets)} packets processed")

