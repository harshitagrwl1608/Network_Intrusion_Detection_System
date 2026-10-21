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
  tcp_seq, tcp_flags, tcp_payload_seq -- TCP sequence/flag metadata for bounded DPI stream tracking
  ip_len             -- total IP packet length in bytes (for volume tracking)
  payload            -- bytes, capped at PAYLOAD_MAX_BYTES (for DPI rule)
  dns_query          -- str FQDN (for DNS anomaly rule, UDP or TCP port 53 queries)

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
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, ARP, Ether, ICMP, ICMPv6EchoRequest,
        DNS, DNSQR, Raw,
    )
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

    # --- IPv4 or IPv6 packet ---
    if IP in pkt or IPv6 in pkt:
        ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
        is_ipv6 = IPv6 in pkt and IP not in pkt
        proto_num = ip_layer.nh if is_ipv6 else ip_layer.proto
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPV6"}
        proto = proto_map.get(proto_num, str(proto_num))

        dst_port    = None
        src_port    = None
        syn_flag    = False
        initial_syn = False
        tcp_seq     = None
        tcp_flags   = None
        tcp_window  = None
        tcp_payload_seq = None
        payload     = b""
        dns_query   = None
        icmp_type   = None
        icmp_code   = None
        ip_len      = pkt[IP].len if not is_ipv6 else (
            int(pkt[IPv6].plen) + 40 if pkt[IPv6].plen is not None else None
        )

        if TCP in pkt:
            proto = "TCP"
            dst_port = pkt[TCP].dport
            src_port = pkt[TCP].sport
            flags = pkt[TCP].flags
            tcp_seq = int(pkt[TCP].seq)
            tcp_flags = int(flags)
            tcp_window = int(pkt[TCP].window) if hasattr(pkt[TCP], "window") else None
            syn_flag = bool(flags & 0x02)  # SYN bit
            initial_syn = bool(flags & 0x02) and not bool(flags & 0x10)  # SYN set, ACK clear
            tcp_payload_seq = (tcp_seq + int(bool(flags & 0x02))) & 0xFFFFFFFF
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)[: _PAYLOAD_MAX_BYTES]
            if DNS in pkt and (dst_port == 53 or src_port == 53) and pkt[DNS].qr == 0:
                try:
                    if pkt[DNS].qd is not None:
                        dns_query = pkt[DNS].qd.qname.decode("utf-8", errors="replace")
                except Exception:
                    dns_query = None
        elif UDP in pkt:
            proto = "UDP"
            dst_port = pkt[UDP].dport
            src_port = pkt[UDP].sport
            # --- DNS query extraction (for DnsRule) ---
            if DNS in pkt and (dst_port == 53 or src_port == 53) and pkt[DNS].qr == 0:
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
        elif ICMPv6EchoRequest in pkt:
            proto = "ICMPV6"
            icmp_type = 128
            icmp_code = pkt[ICMPv6EchoRequest].code

        record.update({
            "type": "IP",
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            # Read the captured field directly.  Scapy's ``Ether.src`` may
            # synthesize a default from conf.iface when the field is absent,
            # which performs host interface lookup during offline replay.
            "src_mac": pkt[Ether].fields.get("src") if Ether in pkt else None,
            "dst_port": dst_port,
            "src_port": src_port,
            "protocol": proto,
            "syn_flag": syn_flag,
            "initial_syn": initial_syn,
            "tcp_seq": tcp_seq,
            "tcp_flags": tcp_flags,
            "tcp_window": tcp_window,
            "tcp_payload_seq": tcp_payload_seq,
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "ip_len": ip_len,
            "payload": payload,
            "dns_query": dns_query,
        })
        return record

    return None  # ignore non-IP, non-ARP packets


def start_sniff(interface: str, rule_engine, packet_filter: str = "ip or ip6 or arp"):
    """
    Start live packet capture on `interface`.
    Hands each packet to rule_engine.check() after extraction.

    For live sniff, pkt.time is used as event_timestamp (Scapy sets this
    from the kernel timestamp at capture time, which is accurate).

    Args:
        interface:     Network interface name (e.g. "eth0", "wlan0")
        rule_engine:   RuleEngine instance with a .check(record) method
        packet_filter: BPF filter string (default captures IPv4, IPv6, and ARP)
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
    from datetime import datetime, date, timedelta

    logger.info(f"Detected ASCII tcpdump text log: {log_path}")
    processed  = 0
    skipped    = 0
    today      = date.today()
    time_only_day = today
    last_time_only_seconds = None

    # Regex that matches both full-date and time-only prefixes
    TS_RE = re.compile(
        r'^'
        r'(?P<ts>(?:\d{4}-\d{2}-\d{2}\s+)?\d{2}:\d{2}:\d{2}(?:\.\d+)?)'
        r'\s+'
    )

    def _parse_ts(ts_str: str) -> float:
        """Return a POSIX timestamp from the matched timestamp string."""
        nonlocal time_only_day, last_time_only_seconds
        ts_str = ts_str.strip()
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%H:%M:%S.%f",
            "%H:%M:%S",
        ):
            try:
                if fmt.startswith("%H"):
                    time_value = datetime.strptime(ts_str, fmt)
                    seconds = (
                        time_value.hour * 3600 + time_value.minute * 60
                        + time_value.second + time_value.microsecond / 1_000_000
                    )
                    # tcpdump's time-only format omits the date. Advance the
                    # replay day when sequential records cross midnight, but
                    # leave small out-of-order timestamps on the same day.
                    if (last_time_only_seconds is not None
                            and last_time_only_seconds - seconds > 12 * 3600):
                        time_only_day += timedelta(days=1)
                    if (last_time_only_seconds is None
                            or seconds >= last_time_only_seconds
                            or last_time_only_seconds - seconds > 12 * 3600):
                        last_time_only_seconds = seconds
                    dt = datetime.strptime(
                        f"{time_only_day} {ts_str}", f"%Y-%m-%d {fmt}"
                    )
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
                        "arp_operation": "reply",
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
                    m_request = re.search(
                        r'Request\s+who-has\s+([^\s,]+)'
                        r'(?:\s+\(.*\))?\s+tell\s+([^\s,]+)',
                        rest_of_line,
                    )
                    if m_request:
                        target_ip, sender_ip = m_request.groups()
                        record = {
                            "type": "ARP",
                            "src_ip": sender_ip,
                            "src_mac": None,  # tcpdump without -e omits link-layer identity
                            "dst_ip": target_ip,
                            "arp_operation": "request",
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
                # The endpoint separator is a colon followed by whitespace.
                # IPv6 address literals contain colons, so splitting at the
                # first colon truncates the destination before its port.
                r'(IP[6]?)\s+([^>]+)\s+>\s+(.+?):\s+(.*)',
                rest_of_line,
            )
            if not m:
                skipped += 1
                continue

            proto_name, src_ep, dst_ep, detail = m.groups()
            src_host, src_port = _parse_tcpdump_endpoint(src_ep.strip())
            dst_host, dst_port = _parse_tcpdump_endpoint(dst_ep.strip())

            # Preserve all tcpdump TCP flag bits so rules that detect FIN/NULL/
            # Xmas scans work on text replays as well as binary PCAPs.
            tcp_flags = None
            flags_match = re.search(r'Flags\s+\[([^]]*)\]', detail)
            if flags_match:
                flag_text = flags_match.group(1).strip()
                if flag_text.lower() in ("", "none"):
                    tcp_flags = 0
                else:
                    flag_bits = {
                        "F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08,
                        ".": 0x10, "A": 0x10, "U": 0x20, "E": 0x40,
                        "W": 0x80,
                    }
                    if all(char in flag_bits for char in flag_text):
                        tcp_flags = 0
                        for char in flag_text:
                            tcp_flags |= flag_bits[char]

            is_any_syn = bool(tcp_flags is not None and tcp_flags & 0x02)
            initial_syn = is_any_syn and not bool(tcp_flags & 0x10)
            syn_flag = is_any_syn

            win_m = re.search(r'\bwin\s+(\d+)\b', detail)
            tcp_window = int(win_m.group(1)) if win_m else None

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
                "tcp_flags": tcp_flags,
                "tcp_window": tcp_window,
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

