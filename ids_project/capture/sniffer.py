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
  payload_len        -- full captured transport-payload length before DPI cap
  dns_query          -- str FQDN (for DNS anomaly rule, UDP or TCP port 53 queries)
  dns_qtype, dns_id  -- DNS question type and transaction ID when present

For ARP packets: type=ARP, src_ip, src_mac, dst_ip are set; port/flag fields are None/False.

Fields are None when the protocol does not provide them.
Rules must fail safely when expected optional fields are absent.

Requires: sudo / CAP_NET_RAW capability for live sniff.
"""

import time
import logging
import sys
import os
import hashlib
import struct
import socket
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

logger = logging.getLogger(__name__)

try:
    from scapy.all import (
        sniff, IP, IPv6, IPv6ExtHdrFragment, TCP, UDP, ARP, Ether, ICMP, ICMPv6EchoRequest,
        ICMPv6EchoReply, DNS, DNSQR, Raw,
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

# Preserve a bounded TCP payload sample for the existing TLS SNI detector.
# ClientHello extensions can occur beyond the smaller DPI payload sample.
_TLS_INSPECTION_PORTS = frozenset({443, 4443, 8443, 9443, 5223, 8083})
_TLS_INSPECTION_MAX_BYTES = 16_389  # maximum TLS record payload plus header


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
            "payload_len": 0,
            "dns_query": None,
        })
        return record

    # --- IPv4 or IPv6 packet ---
    if IP in pkt or IPv6 in pkt:
        ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
        is_ipv6 = IPv6 in pkt and IP not in pkt
        proto_num = ip_layer.nh if is_ipv6 else ip_layer.proto
        ip_fragment_id = None
        ip_fragment_offset = 0
        ip_more_fragments = False
        ip_fragmented = False
        ip_fragment_data_digest = None
        ip_fragment_data_len = 0
        if is_ipv6 and IPv6ExtHdrFragment in pkt:
            fragment_layer = pkt[IPv6ExtHdrFragment]
            proto_num = int(fragment_layer.nh)
            ip_fragment_id = int(fragment_layer.id)
            ip_fragment_offset = int(fragment_layer.offset) * 8
            ip_more_fragments = bool(fragment_layer.m)
            ip_fragmented = True
            fragment_data = bytes(fragment_layer.payload)
            ip_fragment_data_len = len(fragment_data)
            if fragment_data:
                ip_fragment_data_digest = hashlib.blake2s(fragment_data, digest_size=16).digest()
        elif not is_ipv6:
            ip_fragment_offset = int(ip_layer.frag or 0) * 8
            ip_more_fragments = bool(int(ip_layer.flags or 0) & 0x01)
            ip_fragmented = bool(ip_fragment_offset or ip_more_fragments)
            if ip_fragmented:
                ip_fragment_id = int(ip_layer.id)
                fragment_data = bytes(ip_layer.payload)
                ip_fragment_data_len = len(fragment_data)
                if fragment_data:
                    ip_fragment_data_digest = hashlib.blake2s(fragment_data, digest_size=16).digest()
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPV6"}
        proto = proto_map.get(proto_num, str(proto_num))

        dst_port    = None
        src_port    = None
        syn_flag    = False
        initial_syn = False
        tcp_seq     = None
        tcp_ack     = None
        tcp_flags   = None
        tcp_window  = None
        tcp_payload_seq = None
        payload     = b""
        tls_payload = b""
        payload_len = 0
        tcp_payload_digest = None
        dns_query   = None
        dns_qtype   = None
        dns_id      = None
        icmp_type   = None
        icmp_code   = None
        try:
            if not is_ipv6:
                ip_len = int(pkt[IP].len) if hasattr(pkt[IP], "len") and pkt[IP].len is not None else None
            else:
                ip_len = int(pkt[IPv6].plen) + 40 if hasattr(pkt[IPv6], "plen") and pkt[IPv6].plen is not None else None
        except (ValueError, TypeError, OverflowError):
            ip_len = None

        if TCP in pkt:
            proto = "TCP"
            try:
                dst_port = int(pkt[TCP].dport)
            except (ValueError, TypeError, OverflowError):
                dst_port = None
            try:
                src_port = int(pkt[TCP].sport)
            except (ValueError, TypeError, OverflowError):
                src_port = None
            flags = getattr(pkt[TCP], "flags", 0)
            try:
                tcp_flags = int(flags)
            except (ValueError, TypeError):
                tcp_flags = 0
            try:
                tcp_seq = int(pkt[TCP].seq) if pkt[TCP].seq is not None else None
            except (ValueError, TypeError, OverflowError):
                tcp_seq = None
            try:
                tcp_ack = int(pkt[TCP].ack) if pkt[TCP].ack is not None else None
            except (ValueError, TypeError, OverflowError):
                tcp_ack = None
            tcp_window = int(pkt[TCP].window) if hasattr(pkt[TCP], "window") and pkt[TCP].window is not None else None
            syn_flag = bool(tcp_flags & 0x02)  # SYN bit
            initial_syn = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)  # SYN set, ACK clear
            tcp_payload_seq = ((tcp_seq + int(bool(tcp_flags & 0x02))) & 0xFFFFFFFF) if tcp_seq is not None else None
            try:
                tcp_payload = bytes(pkt[TCP].payload)
                payload_len = len(tcp_payload)
                if dst_port in _TLS_INSPECTION_PORTS:
                    tls_payload = tcp_payload[:_TLS_INSPECTION_MAX_BYTES]
                if tcp_payload:
                    tcp_payload_digest = hashlib.blake2s(tcp_payload, digest_size=16).digest()
            except Exception:
                payload_len = 0
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)[: _PAYLOAD_MAX_BYTES]
            if DNS in pkt and (dst_port == 53 or src_port == 53) and getattr(pkt[DNS], "qr", None) == 0:
                try:
                    question = pkt[DNS].qd
                    if isinstance(question, (list, tuple)):
                        question = question[0] if question else None
                    if question is not None:
                        qname_raw = getattr(question, "qname", None)
                        if isinstance(qname_raw, bytes):
                            dns_query = qname_raw.decode("utf-8", errors="replace")
                        elif isinstance(qname_raw, str):
                            dns_query = qname_raw
                        else:
                            dns_query = None
                        dns_qtype = int(question.qtype) if hasattr(question, "qtype") and question.qtype is not None else None
                        dns_id = int(pkt[DNS].id) if hasattr(pkt[DNS], "id") and pkt[DNS].id is not None else None
                except Exception:
                    dns_query = None
        elif UDP in pkt:
            proto = "UDP"
            try:
                dst_port = int(pkt[UDP].dport)
            except (ValueError, TypeError, OverflowError):
                dst_port = None
            try:
                src_port = int(pkt[UDP].sport)
            except (ValueError, TypeError, OverflowError):
                src_port = None
            try:
                payload_len = len(bytes(pkt[UDP].payload))
            except Exception:
                payload_len = 0
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)[: _PAYLOAD_MAX_BYTES]
            # --- DNS query extraction (for DnsRule) ---
            if DNS in pkt and (dst_port == 53 or src_port == 53) and getattr(pkt[DNS], "qr", None) == 0:
                try:
                    question = pkt[DNS].qd
                    if isinstance(question, (list, tuple)):
                        question = question[0] if question else None
                    if question is not None:
                        qname_raw = getattr(question, "qname", None)
                        if isinstance(qname_raw, bytes):
                            dns_query = qname_raw.decode("utf-8", errors="replace")
                        elif isinstance(qname_raw, str):
                            dns_query = qname_raw
                        else:
                            dns_query = None
                        dns_qtype = int(question.qtype) if hasattr(question, "qtype") and question.qtype is not None else None
                        dns_id = int(pkt[DNS].id) if hasattr(pkt[DNS], "id") and pkt[DNS].id is not None else None
                except Exception:
                    dns_query = None
        elif ICMP in pkt:
            try:
                icmp_type = int(pkt[ICMP].type) if pkt[ICMP].type is not None else None
            except (ValueError, TypeError, OverflowError):
                icmp_type = None
            try:
                icmp_code = int(pkt[ICMP].code) if pkt[ICMP].code is not None else None
            except (ValueError, TypeError, OverflowError):
                icmp_code = None
            if Raw in pkt:
                try:
                    raw_bytes = bytes(pkt[Raw].load)
                    payload_len = len(raw_bytes)
                    payload = raw_bytes[: _PAYLOAD_MAX_BYTES]
                except Exception:
                    payload_len = 0
        elif ICMPv6EchoRequest in pkt:
            proto = "ICMPV6"
            icmp_type = 128
            icmp_code = pkt[ICMPv6EchoRequest].code
            echo_data = bytes(getattr(pkt[ICMPv6EchoRequest], "data", b"") or b"")
            payload_len = len(echo_data)
            payload = echo_data[: _PAYLOAD_MAX_BYTES]
        elif ICMPv6EchoReply in pkt:
            proto = "ICMPV6"
            icmp_type = 129
            icmp_code = pkt[ICMPv6EchoReply].code
            echo_data = bytes(getattr(pkt[ICMPv6EchoReply], "data", b"") or b"")
            payload_len = len(echo_data)
            payload = echo_data[: _PAYLOAD_MAX_BYTES]

        # A non-initial IP fragment has no transport header for Scapy to
        # dissect. Its raw fragment bytes are still part of the original
        # transport payload and must be available to volume rules.
        if ip_fragment_offset > 0 and Raw in pkt:
            fragment_payload = bytes(pkt[Raw].load)
            payload_len = len(fragment_payload)
            payload = fragment_payload[: _PAYLOAD_MAX_BYTES]

        # Preserve payload bytes for uncommon IP protocols that Scapy leaves
        # as Raw rather than decoding into a transport-specific layer.
        if payload_len == 0 and Raw in pkt:
            raw_payload = bytes(pkt[Raw].load)
            payload_len = len(raw_payload)
            payload = raw_payload[: _PAYLOAD_MAX_BYTES]

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
            "tcp_ack": tcp_ack,
            "tcp_flags": tcp_flags,
            "tcp_window": tcp_window,
            "tcp_payload_seq": tcp_payload_seq,
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "ip_len": ip_len,
            "ip_fragmented": ip_fragmented,
            "ip_fragment_id": ip_fragment_id,
            "ip_fragment_offset": ip_fragment_offset,
            "ip_more_fragments": ip_more_fragments,
            "ip_fragment_data_len": ip_fragment_data_len,
            "ip_fragment_data_digest": ip_fragment_data_digest,
            "payload": payload,
            "tls_payload": tls_payload,
            "payload_len": payload_len,
            "tcp_payload_digest": tcp_payload_digest,
            "dns_query": dns_query,
            "dns_qtype": dns_qtype,
            "dns_id": dns_id,
        })
        return record

    return None  # ignore non-IP, non-ARP packets


def start_sniff(
    interface: str,
    rule_engine,
    packet_filter: str = "ip or ip6 or arp",
    metrics: Any = None,
    count: int = 0,
    timeout: int | None = None,
    stop_filter: Any = None,
    flow_tracker: Any = None,
    pcap_retention: Any = None,
):
    """
    Start live packet capture on `interface`.
    Wires raw wire byte retention, flow tracking, extraction, and detection.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not installed")

    from capture.metrics import get_active_metrics, set_active_metrics, PacketProcessingMetrics
    if metrics is None:
        metrics = get_active_metrics()
    else:
        set_active_metrics(metrics)

    logger.info(f"Starting capture on interface '{interface}' (filter: '{packet_filter}')")
    logger.info("Press Ctrl+C to stop.")

    if not metrics.is_reporter_running():
        metrics.start_reporter(interval_s=1.0)

    # Attach flow tracker to rule engine if supported
    if flow_tracker is not None and hasattr(rule_engine, "set_flow_tracker"):
        rule_engine.set_flow_tracker(flow_tracker)

    def _handle(pkt):
        t0 = time.perf_counter()
        metrics.record_callback()

        raw_bytes = None
        seg_id = None
        pkt_idx = None

        # 1. Optional raw wire packet retention
        if pcap_retention is not None and getattr(pcap_retention, "enabled", False):
            try:
                raw_bytes = bytes(pkt)
                seg_id, pkt_idx = pcap_retention.record_packet(
                    raw_bytes,
                    capture_ts=float(getattr(pkt, "time", time.time()))
                )
            except Exception as exc:
                logger.debug(f"PCAP retention error: {exc}")

        # 2. Packet extraction
        try:
            # capture_ts=None → _extract() uses pkt.time (kernel timestamp)
            record = _extract(pkt, capture_ts=None)
        except Exception as exc:
            metrics.record_extraction_exception(exc)
            logger.error(f"Packet extraction error: {exc}")
            return

        if record is None:
            metrics.record_ignored()
            return

        metrics.record_extraction_success()
        metrics.record_engine_submission()

        # 3. Wire bytes / hex and flow identity assignment
        if raw_bytes is None:
            try:
                raw_bytes = bytes(pkt)
            except Exception:
                raw_bytes = None
        if raw_bytes is not None:
            record["raw_hex"] = raw_bytes.hex()

        if seg_id is not None:
            record["pcap_segment_id"] = seg_id
            record["packet_index"] = pkt_idx

        if flow_tracker is not None:
            try:
                flow_tracker.process_packet(
                    record,
                    pcap_segment_id=seg_id,
                    packet_index=pkt_idx
                )
            except Exception as exc:
                logger.debug(f"Flow tracking error: {exc}")

        # 4. Stateful RuleEngine evaluation
        try:
            rule_engine.check(record)
            duration = time.perf_counter() - t0
            metrics.record_check_completed(duration)
        except Exception as exc:
            duration = time.perf_counter() - t0
            metrics.record_engine_exception(exc, duration)
            logger.error(f"Detection engine check error: {exc}")

    try:
        sniff_kwargs = {
            "iface": interface,
            "prn": _handle,
            "filter": packet_filter,
            "store": False,       # don't buffer packets in memory
        }
        if count > 0:
            sniff_kwargs["count"] = count
        if timeout is not None:
            sniff_kwargs["timeout"] = timeout
        if stop_filter is not None:
            sniff_kwargs["stop_filter"] = stop_filter

        sniff(**sniff_kwargs)
    finally:
        metrics.stop_reporter()
        logger.info(metrics.format_summary())


def _parse_tcpdump_endpoint(ep: str):
    common_ports = {
        'https': 443, 'http': 80, 'domain': 53, 'ssh': 22,
        'ntp': 123, 'ftp': 21, 'telnet': 23, 'smtp': 25, 'dns': 53,
        'ldap': 389, 'ldaps': 636, 'submission': 587, 'imaps': 993,
        'pop3s': 995, 'ms-sql-s': 1433, 'ms-sql': 1433, 'mysql': 3306,
        'postgres': 5432, 'postgresql': 5432, 'redis': 6379, 'memcache': 11211,
        'rdp': 3389, 'snmp': 161, 'bgp': 179,
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
                "dns_qtype":   None,
                "dns_id":      None,
            }
            rule_engine.check(record)
            processed += 1

    if skipped:
        logger.warning(f"Text log replay: {skipped} lines could not be parsed (skipped)")
    if processed == 0:
        logger.error("Text log replay: zero records were successfully parsed.")
    logger.info(f"Replay complete: {processed} text log entries processed ({skipped} skipped)")
    return {"processed": processed, "total": processed + skipped}


def _parse_dns_query(payload: bytes):
    """
    Fast binary extraction of (dns_query, dns_qtype, dns_id, trailing_payload)
    from DNS header and first Question record.
    """
    if len(payload) < 12:
        return None, None, None, payload
    try:
        dns_id, flags, qdcount = struct.unpack("!HHH", payload[:6])
        qr = (flags >> 15) & 0x01
        if qr != 0 or qdcount == 0:
            return None, None, None, payload
        parts = []
        idx = 12
        n = len(payload)
        visited = 0
        while idx < n and visited < 50:
            l = payload[idx]
            if l == 0:
                idx += 1
                break
            if (l & 0xC0) == 0xC0:
                if idx + 2 > n:
                    break
                ptr = ((l & 0x3F) << 8) | payload[idx + 1]
                idx += 2
                p_parts = []
                p_idx = ptr
                p_vis = 0
                while p_idx < n and p_vis < 20:
                    pl = payload[p_idx]
                    if pl == 0:
                        break
                    p_idx += 1
                    if p_idx + pl > n:
                        break
                    p_parts.append(payload[p_idx : p_idx + pl].decode("utf-8", errors="replace"))
                    p_idx += pl
                    p_vis += 1
                if p_parts:
                    parts.append(".".join(p_parts))
                break
            idx += 1
            if idx + l > n:
                break
            parts.append(payload[idx : idx + l].decode("utf-8", errors="replace"))
            idx += l
            visited += 1

        qname = (".".join(parts) + ".") if parts else None
        qtype = None
        if idx + 2 <= n:
            qtype = struct.unpack("!H", payload[idx : idx + 2])[0]
            idx += 2
            if idx + 2 <= n:
                idx += 2  # skip qclass
        trailing = payload[idx:] if idx < n else b""
        return qname, qtype, dns_id, trailing
    except Exception:
        return None, None, None, payload


def _fast_extract(pkt_bytes: bytes, capture_ts: float | None = None, linktype: int = 1) -> dict | None:
    """
    High-speed binary packet extractor using struct unpacking.
    Returns normalized record dict with 100% field parity with Scapy _extract(),
    or None if the packet is non-IP/non-ARP or cannot be parsed.
    """
    now = time.time()
    event_ts = float(capture_ts) if capture_ts is not None else now
    rec = {
        "event_timestamp": event_ts,
        "processing_timestamp": now,
        "timestamp": event_ts,
    }
    n = len(pkt_bytes)
    offset = 0
    src_mac = None
    ethertype = None

    if linktype == 1:  # LINKTYPE_ETHERNET
        if n < 14:
            return None
        ethertype = struct.unpack("!H", pkt_bytes[12:14])[0]
        offset = 14
        if ethertype == 0x8100:  # 802.1Q VLAN
            if n < 18:
                return None
            ethertype = struct.unpack("!H", pkt_bytes[16:18])[0]
            offset = 18
        src_mac = ":".join(f"{b:02x}" for b in pkt_bytes[6:12])
    elif linktype in (12, 228):  # RAW / IPv4
        ethertype = 0x0800
        offset = 0
    elif linktype == 229:  # IPv6
        ethertype = 0x86dd
        offset = 0
    else:
        return None

    if ethertype == 0x0806:  # ARP
        if n < offset + 28:
            return None
        hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack("!HHBBH", pkt_bytes[offset : offset + 8])
        if hw_len == 6 and proto_len == 4:
            hwsrc = ":".join(f"{b:02x}" for b in pkt_bytes[offset + 8 : offset + 14])
            psrc = socket.inet_ntoa(pkt_bytes[offset + 14 : offset + 18])
            pdst = socket.inet_ntoa(pkt_bytes[offset + 24 : offset + 28])
            rec.update({
                "type": "ARP",
                "src_ip": psrc,
                "src_mac": hwsrc,
                "dst_ip": pdst,
                "dst_port": None,
                "src_port": None,
                "protocol": "ARP",
                "syn_flag": False,
                "initial_syn": False,
                "icmp_type": None,
                "icmp_code": None,
                "ip_len": None,
                "payload": b"",
                "payload_len": 0,
                "dns_query": None,
            })
            return rec
        return None

    if ethertype in (0x0800, 0x86dd):
        is_ipv6 = (ethertype == 0x86dd)
        ip_fragment_offset = 0
        ip_more_fragments = False
        ip_fragmented = False
        ip_fragment_id = None
        ip_fragment_data_len = 0
        ip_fragment_data_digest = None

        if not is_ipv6:
            if n < offset + 20:
                return None
            b0 = pkt_bytes[offset]
            if (b0 >> 4) != 4:
                return None
            ihl = (b0 & 0x0F) * 4
            if ihl < 20 or n < offset + ihl:
                return None
            ip_len, ip_id, flags_frag, ttl, proto_num = struct.unpack("!HHHBB", pkt_bytes[offset + 2 : offset + 10])
            src_ip = socket.inet_ntoa(pkt_bytes[offset + 12 : offset + 16])
            dst_ip = socket.inet_ntoa(pkt_bytes[offset + 16 : offset + 20])
            ip_fragment_offset = (flags_frag & 0x1FFF) * 8
            ip_more_fragments = bool(flags_frag & 0x2000)
            ip_fragmented = bool(ip_fragment_offset or ip_more_fragments)
            ip_fragment_id = ip_id if ip_fragmented else None

            frag_end = min(n, offset + ip_len) if ip_len else n
            frag_data = pkt_bytes[offset + ihl : frag_end]
            ip_fragment_data_len = len(frag_data) if ip_fragmented else 0
            ip_fragment_data_digest = (
                hashlib.blake2s(frag_data, digest_size=16).digest() if (ip_fragmented and frag_data) else None
            )
            to = offset + ihl
        else:
            if n < offset + 40:
                return None
            plen, next_hdr = struct.unpack("!HB", pkt_bytes[offset + 4 : offset + 7])
            src_ip = socket.inet_ntop(socket.AF_INET6, pkt_bytes[offset + 8 : offset + 24])
            dst_ip = socket.inet_ntop(socket.AF_INET6, pkt_bytes[offset + 24 : offset + 40])
            ip_len = plen + 40
            to = offset + 40
            proto_num = next_hdr
            if proto_num == 44:  # IPv6 Fragment
                if n < to + 8:
                    return None
                nh, res, frag_off_m, frag_id = struct.unpack("!BBHI", pkt_bytes[to : to + 8])
                proto_num = nh
                ip_fragment_id = frag_id
                ip_fragment_offset = (frag_off_m >> 3) * 8
                ip_more_fragments = bool(frag_off_m & 1)
                ip_fragmented = True
                to += 8
                frag_data = pkt_bytes[to : min(n, offset + ip_len)]
                ip_fragment_data_len = len(frag_data)
                ip_fragment_data_digest = (
                    hashlib.blake2s(frag_data, digest_size=16).digest() if frag_data else None
                )

        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPV6"}
        proto = proto_map.get(proto_num, str(proto_num))

        dst_port = None
        src_port = None
        syn_flag = False
        initial_syn = False
        tcp_seq = None
        tcp_ack = None
        tcp_flags = None
        tcp_window = None
        tcp_payload_seq = None
        payload = b""
        tls_payload = b""
        payload_len = 0
        tcp_payload_digest = None
        dns_query = None
        dns_qtype = None
        dns_id = None
        icmp_type = None
        icmp_code = None

        if proto_num == 6 and ip_fragment_offset == 0:
            if n >= to + 20:
                src_port, dst_port, tcp_seq, tcp_ack, data_off_res, tcp_flags, tcp_window = struct.unpack(
                    "!HHIIBBH", pkt_bytes[to : to + 16]
                )
                tcp_header_len = ((data_off_res >> 4) & 0x0F) * 4
                if tcp_header_len >= 20 and n >= to + tcp_header_len:
                    syn_flag = bool(tcp_flags & 0x02)
                    initial_syn = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)
                    tcp_payload_seq = ((tcp_seq + int(syn_flag)) & 0xFFFFFFFF) if tcp_seq is not None else None
                    pay_start = to + tcp_header_len
                    pay_end = min(n, offset + ip_len) if ip_len else n
                    tcp_payload = pkt_bytes[pay_start:pay_end] if pay_end > pay_start else b""
                    payload_len = len(tcp_payload)
                    payload = tcp_payload[:_PAYLOAD_MAX_BYTES]
                    if dst_port in _TLS_INSPECTION_PORTS:
                        tls_payload = tcp_payload[:_TLS_INSPECTION_MAX_BYTES]
                    if tcp_payload:
                        tcp_payload_digest = hashlib.blake2s(tcp_payload, digest_size=16).digest()
                    if (dst_port == 53 or src_port == 53) and len(tcp_payload) >= 12:
                        qname, qtype, qid, _ = _parse_dns_query(tcp_payload)
                        if not qname and len(tcp_payload) >= 14:
                            qname, qtype, qid, _ = _parse_dns_query(tcp_payload[2:])
                        if qname:
                            dns_query = qname
                            dns_qtype = qtype
                            dns_id = qid
        elif proto_num == 17 and ip_fragment_offset == 0:
            if n >= to + 8:
                src_port, dst_port, udp_len, udp_csum = struct.unpack("!HHHH", pkt_bytes[to : to + 8])
                pay_start = to + 8
                pay_end = min(n, to + udp_len) if udp_len >= 8 else n
                udp_payload = pkt_bytes[pay_start:pay_end] if pay_end > pay_start else b""
                payload_len = len(udp_payload)
                if dst_port == 53 or src_port == 53:
                    qname, qtype, qid, trailing = _parse_dns_query(udp_payload)
                    if qname:
                        dns_query = qname
                        dns_qtype = qtype
                        dns_id = qid
                        payload = trailing[:_PAYLOAD_MAX_BYTES]
                    else:
                        payload = udp_payload[:_PAYLOAD_MAX_BYTES]
                else:
                    payload = udp_payload[:_PAYLOAD_MAX_BYTES]
        elif proto_num in (1, 58):
            if n >= to + 2:
                icmp_type, icmp_code = struct.unpack("!BB", pkt_bytes[to : to + 2])
                pay_start = to + 8
                pay_end = min(n, offset + ip_len) if ip_len else n
                icmp_payload = pkt_bytes[pay_start:pay_end] if pay_end > pay_start else b""
                payload_len = len(icmp_payload)
                payload = icmp_payload[:_PAYLOAD_MAX_BYTES]

        if ip_fragment_offset > 0:
            payload_len = len(frag_data)
            payload = frag_data[:_PAYLOAD_MAX_BYTES]

        record = {
            "event_timestamp": event_ts,
            "processing_timestamp": now,
            "timestamp": event_ts,
            "type": "IP",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_mac": src_mac,
            "dst_port": dst_port,
            "src_port": src_port,
            "protocol": proto,
            "syn_flag": syn_flag,
            "initial_syn": initial_syn,
            "tcp_seq": tcp_seq,
            "tcp_ack": tcp_ack,
            "tcp_flags": tcp_flags,
            "tcp_window": tcp_window,
            "tcp_payload_seq": tcp_payload_seq,
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "ip_len": ip_len,
            "ip_fragmented": ip_fragmented,
            "ip_fragment_id": ip_fragment_id,
            "ip_fragment_offset": ip_fragment_offset,
            "ip_more_fragments": ip_more_fragments,
            "ip_fragment_data_len": ip_fragment_data_len,
            "ip_fragment_data_digest": ip_fragment_data_digest,
            "payload": payload,
            "tls_payload": tls_payload,
            "payload_len": payload_len,
            "tcp_payload_digest": tcp_payload_digest,
            "dns_query": dns_query,
            "dns_qtype": dns_qtype,
            "dns_id": dns_id,
        }
        return record

    return None


def _replay_fast_pcap(pcap_path: str, rule_engine, progress_callback=None) -> dict | None:
    """
    High-speed binary PCAP replay using struct unpacking.
    Returns {"processed": int, "total": int} on success, or None to fall back to Scapy.
    """
    try:
        with open(pcap_path, "rb") as f:
            f.seek(0, 2)
            file_size = f.tell()
            f.seek(0, 0)
            gh = f.read(24)
            if len(gh) < 24:
                return None
            magic = gh[:4]
            if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                endian = ">"
            elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                endian = "<"
            else:
                return None

            is_nano = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
            network = struct.unpack(endian + "I", gh[20:24])[0]
            if network not in (1, 12, 228, 229):
                return None

            hdr_fmt = endian + "IIII"
            processed = 0
            total = 0
            logger.info(f"Replaying binary pcap via fast binary parser: {pcap_path}")

            while True:
                hdr_bytes = f.read(16)
                if len(hdr_bytes) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(hdr_fmt, hdr_bytes)
                pkt_bytes = f.read(incl_len)
                if len(pkt_bytes) < incl_len:
                    break
                total += 1
                capture_ts = ts_sec + (ts_usec / 1e9 if is_nano else ts_usec / 1e6)
                record = _fast_extract(pkt_bytes, capture_ts, linktype=network)
                if record is not None and record.get("ip_fragmented") and SCAPY_AVAILABLE:
                    try:
                        pkt = Ether(pkt_bytes) if network == 1 else IP(pkt_bytes)
                        scapy_rec = _extract(pkt, capture_ts=capture_ts)
                        if scapy_rec:
                            record = scapy_rec
                    except Exception:
                        pass
                if record is not None:
                    rule_engine.check(record)
                    processed += 1
                elif SCAPY_AVAILABLE:
                    try:
                        pkt = Ether(pkt_bytes) if network == 1 else IP(pkt_bytes)
                        record = _extract(pkt, capture_ts=capture_ts)
                        if record:
                            rule_engine.check(record)
                            processed += 1
                    except Exception:
                        pass

                if progress_callback and total % 50 == 0:
                    pct = min(99.0, round((f.tell() / max(file_size, 1)) * 100.0, 1))
                    try:
                        progress_callback(processed, total, pct)
                    except Exception:
                        pass

            if progress_callback:
                try:
                    progress_callback(processed, total, 100.0)
                except Exception:
                    pass

            logger.info(f"Fast replay complete: {processed}/{total} packets processed")
            return {"processed": processed, "total": total}
    except Exception as exc:
        logger.warning(f"Fast pcap reader exception ({exc}); falling back to Scapy")
        return None


def replay_pcap(pcap_path: str, rule_engine, use_fast_parser: bool | None = None,
                progress_callback=None):
    """
    Replay a saved .pcap or tcpdump text file through the rule engine.
    Automatically detects whether file is binary PCAP or ASCII tcpdump log.
    Returns dict with 'processed' and 'total' packet counts.
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
        return {"processed": 0, "total": 0}

    if not is_binary_pcap:
        # File is ASCII text (e.g. created with `tcpdump > file.pcap` or `tcpdump > file.log`)
        return _replay_text_log(pcap_path, rule_engine)

    # Determine fast parser usage
    if use_fast_parser is None:
        try:
            import config as _cfg
            use_fast = getattr(_cfg, "USE_FAST_PARSER", True)
        except Exception:
            use_fast = True
        if os.environ.get("NETGUARD_FAST_PARSER", "").lower() in ("0", "false", "no"):
            use_fast = False
    else:
        use_fast = use_fast_parser

    if use_fast:
        fast_res = _replay_fast_pcap(pcap_path, rule_engine, progress_callback=progress_callback)
        if fast_res is not None:
            return fast_res

    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not installed")

    from scapy.utils import PcapReader
    logger.info(f"Replaying binary pcap via Scapy: {pcap_path}")
    processed = 0
    total = 0
    reader = PcapReader(pcap_path)
    try:
        for pkt in reader:
            total += 1
            try:
                capture_ts = float(pkt.time)
            except Exception:
                capture_ts = None
            record = _extract(pkt, capture_ts=capture_ts)
            if record:
                rule_engine.check(record)
                processed += 1
            if progress_callback and total % 50 == 0:
                try:
                    progress_callback(processed, total, None)
                except Exception:
                    pass
        if progress_callback:
            try:
                progress_callback(processed, total, 100.0)
            except Exception:
                pass
    finally:
        reader.close()
    logger.info(f"Replay complete: {processed}/{total} packets processed")
    return {"processed": processed, "total": total}

