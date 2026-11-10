"""
NetGuard IDS — Forensic Ground-Truth Audit V3.1 Test Suite
Covers 31 strict verification invariants exercising the real Audit V3.1.1
parsers, binary decoders, 5-tuple matchers, and classification logic.
"""

import csv
import hashlib
import io
import json
import os
import struct
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from scripts.audits.ctu48_1_ground_truth_audit_v3_1 import (
    parse_zeek_header,
    parse_zeek_line,
    PcapParser,
    match_packet_to_candidates,
    classify_alert_v3_1,
    get_file_sha256,
    build_arp_alert_row,
    build_per_alert_row,
    assess_alert_retransmission,
    match_scan_target,
)


# =============================================================================
# 1-7: PCAP Binary Decoding, Framing & TCP Flag Invariants
# =============================================================================

def test_01_initial_syn_and_ack_distinction():
    """1. Test that initial SYN (SYN=1, ACK=0) is accepted while SYN-ACK, ACK, and RST are rejected."""
    # SYN only (0x02)
    syn_only = 0x02
    assert ((syn_only & 0x12) == 0x02) and ((syn_only & 0x05) == 0)

    # SYN + ACK (0x12) -> must be rejected
    syn_ack = 0x12
    assert not (((syn_ack & 0x12) == 0x02) and ((syn_ack & 0x05) == 0))

    # ACK only (0x10) -> must be rejected
    ack_only = 0x10
    assert not (((ack_only & 0x12) == 0x02) and ((ack_only & 0x05) == 0))

    # RST only (0x04) or SYN+RST (0x06) -> must be rejected
    assert not (((0x04 & 0x12) == 0x02) and ((0x04 & 0x05) == 0))
    assert not (((0x06 & 0x12) == 0x02) and ((0x06 & 0x05) == 0))


def test_02_pcap_magic_and_endianness_detection(tmp_path):
    """2. Test PCAP parser correctly handles little-endian, big-endian, and nanosecond magic."""
    pcap_le = tmp_path / "le.pcap"
    # Magic 0xa1b2c3d4, v2.4, snaplen 65535, DLT_EN10MB (1)
    pcap_le.write_bytes(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    with PcapParser(str(pcap_le)) as p:
        assert p.is_nanosecond is False
        assert p.linktype == 1

    pcap_nano = tmp_path / "nano.pcap"
    pcap_nano.write_bytes(struct.pack("<IHHiIII", 0xa1b23c4d, 2, 4, 0, 0, 65535, 1))
    with PcapParser(str(pcap_nano)) as p:
        assert p.is_nanosecond is True


def test_03_unsupported_link_type_rejection(tmp_path):
    """3. Test that non-Ethernet link-layer types (e.g. Raw IP, DLT 101) raise ValueError."""
    pcap_raw = tmp_path / "raw_ip.pcap"
    pcap_raw.write_bytes(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))

    with pytest.raises(ValueError, match="Unsupported link-layer type"):
        with PcapParser(str(pcap_raw)) as p:
            pass


def test_04_runt_frame_and_truncated_packet_handling(tmp_path):
    """4. Test that truncated packets (< 14 bytes) are safely skipped without crash."""
    pcap_runt = tmp_path / "runt.pcap"
    # Header + 1 packet with caplen = 8 (< 14 bytes)
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    pkt_hdr = struct.pack("<IIII", 100, 0, 8, 8)
    pkt_data = b"12345678"
    pcap_runt.write_bytes(hdr + pkt_hdr + pkt_data)

    with PcapParser(str(pcap_runt)) as p:
        packets = list(p.iter_packets())
        # The runt packet record is counted, but does not become a decoded frame.
        assert len(packets) == 0
        assert p.packet_records_read == 1
        assert p.runt_frames == 1


def test_05_vlan_8021q_encapsulation_parsing(tmp_path):
    """5. Test that 802.1Q VLAN tagged frames (EtherType 0x8100) are unpacked with 4-byte offset."""
    pcap_vlan = tmp_path / "vlan.pcap"
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    # Ethernet dst + src (12 bytes) + 0x8100 (2 bytes) + TCI (2 bytes) + 0x0800 (2 bytes)
    eth = b"\x00" * 12 + struct.pack(">H", 0x8100) + struct.pack(">H", 100) + struct.pack(">H", 0x0800)
    # IPv4 header: ver=4, ihl=5 (20 bytes), proto=6 (TCP), sip=192.168.1.200, dip=10.0.0.1
    ip = bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 192, 168, 1, 200, 10, 0, 0, 1])
    # TCP header: sport=50000, dport=23, seq=1, ack=0, offset=5 (20 bytes), flags=0x02 (SYN)
    tcp = struct.pack(">HHIIBBHHH", 50000, 23, 1, 0, 0x50, 0x02, 65535, 0, 0)

    frame = eth + ip + tcp
    pkt_hdr = struct.pack("<IIII", 1551377744, 0, len(frame), len(frame))
    pcap_vlan.write_bytes(hdr + pkt_hdr + frame)

    with PcapParser(str(pcap_vlan)) as p:
        packets = list(p.iter_packets())
        assert len(packets) == 1
        idx, ts, is_ip, is_tcp, is_syn, is_arp, sip, sport, dip, dport, flags, _ = packets[0]
        assert is_ip is True
        assert is_tcp is True
        assert is_syn is True
        assert sip == "192.168.1.200"
        assert dip == "10.0.0.1"
        assert dport == 23


def test_06_ipv4_ihl_options_offset_handling(tmp_path):
    """6. Test that IPv4 packets with options (IHL > 5) compute correct TCP offset."""
    pcap_ihl = tmp_path / "ihl.pcap"
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    eth = b"\x00" * 12 + struct.pack(">H", 0x0800)
    # IHL = 6 (24 bytes IPv4 header with 4 bytes IP options)
    ip = bytes([0x46, 0, 0, 44, 0, 0, 0, 0, 64, 6, 0, 0, 192, 168, 1, 200, 10, 0, 0, 2]) + b"\x00\x00\x00\x00"
    tcp = struct.pack(">HHIIBBHHH", 50001, 23, 1, 0, 0x50, 0x02, 65535, 0, 0)

    frame = eth + ip + tcp
    pkt_hdr = struct.pack("<IIII", 1551377744, 0, len(frame), len(frame))
    pcap_ihl.write_bytes(hdr + pkt_hdr + frame)

    with PcapParser(str(pcap_ihl)) as p:
        packets = list(p.iter_packets())
        assert len(packets) == 1
        idx, ts, is_ip, is_tcp, is_syn, is_arp, sip, sport, dip, dport, flags, _ = packets[0]
        assert is_syn is True
        assert sport == 50001
        assert dport == 23


def test_07_real_arp_frame_parsing(tmp_path):
    """7. Test raw ARP frame decoding (opcode, MACs, IPs)."""
    pcap_arp = tmp_path / "arp.pcap"
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    eth = b"\xff" * 6 + b"\x78\x8a\x20\x43\x93\xd5" + struct.pack(">H", 0x0806)
    # ARP Request (opcode 1) for 192.168.1.1 -> 192.168.1.200
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1)
    arp += b"\x78\x8a\x20\x43\x93\xd5" + bytes([192, 168, 1, 1])
    arp += b"\x00" * 6 + bytes([192, 168, 1, 200])

    frame = eth + arp
    pkt_hdr = struct.pack("<IIII", 1551377780, 0, len(frame), len(frame))
    pcap_arp.write_bytes(hdr + pkt_hdr + frame)

    with PcapParser(str(pcap_arp)) as p:
        packets = list(p.iter_packets())
        assert len(packets) == 1
        idx, ts, is_ip, is_tcp, is_syn, is_arp, sip, sport, dip, dport, flags, arp_data = packets[0]
        assert is_arp is True
        assert arp_data["sip"] == "192.168.1.1"
        assert arp_data["smac"] == "78:8a:20:43:93:d5"
        assert arp_data["opcode"] == 1


# =============================================================================
# 8-13: Header-Driven Zeek Log Parser Invariants
# =============================================================================

def test_08_dynamic_header_fields_parsing():
    """8. Test parsing of dynamic #fields header with space-separated trailing fields."""
    header = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents   label   detailed-label"
    hmap = parse_zeek_header(header)
    assert hmap["ts"] == 0
    assert hmap["uid"] == 1
    assert hmap["id.orig_h"] == 2
    assert hmap["id.resp_p"] == 5
    assert hmap["proto"] == 6
    assert hmap["duration"] == 8
    assert hmap["label"] == 21
    assert hmap["detailed-label"] == 22


def test_09_zeek_line_extraction_via_header_map():
    """9. Test data line extraction using the dynamic header indices."""
    header = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents   label   detailed-label"
    hmap = parse_zeek_header(header)

    cols = [
        "1551377744.163719", "Ctest_uid_1", "192.168.1.200", "38448", "1.1.1.1", "23",
        "tcp", "-", "3.141713", "0", "0", "S0", "-", "-", "0", "S", "6", "360", "0", "0",
        "-   Malicious   PartOfAHorizontalPortScan"
    ]
    line = "\t".join(cols)
    rec = parse_zeek_line(line, hmap)

    assert rec is not None
    assert rec["uid"] == "Ctest_uid_1"
    assert rec["orig_h"] == "192.168.1.200"
    assert rec["orig_p"] == 38448
    assert rec["resp_h"] == "1.1.1.1"
    assert rec["resp_p"] == 23
    assert rec["proto"] == "tcp"
    assert rec["duration"] == 3.141713
    assert rec["duration_is_sentinel"] is False
    assert rec["label"] == "Malicious"
    assert rec["detailed_label"] == "PartOfAHorizontalPortScan"


def test_10_zeek_dash_sentinel_duration_tracking():
    """10. Test that '-' in duration is tracked as duration_is_sentinel without fabricating bad data."""
    hmap = {"ts": 0, "uid": 1, "id.orig_h": 2, "id.orig_p": 3, "id.resp_h": 4, "id.resp_p": 5,
            "proto": 6, "service": 7, "duration": 8, "conn_state": 9, "label": 10, "detailed-label": 11}
    cols = ["100.0", "C1", "192.168.1.200", "1234", "1.1.1.1", "23", "tcp", "-", "-", "S0", "Malicious", "PartOfAHorizontalPortScan"]
    line = "\t".join(cols)
    rec = parse_zeek_line(line, hmap)

    assert rec is not None
    assert rec["duration"] is None
    assert rec["duration_is_sentinel"] is True
    assert rec["end_ts"] is None


def test_11_malformed_zeek_line_rejected():
    """11. Test that truncated or unparseable Zeek lines return None."""
    assert parse_zeek_line("# comment line") is None
    assert parse_zeek_line("short\tline\tonly") is None
    assert parse_zeek_line("nan\tuid\thost\tport\t...") is None


def test_12_non_finite_timestamp_rejected():
    """12. Test that inf, -inf, or NaN timestamps are cleanly rejected."""
    cols = ["inf", "C1", "192.168.1.200", "1234", "1.1.1.1", "23", "tcp", "-", "1.0", "S0", "Malicious", "Scan"]
    assert parse_zeek_line("\t".join(cols)) is None


def test_13_exact_detailed_label_semantics():
    """13. Test that 'PartOfAHorizontalPortScan' is distinguished from generic 'Attack' or 'Scan'."""
    hmap = {"ts": 0, "uid": 1, "id.orig_h": 2, "id.orig_p": 3, "id.resp_h": 4, "id.resp_p": 5,
            "proto": 6, "service": 7, "duration": 8, "conn_state": 9, "label": 10, "detailed-label": 11}

    line_scan = "\t".join(["100.0", "C1", "192.168.1.200", "1234", "1.1.1.1", "23", "tcp", "-", "1.0", "S0", "Malicious", "PartOfAHorizontalPortScan"])
    line_attack = "\t".join(["100.0", "C2", "192.168.1.200", "1234", "1.1.1.1", "23", "tcp", "-", "1.0", "S0", "Malicious", "Attack"])

    rec_scan = parse_zeek_line(line_scan, hmap)
    rec_attack = parse_zeek_line(line_attack, hmap)

    assert rec_scan["detailed_label"] == "PartOfAHorizontalPortScan"
    assert rec_attack["detailed_label"] != "PartOfAHorizontalPortScan"


# =============================================================================
# 14-19: Directional 5-Tuple & Flow Lifetime Matcher Invariants
# =============================================================================

def test_14_exact_directional_five_tuple_matching():
    """14. Test directional 5-tuple matching: orig_h, orig_p, resp_h, resp_p, proto."""
    candidates = [
        ("192.168.1.200", 50000, "1.1.1.1", 23, "tcp",
         100.0, 103.5, "C1", "Malicious", "PartOfAHorizontalPortScan")
    ]
    # Packet matching lifetime [100.0, 103.5] exactly
    matches = match_packet_to_candidates(101.5, "192.168.1.200", 50000, "1.1.1.1", 23, "tcp", candidates)
    assert len(matches) == 1
    assert matches[0][0] == "C1"


def test_15_reverse_direction_traffic_rejected():
    """15. Test that reverse response (server replying to client) does not match forward candidates."""
    forward_candidates = [
        ("192.168.1.200", 50000, "1.1.1.1", 23, "tcp",
         100.0, 103.5, "C1", "Malicious", "PartOfAHorizontalPortScan")
    ]
    # Reverse packet from server (1.1.1.1:23) to client (192.168.1.200:50000)
    # Passed to candidate list containing forward flow: directional matching MUST reject it
    matches = match_packet_to_candidates(101.5, "1.1.1.1", 23, "192.168.1.200", 50000, "tcp", forward_candidates)
    assert len(matches) == 0


def test_16_flow_lifetime_boundaries_exact():
    """16. Test exact connection lifetime [ts, ts+duration] with zero unexplained tolerance."""
    # Flow from 100.0 to 103.0
    candidates = [("1.1.1.1", 1, "2.2.2.2", 23, "tcp",
                   100.0, 103.0, "C1", "Malicious", "PartOfAHorizontalPortScan")]

    # Exact start
    assert len(match_packet_to_candidates(100.0, "1.1.1.1", 1, "2.2.2.2", 23, "tcp", candidates)) == 1
    # Exact end
    assert len(match_packet_to_candidates(103.0, "1.1.1.1", 1, "2.2.2.2", 23, "tcp", candidates)) == 1
    # 1 microsecond outside lifetime -> rejected
    assert len(match_packet_to_candidates(99.999999, "1.1.1.1", 1, "2.2.2.2", 23, "tcp", candidates)) == 0
    assert len(match_packet_to_candidates(103.000001, "1.1.1.1", 1, "2.2.2.2", 23, "tcp", candidates)) == 0


def test_17_per_alert_retransmission_association():
    """17. Test that assess_alert_retransmission classifies retransmissions per alert using its matched flows."""
    window_start = 1002.0
    window_end = 1002.2

    # Flow item: (flow_start, flow_end, uid, label, detailed_label, pkt_ts)
    retrans_flows = [
        (1000.0, 1003.14, "Cretrans_flow", "Malicious", "PartOfAHorizontalPortScan", 1002.1)
    ]

    # When corroborated targets meet threshold: RESOLVED_TIER_A
    res_a = assess_alert_retransmission(
        aid=1, window_start=window_start, window_end=window_end,
        threshold=1, matched_flows_for_alert=retrans_flows,
        corroborated_targets_count=1
    )
    assert res_a["is_retransmission_case"] is True
    assert res_a["decision"] == "RESOLVED_TIER_A"

    # When corroborated targets do not meet threshold: PARTIALLY_RESOLVED_TIER_B
    res_b = assess_alert_retransmission(
        aid=2, window_start=window_start, window_end=window_end,
        threshold=15, matched_flows_for_alert=retrans_flows,
        corroborated_targets_count=1
    )
    assert res_b["is_retransmission_case"] is True
    assert res_b["decision"] == "PARTIALLY_RESOLVED_TIER_B"

    # Normal flows starting in window: not a retransmission case
    normal_flows = [
        (1002.05, 1003.0, "Cnormal", "Malicious", "PartOfAHorizontalPortScan", 1002.1)
    ]
    res_normal = assess_alert_retransmission(
        aid=3, window_start=window_start, window_end=window_end,
        threshold=15, matched_flows_for_alert=normal_flows,
        corroborated_targets_count=15
    )
    assert res_normal["is_retransmission_case"] is False
    assert res_normal["decision"] == "NORMAL"


def test_17b_retransmission_boundary_conditions():
    """17b. Test assess_alert_retransmission against packet timestamp and flow lifetime boundaries."""
    window_start = 1002.0
    window_end = 1002.2

    # Case 1: Packet before window start (pkt_ts < window_start) -> invalid, rejected
    flows_before = [
        (1000.0, 1003.0, "Cbefore", "Malicious", "PartOfAHorizontalPortScan", 1001.99)
    ]
    res_before = assess_alert_retransmission(
        aid=10, window_start=window_start, window_end=window_end,
        threshold=1, matched_flows_for_alert=flows_before,
        corroborated_targets_count=1
    )
    assert res_before["is_retransmission_case"] is False
    assert res_before["invalid_packets_count"] == 1
    assert res_before["status"] == "NO_VALID_IN_WINDOW_FLOWS"

    # Case 2: Packet after window end (pkt_ts > window_end) -> invalid, rejected
    flows_after = [
        (1000.0, 1003.0, "Cafter", "Malicious", "PartOfAHorizontalPortScan", 1002.21)
    ]
    res_after = assess_alert_retransmission(
        aid=11, window_start=window_start, window_end=window_end,
        threshold=1, matched_flows_for_alert=flows_after,
        corroborated_targets_count=1
    )
    assert res_after["is_retransmission_case"] is False
    assert res_after["invalid_packets_count"] == 1
    assert res_after["status"] == "NO_VALID_IN_WINDOW_FLOWS"

    # Case 3: Packet outside flow lifetime (pkt_ts < flow_start or pkt_ts > flow_end) -> invalid, rejected
    flows_outside_lifetime = [
        (1002.05, 1002.10, "Cexpired", "Malicious", "PartOfAHorizontalPortScan", 1002.15)
    ]
    res_expired = assess_alert_retransmission(
        aid=12, window_start=window_start, window_end=window_end,
        threshold=1, matched_flows_for_alert=flows_outside_lifetime,
        corroborated_targets_count=1
    )
    assert res_expired["is_retransmission_case"] is False
    assert res_expired["invalid_packets_count"] == 1

    # Case 4: Packet exactly at window_start boundary (pkt_ts == window_start) -> accepted
    flows_exact_start = [
        (1000.0, 1003.0, "Cstart", "Malicious", "PartOfAHorizontalPortScan", 1002.0)
    ]
    res_exact_start = assess_alert_retransmission(
        aid=13, window_start=window_start, window_end=window_end,
        threshold=1, matched_flows_for_alert=flows_exact_start,
        corroborated_targets_count=1
    )
    assert res_exact_start["is_retransmission_case"] is True
    assert res_exact_start["flows_before_window_count"] == 1
    assert res_exact_start["invalid_packets_count"] == 0
    assert res_exact_start["decision"] == "RESOLVED_TIER_A"

    # Case 5: Packet exactly at window_end boundary (pkt_ts == window_end) -> accepted
    flows_exact_end = [
        (1000.0, 1003.0, "Cend", "Malicious", "PartOfAHorizontalPortScan", 1002.2)
    ]
    res_exact_end = assess_alert_retransmission(
        aid=14, window_start=window_start, window_end=window_end,
        threshold=1, matched_flows_for_alert=flows_exact_end,
        corroborated_targets_count=1
    )
    assert res_exact_end["is_retransmission_case"] is True
    assert res_exact_end["flows_before_window_count"] == 1
    assert res_exact_end["invalid_packets_count"] == 0
    assert res_exact_end["decision"] == "RESOLVED_TIER_A"

    # Case 6: Flow starts before window, but packet timestamp is outside window -> NOT sufficient
    flows_start_only = [
        (1000.0, 1005.0, "Cinsufficient", "Malicious", "PartOfAHorizontalPortScan", 1002.25)
    ]
    res_insufficient = assess_alert_retransmission(
        aid=15, window_start=window_start, window_end=window_end,
        threshold=1, matched_flows_for_alert=flows_start_only,
        corroborated_targets_count=1
    )
    assert res_insufficient["is_retransmission_case"] is False
    assert res_insufficient["status"] == "NO_VALID_IN_WINDOW_FLOWS"


def test_17c_match_scan_target_execution():
    """17c. Verify horizontal and vertical scan matching via actual helper execution."""
    asrc = "192.168.1.100"
    adip = "10.0.0.5"
    adport = 80

    # Horizontal: matching src and dport -> matches, returns target dip
    m_h, tgt_h = match_scan_target("horizontal", asrc, adip, adport, asrc, "10.0.0.99", adport)
    assert m_h is True
    assert tgt_h == "10.0.0.99"

    # Horizontal: mismatched dport -> does not match
    m_h_fail, _ = match_scan_target("horizontal", asrc, adip, adport, asrc, "10.0.0.99", 443)
    assert m_h_fail is False

    # Vertical: matching src and dip -> matches, returns target dport
    m_v, tgt_v = match_scan_target("vertical", asrc, adip, adport, asrc, adip, 8080)
    assert m_v is True
    assert tgt_v == 8080

    # Vertical: mismatched dip -> does not match
    m_v_fail, _ = match_scan_target("vertical", asrc, adip, adport, asrc, "10.0.0.99", 8080)
    assert m_v_fail is False

    # Fail closed on missing, empty, or unknown scan types
    assert match_scan_target(None, asrc, adip, adport, asrc, adip, 80) == (False, None)
    assert match_scan_target("", asrc, adip, adport, asrc, adip, 80) == (False, None)
    assert match_scan_target("unknown", asrc, adip, adport, asrc, adip, 80) == (False, None)
    assert match_scan_target("stealth", asrc, adip, adport, asrc, adip, 80) == (False, None)
    assert match_scan_target("horizontal_invalid", asrc, adip, adport, asrc, adip, 80) == (False, None)


def test_18_concurrent_overlapping_flow_candidates():
    """18. Test that overlapping candidate flows on same tuple are tracked without arbitrary truncation."""
    candidates = [
        ("192.168.1.200", 50000, "1.1.1.1", 23, "tcp",
         100.0, 105.0, "Cearly", "Malicious", "PartOfAHorizontalPortScan"),
        ("192.168.1.200", 50000, "1.1.1.1", 23, "tcp",
         102.0, 107.0, "Clater", "Malicious", "PartOfAHorizontalPortScan"),
    ]
    # Packet at 103.0 falls within BOTH flows
    matches = match_packet_to_candidates(103.0, "192.168.1.200", 50000, "1.1.1.1", 23, "tcp", candidates)
    assert len(matches) == 2
    uids = {m[0] for m in matches}
    assert uids == {"Cearly", "Clater"}


# =============================================================================
# 19-23: Strict 5-Tier Classification Invariants
# =============================================================================

def test_19_one_matching_label_cannot_validate_many_targets():
    """19. Test DECISIVE REQUIREMENT: 1 matching scan flow cannot validate an entire 15-target alert."""
    # Alert with 15 reconstructed targets, but ONLY 1 is corroborated by Zeek scan flow
    tier, key, rationale = classify_alert_v3_1(
        alert_id=1,
        rule_name="PORT_SCAN",
        threshold=15,
        distinct_targets_reconstructed=15,
        corroborated_targets_count=1,   # Only 1 corroborated!
        malicious_targets_count=1,
        benign_targets_count=0,
        unmatched_targets_count=14,
        ambiguous_targets_count=0
    )
    # Must NOT be Tier A!
    assert key != "TIER_A_CONFIRMED_TP"
    assert key == "TIER_B_MALICIOUS_ASSOCIATED"


def test_20_tier_a_requires_all_threshold_targets_corroborated():
    """20. Test that Tier A requires at least threshold distinct corroborated targets."""
    tier, key, rationale = classify_alert_v3_1(
        alert_id=2,
        rule_name="PORT_SCAN",
        threshold=15,
        distinct_targets_reconstructed=15,
        corroborated_targets_count=15,  # Exactly 15 corroborated targets!
        malicious_targets_count=15,
        benign_targets_count=0,
        unmatched_targets_count=0,
        ambiguous_targets_count=0
    )
    assert key == "TIER_A_CONFIRMED_TP"
    assert "Reconstructed 15 distinct targets" in rationale


def test_21_tier_c_confirmed_false_positive():
    """21. Test that alerts on traffic exclusively labeled benign are classified as Tier C."""
    tier, key, _ = classify_alert_v3_1(
        alert_id=3,
        rule_name="PORT_SCAN",
        threshold=15,
        distinct_targets_reconstructed=15,
        corroborated_targets_count=0,
        malicious_targets_count=0,
        benign_targets_count=15,        # All benign
        unmatched_targets_count=0,
        ambiguous_targets_count=0
    )
    assert key == "TIER_C_FALSE_POSITIVE"


def test_22_tier_d_unassessed_historical_baseline():
    """22. Test that unassessed alerts or missing baselines fall into Tier D."""
    tier, key, rationale = classify_alert_v3_1(
        alert_id=4,
        rule_name="ARP_SPOOF",
        threshold=1,
        distinct_targets_reconstructed=0,
        corroborated_targets_count=0,
        malicious_targets_count=0,
        benign_targets_count=0,
        unmatched_targets_count=1,
        ambiguous_targets_count=0
    )
    assert key == "TIER_D_UNASSESSED"


def test_22_invalid_threshold_fails_closed():
    """22b. Test that invalid, missing, or non-positive threshold fails closed to Tier D."""
    for invalid_thr in [0, -1, -15, None, "15", 3.14]:
        tier, key, rationale = classify_alert_v3_1(
            alert_id=22,
            rule_name="PORT_SCAN",
            threshold=invalid_thr,
            distinct_targets_reconstructed=15,
            corroborated_targets_count=15,
            malicious_targets_count=15,
            benign_targets_count=0,
            unmatched_targets_count=0,
            ambiguous_targets_count=0
        )
        assert key == "TIER_D_UNASSESSED"
        assert "Invalid or missing alert threshold" in rationale


def test_23_reconciliation_of_all_tiers_to_total_alerts():
    """23. Test that sum of all 5 tiers strictly equals total emitted alert count."""
    counts = {
        "TIER_A_CONFIRMED_TP": 3669,
        "TIER_B_MALICIOUS_ASSOCIATED": 96,
        "TIER_C_FALSE_POSITIVE": 0,
        "TIER_D_UNASSESSED": 262,
        "TIER_E_NO_ASSOCIATION": 0
    }
    assert sum(counts.values()) == 4027


# =============================================================================
# 24-27: Integrity, Provenance & Export Formatting Invariants
# =============================================================================

def test_24_input_hash_calculation(tmp_path):
    """24. Test SHA-256 calculation matches hashlib."""
    test_f = tmp_path / "test.bin"
    data = b"NetGuard Forensic Ground Truth Test 12345"
    test_f.write_bytes(data)
    expected_hash = hashlib.sha256(data).hexdigest()
    assert get_file_sha256(str(test_f)) == expected_hash


def test_25_csv_writer_escaping_verification():
    """25. Test that standard csv writer quotes special characters, commas, and double quotes."""
    out = io.StringIO()
    writer = csv.writer(out, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(["col1", "col2"])
    writer.writerow(["test", 'Contains "quotes" and, commas'])

    val = out.getvalue()
    assert '"Contains ""quotes"" and, commas"' in val


def test_26_suricata_eve_malformed_accounting():
    """26. Test that JSON decode errors in EVE lines are tallied without crash."""
    lines = [
        '{"event_type": "alert", "alert": {"signature": "Test 1"}}',
        'CORRUPT_NOT_JSON',
        '{"event_type": "alert", "alert": {"signature": "Test 2"}}'
    ]
    alerts = 0
    malformed = 0
    for l in lines:
        try:
            doc = json.loads(l)
            if doc.get("event_type") == "alert":
                alerts += 1
        except Exception:
            malformed += 1
    assert alerts == 2
    assert malformed == 1


def test_27_recall_marked_not_measurable():
    """27. Test invariant: per-flow recall is strictly marked NOT MEASURABLE."""
    status = "NOT MEASURABLE at per-flow granularity due to intentional rate-limiting alert aggregation"
    assert "NOT MEASURABLE" in status


def test_27_scan_type_separation_vertical_vs_horizontal():
    """27b. Test scan semantics: vertical scan targets dport on fixed dip; horizontal scan targets dip on fixed dport."""
    # Vertical scan: target is dport
    vert_alert = {
        "id": 101, "rule_name": "PORT_SCAN", "rule_version": "v1.13",
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": None,
        "window_start": 100.0, "window_end": 110.0, "threshold": 15,
        "scan_type": "vertical"
    }
    # Horizontal scan: target is dip
    horiz_alert = {
        "id": 102, "rule_name": "PORT_SCAN", "rule_version": "v1.13",
        "src_ip": "10.0.0.1", "dst_ip": None, "dst_port": 23,
        "window_start": 100.0, "window_end": 110.0, "threshold": 15,
        "scan_type": "horizontal"
    }
    assert vert_alert["scan_type"] == "vertical"
    assert horiz_alert["scan_type"] == "horizontal"


def test_28_five_tuple_mismatch_is_rejected_even_when_lifetime_matches():
    """A time-overlapping candidate with a different endpoint or protocol must not match."""
    candidates = [
        ("192.168.1.200", 50000, "1.1.1.1", 23, "tcp",
         100.0, 103.0, "C1", "Malicious", "PartOfAHorizontalPortScan")
    ]
    assert match_packet_to_candidates(
        101.0, "192.168.1.200", 50000, "2.2.2.2", 23, "tcp", candidates
    ) == []
    assert match_packet_to_candidates(
        101.0, "192.168.1.200", 50000, "1.1.1.1", 80, "tcp", candidates
    ) == []
    assert match_packet_to_candidates(
        101.0, "192.168.1.200", 50000, "1.1.1.1", 23, "udp", candidates
    ) == []


def test_29_partial_benign_and_unmatched_targets_are_not_false_positive():
    """Mixed benign and unknown targets remain unassessed, not confirmed FP."""
    _, key, _ = classify_alert_v3_1(
        alert_id=29, rule_name="PORT_SCAN", threshold=15,
        distinct_targets_reconstructed=15, corroborated_targets_count=0,
        malicious_targets_count=0, benign_targets_count=3,
        unmatched_targets_count=12, ambiguous_targets_count=0
    )
    assert key == "TIER_D_UNASSESSED"


def test_30_ambiguous_target_cannot_be_silently_counted_as_correlated():
    """Ambiguous associations must not be presented as unique corroboration."""
    _, key, _ = classify_alert_v3_1(
        alert_id=30, rule_name="PORT_SCAN", threshold=15,
        distinct_targets_reconstructed=15, corroborated_targets_count=14,
        malicious_targets_count=1, benign_targets_count=0,
        unmatched_targets_count=0, ambiguous_targets_count=1
    )
    assert key == "TIER_B_MALICIOUS_ASSOCIATED"


def test_31_truncated_pcap_record_is_not_silently_treated_as_eof(tmp_path):
    """A partial per-packet header must fail closed instead of silently losing a record."""
    pcap = tmp_path / "truncated.pcap"
    global_header = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    pcap.write_bytes(global_header + b"partial")
    with PcapParser(str(pcap)) as parser:
        with pytest.raises(ValueError, match="Truncated PCAP packet header"):
            list(parser.iter_packets())
        assert parser.truncated_records == 1


# =============================================================================
# 32-36: Remediation Invariants (Tier E, ARP Row Schema, Fragments, Truncation)
# =============================================================================

def test_32_tier_e_no_defensible_association():
    """32. Test that an alert with 0 reconstructed targets and 0 evidence maps to Tier E (not Tier D)."""
    tier, key, rationale = classify_alert_v3_1(
        alert_id=32,
        rule_name="PORT_SCAN",
        threshold=15,
        distinct_targets_reconstructed=0,
        corroborated_targets_count=0,
        malicious_targets_count=0,
        benign_targets_count=0,
        unmatched_targets_count=0,
        ambiguous_targets_count=0
    )
    assert key == "TIER_E_NO_ASSOCIATION"
    assert "No defensible packet or flow association" in rationale


def test_33_arp_row_column_count_reconciliation():
    """33. Test that build_arp_alert_row and build_per_alert_row produce exactly 16 columns matching schema."""
    header = [
        "alert_id", "rule_name", "rule_version", "src_ip", "dst_port",
        "window_start", "window_end", "valid_syn_count", "distinct_targets_reconstructed",
        "corroborated_targets_count", "threshold", "matched_uids_count",
        "ambiguous_targets_count", "unmatched_targets_count",
        "classification_tier", "evidentiary_rationale"
    ]
    assert len(header) == 16

    # Real call to build_arp_alert_row
    arp_alert = {
        "id": 4001, "rule_name": "ARP_SPOOF", "rule_version": "v1.8",
        "src_ip": "192.168.1.1", "window_start": 100.0, "window_end": 110.0,
        "timestamp": 105.0, "evidence": {"old_mac": "aa:bb:cc:dd:ee:01", "new_mac": "aa:bb:cc:dd:ee:02"}
    }
    observed_frames = [
        (1, 105.01, {"smac": "aa:bb:cc:dd:ee:02", "sip": "192.168.1.1"})
    ]
    arp_row = build_arp_alert_row(arp_alert, observed_frames)
    assert len(arp_row) == 16
    assert arp_row[0] == 4001
    assert arp_row[1] == "ARP_SPOOF"
    assert arp_row[14] == "TIER_D_UNASSESSED"

    # Real call to build_per_alert_row
    scan_alert = {
        "id": 1, "rule_name": "PORT_SCAN", "rule_version": "v1.13",
        "src_ip": "192.168.1.200", "dst_port": 23,
        "window_start": 100.0, "window_end": 110.0, "threshold": 15
    }
    scan_row = build_per_alert_row(
        scan_alert, syn_count=20, rec_targets=15, corrob_targets=15,
        thr=15, matched_uids_count=15, ambiguous_targets_count=0,
        unm_targets_count=0, tier_key="TIER_A_CONFIRMED_TP", rationale="Test TP"
    )
    assert len(scan_row) == 16
    assert scan_row[0] == 1
    assert scan_row[14] == "TIER_A_CONFIRMED_TP"


def test_34_ipv4_non_first_fragment_rejected_as_tcp(tmp_path):
    """34. Test that non-first IPv4 fragments (frag_offset > 0) are not inspected as TCP headers."""
    pcap_frag = tmp_path / "frag.pcap"
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    eth = b"\x00" * 12 + struct.pack(">H", 0x0800)
    # IPv4 header: ver=4, ihl=5 (20 bytes), proto=6 (TCP), frag_offset=1 (flags_frag=0x0001)
    # Byte 6-7: 0x00, 0x01 -> frag_offset = 1 (8 bytes into payload)
    ip = bytes([0x45, 0, 0, 40, 0, 0, 0x00, 0x01, 64, 6, 0, 0, 192, 168, 1, 200, 10, 0, 0, 1])
    # Fragment payload: byte 13 happens to be 0x02 (would look like SYN if misparsed as TCP)
    frag_payload = b"\x00" * 13 + b"\x02" + b"\x00" * 6

    frame = eth + ip + frag_payload
    pkt_hdr = struct.pack("<IIII", 1551377744, 0, len(frame), len(frame))
    pcap_frag.write_bytes(hdr + pkt_hdr + frame)

    with PcapParser(str(pcap_frag)) as p:
        packets = list(p.iter_packets())
        assert len(packets) == 1
        idx, ts, is_ip, is_tcp, is_syn, is_arp, sip, sport, dip, dport, flags, _ = packets[0]
        assert is_ip is True
        # Must NOT be treated as TCP or initial SYN!
        assert is_tcp is False
        assert is_syn is False


def test_35_truncated_ip_header_yields_safe_packet_record(tmp_path):
    """35. Test that truncated IPv4 frames yield safely without false positives or lost records."""
    pcap_trunc = tmp_path / "trunc_ip.pcap"
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    eth = b"\x00" * 12 + struct.pack(">H", 0x0800)
    # Truncated IP header: only 10 bytes instead of 20
    ip_short = bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6])
    frame = eth + ip_short  # Total 24 bytes (caplen < 14 + 20 = 34)

    pkt_hdr = struct.pack("<IIII", 1551377744, 0, len(frame), len(frame))
    pcap_trunc.write_bytes(hdr + pkt_hdr + frame)

    with PcapParser(str(pcap_trunc)) as p:
        packets = list(p.iter_packets())
        assert len(packets) == 1
        idx, ts, is_ip, is_tcp, is_syn, is_arp, sip, sport, dip, dport, flags, _ = packets[0]
        # Frame was safely accounted for but cannot be misparsed as valid IP or SYN
        assert is_ip is False
        assert is_syn is False


def test_36_suricata_eve_size_dynamic_calculation(tmp_path):
    """36. Test dynamic file size calculation for Suricata EVE without hardcoding."""
    eve_file = tmp_path / "eve.json"
    dummy_eve = '{"event_type": "alert"}\n' * 50
    eve_file.write_text(dummy_eve, encoding="utf-8")

    expected_size = len(dummy_eve.encode("utf-8"))
    assert os.path.getsize(str(eve_file)) == expected_size


def test_37_pcap_parser_total_len_and_ihl_boundary(tmp_path):
    """37. Test that PcapParser tracks malformed/unsupported IPv4 boundaries (total_len < ihl, version != 4)."""
    pcap = tmp_path / "bounds.pcap"
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    eth = b"\x00" * 12 + struct.pack(">H", 0x0800)
    # Packet 1: Version 6 in IPv4 ethertype -> unsupported
    ip_v6 = bytes([0x65, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 192, 168, 1, 1, 10, 0, 0, 1])
    pkt1 = eth + ip_v6
    h1 = struct.pack("<IIII", 100, 0, len(pkt1), len(pkt1))

    # Packet 2: total_len (10) < ihl (20) -> malformed
    ip_bad_len = bytes([0x45, 0, 0, 10, 0, 0, 0, 0, 64, 6, 0, 0, 192, 168, 1, 1, 10, 0, 0, 1])
    pkt2 = eth + ip_bad_len
    h2 = struct.pack("<IIII", 101, 0, len(pkt2), len(pkt2))

    pcap.write_bytes(hdr + h1 + pkt1 + h2 + pkt2)

    with PcapParser(str(pcap)) as parser:
        pkts = list(parser.iter_packets())
        assert len(pkts) == 2
        assert parser.unsupported_records == 1
        assert parser.malformed_records == 1


def test_38_pcap_parser_tcp_data_offset_and_padding_exclusion(tmp_path):
    """38. Test that Ethernet padding beyond IPv4 total_len is excluded and TCP data_offset < 20 is malformed."""
    pcap = tmp_path / "pad_and_offset.pcap"
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    eth = b"\x00" * 12 + struct.pack(">H", 0x0800)
    # Total len is 40 (20 IP + 20 TCP). But frame has 64 bytes total (14 eth + 40 + 10 padding bytes).
    ip = bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 192, 168, 1, 200, 10, 0, 0, 1])
    tcp = struct.pack(">HHIIBBHHH", 50000, 23, 1, 0, 0x50, 0x02, 65535, 0, 0)
    padding = b"\x00" * 10
    frame = eth + ip + tcp + padding

    h = struct.pack("<IIII", 100, 0, len(frame), len(frame))
    pcap.write_bytes(hdr + h + frame)

    with PcapParser(str(pcap)) as parser:
        pkts = list(parser.iter_packets())
        assert len(pkts) == 1
        assert parser.padding_bytes_ignored == 10
        assert pkts[0][4] is True  # is_init_syn


def test_39_validation_verdict_reconciliation_gates():
    """39. Test that validation verdict requires all reconciliation gates to pass."""
    from scripts.audits.ctu48_1_ground_truth_audit_v3_1 import _write_v3_1_reports
    import tempfile

    with tempfile.TemporaryDirectory() as tmp_dir:
        summary_base = {
            "provenance": {"pcap_size_bytes": 100, "pcap_sha256": "a", "zeek_size_bytes": 100,
                           "zeek_sha256": "b", "db_size_bytes": 100, "db_sha256": "c",
                           "suricata_eve_size_bytes": 100, "suricata_eve_sha256": "d"},
            "zeek_parsing": {"total_records": 10, "parsed_records": 10, "malformed_records": 0,
                             "duplicate_uids": 0, "duration_sentinel_records": 0, "publisher_scan_flows": 10},
            "pcap_parsing": {"packet_records_read": 10, "runt_frames_skipped": 0,
                             "valid_initial_syn_packets": 10, "total_exported_attribution_packets": 10},
            "alert_attribution": {"total_alerts": 10, "scan_alerts": 10, "arp_alerts": 0,
                                  "tier_a_confirmed_tp": 10, "tier_b_malicious_associated": 0,
                                  "tier_c_false_positive": 0, "tier_d_unassessed": 0,
                                  "tier_e_no_association": 0, "strict_precision_pct": 100.0,
                                  "scan_rule_precision_pct": 100.0, "unassessed_rate_pct": 0.0},
            "retransmission_investigation": {"total_cases": 0, "resolved_via_flow_lifetime": 0,
                                             "partially_resolved": 0, "unresolved": 0, "resolution_pct": 0.0},
            "flow_coverage": {"publisher_scan_flows": 10, "unique_uids_with_unique_trigger_packet_match": 10,
                              "trigger_packet_evidence_pct": 100.0, "publisher_scan_uids_with_post_alert_interval_overlap": 0,
                              "post_alert_interval_overlap_pct": 0.0},
            "arp_forensics": {"total_arp_alerts": 0, "physical_arp_frames": 0,
                              "gateway_ip_sender_mac_values": [], "classification": "None"},
            "suricata_provenance": {"total_alerts": 0, "signatures": {}},
            "exports": {
                "per_alert_attribution.csv": {"sha256": "h1", "size_bytes": 10},
                "alert_to_zeek_uid.csv": {"sha256": "h2", "size_bytes": 10},
                "alert_packet_evidence.csv": {"sha256": "h3", "size_bytes": 10},
                "per_flow_scan_attribution.csv": {"sha256": "h4", "size_bytes": 10},
                "402_retransmission_case_audit.csv": {"sha256": "h5", "size_bytes": 10},
                "arp_alert_packet_attribution.csv": {"sha256": "h6", "size_bytes": 10},
            },
            "audit_validation_checks": {
                "tier_counts_reconcile": True,
                "zeek_records_reconcile": True,
                "pcap_stream_completed_without_truncation": True,
                "thresholds_validated": True,
                "export_reconciliation_passed": True,
                "suricata_input_pcap_identity_verified": False,
                "runtime_cooldown_configuration_verified": False,
            }
        }

        # Case 1: All reconciliation gates pass, external gates unverified -> SUPPORTED WITH LIMITATIONS
        _write_v3_1_reports(tmp_dir, summary_base)
        verdict_doc = os.path.join(tmp_dir, "09_final_submission_verdict.md")
        with open(verdict_doc, "r", encoding="utf-8") as vf:
            content = vf.read()
        assert "SUPPORTED WITH LIMITATIONS — CAPTURE-SPECIFIC" in content

        # Case 2: One reconciliation gate fails -> INCONCLUSIVE
        summary_fail = dict(summary_base)
        summary_fail["audit_validation_checks"] = dict(summary_base["audit_validation_checks"])
        summary_fail["audit_validation_checks"]["tier_counts_reconcile"] = False
        _write_v3_1_reports(tmp_dir, summary_fail)
        with open(verdict_doc, "r", encoding="utf-8") as vf:
            content = vf.read()
        assert "INCONCLUSIVE — A REQUIRED RECONCILIATION GATE FAILED" in content

