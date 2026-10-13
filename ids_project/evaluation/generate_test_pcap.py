"""
evaluation/generate_test_pcap.py
--------------------------------
Generates a realistic test .pcap file containing all 4 threat patterns:
  1. Port Scan attack (probes 30 distinct destination ports)
  2. SYN Flood attack (120 SYN packets in rapid succession)
  3. Malicious IP communication (connection attempt to a blocklisted IP)
  4. ARP Spoofing attack (IP 192.168.1.1 changes claimed MAC)
"""

import time
import os
import sys

# Ensure scapy is present
from scapy.all import Ether, IP, TCP, ARP, wrpcap

OUTPUT_PCAP = "data/test_attacks.pcap"
TEST_MALICIOUS_IP = "198.51.100.42"

def generate_attacks():
    print(f"[*] Crafting synthetic attack packets...")
    packets = []
    base_time = time.time()

    # 1. Normal traffic (baseline)
    for i in range(5):
        pkt = Ether(src="aa:bb:cc:11:22:33", dst="ff:ff:ff:ff:ff:ff") / \
              IP(src="192.168.1.10", dst="192.168.1.1") / \
              TCP(sport=50000+i, dport=80, flags="PA")
        pkt.time = base_time + (i * 0.1)
        packets.append(pkt)

    # 2. Blocklist hit: Device at 192.168.1.55 contacting known malicious IP
    print("  -> Adding Blocklist connection packet...")
    bl_pkt = Ether(src="aa:bb:cc:55:55:55", dst="00:11:22:33:44:55") / \
             IP(src="192.168.1.55", dst=TEST_MALICIOUS_IP) / \
             TCP(sport=43210, dport=443, flags="S")
    bl_pkt.time = base_time + 1.0
    packets.append(bl_pkt)

    # 3. Port Scan: Attacker at 192.168.1.105 scanning 30 ports on 192.168.1.1
    print("  -> Adding Port Scan packets (30 ports)...")
    for port in range(20, 51):
        scan_pkt = Ether(src="de:ad:be:ef:01:05", dst="00:11:22:33:44:55") / \
                   IP(src="192.168.1.105", dst="192.168.1.1") / \
                   TCP(sport=55000+port, dport=port, flags="S")
        scan_pkt.time = base_time + 2.0 + (port * 0.05)
        packets.append(scan_pkt)

    # 4. SYN Flood: Attacker at 192.168.1.200 blasting 120 SYN packets to port 80
    print("  -> Adding SYN Flood packets (120 SYNs)...")
    for seq in range(120):
        flood_pkt = Ether(src="de:ad:be:ef:02:00", dst="00:11:22:33:44:55") / \
                    IP(src="192.168.1.200", dst="192.168.1.1") / \
                    TCP(sport=10000+seq, dport=80, flags="S")
        flood_pkt.time = base_time + 5.0 + (seq * 0.01)
        packets.append(flood_pkt)

    # 5. ARP Spoofing: First legitimate ARP mapping, then forged claim
    print("  -> Adding ARP Spoof packets...")
    # Normal gateway ARP announcement
    normal_arp = Ether(src="00:11:22:33:44:01", dst="ff:ff:ff:ff:ff:ff") / \
                 ARP(op="is-at", psrc="192.168.1.1", hwsrc="00:11:22:33:44:01", pdst="192.168.1.50")
    normal_arp.time = base_time + 7.0
    packets.append(normal_arp)

    # Rogue ARP response claiming 192.168.1.1 has a different MAC
    spoofed_arp = Ether(src="de:ad:be:ef:99:99", dst="ff:ff:ff:ff:ff:ff") / \
                  ARP(op="is-at", psrc="192.168.1.1", hwsrc="de:ad:be:ef:99:99", pdst="192.168.1.50")
    spoofed_arp.time = base_time + 8.0
    packets.append(spoofed_arp)

    os.makedirs(os.path.dirname(OUTPUT_PCAP), exist_ok=True)
    wrpcap(OUTPUT_PCAP, packets)
    print(f"[✔] Successfully generated {len(packets)} packets in '{OUTPUT_PCAP}'")

    # Ensure test malicious IP is in blocklist.txt
    bl_file = "data/blocklist.txt"
    os.makedirs("data", exist_ok=True)
    existing = set()
    if os.path.exists(bl_file):
        with open(bl_file) as f:
            existing = {line.strip() for line in f}
    if TEST_MALICIOUS_IP not in existing:
        with open(bl_file, "a") as f:
            f.write(f"\n{TEST_MALICIOUS_IP}\n")
        print(f"[✔] Added test IP {TEST_MALICIOUS_IP} to '{bl_file}'")

if __name__ == "__main__":
    generate_attacks()
