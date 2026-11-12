from scapy.all import Ether, IP, UDP, Raw, wrpcap

PACKET_COUNT = 12000

packets = []

for i in range(PACKET_COUNT):
    packet = (
        Ether(
            src="02:00:00:00:00:01",
            dst="02:00:00:00:00:02"
        )
        / IP(
            src="10.10.0.1",
            dst="10.10.0.2",
            id=i % 65536
        )
        / UDP(sport=40000, dport=9999)
        / Raw(load=f"NETGUARD-LIVE-BENCH-{i:08d}".encode().ljust(64, b"X"))
    )
    packets.append(packet)

wrpcap("benchmark/live_12k/traffic.pcap", packets)

print(f"Generated {len(packets)} packets")
