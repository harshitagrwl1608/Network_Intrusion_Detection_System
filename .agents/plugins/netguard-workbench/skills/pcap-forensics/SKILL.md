---
name: pcap-forensics
description: "Perform deep PCAP forensics, protocol distribution profiling, TCP stream reconstruction, and packet inspection using tshark and Scapy."
---

# PCAP Forensics and Packet Analysis

This skill guides packet analysis and traffic forensic investigations for NetGuard IDS captures.

## When to Use
- Analyzing `.pcap` or `.pcapng` capture files to extract network indicators.
- Investigating TCP anomalies, illegal flag combinations, or unusual window sizes.
- Profiling protocol distributions (Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP, TLS).
- Validating synthetic test fixtures against captured network behavior.

## Core Analysis Procedures

### 1. Protocol Distribution & Packet Counts
Use `tshark` to quickly summarize packet hierarchies:

```bash
tshark -r <path_to_pcap> -q -z io,phs
```

### 2. Conversation & Flow Profiling
Extract IP conversations and TCP/UDP session metadata:

```bash
# IP conversation summary
tshark -r <path_to_pcap> -q -z conv,ip

# TCP conversation summary
tshark -r <path_to_pcap> -q -z conv,tcp
```

### 3. TCP Flag Anomaly Analysis
Isolate suspicious TCP flag configurations (NULL, FIN, XMAS, SYN+FIN):

```bash
# Find SYN+FIN packets
tshark -r <path_to_pcap> -Y "tcp.flags.syn == 1 && tcp.flags.fin == 1"

# Find NULL packets (no flags set)
tshark -r <path_to_pcap> -Y "tcp.flags == 0"

# Find XMAS scan packets (FIN, PSH, URG all set)
tshark -r <path_to_pcap> -Y "tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1"
```

### 4. Scapy Programmatic Forensic Extraction
For automated Python analysis:

```python
from scapy.all import rdpcap, IP, TCP, UDP, DNS

packets = rdpcap("<path_to_pcap>")
print(f"Total packets: {len(packets)}")

tcp_flows = set()
for pkt in packets:
    if IP in pkt and TCP in pkt:
        flow = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        tcp_flows.add(flow)

print(f"Unique TCP flows: {len(tcp_flows)}")
```

## Guardrails
- Never commit PCAP files larger than 1 MB to git repository tracking.
- Sanitize payload strings when logging to prevent terminal injection or control character escape.
