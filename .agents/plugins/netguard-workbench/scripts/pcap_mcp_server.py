#!/usr/bin/env python3
"""
NetGuard PCAP Analysis MCP Server.
Provides dedicated JSON-RPC 2.0 stdio MCP interface for packet capture inspection:
- pcap_metadata
- protocol_distribution
- flow_summary
- tcp_flags
- dns_inventory
- suricata_eve_summary
- dataset_hash_verify
"""

import hashlib
import json
import math
import os
import sys
from collections import Counter, defaultdict

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw
except ImportError:
    rdpcap = None


def calc_shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in freq.values())


# Tool implementations
def tool_pcap_metadata(pcap_path: str):
    if not os.path.isfile(pcap_path):
        return {"error": f"File not found: {pcap_path}"}
    if rdpcap is None:
        return {"error": "Scapy library not installed."}

    file_size = os.path.getsize(pcap_path)
    packets = rdpcap(pcap_path)
    total_packets = len(packets)

    timestamps = [float(p.time) for p in packets if hasattr(p, "time")]
    if timestamps:
        start_ts = min(timestamps)
        end_ts = max(timestamps)
        duration = end_ts - start_ts
    else:
        start_ts, end_ts, duration = 0.0, 0.0, 0.0

    return {
        "pcap_path": os.path.abspath(pcap_path),
        "file_size_bytes": file_size,
        "total_packets": total_packets,
        "first_timestamp": start_ts,
        "last_timestamp": end_ts,
        "duration_seconds": round(duration, 4),
    }


def tool_protocol_distribution(pcap_path: str):
    if not os.path.isfile(pcap_path):
        return {"error": f"File not found: {pcap_path}"}
    if rdpcap is None:
        return {"error": "Scapy library not installed."}

    packets = rdpcap(pcap_path)
    proto_counts = Counter()

    for p in packets:
        if ARP in p:
            proto_counts["ARP"] += 1
        elif IP in p or IPv6 in p:
            proto_counts["IP"] += 1
            if TCP in p:
                proto_counts["TCP"] += 1
                if p[TCP].dport == 53 or p[TCP].sport == 53 or DNS in p:
                    proto_counts["DNS"] += 1
                elif p[TCP].dport in (80, 8080) or p[TCP].sport in (80, 8080):
                    proto_counts["HTTP"] += 1
                elif p[TCP].dport in (443, 8443) or p[TCP].sport in (443, 8443):
                    proto_counts["TLS/HTTPS"] += 1
            elif UDP in p:
                proto_counts["UDP"] += 1
                if p[UDP].dport == 53 or p[UDP].sport == 53 or DNS in p:
                    proto_counts["DNS"] += 1
            elif ICMP in p:
                proto_counts["ICMP"] += 1
            else:
                proto_counts["OTHER_IP"] += 1
        else:
            proto_counts["NON_IP"] += 1

    return {
        "total_packets": len(packets),
        "protocol_breakdown": dict(proto_counts)
    }


def tool_flow_summary(pcap_path: str, top_n: int = 10):
    if not os.path.isfile(pcap_path):
        return {"error": f"File not found: {pcap_path}"}
    if rdpcap is None:
        return {"error": "Scapy library not installed."}

    packets = rdpcap(pcap_path)
    flows = Counter()
    talkers = Counter()

    for p in packets:
        src = p[IP].src if IP in p else (p[IPv6].src if IPv6 in p else None)
        dst = p[IP].dst if IP in p else (p[IPv6].dst if IPv6 in p else None)
        if not src or not dst:
            continue

        talkers[src] += 1
        sport = p[TCP].sport if TCP in p else (p[UDP].sport if UDP in p else 0)
        dport = p[TCP].dport if TCP in p else (p[UDP].dport if UDP in p else 0)
        proto = "TCP" if TCP in p else ("UDP" if UDP in p else "OTHER")

        flow_key = f"{src}:{sport} -> {dst}:{dport} [{proto}]"
        flows[flow_key] += 1

    return {
        "total_unique_flows": len(flows),
        "top_talkers": talkers.most_common(top_n),
        "top_flows": [{"flow": k, "packet_count": v} for k, v in flows.most_common(top_n)]
    }


def tool_tcp_flags(pcap_path: str):
    if not os.path.isfile(pcap_path):
        return {"error": f"File not found: {pcap_path}"}
    if rdpcap is None:
        return {"error": "Scapy library not installed."}

    packets = rdpcap(pcap_path)
    flag_counts = Counter()
    anomalies = []

    for idx, p in enumerate(packets):
        if TCP in p:
            flags = int(p[TCP].flags)
            is_syn = bool(flags & 0x02)
            is_fin = bool(flags & 0x01)
            is_rst = bool(flags & 0x04)
            is_psh = bool(flags & 0x08)
            is_ack = bool(flags & 0x10)
            is_urg = bool(flags & 0x20)

            if is_syn and not is_ack:
                flag_counts["SYN_ONLY"] += 1
            if is_syn and is_ack:
                flag_counts["SYN_ACK"] += 1
            if is_ack and not is_syn:
                flag_counts["ACK_ONLY"] += 1
            if is_fin:
                flag_counts["FIN"] += 1
            if is_rst:
                flag_counts["RST"] += 1

            # Anomaly checks
            if flags == 0:
                flag_counts["ANOMALY_NULL"] += 1
                if len(anomalies) < 10:
                    anomalies.append(f"Packet #{idx}: NULL flags (0x00) from {p[IP].src}")
            elif is_syn and is_fin:
                flag_counts["ANOMALY_SYN_FIN"] += 1
                if len(anomalies) < 10:
                    anomalies.append(f"Packet #{idx}: SYN+FIN flags from {p[IP].src}")
            elif is_fin and is_psh and is_urg:
                flag_counts["ANOMALY_XMAS"] += 1
                if len(anomalies) < 10:
                    anomalies.append(f"Packet #{idx}: XMAS scan flags (FIN+PSH+URG) from {p[IP].src}")

    return {
        "flag_distribution": dict(flag_counts),
        "anomalies_detected": anomalies,
        "total_anomalous_flags": sum(v for k, v in flag_counts.items() if k.startswith("ANOMALY_"))
    }


def tool_dns_inventory(pcap_path: str):
    if not os.path.isfile(pcap_path):
        return {"error": f"File not found: {pcap_path}"}
    if rdpcap is None:
        return {"error": "Scapy library not installed."}

    packets = rdpcap(pcap_path)
    queries = []
    domains = Counter()

    for p in packets:
        if DNS in p and p[DNS].qr == 0 and p[DNS].qd:
            qname = p[DNS].qd.qname.decode("utf-8", errors="replace").rstrip(".")
            qtype = p[DNS].qd.qtype
            entropy = calc_shannon_entropy(qname)
            domains[qname] += 1
            queries.append({
                "qname": qname,
                "qtype": qtype,
                "entropy": round(entropy, 3),
                "is_suspicious_length": len(qname) > 50,
                "is_high_entropy": entropy > 3.8
            })

    return {
        "total_dns_queries": len(queries),
        "unique_domains": len(domains),
        "top_queried_domains": domains.most_common(10),
        "sample_queries": queries[:15]
    }


def tool_suricata_eve_summary(eve_path: str):
    if not os.path.isfile(eve_path):
        return {"error": f"File not found: {eve_path}"}

    total_records = 0
    alert_count = 0
    signatures = Counter()
    categories = Counter()
    top_src = Counter()
    top_dst = Counter()

    with open(eve_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total_records += 1
            try:
                record = json.loads(line)
            except Exception:
                continue

            if record.get("event_type") == "alert":
                alert_count += 1
                alert_data = record.get("alert") or {}
                sig = alert_data.get("signature", "Unknown")
                cat = alert_data.get("category", "Uncategorized")
                src = record.get("src_ip", "0.0.0.0")
                dst = record.get("dest_ip") or record.get("dst_ip", "0.0.0.0")

                signatures[sig] += 1
                categories[cat] += 1
                top_src[src] += 1
                top_dst[dst] += 1

    return {
        "eve_path": os.path.abspath(eve_path),
        "total_eve_records": total_records,
        "total_alerts": alert_count,
        "top_signatures": signatures.most_common(10),
        "categories": dict(categories),
        "top_attacker_ips": top_src.most_common(5),
        "top_target_ips": top_dst.most_common(5)
    }


def tool_dataset_hash_verify(file_path: str, expected_sha256: str = None):
    if not os.path.isfile(file_path):
        return {"error": f"File not found: {file_path}"}

    sha256_h = hashlib.sha256()
    md5_h = hashlib.md5()
    size = 0

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            size += len(chunk)
            sha256_h.update(chunk)
            md5_h.update(chunk)

    computed_sha256 = sha256_h.hexdigest()
    computed_md5 = md5_h.hexdigest()

    result = {
        "file_path": os.path.abspath(file_path),
        "file_size_bytes": size,
        "sha256": computed_sha256,
        "md5": computed_md5
    }

    if expected_sha256:
        clean_exp = expected_sha256.strip().lower()
        result["expected_sha256"] = clean_exp
        result["matches_expected"] = (computed_sha256 == clean_exp)

    return result


# MCP Server Schema Definitions
TOOLS_SCHEMA = [
    {
        "name": "pcap_metadata",
        "description": "Extract file metadata, packet count, time range, and duration from a PCAP capture.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pcap_path": {"type": "string", "description": "Path to the .pcap or .pcapng file."}
            },
            "required": ["pcap_path"]
        }
    },
    {
        "name": "protocol_distribution",
        "description": "Calculate packet distribution across network protocols (Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP, TLS).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pcap_path": {"type": "string", "description": "Path to the .pcap or .pcapng file."}
            },
            "required": ["pcap_path"]
        }
    },
    {
        "name": "flow_summary",
        "description": "Extract 5-tuple flow statistics and top communicating talkers from a capture.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pcap_path": {"type": "string", "description": "Path to the .pcap file."},
                "top_n": {"type": "integer", "description": "Number of top flows to return (default 10)."}
            },
            "required": ["pcap_path"]
        }
    },
    {
        "name": "tcp_flags",
        "description": "Analyze TCP flag distributions and detect anomalous combinations (SYN+FIN, NULL, XMAS).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pcap_path": {"type": "string", "description": "Path to the .pcap file."}
            },
            "required": ["pcap_path"]
        }
    },
    {
        "name": "dns_inventory",
        "description": "Inspect DNS query transactions, calculate Shannon entropy for DGA/tunneling detection, and summarize domains.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pcap_path": {"type": "string", "description": "Path to the .pcap file."}
            },
            "required": ["pcap_path"]
        }
    },
    {
        "name": "suricata_eve_summary",
        "description": "Ingest and summarize Suricata EVE JSON alert telemetry, extracting top signatures and categories.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "eve_path": {"type": "string", "description": "Path to the eve.json file."}
            },
            "required": ["eve_path"]
        }
    },
    {
        "name": "dataset_hash_verify",
        "description": "Compute cryptographic checksums (SHA-256, MD5) for PCAP files and verify against expected values.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the file to hash."},
                "expected_sha256": {"type": "string", "description": "Optional expected SHA-256 hash to compare against."}
            },
            "required": ["file_path"]
        }
    }
]


def handle_request(req):
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "netguard-pcap-mcp",
                    "version": "1.0.0"
                }
            }
        }
    elif method == "notifications/initialized":
        return None
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": TOOLS_SCHEMA
            }
        }
    elif method == "tools/call":
        params = req.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})

        try:
            if tool_name == "pcap_metadata":
                out = tool_pcap_metadata(args.get("pcap_path"))
            elif tool_name == "protocol_distribution":
                out = tool_protocol_distribution(args.get("pcap_path"))
            elif tool_name == "flow_summary":
                out = tool_flow_summary(args.get("pcap_path"), args.get("top_n", 10))
            elif tool_name == "tcp_flags":
                out = tool_tcp_flags(args.get("pcap_path"))
            elif tool_name == "dns_inventory":
                out = tool_dns_inventory(args.get("pcap_path"))
            elif tool_name == "suricata_eve_summary":
                out = tool_suricata_eve_summary(args.get("eve_path"))
            elif tool_name == "dataset_hash_verify":
                out = tool_dataset_hash_verify(args.get("file_path"), args.get("expected_sha256"))
            else:
                out = {"error": f"Unknown tool: {tool_name}"}
        except Exception as e:
            out = {"error": f"Tool execution failed: {str(e)}"}

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(out, indent=2)
                    }
                ]
            }
        }
    elif method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {}
        }
    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}"
            }
        }


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue

        resp = handle_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
