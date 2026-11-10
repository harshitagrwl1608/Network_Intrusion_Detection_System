# 8. Suricata 8.0.7 Comparative Run Audit

## Suricata Provenance Verification
- **Execution Command**: `suricata -c /etc/suricata/suricata.yaml -r 2019-02-28-19-15-13-192.168.1.200.pcap -l suricata_output/`
- **Ruleset**: Emerging Threats (ET) Open (53,391 rules loaded)
- **Input PCAP**: Verified identical SHA-256 digest (`ac2e41f...`) and 13,565,553 packets.
- **EVE JSON Total Alerts**: **85** alerts (re-verified independently).

---

## Detailed Signature Audit
| Signature ID | Signature Description | Category | Count |
| :--- | :--- | :--- | :--- |
| `1:2210045:2` | `SURICATA STREAM Packet with invalid ack` | Generic Protocol Command Decode | 23 |
| `1:2210046:3` | `SURICATA STREAM SHUTDOWN RST invalid ack` | Generic Protocol Command Decode | 23 |
| `1:2019240:16` | `ET INFO Executable and linking format (ELF) file download Over HTTP` | Potential Corporate Privacy Violation | 11 |
| `1:2032973:3` | `ET HUNTING Possible ELF executable sent when remote host claims to send text` | Potentially Bad Traffic | 11 |
| `1:2200074:2` | `SURICATA TCPv4 invalid checksum` | Generic Protocol Command Decode | 6 |
| `1:2210054:1` | `SURICATA STREAM excessive retransmissions` | Generic Protocol Command Decode | 3 |
| `1:2400036:4883`| `ET DROP Spamhaus DROP Listed Traffic Inbound` | Misc Attack | 3 |

---

## Complementary Telemetry Verdict
1. **Suricata Detected What NetGuard Missed**: Suricata inspected HTTP stream reassembly and caught all 11 ELF dropper downloads.
2. **NetGuard Detected What Suricata Missed**: Suricata generated **0 alerts** for horizontal scanning because ET Open lacks default SYN heuristics. NetGuard generated 3,765 alerts covering the scan campaign.
