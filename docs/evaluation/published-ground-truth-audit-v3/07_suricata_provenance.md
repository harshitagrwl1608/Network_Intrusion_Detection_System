# 7. Suricata 8.0.7 Execution & Provenance Audit

## Execution Environment
- Command Line: `suricata -r 2019-02-28-19-15-13-192.168.1.200.pcap -l suricata_output/`
- Runtime: **85.51 seconds** (158,637 pps)
- Total Alerts: **85**
- Packets Read: **13,565,553 packets**

---

## Top Signatures Breakdown
- 23: `SURICATA STREAM Packet with invalid ack`
- 23: `SURICATA STREAM SHUTDOWN RST invalid ack`
- 11: `ET INFO Executable and linking format (ELF) file download Over HTTP`
- 11: `ET HUNTING Possible ELF executable sent when remote host claims to send a Text File`
- 6: `SURICATA TCPv4 invalid checksum`

Suricata produced 0 alerts for the horizontal port scan, highlighting complementary IDS coverage.
