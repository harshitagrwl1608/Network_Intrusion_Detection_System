# 5. Layer-2 ARP Forensic Audit & State Contamination Analysis

## Root Cause of All 262 ARP_SPOOF Alerts
Investigation of `ids_project/data/arp_table.json` revealed:
```json
{
  "192.168.1.1": "00:11:22:33:44:01",
  "192.168.1.200": "..."
}
```
The file contained a hardcoded dummy MAC address (`00:11:22:33:44:01`) for the gateway `192.168.1.1`.

---

## PCAP Packet Inspection
Every ARP packet in `2019-02-28-19-15-13-192.168.1.200.pcap` was extracted using TShark:
- **Total ARP Packets**: `6,252`
- **Observed MAC for `192.168.1.1`**: Strictly `78:8a:20:43:93:d5` across all 9.77 hours.
- **Observed MAC for `192.168.1.200`**: Strictly `b8:27:eb:e1:1a:08` across all 9.77 hours.
- **Conflicting MAC Claims**: **0** (Zero conflicting MAC announcements).
- **Gratuitous ARP Poisoning**: **0** (Zero ARP poisoning packets).

---

## Audit Finding
1. There was **NO ARP SPOOFING** in CTU IoT-23 Capture 48-1.
2. The real gateway `192.168.1.1` broadcasted legitimate ARP announcements every ~120 seconds.
3. NetGuard compared the genuine MAC (`78:8a:20:43:93:d5`) against the contaminated pre-loaded file (`00:11:22:33:44:01`), generating an alert on every broadcast.
4. **Verdict**: All 262 `ARP_SPOOF` alerts are **CONFIRMED FALSE POSITIVES / INITIAL STATE CONTAMINATION ARTIFACTS**.
