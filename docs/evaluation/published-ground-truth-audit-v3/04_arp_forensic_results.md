# 4. Layer-2 ARP Forensic Results

## Inventory & Packet Analysis
NetGuard emitted **262 ARP_SPOOF alerts**.

---

## Physical PCAP Evidence
- Total ARP frames in capture: **6,252 packets**.
- Gateway `192.168.1.1` MAC: strictly **78:8a:20:43:93:d5** throughout all 9.77 hours.
- Device `192.168.1.200` MAC: strictly **b8:27:eb:e1:1a:08**.
- Claimed old MAC in alerts (`00:11:22:33:44:01`): **NEVER APPEARED IN THE PCAP**.

---

## Evidentiary Assessment
1. The historical runtime `arp_table.json` state was not preserved in Git.
2. The repository contains a synthetic test fixture in `ids_project/data/arp_table.json` containing `00:11:22:33:44:01`.
3. While circumstantial evidence strongly indicates initial fixture contamination, strict forensic rigor classifies these alerts as:
   **Unsupported False Alarms on this Capture**.
4. Zero genuine ARP poisoning occurred.
