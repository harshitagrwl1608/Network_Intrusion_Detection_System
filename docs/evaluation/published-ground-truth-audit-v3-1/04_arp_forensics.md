# 4. Layer-2 ARP Forensic Results

## Physical Evidence & Evidentiary Standard
- Total ARP Frames in PCAP: **6,252**
- Physical Gateway MAC: strictly **78:8a:20:43:93:d5** across all 9.77 hours.
- Claimed previous MAC (`00:11:22:33:44:01`): **Never observed in capture**.
- Because the historical runtime `arp_table.json` was not preserved in Git, the 262 ARP alerts are conservatively classified as:
  **Tier D (Unassessed due to missing historical runtime arp_table.json)**.
