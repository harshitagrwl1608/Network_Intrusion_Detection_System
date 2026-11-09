# 1. Historical Run & Engine Provenance Audit

## Executive Verdict: SUPPORTED WITH LIMITATIONS
The core detection rules and packet parsing engine were demonstrably identical between the performance engine commit (`f7e816a`) and the evaluation commit (`59520d4`). However, the aggregate engine fingerprint changed from `86c41a7839fcaae6660190615a2da8681f6a60283377817542d720c324de22d7` to `86c41a7839fcaae6660190615a2da8681f6a60283377817542d720c324de22d7` due to modifications within `ids_project/evaluation/compare.py` required to parse the space-separated fields of NetflowLabeler.

---

## Commit & Lineage Manifest
- **Evaluation Commit**: `59520d48f704b3a89be3c0c5dc819b33d992264d` (Date: Nov 9, 2026)
- **Parent Engine Commit**: `f7e816a5f0dc41e3f1db458001899b145abfbca4` (Date: Nov 9, 2026)
- **Branch**: `antigravity/overnight-work` (Authorized)
- **Engine Fingerprint at Engine Commit**: `0fa76204c8dffca337db69b9790596d8eb5f5b7195b225e06b1b1427be3d6e76`
- **Engine Fingerprint at Evaluation Commit**: `86c41a7839fcaae6660190615a2da8681f6a60283377817542d720c324de22d7`

### Individual Core File Hashes
| File Path | SHA-256 Digest | Status During Evaluation |
| :--- | :--- | :--- |
| `engine/rules.py` | `5fe6b3dd4f7a6be5a632476cc136ac2478a7437ab8f34c4c1596d49ca5c45dc1` | **FROZEN / UNMODIFIED** |
| `capture/sniffer.py` | `128ae8456e01d2b3d006e545029467b55507e3e58c044b110f3ed284044d732f` | **FROZEN / UNMODIFIED** |
| `config.py` | `6f60e0b6c9d16470137c861b290f1cebe8d646aa54f9d5a34b9f8f2936347f77` | **FROZEN / UNMODIFIED** |
| `storage/db.py` | `0bf2e40a05ee01c3e0c01e6ad6c412584bd4028d6b38b35c883e5699805ec2e8` | **FROZEN / UNMODIFIED** |
| `evaluation/replay.py` | `29f0a31873570b09ee242d63abf8d2e277aacab4d2f58e268b727a7060285021` | **FROZEN / UNMODIFIED** |
| `evaluation/pipeline.py` | `430a98c022809396edb2145e851f790bb6d250b7f79f22cb071c461387c2446e` | **FROZEN / UNMODIFIED** |
| `evaluation/compare.py` | `d643594f6b8f40836d472120082d1bffad848a55d0c43f1fd028105aa16105b5` | **MODIFIED** (Added NetflowLabeler parser) |

---

## Effective Configuration Audit
The effective detection configuration was extracted directly from `ids_project/config.py`:
- `PORT_SCAN_THRESHOLD`: **15** distinct hosts
- `TIME_WINDOW`: **10** seconds
- `SLOW_SCAN_THRESHOLD`: **30** distinct hosts
- `SLOW_SCAN_WINDOW`: **120** seconds
- `SLOW_SCAN_COOLDOWN_S`: **120.0** seconds
- `ARP_TABLE_PATH`: `'data/arp_table.json'` (Pre-existing static test file)
- `TRUSTED_HOSTS`: `{'192.168.29.1', 'reliance.reliance'}`

### Discrepancy Found in Reported Threshold
The original report stated: *"PORT_SCAN sent SYN to port 23 on at least 30 distinct hosts in 10s"*.  
**Forensic Explanation**: In `PortScanRule`, `self.threshold` is 15. The rule caps retained target history at `_max_evidence = self.threshold * 2 = 30`. When 30 targets are reached, the state marks saturation (`_horiz_saturated`), producing the alert text `"at least 30 distinct hosts"`. The actual trigger threshold is 15, but intense Mirai scanning saturated the evidence buffer to 30 on every alert.
