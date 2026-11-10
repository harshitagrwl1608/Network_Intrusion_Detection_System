# 2. Dataset Integrity & Label Reconciliation Audit

## Cryptographic Hashes
- **PCAP File**: `2019-02-28-19-15-13-192.168.1.200.pcap`
  - Verified SHA-256: `ac2e41f0d5b2479ce5e1779fbaa6d6b73a6151050d86f04f80a872759034865c`
  - Packet Count: `13,565,553` (Matches publisher README exactly)
- **Zeek Labeled Log**: `2019-02-28-19-15-13-192.168.1.200-zeek-conn-log.labeled`
  - Verified SHA-256: `9f69946243df93c199876c0783cb4b5fb188e6d2325c593858f2db8fb5fa847f`
  - Total Connection Records: `3,394,338`

---

## Label Reconciliation
The official NetflowLabeler configuration (`2019-02-28-19-15-13-192.168.1.200-labels.config`) specifies:
1. `Background` (all traffic default)
2. `Malicious, From_Malware` and `Malicious, Horizontal-Scan`
3. `Benign, Answers` (ICMP replies) and `Benign, Windows`

### Complete Flow Distribution
| Generic Label | Detailed Label | Count | Percentage | Semantics |
| :--- | :--- | :--- | :--- | :--- |
| **Malicious** | `PartOfAHorizontalPortScan` | `3,386,119` | `99.76%` | Mirai SYN scan on port 23 |
| **Malicious** | `Attack` | `2,752` | `0.08%` | Secondary scan bursts on port 23 |
| **Malicious** | `C&C-PartOfAHorizontalPortScan`| `888` | `0.03%` | Scan coordination flows |
| **Malicious** | `C&C-HeartBeat-Attack` | `834` | `0.02%` | C&C beaconing on port 23 |
| **Malicious** | `C&C-HeartBeat-FileDownload` | `11` | `0.00%` | HTTP ELF dropper downloads |
| **Benign** | `-` (Empty detailed label) | `3,734` | `0.11%` | Baseline ICMP unreachable / NTP |

### Markdown Display Bug Correction
In the previous report table, the 3,734 benign flows appeared blank due to an unescaped hyphen. This audit reconciles the exact raw count: **3,734 Benign flows** with empty detailed label.
