# 2. Ground-Truth Label Distribution & Traffic Coverage

## Publisher Ground-Truth Summary
Total flows analyzed: **3,394,338**.

### Generic Label Distribution
| Label | Flow Count | Percentage | Interpretation |
| :--- | :--- | :--- | :--- |
| **Malicious** | `3,390,604` | `99.89%` | Confirmed malware attack traffic |
| **Benign** | `3,734` | `0.11%` | Normal background and protocol replies |

### Detailed Attack Label Distribution
| Detailed Label | Flow Count | Percentage | Protocol / Attack Type |
| :--- | :--- | :--- | :--- |
| `PartOfAHorizontalPortScan` | `3,386,119` | `99.76%` | Mirai SYN scanning on port 23 |
| `Attack` | `2,752` | `0.08%` | Secondary scan / attack bursts |
| `C&C-PartOfAHorizontalPortScan` | `888` | `0.03%` | Coordinated scan commands |
| `C&C-HeartBeat-Attack` | `834` | `0.02%` | Command & Control beaconing |
| `C&C-HeartBeat-FileDownload` | `11` | `0.00%` | Initial HTTP payload downloads |
| `-` (Benign baseline) | `0` | `0.00%` | ICMP replies & gateway baseline |
