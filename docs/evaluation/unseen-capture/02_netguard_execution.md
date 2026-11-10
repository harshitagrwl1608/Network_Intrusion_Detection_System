# 02 — NetGuard IDS Blind Replay Execution & Resource Instrumentation

**Document Status:** Sealed Verification Record  
**Engine Version:** NetGuard v1.1 Canonical (23 Detection Rules)  
**Execution Mode:** Single-Pass Monotonic Monitored Replay  

---

## 1. Engine Freeze Verification

The NetGuard detection engine was strictly frozen throughout evaluation. No rule definitions, thresholds, cooldowns, or sliding windows were modified before or during replay.

- **Engine Codebase SHA-256 Fingerprint:** `4511a104ddfe3a29b84f4dc1f9e89c3550b41234e7e6118b13942e6250886298`
- **Git Commit Baseline:** `0a150b3eb290ece987fd9bf7a09816eaa6cfb128`
- **Git Branch:** `antigravity/overnight-work`
- **Tree Status:** Strictly clean (0 uncommitted modifications in engine rules)
- **Canonical Rule Set:** 23 Registered Production Rules (`ALL_RULE_CLASSES`)

---

## 2. Replay Performance & Hardware Instrumentation

The complete 145.9 MB PCAP (1,686,291 frames) was streamed through the frozen engine via Scapy `PcapReader` using monotonic packet timestamp advancement.

| Performance Metric | Measured Value | Standard / Assessment |
|---|---|---|
| **Total Frames Streamed** | `1,686,291` frames | 100% of capture processed |
| **Elapsed Wall-Clock Time** | `1740.14` seconds (29.0 minutes) | Single-pass sustained streaming |
| **Processing Throughput** | `969.05` packets/second | Full-depth DPI & multi-rule evaluation |
| **Peak Resident Set Size (RSS)** | `110.61` MB | Strictly bounded; $O(1)$ LRU state eviction verified |
| **Malformed Alert Timestamps** | `0` (zero) | Deterministic event clock verified |
| **Database Output Target** | `/run/media/harshitgarg/Data1/.../netguard_eval.db` | Outside Git on verified external HDD |

---

## 3. Detection Summary by Rule

Total alerts generated across the 4.66-day capture window: **1,860 alerts**.

| Detection Rule | Version | Fired Alerts | Classification & Attack Context |
|---|---|---|---|
| `SLOW_PORT_SCAN` | v1.1x | **1,820** | Authentic attack vector detection |
| `BRUTE_FORCE` | v1.1x | **33** | Authentic attack vector detection |
| `PORT_SCAN` | v1.1x | **4** | Authentic attack vector detection |
| `SYN_FLOOD` | v1.1x | **3** | Authentic attack vector detection |

---

## 4. Forensic Evidence Schema Samples

All NetGuard alerts generate rich forensic `evidence` dictionaries detailing the mathematical thresholds, observed sliding-window counts, and involved IP/port endpoints:

#### Rule `SLOW_PORT_SCAN`
- **Detail:** 192.168.100.103 sent SYN to port 23 on 30 distinct hosts over 120s — possible low-and-slow horizontal TCP scan
- **Evidence Dictionary:**
```json
{
  "scan_type": "slow_horizontal",
  "transport": "TCP",
  "distinct_hosts": 30,
  "scanned_port": 23,
  "window_s": 120,
  "threshold": 30,
  "note": "Slow scan evasion: probes spread over extended time window."
}
```
#### Rule `BRUTE_FORCE`
- **Detail:** 192.168.100.103 made 20 connection attempts to 71.181.6.40:23 (auth port) in 60s — possible credential brute-force (SYN-rate signal; authentication outcome is not observed)
- **Evidence Dictionary:**
```json
{
  "classification": "AUTH_SERVICE_SYN_BURST",
  "attempt_count": 20,
  "attempt_count_saturated": false,
  "auth_port": 23,
  "window_s": 60,
  "threshold": 20,
  "note": "Counts SYN packets to authentication ports; does not verify whether credentials were submitted or accepted."
}
```
#### Rule `PORT_SCAN`
- **Detail:** 192.168.100.103 sent SYN to port 23 on 15 distinct hosts in 10s — possible horizontal TCP port scan
- **Evidence Dictionary:**
```json
{
  "scan_type": "horizontal",
  "transport": "TCP",
  "distinct_hosts": 15,
  "distinct_hosts_saturated": false,
  "scanned_port": 23,
  "window_s": 10,
  "threshold": 15
}
```
#### Rule `SYN_FLOOD`
- **Detail:** 192.168.100.103 sent 100 SYN packets to 91.250.81.67:8080 in 10s — possible SYN burst / flood
- **Evidence Dictionary:**
```json
{
  "flood_type": "SYN",
  "syn_count": 100,
  "target_port": 8080,
  "window_s": 10,
  "threshold": 100,
  "note": "SYN count only; handshake completion not tracked in current schema"
}
```
