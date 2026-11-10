# NetGuard IDS — Configuration Reference

All configuration is in [`ids_project/config.py`](../ids_project/config.py).
Every setting can be overridden via an environment variable or by placing a `.env` file at `ids_project/.env` (requires `python-dotenv`).

The table below lists every configurable parameter, its default value, the environment variable name to override it, and what it controls.

---

## Network

| Variable | Default | Env var | Description |
|---|---|---|---|
| `INTERFACE` | `"eth0"` | `IDS_INTERFACE` | Network interface for live packet capture |

---

## Storage

| Variable | Default | Env var | Description |
|---|---|---|---|
| `DB_BACKEND` | `"sqlite"` | `DB_BACKEND` | Backend type: `"sqlite"` or `"postgres"` |
| `SQLITE_PATH` | `"storage/alerts.db"` | `SQLITE_PATH` | SQLite database file path (relative to `ids_project/`) |
| `POSTGRES_URL` | `""` | `POSTGRES_URL` | PostgreSQL connection URL (e.g. `postgresql://user:pass@host/db`) |

---

## Blocklist

| Variable | Default | Env var | Description |
|---|---|---|---|
| `BLOCKLIST_PATH` | `"data/blocklist.txt"` | `BLOCKLIST_PATH` | Local path to the IP blocklist file |
| `BLOCKLIST_URL` | `"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"` | — | URL for automatic blocklist refresh |
| `ARP_TABLE_PATH` | `"data/arp_table.json"` | — | Persistent IP→MAC mapping for ARP spoof detection |

---

## Trusted Hosts

| Variable | Default | Env var | Description |
|---|---|---|---|
| `TRUSTED_HOSTS` | `{GATEWAY_IP}` | — | Set of IPs/CIDRs exempt from scan, SYN-flood, and ICMP sweep rules |
| `GATEWAY_IP` | `"192.168.1.1"` | `GATEWAY_IP` | Your default gateway; added to `TRUSTED_HOSTS` automatically |
| _(extra)_ | — | `IDS_TRUSTED` | Comma-separated additional trusted IPs/hostnames (e.g. `IDS_TRUSTED=1.2.3.4,router.local`) |

---

## Detection Thresholds

### Port and UDP Scans

| Variable | Default | Env var | Description |
|---|---|---|---|
| `PORT_SCAN_THRESHOLD` | `15` | `PORT_SCAN_THRESHOLD` | Distinct TCP destination ports or hosts within `TIME_WINDOW` to trigger `PORT_SCAN` |
| `TCP_STEALTH_SCAN_THRESHOLD` | `15` | `TCP_STEALTH_SCAN_THRESHOLD` | Distinct FIN/NULL/Xmas destination ports to trigger `TCP_STEALTH_SCAN` |
| `UDP_SCAN_THRESHOLD` | `15` | `UDP_SCAN_THRESHOLD` | Distinct UDP destination ports or hosts within `TIME_WINDOW` to trigger `UDP_SCAN` |
| `SLOW_SCAN_THRESHOLD` | `30` | `SLOW_SCAN_THRESHOLD` | Distinct ports/hosts in `SLOW_SCAN_WINDOW` to trigger `SLOW_PORT_SCAN` |
| `SLOW_SCAN_WINDOW` | `120` | `SLOW_SCAN_WINDOW` | Slow scan sliding window in seconds |
| `SLOW_SCAN_COOLDOWN_S` | `120.0` | `SLOW_SCAN_COOLDOWN_S` | Per-source cooldown after a slow scan alert |
| `TIME_WINDOW` | `10` | `TIME_WINDOW` | General sliding window duration in seconds (used by PORT_SCAN, SYN_FLOOD, ICMP rules) |

### Flood Thresholds

| Variable | Default | Env var | Description |
|---|---|---|---|
| `SYN_FLOOD_THRESHOLD` | `100` | `SYN_FLOOD_THRESHOLD` | SYN packets to a single target in `TIME_WINDOW` to trigger `SYN_FLOOD` |
| `RST_FLOOD_THRESHOLD` | `100` | `RST_FLOOD_THRESHOLD` | RST packets in `TIME_WINDOW` to trigger RST flood detection (sub-rule of `SYN_FLOOD`) |
| `RST_RESPONSE_GRACE_SECONDS` | `5.0` | `RST_RESPONSE_GRACE_SECONDS` | Grace period to match a SYN to a closed-port RST (benign RST suppression) |
| `DISTRIBUTED_SYN_FLOOD_THRESHOLD` | `500` | `DISTRIBUTED_SYN_FLOOD_THRESHOLD` | Total SYN packets to a single target from multiple sources |
| `DISTRIBUTED_SYN_FLOOD_MIN_SOURCES` | `20` | `DISTRIBUTED_SYN_FLOOD_MIN_SOURCES` | Minimum distinct source IPs to classify as distributed |
| `UDP_FLOOD_THRESHOLD` | `50` | `UDP_FLOOD_THRESHOLD` | UDP packets to a single target within `UDP_FLOOD_WINDOW` |
| `UDP_FLOOD_WINDOW` | `5` | `UDP_FLOOD_WINDOW` | UDP flood sliding window in seconds |
| `UDP_FLOOD_WEB_THRESHOLD` | `500` | `UDP_FLOOD_WEB_THRESHOLD` | Burst threshold for QUIC/UDP port 443 (higher threshold to reduce false positives on QUIC) |
| `ICMP_FLOOD_THRESHOLD` | `50` | `ICMP_FLOOD_THRESHOLD` | ICMP echo requests to a single target within `ICMP_FLOOD_WINDOW` |
| `ICMP_FLOOD_WINDOW` | `5` | `ICMP_FLOOD_WINDOW` | ICMP flood sliding window in seconds |
| `ICMP_SWEEP_THRESHOLD` | `12` | `ICMP_SWEEP_THRESHOLD` | Distinct ICMP echo targets within `TIME_WINDOW` to trigger `ICMP_SWEEP` |

### Brute Force

| Variable | Default | Env var | Description |
|---|---|---|---|
| `BRUTE_FORCE_THRESHOLD` | `20` | `BRUTE_FORCE_THRESHOLD` | SYN attempts to auth ports within `BRUTE_FORCE_WINDOW` |
| `BRUTE_FORCE_WINDOW` | `60` | `BRUTE_FORCE_WINDOW` | Brute force sliding window in seconds |
| `BRUTE_FORCE_EXTRA_PORTS` | `()` | `BRUTE_FORCE_EXTRA_PORTS` | Additional ports to monitor for brute force (comma-separated integers) |

### Data Exfiltration

| Variable | Default | Env var | Description |
|---|---|---|---|
| `DATA_EXFIL_BYTE_THRESHOLD` | `50000` | `DATA_EXFIL_BYTE_THRESHOLD` | Outbound bytes within `DATA_EXFIL_WINDOW` to trigger `DATA_EXFIL` |
| `DATA_EXFIL_WINDOW` | `30` | `DATA_EXFIL_WINDOW` | Data exfil sliding window in seconds |
| `DATA_EXFIL_WEB_BYTE_THRESHOLD` | `1000000` | `DATA_EXFIL_WEB_BYTE_THRESHOLD` | Higher threshold for web traffic (port 80/443) to reduce false positives on large downloads |

### TCP Anomalies

| Variable | Default | Env var | Description |
|---|---|---|---|
| `TCP_ZERO_WINDOW_THRESHOLD` | `20` | `TCP_ZERO_WINDOW_THRESHOLD` | Zero-window packets within `TCP_ZERO_WINDOW_WINDOW` per flow pair |
| `TCP_ZERO_WINDOW_WINDOW` | `10` | `TCP_ZERO_WINDOW_WINDOW` | TCP zero-window sliding window in seconds |
| `TCP_ZERO_WINDOW_COOLDOWN` | `60.0` | `TCP_ZERO_WINDOW_COOLDOWN` | Per-pair cooldown after a zero-window alert |
| `TCP_ZERO_WINDOW_MIN_FLOWS` | `3` | `TCP_ZERO_WINDOW_MIN_FLOWS` | Minimum concurrent affected flow pairs for corroboration |

---

## Deep Packet Inspection (PAYLOAD_HIT)

| Variable | Default | Env var | Description |
|---|---|---|---|
| `PAYLOAD_INSPECTION` | `True` | `PAYLOAD_INSPECTION` | Enable/disable DPI entirely (`"true"` / `"false"`) |
| `PAYLOAD_MAX_BYTES` | `512` | `PAYLOAD_MAX_BYTES` | Per-packet payload bytes forwarded to DPI signatures |
| `PAYLOAD_ALERT_COOLDOWN_S` | `60.0` | `PAYLOAD_ALERT_COOLDOWN_S` | Per-flow, per-signature cooldown between repeated alerts |

---

## DNS Anomaly Detection

| Variable | Default | Env var | Description |
|---|---|---|---|
| `DNS_ENTROPY_THRESHOLD` | `3.8` | `DNS_ENTROPY_THRESHOLD` | Shannon entropy threshold for DGA detection (bits/char) |
| `DNS_QUERY_MAX_LEN` | `60` | `DNS_QUERY_MAX_LEN` | Maximum label length before flagging as DNS tunnel candidate |
| `DNS_FREQ_THRESHOLD` | `20` | `DNS_FREQ_THRESHOLD` | Query count within `DNS_FREQ_WINDOW` to trigger high-frequency alert |
| `DNS_FREQ_WINDOW` | `60` | `DNS_FREQ_WINDOW` | DNS frequency sliding window in seconds |
| `DNS_SUBDOMAIN_THRESHOLD` | `20` | `DNS_SUBDOMAIN_THRESHOLD` | Distinct subdomains within `DNS_SUBDOMAIN_WINDOW` to flag |
| `DNS_SUBDOMAIN_WINDOW` | `60` | `DNS_SUBDOMAIN_WINDOW` | DNS subdomain sliding window in seconds |
| `NON_DNS_ON_DNS_PORT_COOLDOWN_S` | `60.0` | `NON_DNS_ON_DNS_PORT_COOLDOWN_S` | Per-flow cooldown for non-DNS traffic on port 53 |

---

## TLS / HTTPS Inspection

| Variable | Default | Env var | Description |
|---|---|---|---|
| `TLS_INSPECTION` | `True` | `TLS_INSPECTION` | Enable TLS anomaly detection (`"true"` / `"1"` to enable) |
| `TLS_COOLDOWN_S` | `60.0` | `TLS_COOLDOWN_S` | Per-flow cooldown after a TLS anomaly alert |
| `CLEAR_HTTP_TLS_COOLDOWN_S` | `600.0` | `CLEAR_HTTP_TLS_COOLDOWN_S` | Cooldown between `CLEAR_HTTP_ON_TLS_PORT` alerts for a flow |
| `CLEAR_HTTP_TLS_WINDOW_S` | `600.0` | `CLEAR_HTTP_TLS_WINDOW_S` | Window for counting cleartext HTTP requests on TLS ports |
| `CLEAR_HTTP_TLS_MIN_REQUESTS` | `2` | `CLEAR_HTTP_TLS_MIN_REQUESTS` | Minimum cleartext requests within window before alerting |

---

## IP Fragmentation

| Variable | Default | Env var | Description |
|---|---|---|---|
| `IP_FRAGMENT_ANOMALY_COOLDOWN_S` | `60.0` | `IP_FRAGMENT_ANOMALY_COOLDOWN_S` | Cooldown between `IP_FRAGMENT_ANOMALY` alerts per source |
| `IP_FRAGMENT_REASSEMBLY_TIMEOUT_S` | `30.0` | `IP_FRAGMENT_REASSEMBLY_TIMEOUT_S` | Timeout before incomplete fragment reassembly is abandoned |

---

## ICMP Tunnel

| Variable | Default | Env var | Description |
|---|---|---|---|
| `ICMP_TUNNEL_ENTROPY_THRESHOLD` | `4.5` | `ICMP_TUNNEL_ENTROPY_THRESHOLD` | Shannon entropy of ICMP payload to flag as tunnel candidate |
| `ICMP_TUNNEL_MIN_BYTES` | `64` | `ICMP_TUNNEL_MIN_BYTES` | Minimum ICMP payload bytes to evaluate for tunnel |
| `ICMP_TUNNEL_COOLDOWN_S` | `60.0` | `ICMP_TUNNEL_COOLDOWN_S` | Per-pair cooldown between ICMP tunnel alerts |

---

## IRC C2 Beaconing

| Variable | Default | Env var | Description |
|---|---|---|---|
| `IRC_BEACONING_THRESHOLD` | `5` | `IRC_BEACONING_THRESHOLD` | SYN count to IRC ports within `IRC_BEACONING_WINDOW` |
| `IRC_BEACONING_WINDOW` | `300` | `IRC_BEACONING_WINDOW` | IRC beaconing sliding window in seconds (5 min) |
| `IRC_BEACONING_COOLDOWN_S` | `300.0` | `IRC_BEACONING_COOLDOWN_S` | Per-pair cooldown after an IRC C2 alert |
| `IRC_BEACONING_MAX_SOURCES` | `2048` | `IRC_BEACONING_MAX_SOURCES` | LRU state cap for source tracking |

---

## Operational

| Variable | Default | Env var | Description |
|---|---|---|---|
| `ANALYSIS_INTERVAL` | `30` | `ANALYSIS_INTERVAL` | Seconds between analysis loop runs (plain-language threat summary) |
| `ALERT_RETENTION_DAYS` | `7` | `ALERT_RETENTION_DAYS` | Alerts older than this are pruned from the database (0 = keep forever) |
| `HISTORY_DAYS` | `7` | `HISTORY_DAYS` | History window for dashboard trend views |
| `FEEDBACK_PATH` | `"data/feedback.jsonl"` | `FEEDBACK_PATH` | JSONL file for analyst TP/FP feedback |

---

## Dashboard

| Variable | Default | Env var | Description |
|---|---|---|---|
| `DASHBOARD_HOST` | `"127.0.0.1"` | `DASHBOARD_HOST` | Flask listen address |
| `DASHBOARD_PORT` | `5000` | `DASHBOARD_PORT` | Flask listen port |
| `DASHBOARD_DEBUG` | `False` | `DASHBOARD_DEBUG` | Enable Flask debug mode (`"true"` to enable — **never in production**) |

---

## Example `.env` File

```dotenv
# ids_project/.env
IDS_INTERFACE=ens3
GATEWAY_IP=10.0.0.1
IDS_TRUSTED=10.0.0.1,10.0.0.2
SQLITE_PATH=storage/production.db
ALERT_RETENTION_DAYS=30
PAYLOAD_INSPECTION=true
PORT_SCAN_THRESHOLD=20
SYN_FLOOD_THRESHOLD=150
```

