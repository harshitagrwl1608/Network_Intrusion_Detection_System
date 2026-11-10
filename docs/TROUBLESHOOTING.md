# NetGuard IDS — Troubleshooting Guide & Operational FAQ

---

## 1. Common Runtime Issues & Remediation

### 1.1 `PermissionError: [Errno 1] Operation not permitted`
**Symptom:**
```
Traceback (most recent call last):
  ...
PermissionError: [Errno 1] Operation not permitted
```
**Root Cause:**
Opening raw sockets for live packet capture via Scapy requires Linux root privileges or the `CAP_NET_RAW` capability.

**Solution:**
- Run the entry point with `sudo`:
  ```bash
  sudo python3 ids_project/main.py
  ```
- Alternatively, grant the Python binary raw socket capabilities without full root access:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
  ```

---

### 1.2 `editcap: command not found`
**Symptom:**
Converting `.pcapng` files to classic `.pcap` fails with `editcap: command not found`.

**Root Cause:**
`editcap` is part of the Wireshark utility suite and is not installed by default on minimal Linux installations.

**Solution:**
Install Wireshark command-line utilities via your distribution package manager:
- **Debian / Ubuntu:**
  ```bash
  sudo apt-get update && sudo apt-get install -y wireshark-tools
  ```
- **Fedora / RHEL:**
  ```bash
  sudo dnf install -y wireshark-cli
  ```
- **Arch Linux:**
  ```bash
  sudo pacman -S wireshark-cli
  ```

---

### 1.3 `FileNotFoundError` During Full Benchmark Replay
**Symptom:**
```
FileNotFoundError: [Errno 2] No such file or directory: '.../verified/ws_teardrop.pcap'
```
**Root Cause:**
Large benchmark datasets (e.g. Wireshark samples, CTU-IoT-23, Fox-IT Log4Shell) are stored on external storage or in a dedicated data directory to keep the Git repository lightweight.

**Solution:**
1. Connect or mount your external dataset volume.
2. Verify that the file paths exist or match the paths configured in `data/external_benchmarks/ground_truth/manifest.csv`.
3. If datasets are located in a custom directory, update the paths in `manifest.csv` or create a symlink to your dataset location.

---

### 1.4 `sqlite3.OperationalError: no such column: evidence`
**Symptom:**
Custom SQL queries against `storage/alerts.db` fail with `no such column: evidence`.

**Root Cause:**
The alert table schema names the forensic evidence column `evidence_json`, not `evidence`.

**Solution:**
Use the correct column name in SQL queries:
```sql
SELECT id, rule_name, severity, evidence_json FROM alerts ORDER BY timestamp DESC LIMIT 10;
```

---

### 1.5 `re.PatternError: global flags not at the start of expression`
**Symptom:**
```
re.PatternError: global flags not at the start of expression at position 1
```
**Root Cause:**
In Python 3.11 and newer, inline regex flags such as `(?i)` must appear at the absolute start of the regular expression string (e.g., `(?i)^pattern` rather than `^(?i)pattern`).

**Solution:**
Ensure inline flags are positioned at index 0 of the regex pattern:
```python
# Incorrect:
re.compile(r"^(?i)select\s+")

# Correct:
re.compile(r"(?i)^select\s+")
```

---

### 1.6 High False-Positive Rate on Internal Gateways or CDNs
**Symptom:**
Frequent `PORT_SCAN`, `SYN_FLOOD`, or `ICMP_SWEEP` alerts targeting your local router, DNS resolver, or CDN edge IPs.

**Root Cause:**
Network infrastructure devices naturally handle high packet volumes and diverse ports. If they are not declared as trusted, volumetric heuristics may classify normal traffic as attacks.

**Solution:**
Declare trusted infrastructure IPs in [`ids_project/.env`](../ids_project/config.py):
```dotenv
GATEWAY_IP=192.168.1.1
IDS_TRUSTED=192.168.1.1,192.168.1.254,1.1.1.1,8.8.8.8
```

---

### 1.7 UDP Flood Alerts During YouTube or Video Streaming
**Symptom:**
`UDP_FLOOD` alerts fire when streaming video over web browsers.

**Root Cause:**
Modern browsers use HTTP/3 over QUIC (UDP port 443), which generates high UDP packet bursts.

**Solution:**
NetGuard includes a dedicated `UDP_FLOOD_WEB_THRESHOLD` setting for UDP port 443 (default: 500 packets / 5s, compared to 50 packets for other UDP ports). If you experience false positives on high-speed connections, increase this threshold:
```dotenv
UDP_FLOOD_WEB_THRESHOLD=1000
```

---

## 2. Privacy & Operational Security Safeguards

### 2.1 Credential & Token Redaction in Alert Evidence
Because deep packet inspection parses application-layer payloads, packet buffers may contain sensitive credentials (e.g., HTTP Basic authorization headers, bearer tokens, form-encoded passwords).

NetGuard implements automatic credential scrubbing in [`ids_project/engine/http_parser.py`](../ids_project/engine/http_parser.py):
- Any matched string containing `password=...`, `passwd=...`, or `pwd=...` is replaced with `password=[REDACTED]`.
- Bearer tokens (`Bearer <token>`) and Basic auth strings (`Basic <base64>`) are sanitized with `[REDACTED]` prior to alert persistence.

### 2.2 Alert Database Storage & Access Control
- The SQLite alert database (`storage/alerts.db`) contains sensitive network metadata (IP addresses, hostnames, timestamps, port numbers).
- **Invariants:**
  - Never commit `alerts.db` or `.db` files to version control (`.gitignore` excludes `*.db`).
  - Restrict filesystem permissions on the storage directory:
    ```bash
    chmod 700 ids_project/storage
    chmod 600 ids_project/storage/alerts.db
    ```
  - For production deployments with compliance requirements (e.g. GDPR, HIPAA), switch to PostgreSQL (`DB_BACKEND=postgres`) with encrypted transport and role-based access control.

### 2.3 Automated Data Retention & Pruning
To prevent unbounded disk growth and comply with data minimization principles:
- Configure `ALERT_RETENTION_DAYS` in [`ids_project/config.py`](../ids_project/config.py) (default: 7 days).
- The background analysis loop automatically purges alert records older than the retention threshold once every 24 hours.

