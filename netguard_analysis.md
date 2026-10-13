# NetGuard IDS — Detailed Proposal & Brainstorm Report

This report outlines proposed enhancements for the NetGuard IDS project. Each section details the current state of the system, the proposed changes, and exactly what will improve as a result.

---

## 1. Detection Engine Enhancements (Security & Intelligence)

Currently, NetGuard relies on a few solid but basic signature-based rules (Blocklist, SYN Flood, Port Scan, ARP Spoof). We can significantly elevate its threat detection capabilities.

### 1.1 Deep Packet Inspection (DPI) & Payload Analysis
*   **Current State:** The rule engine (`sniffer.py` and `rules.py`) only extracts and inspects network headers (IP addresses, MACs, TCP/UDP ports, SYN flags).
*   **Proposed Change:** Introduce a `PayloadRule` that inspects the raw data payload (using Scapy's `Raw` layer). We will run regular expressions to detect common application-layer attack signatures.
*   **Why it's better:** It allows the IDS to catch actual malicious payloads, such as SQL Injection attempts (e.g., `SELECT * FROM`), Cross-Site Scripting (XSS), or the transmission of plaintext credentials over unencrypted protocols (HTTP/FTP), which currently pass through unnoticed.

### 1.2 DNS Tunneling & DGA Detection
*   **Current State:** DNS traffic (UDP port 53) is treated like any other traffic; only the ports and IPs are logged.
*   **Proposed Change:** Add a `DnsRule` to parse DNS queries. We will calculate the Shannon entropy of queried domain names and flag unusually long or random-looking domains.
*   **Why it's better:** Modern malware and botnets often use Domain Generation Algorithms (DGAs) or tunnel data out of the network via DNS queries. This rule will detect these sophisticated Command & Control (C2) communications that evade standard blocklists.

### 1.3 Machine Learning / Anomaly Detection
*   **Current State:** Rules use strict, static thresholds (e.g., `PORT_SCAN_THRESHOLD = 15`).
*   **Proposed Change:** Implement a lightweight anomaly detection model (like Isolation Forest via `scikit-learn`). It will baseline "normal" traffic metrics (packet rates, unique IPs connected to per minute) and flag significant statistical deviations.
*   **Why it's better:** Static thresholds can be bypassed by "low and slow" attacks. Anomaly detection catches zero-day attacks and abnormal behavior without needing a predefined signature.

---

## 2. Dashboard & User Experience (UX)

The frontend is already beautiful with a dark glassmorphism aesthetic. We can make it feel more like a premium, enterprise-grade Security Operations Center (SOC) dashboard.

### 2.1 Real-Time WebSockets (Server-Sent Events)
*   **Current State:** The `dashboard.js` script uses `setInterval` to poll the `/api/*` endpoints every 30 seconds to fetch new alerts.
*   **Proposed Change:** Replace polling with Server-Sent Events (SSE) or WebSockets using `Flask-SocketIO`. The backend will push alerts to the frontend the millisecond they occur.
*   **Why it's better:** 
    1. **Speed:** Critical threat alerts appear instantly, enabling faster response times.
    2. **Efficiency:** Reduces unnecessary HTTP requests and server load compared to constant 30-second polling.

### 2.2 GeoIP Tracking & Interactive Maps
*   **Current State:** The alerts table and devices list only show raw IP addresses (e.g., `142.250.190.46`).
*   **Proposed Change:** Integrate the MaxMind GeoLite2 database (or a free GeoIP API) to map external IPs to their country and city. We can display country flags in the alerts table and potentially add an interactive global map showing attack origins.
*   **Why it's better:** Provides immediate contextual awareness. An admin can instantly see if a sudden spike in traffic is coming from an unexpected foreign country, helping prioritize investigations.

### 2.3 Device Fingerprinting (MAC OUI Mapping)
*   **Current State:** The "Network Devices" tab displays raw MAC addresses (e.g., `b8:27:eb:11:22:33`).
*   **Proposed Change:** Download an IEEE OUI (Organizationally Unique Identifier) database. The backend will parse the first 3 bytes of the MAC address to identify the manufacturer (e.g., Apple, Intel, Raspberry Pi).
*   **Why it's better:** Makes the device list much more human-readable. It allows admins to quickly spot unauthorized or rogue devices (e.g., "Why is there a Raspberry Pi on the guest network?").

---

## 3. Architecture & Operations

### 3.1 Automated IPS (Intrusion Prevention)
*   **Current State:** NetGuard is purely an Intrusion *Detection* System (IDS). It logs alerts but takes no action.
*   **Proposed Change:** Add an optional "Active Defense" toggle. When enabled, if a high-severity alert (like a Blocklist match or SYN Flood) is triggered, the system executes a host firewall command (`iptables` or `ufw`) to drop traffic from the offending IP for a set duration (e.g., 1 hour).
*   **Why it's better:** Transitions the project from a passive monitor to an active Intrusion *Prevention* System (IPS), stopping attacks in real-time without requiring human intervention.

### 3.2 Webhook Alerts (Slack / Discord)
*   **Current State:** Alerts are only visible if an admin is actively looking at the dashboard.
*   **Proposed Change:** Add a configuration option to send JSON payloads to external Webhooks whenever a High-Severity alert is generated.
*   **Why it's better:** Security teams get notified immediately via Slack, Discord, or email, ensuring critical threats aren't missed when the dashboard is closed.

### 3.3 Multiprocessing for Packet Capture
*   **Current State:** The `main.py` script runs the packet sniffer and the analysis loop in Python threads (`threading.Thread`).
*   **Proposed Change:** Move the packet capture loop to a completely separate background process using Python's `multiprocessing` module.
*   **Why it's better:** Python's Global Interpreter Lock (GIL) prevents threads from executing bytecode simultaneously. Under high network load, the sniffer thread could bottleneck the Flask web server or drop packets. Multiprocessing bypasses the GIL, significantly improving packet throughput and overall stability.
