# External Dataset Inventory and Coverage

This inventory records public telemetry selected for testing existing NetGuard
detections. It does not define new detections. Hashes identify the exact files
used for reproducibility; temporary downloaded data is kept outside the
repository under `/tmp/netguard-external-datasets`.

## Approved-source inventory

| Dataset | Source and version | Format / telemetry | License / use note | Selection status |
|---|---|---|---|---|
| CTU-13 Scenario 1 / CTU-Malware-Capture-Botnet-42 (Neris) | [Stratosphere CTU-13 scenario page](https://www.stratosphereips.org/datasets-ctu13/), scenario directory `https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/`; retrieved 2026-11-03 | 56 MB botnet-only PCAP, 323,154 packets; network payload and protocol metadata | Dataset overview states CC-BY; scenario page permits use with attribution and warns the executable is malware. Only the PCAP was downloaded and analyzed offline; the executable was not downloaded or executed. | Selected as a manageable network subset because it exercises existing scan, DNS, flood, payload and brute-force rules. SHA-256: `b89cd5931f62d87ceff266568c97c6e36e56dd0330813cacadbc14a6c5576a36` |
| EVTX-ATTACK-SAMPLES | [Project repository](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | EVTX Windows event logs | Repository identifies GPL licensing; endpoint telemetry is currently outside this packet-oriented engine's input path. | Discovered; not downloaded in this network-focused cycle |
| OTRF Security Datasets | [Project repository](https://github.com/OTRF/Security-Datasets) | Mixed endpoint and security telemetry | Repository documents GPL-3.0; endpoint field compatibility is not present in the current engine. | Discovered; not downloaded in this network-focused cycle |
| Splunk BOTS v2 | [Project repository](https://github.com/splunk/botsv2) | Splunk/SIEM telemetry | Dataset-specific terms require review before ingestion; no SPL implementation is present in this repository. | Discovered; not downloaded in this network-focused cycle |
| Atomic Red Team | [Project repository](https://github.com/redcanaryco/atomic-red-team) | Controlled attack simulations, not a passive dataset | Tests require an isolated authorized host; no tests were executed. | Discovered; execution deferred because this cycle uses passive external telemetry |

For the network-PCAP stratum, the candidate set was the thirteen CTU-13
botnet scenarios 42 through 54. A reproducible seeded selection was used:
`random.Random(2).choice(range(42, 55))` selected scenario 42. This is one
sample from the stratum, not comprehensive CTU-13 coverage; later cycles must
use a different seed or explicitly justify a repeat.

## Rule-by-rule coverage

The engine has 19 existing Python rules. This capture fired six of them in the
original baseline. A zero means the rule did not fire in this selected capture;
it does not show that the rule is ineffective. The rule schema has no MITRE
ATT&CK identifiers, so this review does not infer technique mappings from rule
names.

| Existing rule | Telemetry needed | Baseline alerts | Relevant Suricata evidence |
|---|---|---:|---|
| `BLOCKLIST` | IP addresses and configured indicators | 0 | No matching indicator alert |
| `TCP_FLAG_ANOMALY` | TCP flags and packet direction | 0 | Parser and checksum diagnostics are not flag-anomaly equivalents |
| `PORT_SCAN` | TCP SYNs, ports, hosts and timestamps | 0 | No NetGuard alert to compare |
| `UDP_SCAN` | UDP destinations and timestamps | 184 | No behavior alert; all 184 alert windows independently align with at least the reported DNS destination cardinality in EVE |
| `UDP_FLOOD` | UDP packet counts by destination and time | 79 | No behavior alert; EVE records 50–52 DNS requests per alert window, with 25–47 distinct query identities |
| `TCP_STEALTH_SCAN` | TCP flags, destinations and timestamps | 0 | No NetGuard alert to compare |
| `SYN_FLOOD` | TCP SYN rates by destination | 0 | No NetGuard alert to compare |
| `DISTRIBUTED_SYN_FLOOD` | TCP SYN rates grouped across sources | 0 | No NetGuard alert to compare |
| `ICMP_SWEEP` | ICMP requests, hosts and timestamps | 0 | No NetGuard alert to compare |
| `ICMP_FLOOD` | ICMP packet rates | 0 | No NetGuard alert to compare |
| `ARP_SPOOF` | ARP sender IP/MAC pairs and time | 0 | No NetGuard alert to compare |
| `PAYLOAD_HIT` | Application payload and bounded TCP reassembly | 20 | Suricata's emitted parser/integrity alerts do not match these content signatures |
| `DNS_ANOMALY` | DNS labels, queries and timestamps | 81 | No behavior alert; EVE contains at least the reported 20 unique requests for all 76 frequency windows and the queried name for all 5 DGA alerts |
| `BRUTE_FORCE` | TCP attempts to configured authentication ports | 2 | No behavior alert; packet review found 20 unique initial SYNs per alert window and no FTP authentication payload or SYN-ACK |
| `SLOW_PORT_SCAN` | TCP SYNs, target cardinality and 120-second windows | 98 | 199 excessive-SYN alerts; 11 alerts shared source/destination/port with NetGuard scans (4 distinct endpoint triples), and 1 pair was within 120 seconds. This is partial behavioral overlap, not ground truth. |
| `DATA_EXFIL` | Directional byte volume and time | 0 | No NetGuard alert to compare |
| `TLS_ANOMALY` | TLS ClientHello and SNI fields | 0 | No NetGuard alert to compare |
| `CLEAR_HTTP_ON_TLS_PORT` | HTTP payload and service port | 0 | No NetGuard alert to compare |
| `TCP_ZERO_WINDOW` | TCP window advertisements by flow and time | 0 | No NetGuard alert to compare |

Suricata also recorded 84,570 DNS events and 17,357 flow events, which confirm
protocol telemetry was present for DNS and flow-based review. Rule-specific
event and packet checks are summarized below; they compare only behaviors
covered by the 19 existing NetGuard rules. The 2,632
invalid-checksum alerts and other parser/integrity alerts are not treated as
missed NetGuard behavioral detections.

## Reproduction commands

```text
# Suricata 8.0.7, packaged existing ruleset in /tmp
LD_LIBRARY_PATH=/tmp/netguard-suricata-root/usr/lib/x86_64-linux-gnu \
  /tmp/netguard-suricata-root/usr/bin/suricata \
  -c /tmp/netguard-suricata.yaml \
  -S /tmp/netguard-suricata-data/rules/suricata.rules \
  -r /tmp/netguard-external-datasets/ctu13-b42/botnet-capture-20110810-neris.pcap \
  -l /tmp/netguard-suricata-ctu42 --runmode autofp

# NetGuard existing engine, isolated database (original baseline)
python3 ids_project/evaluation/replay.py \
  --pcap /tmp/netguard-external-datasets/ctu13-b42/botnet-capture-20110810-neris.pcap \
  --db /tmp/netguard-ng-ctu42.db \
  --arp-table /tmp/netguard-ng-ctu42-arp.json \
  --blocklist ids_project/data/test_blocklist.txt

# Final improved existing rules, isolated database
python3 ids_project/evaluation/replay.py \
  --pcap /tmp/netguard-external-datasets/ctu13-b42/botnet-capture-20110810-neris.pcap \
  --db /tmp/netguard-ng-ctu42-settled.db \
  --arp-table /tmp/netguard-ng-ctu42-settled-arp.json \
  --blocklist ids_project/data/test_blocklist.txt
```

The final alert counts and agreement/disagreement summary are appended only
after the replay process exits successfully. Suricata is a comparison source,
not ground truth; labels and packet evidence remain necessary to distinguish
coverage differences from detection failures.

## Completed CTU-13 Scenario 1 comparison

Both NetGuard counts below use the same PCAP hash, isolated blocklist and fresh
ARP table. The final replay processed `323154/323154` packets, persisted 444
alerts, and reported `alerts_dropped=0`.

| Existing NetGuard rules | Alerts | Per-rule counts |
|---|---:|---|
| Original baseline | 464 | `UDP_SCAN` 184, `SLOW_PORT_SCAN` 98, `DNS_ANOMALY` 81, `UDP_FLOOD` 79, `PAYLOAD_HIT` 20, `BRUTE_FORCE` 2 |
| Improved candidate (`PAYLOAD_HIT` v1.17) | 444 | `UDP_SCAN` 184, `SLOW_PORT_SCAN` 98, `DNS_ANOMALY` 81, `UDP_FLOOD` 79, `BRUTE_FORCE` 2, `PAYLOAD_HIT` 0 |
| Suricata 8.0.7 existing packaged/ET rules | 3,165 | 2,632 invalid TCP checksum, 199 excessive SYN variation, 181 excessive HTTP headers, 144 one-direction app-layer protocol, 4 RST injection, 2 invalid ICMP checksum, 2 invalid HTTP chunk length, 1 unmatched HTTP response |

The improvement is limited to the existing `PAYLOAD_HIT` rule. Its 20 baseline
alerts comprised 18 generic command-substitution matches, 1 SSRF match on a
`file://` URI embedded in SMTP narrative, and 1 SQL match on `#` within binary
SMTP content. Packet review showed the command-substitution matches did not
contain a recognizable command; the URI was not in a fetch parameter; and the
SQL marker was followed by an embedded line break inside a binary segment.
The revised conditions require a known command token inside `$()`/backticks,
require non-HTTP SSRF schemes to appear in a URL/fetch context, and require
SQL `#` comments to follow a SQL-like value or whitespace. Tests retain
positive cases for command substitution, URL-parameter SSRF, and MySQL comments
with and without a line ending. The replay removed all 20 observed payload
alerts while leaving each of the other five firing rules at its baseline
count. No new rule or Suricata signature was added.

Suricata was used as a targeted cross-check, not as a wider alert-count target.
Of its 199 excessive-SYN alerts, 11 shared source, destination and destination
port with NetGuard `SLOW_PORT_SCAN` alerts (4 distinct endpoint triples); 1
alert pair fell within the NetGuard 120-second window. This indicates partial
behavioral overlap, not ground truth.

For the 76 `DNS_FREQ` alerts, each NetGuard window had at least 20 distinct
Suricata DNS request identities matching the source and parent domain (20–23
identities per window). Each of the 5 `DNS_DGA` alerts had its exact queried
name in Suricata DNS requests. For all 184 `UDP_SCAN` windows, the Suricata DNS
request records from the same source and time window covered at least the
distinct destination count reported by NetGuard (15–34 destinations, versus
15–30 reported). For all 79 `UDP_FLOOD` windows, Suricata recorded 50–52 DNS
requests, while deduplication by source, resolver, DNS transaction ID, type
and name yielded 25–47 distinct query identities (median 29). These checks
support that the rules fired on DNS activity in this capture; they do not
establish whether the activity was malicious or benign.

Packet review of both `BRUTE_FORCE` windows found 20 distinct initial SYN
attempts, no SYN-ACKs, and no FTP `USER`/`PASS` payload. The rule already
describes this as a SYN-rate signal because authentication outcome is not
observed. Repeated UDP datagrams contribute to packet rate by design, so the
lower count of distinct DNS query identities in some `UDP_FLOOD` windows is
not sufficient evidence to suppress repeated packets or reduce coverage.
Suricata emitted no corresponding DNS-frequency/DGA, UDP-scan/flood,
brute-force, or payload-content behavior alert in this ruleset. Its checksum
and parser alerts are not counted as NetGuard misses. The botnet-only sample
has no benign companion, so these alignments do not provide false-positive
or precision estimates.

The repository's generic `compare.py` matcher reports zero exact matches for
this run. It does not map the packaged Suricata excessive-SYN signature to the
NetGuard scan family, so that zero is not a coverage score; the rule-specific
endpoint/time review above is the relevant comparison. The CTU-13 scenario is
botnet-only and has no benign companion, so it cannot estimate the false
positive rate. The report makes no precision or recall claim.

For the repository's local captures, the same procedure produced 38 NetGuard
attack alerts versus 0 Suricata alerts, and 0 NetGuard benign alerts versus 2
Suricata stream diagnostics. Those synthetic/local results are retained as
regression evidence but are not treated as real-world validation.
