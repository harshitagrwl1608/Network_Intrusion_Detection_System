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

## Coverage matrix

| Existing rule family | Required telemetry | CTU-13 Scenario 1 | Suricata comparison | Result / limitation |
|---|---|---|---|---|
| `SLOW_PORT_SCAN` | TCP SYNs, source and destination cardinality, timestamps | Applicable | Existing ET/package rules loaded; final cross-engine report is recorded after replay completion | Real botnet traffic generated repeated horizontal TCP scan alerts; Suricata may classify the same traffic under protocol or scan signatures with different aggregation |
| `UDP_SCAN`, `UDP_FLOOD` | UDP destinations, timestamps and packet counts | Applicable | Same PCAP processed offline by Suricata | Rule output is engine-specific and must be compared by endpoint/time windows, not assumed ground truth |
| `DNS_ANOMALY` | DNS queries, labels, timestamps | Applicable | Same PCAP processed offline by Suricata | CTU traffic produced frequency/DGA candidates; DNS parser and Suricata protocol visibility differ |
| `PAYLOAD_HIT` | Reassembled application payload | Applicable for observed cleartext payloads | Same PCAP processed offline by Suricata | Existing signatures and protocol parsers differ; no rule is added because of this comparison |
| `BRUTE_FORCE` | Repeated connection attempts to an authentication service | Applicable | Same PCAP processed offline by Suricata | Authentication outcome is not visible; results are rate-signal evidence only |
| Endpoint detections | EVTX/Sysmon/Splunk fields | Not applicable | Suricata not applicable | No endpoint rules or Sigma/SPL files are present in this repository; absence of a test is a telemetry limitation, not a detection result |

## Reproduction commands

```text
# Suricata 8.0.7, packaged existing ruleset in /tmp
LD_LIBRARY_PATH=/tmp/netguard-suricata-root/usr/lib/x86_64-linux-gnu \
  /tmp/netguard-suricata-root/usr/bin/suricata \
  -c /tmp/netguard-suricata.yaml \
  -S /tmp/netguard-suricata-data/rules/suricata.rules \
  -r /tmp/netguard-external-datasets/ctu13-b42/botnet-capture-20110810-neris.pcap \
  -l /tmp/netguard-suricata-ctu42 --runmode autofp

# NetGuard existing engine, isolated database
python3 ids_project/evaluation/replay.py \
  --pcap /tmp/netguard-external-datasets/ctu13-b42/botnet-capture-20110810-neris.pcap \
  --db /tmp/netguard-ng-ctu42.db \
  --arp-table /tmp/netguard-ng-ctu42-arp.json \
  --blocklist ids_project/data/test_blocklist.txt
```

The final alert counts and agreement/disagreement summary are appended only
after the replay process exits successfully. Suricata is a comparison source,
not ground truth; labels and packet evidence remain necessary to distinguish
coverage differences from detection failures.

## Completed CTU-13 Scenario 1 comparison

The full selected PCAP replay completed successfully (`323154/323154` packets;
NetGuard alert writer reported `alerts_dropped=0`). Results for the exact
download hash above:

| Engine | Alerts | Main result |
|---|---:|---|
| NetGuard existing rules | 464 | `UDP_SCAN` 184, `SLOW_PORT_SCAN` 98, `DNS_ANOMALY` 81, `UDP_FLOOD` 79, `PAYLOAD_HIT` 20, `BRUTE_FORCE` 2 |
| Suricata 8.0.7 existing packaged/ET rules | 3,165 | 2,632 invalid TCP checksum, 199 excessive SYN variation, 181 excessive HTTP headers, 144 one-direction app-layer protocol, 4 RST injection, 2 invalid ICMP checksum, 2 invalid HTTP chunk length, 1 unmatched HTTP response |

The existing agreement matcher found 0 exact matches, 464 NetGuard-only
events and 3,165 Suricata-only events. This is a comparison result, not a
precision or recall claim: Suricata's alerts are dominated by packet-integrity
and stream/parser diagnostics, while the NetGuard alerts are behavioral
aggregations. The CTU-13 scenario is botnet-only, so it supplies no benign
counterpart for false-positive estimation. The observed data supports keeping
the existing rules unchanged in this cycle; no demonstrated condition-level
fix was isolated, and no new detection rule or Suricata signature was added.

For the repository's local captures, the same procedure produced 38 NetGuard
attack alerts versus 0 Suricata alerts, and 0 NetGuard benign alerts versus 2
Suricata stream diagnostics. Those synthetic/local results are retained as
regression evidence but are not treated as real-world validation.
