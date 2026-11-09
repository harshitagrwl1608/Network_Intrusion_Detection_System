# 1. Dataset Provenance — CTU IoT-23 v2 / Capture 48-1 (Mirai)

## Dataset Metadata
- **Dataset Identification**: CTU-IoT-Malware-Capture-48-1
- **Official Publisher**: Stratosphere Laboratory, Czech Technical University in Prague (CTU)
- **Publication Directory**: `https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-48-1/`
- **Device Under Test**: Raspberry Pi (ARM architecture)
- **Infected Host IP**: `192.168.1.200`
- **Malware Family**: Mirai (Linux botnet scanning Telnet port 23)

## Cryptographic Hashes & File Manifest
| File Name | Size | SHA-256 Digest | Provenance |
| :--- | :--- | :--- | :--- |
| `2019-02-28-19-15-13-192.168.1.200.pcap` | 1.19 GB | `ac2e41f0d5b2479ce5e1779fbaa6d6b73a6151050d86f04f80a872759034865c` | Official CTU IoT-23 v2 Archive |
| `2019-02-28-19-15-13-192.168.1.200-zeek-conn-log.labeled` | 507.1 MB | `9f69946243df93c199876c0783cb4b5fb188e6d2325c593858f2db8fb5fa847f` | Expert Manually Labeled via NetflowLabeler |
| `2019-02-28-19-15-13-192.168.1.200-labels.config` | 1,585 B | `ca8a089481ee446de3518d2711ee7b8d515c86400df31ac2be7c13008426f479` | NetflowLabeler Configuration |
| `README.md` | 2,653 B | `5eb6dac6ba639050eeb85dd5ecdb4490863a4915af630386ccc3683906d4d2b1` | Official Scenario Description |

## Packet & Time Characteristics
- **Total Packets**: `13,565,553` packets
- **Capture Duration**: `9.77` hours (35,180 seconds)
- **Time Order**: Strictly ascending time order verified (`Strict time order: True`)
- **Link Layer**: Ethernet (10/100 Mbps)
