# 1. Provenance & Input Integrity Audit

## Target Dataset & Input Verification
All analyses were performed on official CTU IoT-23 Capture 48-1 dataset artifacts.

| Input File | Size (Bytes) | Exact SHA-256 Digest | Status |
| :--- | :--- | :--- | :--- |
| **PCAP** | 1,222,967,296 | `ac2e41f0d5b2479ce5e1779fbaa6d6b73a6151050d86f04f80a872759034865c` | **VERIFIED** |
| **Zeek Conn Log** | 531,738,215 | `9f69946243df93c199876c0783cb4b5fb188e6d2325c593858f2db8fb5fa847f` | **VERIFIED** |
| **SQLite DB** | 2,224,128 | `6bb5376835c5b25ba721e80fa2547c6cbadb56f38710a8d28650dc8ec6cff042` | **VERIFIED** |
| **Suricata EVE** | 943,092,234 | `47def6819b58635e4f27be0d06dee4470f62f98e278173aa65abfe25da30b762` | **VERIFIED** |

---

## Provenance Resolution
Direct cryptographic hashing of the local file on disk establishes `ac2e41f0d5b2479ce5e1779fbaa6d6b73a6151050d86f04f80a872759034865c` as the sole genuine SHA-256 digest of the 1,222,967,296-byte PCAP.
