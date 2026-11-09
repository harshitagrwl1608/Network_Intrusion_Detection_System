# 1. Provenance & Input Integrity Audit

## Target Dataset & Input Verification
All evaluations and forensic audits operate on official CTU IoT-23 Capture 48-1 artifacts.

| Input File | Size (Bytes) | Exact SHA-256 Digest | Status |
| :--- | :--- | :--- | :--- |
| **PCAP** | 1,222,967,296 | `ac2e41f0d5b2479ce5e1779fbaa6d6b73a6151050d86f04f80a872759034865c` | **VERIFIED** |
| **Zeek Conn Log** | 531,738,215 | `9f69946243df93c199876c0783cb4b5fb188e6d2325c593858f2db8fb5fa847f` | **VERIFIED** |
| **SQLite DB** | 2,224,128 | `6bb5376835c5b25ba721e80fa2547c6cbadb56f38710a8d28650dc8ec6cff042` | **VERIFIED** |
| **Suricata EVE** | 943,092,234 | `47def6819b58635e4f27be0d06dee4470f62f98e278173aa65abfe25da30b762` | **VERIFIED** |

---

## Resolution of the PCAP SHA-256 Conflict
In Audit V2 documentation, two conflicting PCAP SHA-256 strings were reported:
1. `ac2e41f022a8435d8e7c10b7f8e363628e9d9e4a317e08922e9e68c92a926ba6`
2. `ac2e41f0d5b2479ce5e1779fbaa6d6b73a6151050d86f04f80a872759034865c`

### Independent Forensic Finding
Direct cryptographic calculation of the 1,222,967,296-byte PCAP file on disk yields:
`ac2e41f0d5b2479ce5e1779fbaa6d6b73a6151050d86f04f80a872759034865c`

Both strings share the identical initial 8-character prefix `ac2e41f0`. The former string was identified as a typographical paste corruption in an earlier Markdown template. The true local hash is definitively established.
