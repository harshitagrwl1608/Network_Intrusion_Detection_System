---
name: dataset-deduplication
description: "Detect duplicate network datasets, normalize mirror sources, identify overlapping capture windows, and verify cryptographic provenance."
---

# Dataset Deduplication and Provenance Discipline

This skill provides methodologies for identifying duplicate, mirrored, or overlapping packet captures across external repositories.

## When to Use
- Ingesting newly discovered captures from mirror or secondary hosting sites.
- Checking whether a PCAP is an identical slice or renamed copy of an existing dataset.
- Maintaining rigorous independent counts in the dataset registry.

## Deduplication Methodology

### 1. Multi-Tier Duplicate Detection
1. **Tier 1: Exact File Hash Match**
   - Check SHA-256 against existing records in `docs/autonomy/dataset-registry.md`.
2. **Tier 2: Frame-by-Frame Hash Normalization**
   - Strips packet link-layer headers or capture timestamps to identify converted PCAP/PCAPNG formats of identical traffic.
3. **Tier 3: Flow & IP Hash Fingerprint**
   - Generate unique set of `(src_ip, dst_ip, sport, dport, proto)` 5-tuples. A >98% Jaccard index indicates a derivative slice.

### 2. Verification Procedure in Python
Use Scapy to calculate the unique flow fingerprint:

```python
import hashlib
from scapy.all import rdpcap, IP, TCP, UDP

def compute_pcap_fingerprint(pcap_path):
    packets = rdpcap(pcap_path)
    flows = set()
    for p in packets:
        if IP in p:
            proto = p.proto
            sport = p[TCP].sport if TCP in p else (p[UDP].sport if UDP in p else 0)
            dport = p[TCP].dport if TCP in p else (p[UDP].dport if UDP in p else 0)
            flows.add((p[IP].src, p[IP].dst, sport, dport, proto))
    
    sorted_flows = sorted(list(flows))
    digest = hashlib.sha256(str(sorted_flows).encode()).hexdigest()
    return len(packets), len(flows), digest
```

## Guardrails
- If a dataset is confirmed as an exact duplicate or renamed mirror, log the alias in `docs/autonomy/dataset-registry.md` but exclude it from the independent dataset count.
