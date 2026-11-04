---
name: memory-performance-audit
description: "Audit memory usage, detect stale state buildup, verify OrderedDict LRU eviction, and benchmark garbage collection in NetGuard rules."
---

# Memory and Performance Auditing

This skill guides the profiling and optimization of memory structures, eviction lifecycles, and garbage collection mechanisms in NetGuard IDS.

## When to Use
- Auditing stateful rules for unbounded growth or memory leaks during long-running captures.
- Verifying $O(1)$ LRU eviction logic in `OrderedDict` caches.
- Measuring rule execution overhead and packet throughput.

## Auditing Procedures

### 1. LRU Eviction Verification Pattern
Verify that tracking state bounds itself deterministically:

```python
from collections import OrderedDict

class BoundedState:
    MAX_ENTRIES = 1000

    def __init__(self):
        self._cache = OrderedDict()

    def record(self, key, value):
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = value
        if len(self._cache) > self.MAX_ENTRIES:
            self._cache.popitem(last=False)
```

### 2. Stale State Pruning Pattern
Verify `prune_stale` implementation:

```python
import time

def prune_stale(self, now: float = None) -> None:
    if now is None:
        now = time.time()
    stale_keys = [k for k, v in self._state.items() if now - v > self.TTL or v > now]
    for k in stale_keys:
        self._state.pop(k, None)
```

### 3. Memory Profiling Command
Run continuous replay under memory profiling:

```bash
python3 -m pytest ids_project/tests/test_pcap_replay_and_parsing.py -k "memory or prune"
```

## Guardrails
- LRU bounding must preserve recent active attackers; never evict active malicious hosts in favor of inactive benign IPs.
- Never use direct `del self._dict[k]` during iterations without snapshotting keys or using `.pop(k, None)` to prevent `KeyError` concurrency issues.
