# 5. False Positive & Unassessed Alert Analysis

## Empirical False Positive Audit
- Total False Positives on explicitly labeled Benign traffic: **5**.
- Benign flows in ground truth: `3,734` (mainly ICMP destination unreachable and ARP/NTP baseline).
- None of the benign baseline flows triggered port scan or brute force alerts. NetGuard correctly suppressed benign traffic.

## Unassessed Traffic Audit
- Alerts classified as Unassessed: `0`.
- These occur only when detection windows capture a mixture of background packets without definitive malware labeling.
