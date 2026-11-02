import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from evaluation.compare import _endpoint_correlations, _events_match, match_alerts_agreement


class TestComparisonMatching(unittest.TestCase):
    def test_threshold_scan_matches_across_triggering_ports(self):
        netguard = {
            "rule_name": "PORT_SCAN", "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1", "dst_port": 3306,
            "protocol": "TCP", "timestamp": 100.0,
        }
        suricata = {
            "signature": "LOCAL TCP SYN scan-like burst >=15 packets/10s",
            "src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
            "dst_port": 16018, "protocol": "TCP", "timestamp": 103.0,
        }
        self.assertTrue(_events_match(netguard, suricata))

    def test_slow_scan_uses_long_window_but_requires_same_hosts(self):
        netguard = {
            "rule_name": "SLOW_PORT_SCAN", "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1", "dst_port": 22,
            "protocol": "TCP", "timestamp": 100.0,
        }
        suricata = {
            "signature": "LOCAL slow TCP SYN burst >=30 packets/120s",
            "src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
            "dst_port": 443, "protocol": "TCP", "timestamp": 210.0,
        }
        self.assertTrue(_events_match(netguard, suricata))
        suricata["dst_ip"] = "198.51.100.9"
        self.assertFalse(_events_match(netguard, suricata))

    def test_unrelated_alerts_keep_exact_destination_port_matching(self):
        first = {
            "rule_name": "DATA_EXFIL", "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1", "dst_port": 443,
            "protocol": "TCP", "timestamp": 100.0,
        }
        second = dict(first, dst_port=80)
        self.assertFalse(_events_match(first, second))

    def test_http_parser_overlap_is_reported_separately_from_exact_match(self):
        netguard = [{
            "rule_name": "CLEAR_HTTP_ON_TLS_PORT", "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1", "dst_port": 443, "protocol": "TCP",
            "timestamp": 100.0,
        }]
        suricata = [{
            "signature": "SURICATA HTTP request missing protocol",
            "src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
            "dst_port": 443, "protocol": "TCP", "timestamp": 900.0,
        }]
        result = match_alerts_agreement(netguard, suricata)
        self.assertEqual(len(result["both"]), 0)
        self.assertEqual(len(result["endpoint_correlations"]), 1)
        row = result["endpoint_correlations"][0]
        self.assertEqual(row["family"], "cleartext_http_on_tls_port")
        self.assertEqual(row["netguard_events"], 1)
        self.assertEqual(row["suricata_events"], 1)

    def test_http_parser_overlap_requires_same_service_endpoint(self):
        netguard = [{
            "rule_name": "CLEAR_HTTP_ON_TLS_PORT", "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1", "dst_port": 443, "protocol": "TCP",
        }]
        suricata = [{
            "signature": "SURICATA HTTP request missing protocol",
            "src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
            "dst_port": 80, "protocol": "TCP",
        }]
        self.assertEqual(_endpoint_correlations(netguard, suricata), [])


if __name__ == "__main__":
    unittest.main()
