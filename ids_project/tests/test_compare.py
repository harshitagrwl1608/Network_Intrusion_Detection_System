import os
import sys
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from evaluation.compare import (
    _endpoint_correlations,
    _events_match,
    _norm_ip,
    _norm_port,
    _semantic_family,
    load_suricata_alerts,
    match_alerts_agreement,
)
import tempfile



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

        # String port 443 matches integer port 443
        third = dict(first, dst_port="443")
        self.assertTrue(_events_match(first, third))

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

    def test_ipv6_normalization_in_events_match(self):
        netguard = {
            "rule_name": "DATA_EXFIL",
            "src_ip": " 2001:0db8:0000:0000:0000:0000:0000:0001 ",
            "dst_ip": "2001:db8::2",
            "dst_port": 443,
            "protocol": "TCP",
            "timestamp": 100.0,
        }
        suricata = {
            "signature": "Custom Exfil",
            "src_ip": "2001:db8::1",
            "dst_ip": "2001:0db8:0000:0000:0000:0000:0000:0002",
            "dst_port": 443,
            "protocol": "TCP",
            "timestamp": 101.5,
        }
        self.assertTrue(_events_match(netguard, suricata))

    def test_load_suricata_alerts_resilience(self):
        sample_eve = (
            "\n"  # Leading empty line
            '{"event_type": "stats"}\n'  # Non-alert event
            '{"event_type": "alert", "timestamp": "2023-01-01T12:00:00.123456+0000", "src_ip": "192.168.1.10", "dest_ip": "198.51.100.5", "src_port": 50000, "dest_port": 80, "proto": "TCP", "alert": {"signature": "ET WEB_SERVER SQL Injection Attempt", "category": "Web Application Attack", "severity": 1}, "flow_id": 12345, "app_proto": "http"}\n'
            '{"event_type": "alert", "timestamp": "2023-01-01T12:00:05.500000Z", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": "54321", "dst_port": "443", "proto": "tcp", "alert": null}\n'  # null alert object
            '{"event_type": "alert", "timestamp": 1672574410.0, "src_ip": "172.16.0.5", "dest_ip": "172.16.0.1", "dest_port": 53, "proto": "UDP", "alert": {"signature": "ET MALWARE Suspicious DNS Tunnel"}}\n'
            "   \n"  # Trailing whitespace line
        )
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tf:
            tf.write(sample_eve)
            tf_path = tf.name

        try:
            alerts = load_suricata_alerts(tf_path)
            self.assertEqual(len(alerts), 3)

            # Check alert 1
            self.assertEqual(alerts[0]["src_ip"], "192.168.1.10")
            self.assertEqual(alerts[0]["dst_ip"], "198.51.100.5")
            self.assertEqual(alerts[0]["dst_port"], 80)
            self.assertEqual(alerts[0]["signature"], "ET WEB_SERVER SQL Injection Attempt")
            self.assertEqual(alerts[0]["app_proto"], "http")
            self.assertEqual(alerts[0]["flow_id"], 12345)
            self.assertGreater(alerts[0]["timestamp"], 0.0)

            # Check alert 2 (null alert object and string ports handled safely)
            self.assertEqual(alerts[1]["dst_port"], 443)
            self.assertEqual(alerts[1]["src_port"], 54321)
            self.assertEqual(alerts[1]["signature"], "")

            # Check alert 3 (numeric epoch float timestamp)
            self.assertEqual(alerts[2]["timestamp"], 1672574410.0)
            self.assertEqual(alerts[2]["dst_port"], 53)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_semantic_family_cross_engine_corroboration(self):
        # SQL Injection corroboration
        ng_sqli = {"rule_name": "PAYLOAD_HIT", "detail": "matched DPI signature(s): SQL_INJECTION"}
        sur_sqli = {"signature": "ET WEB_SERVER Possible SQL Injection Attempt"}
        self.assertEqual(_semantic_family(ng_sqli), "sql_injection")
        self.assertEqual(_semantic_family(sur_sqli), "sql_injection")

        # Command injection corroboration
        ng_cmd = {"rule_name": "PAYLOAD_HIT", "detail": "matched DPI signature(s): CMD_INJECTION"}
        sur_cmd = {"signature": "ET EXPLOIT Possible Unix Command Injection"}
        self.assertEqual(_semantic_family(ng_cmd), "command_injection")
        self.assertEqual(_semantic_family(sur_cmd), "command_injection")

        # Log4Shell corroboration
        ng_log4j = {"rule_name": "PAYLOAD_HIT", "detail": "matched DPI signature(s): LOG4SHELL"}
        sur_log4j = {"signature": "ET EXPLOIT Apache Log4j RCE (CVE-2021-44228)"}
        self.assertEqual(_semantic_family(ng_log4j), "log4shell")
        self.assertEqual(_semantic_family(sur_log4j), "log4shell")

        # SYN flood corroboration
        ng_syn = {"rule_name": "SYN_FLOOD"}
        sur_syn = {"signature": "SURICATA TCP SYN flood detected"}
        self.assertEqual(_semantic_family(ng_syn), "syn_flood")
        self.assertEqual(_semantic_family(sur_syn), "syn_flood")

        # DNS tunnel corroboration
        ng_dns = {"rule_name": "DNS_ANOMALY", "detail": "possible DNS_TUNNEL"}
        sur_dns = {"signature": "ET INFO Suspicious DNS Tunneling Technique"}
        self.assertEqual(_semantic_family(ng_dns), "dns_tunnel")
        self.assertEqual(_semantic_family(sur_dns), "dns_tunnel")



if __name__ == "__main__":
    unittest.main()
