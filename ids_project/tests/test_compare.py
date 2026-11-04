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

        # XSS corroboration
        ng_xss = {"rule_name": "PAYLOAD_HIT", "detail": "matched DPI signature(s): XSS"}
        sur_xss = {"signature": "ET WEB_CLIENT Cross Site Scripting Attempt"}
        self.assertEqual(_semantic_family(ng_xss), "xss")
        self.assertEqual(_semantic_family(sur_xss), "xss")

        # SSRF corroboration
        ng_ssrf = {"rule_name": "PAYLOAD_HIT", "detail": "matched DPI signature(s): SSRF"}
        sur_ssrf = {"signature": "ET SCAN Suspicious AWS Cloud Metadata Access SSRF"}
        self.assertEqual(_semantic_family(ng_ssrf), "ssrf")
        self.assertEqual(_semantic_family(sur_ssrf), "ssrf")

        # Brute-force corroboration
        ng_bf = {"rule_name": "BRUTE_FORCE"}
        sur_bf = {"signature": "ET SCAN Potential SSH BruteForce Attack"}
        self.assertEqual(_semantic_family(ng_bf), "brute_force")
        self.assertEqual(_semantic_family(sur_bf), "brute_force")

        # TCP Zero-Window corroboration
        ng_zw = {"rule_name": "TCP_ZERO_WINDOW"}
        sur_zw = {"signature": "SURICATA TCP Zero Window advertisement flood"}
        self.assertEqual(_semantic_family(ng_zw), "tcp_zero_window")
        self.assertEqual(_semantic_family(sur_zw), "tcp_zero_window")

        # ICS / SCADA Triconex TriStation corroboration
        ng_ics = {"rule_name": "PAYLOAD_HIT", "detail": "matched DPI signature(s): ICS_TRISTATION_EXPLOIT"}
        sur_ics = {"signature": "ET INDUSTRIAL Schneider Electric Triconex MP communication"}
        self.assertEqual(_semantic_family(ng_ics), "ics_scada_exploit")
        self.assertEqual(_semantic_family(sur_ics), "ics_scada_exploit")

        # ICMP Tunnel corroboration
        ng_icmp = {"rule_name": "ICMP_TUNNEL", "detail": "oversized high-entropy ICMP payload"}
        sur_icmp = {"signature": "ET INFO Suspicious ICMP Packet Size / Tunneling"}
        self.assertEqual(_semantic_family(ng_icmp), "icmp_tunnel")
        self.assertEqual(_semantic_family(sur_icmp), "icmp_tunnel")

        # TCP Stealth Scan / Flag Anomaly corroboration
        ng_flags = {"rule_name": "TCP_FLAG_ANOMALY", "detail": "SYN+FIN flags set simultaneously"}
        sur_flags = {"signature": "ET SCAN Nmap OS Detection Probe (SYN+FIN)"}
        self.assertEqual(_semantic_family(ng_flags), "tcp_stealth_scan")
        self.assertEqual(_semantic_family(sur_flags), "tcp_stealth_scan")

        # DNS DGA / Anomaly corroboration
        ng_dga = {"rule_name": "DNS_ANOMALY", "detail": "possible DNS_DGA high entropy"}
        sur_dga = {"signature": "ET MALWARE Suspicious DNS DGA High Entropy Query"}
        self.assertEqual(_semantic_family(ng_dga), "dns_dga")
        self.assertEqual(_semantic_family(sur_dga), "dns_dga")

        # UDP flood corroboration
        ng_udp = {"rule_name": "UDP_FLOOD"}
        sur_udp = {"signature": "ET DOS UDP Flood Inbound Possible DDoS"}
        self.assertEqual(_semantic_family(ng_udp), "udp_flood")
        self.assertEqual(_semantic_family(sur_udp), "udp_flood")

        # Data exfiltration corroboration
        ng_exfil = {"rule_name": "DATA_EXFIL"}
        sur_exfil = {"signature": "ET POLICY Outbound Data Exfiltration Detected"}
        self.assertEqual(_semantic_family(ng_exfil), "data_exfil")
        self.assertEqual(_semantic_family(sur_exfil), "data_exfil")

        # Non-DNS on port 53 corroboration
        ng_nondns = {"rule_name": "NON_DNS_TRAFFIC_ON_DNS_PORT"}
        sur_nondns = {"signature": "ET INFO Non-DNS traffic on DNS port 53"}
        self.assertEqual(_semantic_family(ng_nondns), "non_dns_on_dns_port")
        self.assertEqual(_semantic_family(sur_nondns), "non_dns_on_dns_port")

        # Blocklist / Threat Intel corroboration
        ng_bl = {"rule_name": "BLOCKLIST"}
        sur_bl = {"signature": "ET DROP Spamhaus DROP Listed Traffic"}
        self.assertEqual(_semantic_family(ng_bl), "blocklist_threat_intel")
        self.assertEqual(_semantic_family(sur_bl), "blocklist_threat_intel")

        # ARP spoofing corroboration
        ng_arp = {"rule_name": "ARP_SPOOF"}
        sur_arp = {"signature": "ET SCAN Suspicious ARP Spoofing Probe"}
        self.assertEqual(_semantic_family(ng_arp), "arp_spoof")
        self.assertEqual(_semantic_family(sur_arp), "arp_spoof")

    def test_icmp_port_none_and_zero_matching(self):
        # ICMP events with port None vs 0 should match because ICMP has no ports
        ng_icmp = {
            "rule_name": "ICMP_TUNNEL",
            "src_ip": "192.168.0.35",
            "dst_ip": "192.168.1.1",
            "dst_port": None,
            "protocol": "ICMP",
            "timestamp": 100.0,
        }
        sur_icmp = {
            "signature": "ET INFO Suspicious ICMP",
            "src_ip": "192.168.0.35",
            "dst_ip": "192.168.1.1",
            "dst_port": 0,
            "protocol": "ICMP",
            "timestamp": 101.0,
        }
        self.assertTrue(_events_match(ng_icmp, sur_icmp))

    def test_tcp_stealth_scan_cross_engine_matching(self):
        ng_scan = {
            "rule_name": "TCP_FLAG_ANOMALY",
            "src_ip": "192.168.100.103",
            "dst_ip": "192.168.100.101",
            "dst_port": 139,
            "protocol": "TCP",
            "timestamp": 200.0,
        }
        sur_scan = {
            "signature": "ET SCAN Nmap OS Detection Probe",
            "src_ip": "192.168.100.103",
            "dst_ip": "192.168.100.101",
            "dst_port": 445,
            "protocol": "TCP",
            "timestamp": 202.0,
        }
        # In stealth scans, destination ports can vary across probe packets
        self.assertTrue(_events_match(ng_scan, sur_scan))

    def test_load_suricata_alerts_canonicalizes_ipv6(self):
        sample_eve = (
            '{"event_type": "alert", "timestamp": "2023-01-01T12:00:00Z", '
            '"src_ip": " 2001:0db8:0000:0000:0000:0000:0000:0001 ", '
            '"dest_ip": "2001:0db8:0000:0000:0000:0000:0000:0002", '
            '"src_port": 50000, "dest_port": 80, "proto": "TCP", '
            '"alert": {"signature": "ET SCAN IPv6 Recon"}}\n'
        )
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tf:
            tf.write(sample_eve)
            tf_path = tf.name

        try:
            alerts = load_suricata_alerts(tf_path)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["src_ip"], "2001:db8::1")
            self.assertEqual(alerts[0]["dst_ip"], "2001:db8::2")
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)


if __name__ == "__main__":
    unittest.main()

