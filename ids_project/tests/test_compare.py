import json
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
    correlate_netguard_zeek,
    load_suricata_alerts,
    load_zeek_connections,
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

    def test_get_conn_does_not_mutate_global_config(self):
        import config
        from evaluation.compare import _get_conn
        orig_sqlite = config.SQLITE_PATH
        with tempfile.NamedTemporaryFile(suffix=".db") as tf:
            conn = _get_conn(tf.name)
            try:
                self.assertIsNotNone(conn)
                self.assertEqual(config.SQLITE_PATH, orig_sqlite, "_get_conn must not mutate global config.SQLITE_PATH")
            finally:
                conn.close()

    def test_compare_labels_bidirectional_and_partial(self):
        import io
        import sqlite3
        from evaluation.compare import run_ground_truth
        from storage.db import init_db

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as db_f, \
             tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as lbl_f:
            db_path = db_f.name
            lbl_path = lbl_f.name

            # Write scenario with reverse endpoints to test bidirectional matching
            lbl_f.write(
                "scenario_id,expected_rule,src_ip,dst_ip,dst_port,protocol,coverage,description\n"
                "sc-1,SYN_FLOOD,10.0.0.1,10.0.0.2,80,TCP,partial,Test reverse matching\n"
            )

        try:
            conn = sqlite3.connect(db_path)
            init_db(conn)
            cur = conn.cursor()
            # Insert alert where src/dst are reversed relative to label
            cur.execute(
                "INSERT INTO alerts (rule_name, rule_version, src_ip, dst_ip, src_port, dst_port, protocol, detail, severity, confidence, timestamp) "
                "VALUES ('SYN_FLOOD', '1.0', '10.0.0.2', '10.0.0.1', 80, 54321, 'TCP', 'Test detail', 'HIGH', 1.0, 100.0)"
            )
            # Insert an extra alert that was not in labels
            cur.execute(
                "INSERT INTO alerts (rule_name, rule_version, src_ip, dst_ip, src_port, dst_port, protocol, detail, severity, confidence, timestamp) "
                "VALUES ('PORT_SCAN', '1.0', '192.168.1.1', '192.168.1.2', 22, 54322, 'TCP', 'Scan detail', 'MEDIUM', 0.8, 105.0)"
            )
            conn.commit()
            conn.close()

            # Capture stdout from run_ground_truth
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                run_ground_truth(lbl_path, db_path)
                out = sys.stdout.getvalue()
            finally:
                sys.stdout = old_stdout

            self.assertIn("Detected  (TP — scenario matched):       1", out)
            self.assertIn("Unassessed (partial label coverage):     1", out)
            self.assertIn("Precision:   N/A", out)
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
            if os.path.exists(lbl_path):
                os.remove(lbl_path)


    def test_semantic_family_irc_and_fragment(self):
        """Verify _semantic_family maps IRC_C2_BEACONING and IP_FRAGMENT_ANOMALY correctly."""
        irc_ng = {"rule_name": "IRC_C2_BEACONING", "src_ip": "10.0.0.1", "dst_ip": "1.2.3.4"}
        self.assertEqual(_semantic_family(irc_ng), "botnet_c2")

        sur_irc = {"signature": "ET CHAT IRC PONG response", "src_ip": "10.0.0.1"}
        self.assertEqual(_semantic_family(sur_irc), "botnet_c2")

        frag_ng = {"rule_name": "IP_FRAGMENT_ANOMALY", "src_ip": "10.0.0.1"}
        self.assertEqual(_semantic_family(frag_ng), "ip_fragment_anomaly")

        sur_frag = {"signature": "SURICATA IP fragment overlap attack detected"}
        self.assertEqual(_semantic_family(sur_frag), "ip_fragment_anomaly")

    def test_load_zeek_connections_tsv(self):
        sample_zeek_tsv = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tlabel\n"
            "1545403816.962094\tCrDn63WjJEmrWGjqf\t192.168.1.195\t41040\t185.244.25.235\t80\ttcp\t-\t3.139211\t0\t0\tS0\tS\t3\tBenign\n"
            "1545403848.981338\tCDrkrSobGYxHhYfth\t192.168.1.195\t41040\t185.244.25.235\t80\ttcp\thttp\t1.477656\t149\t128252\tSF\tShADadttcfF\t94\tBenign\n"
            "#close\t2019-03-15-14-50-49\n"
        )
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".log") as tf:
            tf.write(sample_zeek_tsv)
            tf_path = tf.name

        try:
            conns = load_zeek_connections(tf_path)
            self.assertEqual(len(conns), 2)
            # Row 1: S0 scan attempt
            self.assertEqual(conns[0]["src_ip"], "192.168.1.195")
            self.assertEqual(conns[0]["dst_ip"], "185.244.25.235")
            self.assertEqual(conns[0]["dst_port"], 80)
            self.assertEqual(conns[0]["conn_state"], "S0")
            self.assertEqual(conns[0]["history"], "S")
            self.assertEqual(conns[0]["orig_pkts"], 3)
            # Row 2: SF established HTTP
            self.assertEqual(conns[1]["conn_state"], "SF")
            self.assertEqual(conns[1]["service"], "http")
            self.assertEqual(conns[1]["orig_bytes"], 149)
            self.assertEqual(conns[1]["resp_bytes"], 128252)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_load_zeek_connections_json(self):
        sample_json = (
            '{"ts": 1545403816.962, "id.orig_h": "192.168.1.195", "id.orig_p": 41040, "id.resp_h": "185.244.25.235", "id.resp_p": 80, "proto": "tcp", "conn_state": "S0", "history": "S"}\n'
            '{"ts": 1545403820.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 443, "proto": "tcp", "conn_state": "SF"}\n'
        )
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".log") as tf:
            tf.write(sample_json)
            tf_path = tf.name

        try:
            conns = load_zeek_connections(tf_path)
            self.assertEqual(len(conns), 2)
            self.assertEqual(conns[0]["src_ip"], "192.168.1.195")
            self.assertEqual(conns[0]["conn_state"], "S0")
            self.assertEqual(conns[1]["src_ip"], "10.0.0.1")
            self.assertEqual(conns[1]["dst_port"], 443)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_correlate_netguard_zeek_scan_s0(self):
        alerts = [{
            "rule_name": "PORT_SCAN",
            "src_ip": "192.168.1.195",
            "dst_ip": "185.244.25.235",
            "dst_port": 80,
            "protocol": "TCP",
            "timestamp": 1545403816.0,
        }]
        zeek_conns = [{
            "timestamp": 1545403816.96,
            "src_ip": "192.168.1.195",
            "dst_ip": "185.244.25.235",
            "dst_port": 80,
            "protocol": "TCP",
            "conn_state": "S0",
            "history": "S",
            "orig_bytes": 0,
            "orig_pkts": 3,
        }]
        res = correlate_netguard_zeek(alerts, zeek_conns, tolerance=10.0)
        self.assertEqual(len(res["corroborated"]), 1)
        self.assertEqual(len(res["unmatched"]), 0)
        self.assertEqual(res["corroborated"][0]["corroboration_type"], "UNANSWERED_SYN_SCAN")

    def test_correlate_netguard_zeek_data_exfil(self):
        alerts = [{
            "rule_name": "DATA_EXFIL",
            "src_ip": "10.0.0.5",
            "dst_ip": "198.51.100.99",
            "dst_port": 9000,
            "protocol": "TCP",
            "timestamp": 100.0,
        }]
        zeek_conns = [{
            "timestamp": 102.0,
            "src_ip": "10.0.0.5",
            "dst_ip": "198.51.100.99",
            "dst_port": 9000,
            "protocol": "TCP",
            "conn_state": "SF",
            "history": "ShADadFf",
            "orig_bytes": 150000,
            "orig_pkts": 120,
        }]
        res = correlate_netguard_zeek(alerts, zeek_conns, tolerance=10.0)
        self.assertEqual(len(res["corroborated"]), 1)
        self.assertEqual(res["corroborated"][0]["corroboration_type"], "HIGH_VOLUME_EGRESS")

    def test_correlate_netguard_zeek_unmatched(self):
        alerts = [{
            "rule_name": "BRUTE_FORCE",
            "src_ip": "10.0.0.99",
            "dst_ip": "10.0.0.1",
            "dst_port": 22,
            "protocol": "TCP",
            "timestamp": 500.0,
        }]
        zeek_conns = [{
            "timestamp": 100.0,
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.2",
            "dst_port": 80,
            "protocol": "TCP",
            "conn_state": "SF",
        }]
        res = correlate_netguard_zeek(alerts, zeek_conns, tolerance=10.0)
        self.assertEqual(len(res["corroborated"]), 0)
        self.assertEqual(len(res["unmatched"]), 1)
        self.assertEqual(res["unmatched"][0]["reason"], "NO_MATCHING_FLOW")

    def test_real_zeek_log_parsing_if_mounted(self):
        """Parse genuine 23,145-flow CTU IoT-23 Zeek log when external drive is mounted."""
        zeek_path = "/run/media/harshitgarg/Data1/NetGuard-datasets/verified/iot23_malware_34_1_zeek_conn.log"
        if not (os.path.ismount("/run/media/harshitgarg/Data1") and os.path.isfile(zeek_path)):
            self.skipTest("Zeek dataset not available on external storage.")

        conns = load_zeek_connections(zeek_path, max_records=500)
        self.assertEqual(len(conns), 500)
        self.assertTrue(all(isinstance(c["timestamp"], float) for c in conns))
        self.assertTrue(all(isinstance(c["src_ip"], str) for c in conns))
        # Ensure at least some S0 scan states are captured
        s0_count = sum(1 for c in conns if c["conn_state"] == "S0")
        self.assertGreater(s0_count, 10)

    def test_dual_zeek_suricata_cli_json_db(self):
        """Verify dual corroboration mode (both --zeek and --eve) works with JSON evaluation inputs."""
        import subprocess
        # Mock Zeek log
        zeek_content = (
            '{"ts": 1545403816.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80, "proto": "tcp", "conn_state": "S0", "history": "S"}\n'
        )
        # Mock Suricata EVE
        eve_content = (
            '{"timestamp": "2018-12-21T14:50:16.000000+0000", "event_type": "alert", "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "dest_port": 80, "proto": "TCP", "alert": {"signature": "ET SCAN Possible Port Scan", "severity": 2}}\n'
        )
        # Mock NetGuard eval JSON
        eval_json_content = json.dumps({
            "id": "mock_test",
            "alerts_sample": [{
                "rule_name": "PORT_SCAN",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "protocol": "TCP",
                "timestamp": 1545403816.0,
                "detail": "Port scan detected"
            }]
        })

        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".log") as f_zeek, \
             tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as f_eve, \
             tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as f_db:
            f_zeek.write(zeek_content)
            f_eve.write(eve_content)
            f_db.write(eval_json_content)
            p_zeek, p_eve, p_db = f_zeek.name, f_eve.name, f_db.name

        try:
            cmd = [
                sys.executable,
                os.path.join(os.path.dirname(os.path.dirname(__file__)), "evaluation", "compare.py"),
                "--zeek", p_zeek,
                "--eve", p_eve,
                "--db", p_db
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.assertIn("ZEEK CROSS-ENGINE TELEMETRY CORROBORATION REPORT", res.stdout)
            self.assertIn("ENGINE AGREEMENT REPORT", res.stdout)
            self.assertIn("Corroborated by Zeek:", res.stdout)
            self.assertIn("Matched by both engines:", res.stdout)
        finally:
            for p in (p_zeek, p_eve, p_db):
                if os.path.exists(p):
                    os.remove(p)


if __name__ == "__main__":
    unittest.main()

