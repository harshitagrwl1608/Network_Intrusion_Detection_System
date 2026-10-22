import os
import sys
import tempfile
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import DnsRule, ArpSpoofRule


class TestDnsAndArpDetection(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.arp_table_path = os.path.join(self.tmp_dir, "arp_table.json")

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_dns_freq_threshold_zero_disables_frequency_alerts(self):
        """
        DNS_FREQ_THRESHOLD=0 is documented to disable frequency detection.
        In the unfixed code, query_count >= 0 evaluated to True on the first query.
        """
        dns_rule = DnsRule(
            entropy_threshold=4.5,
            max_query_len=100,
            freq_threshold=0,  # 0 means disabled
            freq_window=60,
        )

        # Send a benign short low-entropy query
        record = {
            "type": "IP",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 53,
            "protocol": "UDP",
            "dns_query": "google.com",
            "timestamp": 1000.0,
        }
        alert = dns_rule.check(record)
        self.assertIsNone(alert, "freq_threshold=0 should disable frequency alerts, but an alert was returned")
        self.assertEqual(dns_rule._freq, {}, "disabled frequency detection should retain no query history")

    def test_dns_over_tcp_preserves_transport_in_alert(self):
        dns_rule = DnsRule(
            entropy_threshold=3.5,
            max_query_len=100,
            freq_threshold=0,
            freq_window=60,
        )
        alert = dns_rule.check({
            "type": "IP", "src_ip": "192.0.2.4", "dst_ip": "192.0.2.53",
            "src_port": 42000, "dst_port": 53, "protocol": "TCP",
            "dns_query": "xvqrztmplwbsnfhk.badactor.example", "timestamp": 1000.0,
        })
        self.assertIsNotNone(alert)
        self.assertEqual(alert["protocol"], "TCP")

    def test_late_dns_observation_does_not_corrupt_frequency_window(self):
        rule = DnsRule(entropy_threshold=5.0, max_query_len=60,
                       freq_threshold=3, freq_window=10)
        def query(label, ts):
            return {
                "type": "IP", "protocol": "UDP", "src_ip": "203.0.113.40",
                "dst_ip": "192.0.2.53", "src_port": 40000, "dst_port": 53,
                "dns_query": f"{label}.example.com", "timestamp": ts,
            }
        self.assertIsNone(rule.check(query("one", 20)))
        self.assertIsNone(rule.check(query("two", 21)))
        self.assertIsNone(rule.check(query("late", 19)))
        alert = rule.check(query("three", 22))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["query_count_in_window"], 3)

    def test_dns_frequency_groups_case_insensitive_names(self):
        rule = DnsRule(entropy_threshold=9.0, max_query_len=200,
                       freq_threshold=3, freq_window=10)
        alert = None
        for domain, ts in (("one.Example.COM.", 100),
                           ("two.example.com.", 101),
                           ("THREE.EXAMPLE.com.", 102)):
            alert = rule.check({
                "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.20",
                "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
                "dns_query": domain, "timestamp": ts,
            })
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["parent_domain"], "example.com")
        self.assertEqual(alert["evidence"]["query_count_in_window"], 3)

    def test_dns_frequency_cooldown_groups_randomized_names_by_parent(self):
        rule = DnsRule(entropy_threshold=9.0, max_query_len=200,
                       freq_threshold=3, freq_window=10)
        def query(domain, ts):
            return {
                "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.30",
                "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
                "dns_query": domain, "timestamp": ts,
            }
        self.assertIsNone(rule.check(query("one.example.com", 100)))
        self.assertIsNone(rule.check(query("two.example.com", 101)))
        self.assertIsNotNone(rule.check(query("three.example.com", 102)))
        self.assertIsNone(rule.check(query("four.example.com", 103)))
        self.assertEqual(len(rule._seen), 1)

    def test_dns_frequency_state_is_bounded_and_reports_saturation(self):
        rule = DnsRule(entropy_threshold=9.0, max_query_len=200,
                       freq_threshold=3, freq_window=10, max_frequency_keys=2)
        rule.ALERT_COOLDOWN_S = 0
        def query(domain, ts):
            return {
                "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.31",
                "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
                "dns_query": domain, "timestamp": ts,
            }
        self.assertIsNone(rule.check(query("one.example.com", 100)))
        self.assertIsNone(rule.check(query("two.example.com", 101)))
        alert = rule.check(query("three.example.com", 102))
        self.assertIsNotNone(alert)
        self.assertFalse(alert["evidence"]["query_count_saturated"])
        saturated = rule.check(query("four.example.com", 103))
        self.assertIsNotNone(saturated)
        self.assertTrue(saturated["evidence"]["query_count_saturated"])
        rule.check(query("one.other.com", 104))
        rule.check(query("one.third.com", 105))
        self.assertLessEqual(len(rule._freq), 2)

    def test_dns_entropy_checks_nested_and_registered_domain_labels(self):
        rule = DnsRule(entropy_threshold=3.8, max_query_len=100,
                       freq_threshold=0, freq_window=10)
        alert = rule.check({
            "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.21",
            "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
            "dns_query": "api.xvqrztmplwbsnfhk.example.com", "timestamp": 100,
        })
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["subdomain"], "api")
        self.assertEqual(alert["evidence"]["entropy_label"], "xvqrztmplwbsnfhk")

    def test_dns_entropy_does_not_flag_nested_human_readable_names(self):
        rule = DnsRule(entropy_threshold=3.8, max_query_len=100,
                       freq_threshold=0, freq_window=10)
        alert = rule.check({
            "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.22",
            "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
            "dns_query": "api.services.example.com", "timestamp": 100,
        })
        self.assertIsNone(alert)

    def test_srv_service_discovery_name_is_not_mislabeled_as_dns_tunnel(self):
        rule = DnsRule(max_query_len=60, freq_threshold=0, subdomain_threshold=0)
        alert = rule.check({
            "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.22",
            "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
            "dns_query": "_ldap._tcp.default-first-site-name._sites.dc._msdcs.techbros.tech",
            "dns_qtype": 33, "timestamp": 100,
        })
        self.assertIsNone(alert)

    def test_cloudflare_insights_hostname_is_not_flagged_by_entropy_only(self):
        rule = DnsRule(freq_threshold=0, subdomain_threshold=0)
        alert = rule.check({
            "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.23",
            "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
            "dns_query": "static.cloudflareinsights.com", "timestamp": 100,
        })
        self.assertIsNone(alert)

    def test_dga_whitelist_does_not_suppress_dns_tunneling(self):
        """
        Domains on the CDN whitelist (e.g. cloudfront.net) should be exempt from entropy checks,
        but must NOT suppress excessive length checks (DNS tunneling).
        """
        dns_rule = DnsRule(
            entropy_threshold=3.5,
            max_query_len=60,
            freq_threshold=20,
            freq_window=60,
        )

        # 1. High-entropy CDN query under amazonaws.com (normal length < 60) -> should be exempt
        cdn_record = {
            "type": "IP",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 53,
            "protocol": "UDP",
            "dns_query": "d111111abcdef8.amazonaws.com",
            "timestamp": 1000.0,
        }
        self.assertIsNone(dns_rule.check(cdn_record), "Normal length CDN query should not alert")

        # 2. Tunneling payload disguised under amazonaws.com (> 60 chars) -> MUST fire DNS_TUNNEL
        tunnel_domain = "a" * 50 + "b" * 30 + ".amazonaws.com"  # 94 chars > 60
        tunnel_record = {
            "type": "IP",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 53,
            "protocol": "UDP",
            "dns_query": tunnel_domain,
            "timestamp": 1001.0,
        }
        alert = dns_rule.check(tunnel_record)
        self.assertIsNotNone(alert, "Excessive length under CDN suffix must not be suppressed")
        self.assertEqual(alert.get("evidence", {}).get("sub_type"), "DNS_TUNNEL")

    def test_arp_spoof_cooldown_prevents_alert_storm(self):
        """ARP spoofing alerts should have cooldown for the same IP to prevent alert storms."""
        arp_rule = ArpSpoofRule(table_path=self.arp_table_path)

        # Learn initial MAC
        arp_rule.check({
            "type": "ARP",
            "src_ip": "192.168.1.1",
            "src_mac": "00:11:22:33:44:01",
            "timestamp": 100.0,
        })

        # Conflicting MAC arrives -> first alert must fire
        alert1 = arp_rule.check({
            "type": "ARP",
            "src_ip": "192.168.1.1",
            "src_mac": "00:11:22:33:44:99",
            "timestamp": 101.0,
        })
        self.assertIsNotNone(alert1, "First ARP spoof event must fire")

        # Second conflicting MAC arrives 2 seconds later -> should be suppressed by cooldown
        alert2 = arp_rule.check({
            "type": "ARP",
            "src_ip": "192.168.1.1",
            "src_mac": "00:11:22:33:44:99",
            "timestamp": 103.0,
        })
        self.assertIsNone(alert2, "Rapid repeat ARP spoof for same IP should be suppressed by cooldown")

    def test_arp_rule_ignores_invalid_identity_claims(self):
        rule = ArpSpoofRule(self.arp_table_path)
        for ip, mac in (
            ("0.0.0.0", "00:11:22:33:44:01"),
            ("224.0.0.1", "00:11:22:33:44:01"),
            ("192.0.2.1", "01:11:22:33:44:01"),  # multicast MAC
            ("192.0.2.2", "ff:ff:ff:ff:ff:ff"),  # broadcast MAC
            ("not-an-ip", "00:11:22:33:44:01"),
            ("192.0.2.3", "bad-mac"),
            ("192.0.2.4", "+1:11:22:33:44:55"),
            ("192.0.2.5", " 1:11:22:33:44:55"),
        ):
            self.assertIsNone(rule.check({"type": "ARP", "src_ip": ip, "src_mac": mac}))
        self.assertEqual(rule._table, {})

    def test_arp_mapping_and_cooldown_capacity_preserve_known_entries(self):
        rule = ArpSpoofRule(self.arp_table_path, max_entries=2, max_cooldowns=1)
        def claim(ip, mac, ts):
            return rule.check({"type": "ARP", "src_ip": ip,
                               "src_mac": mac, "timestamp": ts})

        claim("192.0.2.1", "00:11:22:33:44:01", 100)
        claim("192.0.2.2", "00:11:22:33:44:02", 100)
        # Capacity preserves the first two learned mappings instead of evicting.
        claim("192.0.2.3", "00:11:22:33:44:03", 100)
        self.assertEqual(len(rule._table), 2)
        self.assertIsNotNone(claim("192.0.2.1", "00:11:22:33:44:99", 101))
        self.assertIsNotNone(claim("192.0.2.2", "00:11:22:33:44:98", 102))
        self.assertLessEqual(len(rule._cooldown), 1)

    def test_low_entropy_hex_chunk_dns_tunneling_detected(self):
        # 28-char hex chunk: entropy is ~3.08 (well below 3.8), length is 39 (well below 50).
        rule = DnsRule(entropy_threshold=3.8, max_query_len=50, freq_threshold=20)
        query = {
            "type": "IP", "protocol": "UDP", "src_ip": "192.168.1.50",
            "dst_ip": "8.8.8.8", "src_port": 53000, "dst_port": 53,
            "dns_query": "61646d696e3a70617373776f7264.covert.net",
            "timestamp": 100.0,
        }
        alert = rule.check(query)
        self.assertIsNotNone(alert, "Hex chunk DNS tunneling should trigger DNS_ANOMALY")
        self.assertEqual(alert["rule_name"], "DNS_ANOMALY")
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["evidence"]["sub_type"], "DNS_TUNNEL")
        self.assertEqual(alert["evidence"]["hex_encoded_chunk"], "61646d696e3a70617373776f7264")

    def test_cdn_whitelisted_hex_label_is_exempt(self):
        rule = DnsRule(entropy_threshold=3.8, max_query_len=60, freq_threshold=20)
        query = {
            "type": "IP", "protocol": "UDP", "src_ip": "192.168.1.50",
            "dst_ip": "8.8.8.8", "src_port": 53000, "dst_port": 53,
            "dns_query": "61646d696e3a70617373776f7264313233.cloudflare.com",
            "timestamp": 100.0,
        }
        alert = rule.check(query)
        self.assertIsNone(alert, "Allowlisted CDN suffix should be exempt from hex chunk detection")

    def test_uuid_with_hyphens_does_not_fire_hex_chunk(self):
        rule = DnsRule(entropy_threshold=3.8, max_query_len=60, freq_threshold=20)
        query = {
            "type": "IP", "protocol": "UDP", "src_ip": "192.168.1.50",
            "dst_ip": "8.8.8.8", "src_port": 53000, "dst_port": 53,
            "dns_query": "123e4567-e89b-12d3-a456-426614174000.example.com",
            "timestamp": 100.0,
        }
        alert = rule.check(query)
        self.assertIsNone(alert, "UUID with hyphens should not trigger hex chunk detection")

    def test_purely_alphabetic_long_label_does_not_fire_hex_chunk(self):
        rule = DnsRule(entropy_threshold=3.8, max_query_len=60, freq_threshold=20)
        query = {
            "type": "IP", "protocol": "UDP", "src_ip": "192.168.1.50",
            "dst_ip": "8.8.8.8", "src_port": 53000, "dst_port": 53,
            "dns_query": "internationalizationorganization.example.com",
            "timestamp": 100.0,
        }
        alert = rule.check(query)
        self.assertIsNone(alert, "Purely alphabetic label should not trigger hex chunk detection")


if __name__ == "__main__":
    unittest.main()
