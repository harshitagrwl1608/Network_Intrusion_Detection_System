import math
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

    def test_nonpositive_dns_entropy_and_length_thresholds_use_safe_defaults(self):
        entropy_rule = DnsRule(
            entropy_threshold=0, max_query_len=60,
            freq_threshold=0, subdomain_threshold=0)
        entropy_alert = entropy_rule.check({
            "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.30",
            "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
            "dns_query": "abcdefgh.example.com", "timestamp": 100.0,
        })
        self.assertEqual(entropy_rule.entropy_threshold, 3.8)
        self.assertIsNone(entropy_alert)

        length_rule = DnsRule(
            entropy_threshold=9.0, max_query_len=0,
            freq_threshold=0, subdomain_threshold=0)
        length_alert = length_rule.check({
            "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.31",
            "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
            "dns_query": "google.com", "timestamp": 100.0,
        })
        self.assertEqual(length_rule.max_query_len, 60)
        self.assertIsNone(length_alert)

    def test_invalid_dns_thresholds_use_defaults_while_zero_still_disables(self):
        rule = DnsRule(
            freq_threshold="invalid", subdomain_threshold=-1,
            max_frequency_keys="invalid", max_seen_keys=0,
        )
        self.assertEqual(rule._freq_threshold, 20)
        self.assertEqual(rule._subdomain_threshold, 20)
        self.assertEqual(rule._max_frequency_keys, 10_000)
        self.assertEqual(rule._max_seen_keys, 10_000)
        disabled = DnsRule(freq_threshold=0, subdomain_threshold=0)
        self.assertEqual(disabled._freq_threshold, 0)
        self.assertEqual(disabled._subdomain_threshold, 0)

    def test_invalid_dns_windows_fall_back_without_losing_frequency_coverage(self):
        rule = DnsRule(
            entropy_threshold=9.0, max_query_len=60,
            freq_threshold=2, freq_window=0,
            subdomain_threshold=0,
        )
        self.assertEqual(rule._freq_window, 60)
        def query(ts):
            return {
                "type": "IP", "protocol": "UDP", "src_ip": "203.0.113.45",
                "dst_ip": "192.0.2.53", "src_port": 40000, "dst_port": 53,
                "dns_query": "api.example.com", "timestamp": ts,
            }
        self.assertIsNone(rule.check(query(100.0)))
        alert = rule.check(query(101.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["sub_type"], "DNS_FREQ")

    def test_invalid_subdomain_window_falls_back_and_keeps_distinct_query_detection(self):
        rule = DnsRule(
            entropy_threshold=9.0, max_query_len=60,
            freq_threshold=0, subdomain_threshold=2, subdomain_window="invalid",
        )
        self.assertEqual(rule._subdomain_window, 60)
        def query(label, ts):
            return {
                "type": "IP", "protocol": "UDP", "src_ip": "203.0.113.46",
                "dst_ip": "192.0.2.53", "src_port": 40001, "dst_port": 53,
                "dns_query": f"{label}.example.com", "timestamp": ts,
            }
        self.assertIsNone(rule.check(query("one", 100.0)))
        alert = rule.check(query("two", 101.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["sub_type"], "DNS_EXFIL")

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

    def test_dns_subdomain_history_is_bounded_after_threshold(self):
        rule = DnsRule(
            entropy_threshold=10.0, max_query_len=200, freq_threshold=0,
            subdomain_threshold=3, subdomain_window=60)
        alert = None
        threshold_alert = None
        for i in range(1000):
            alert = rule.check({
                "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.35",
                "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
                "dns_query": f"chunk{i:04d}.tunnel.example.com",
                "timestamp": 100.0 + i * 0.001,
            })
            if alert is not None and threshold_alert is None:
                threshold_alert = alert
        history = rule._subdomain_freq[("192.0.2.35", "example.com")]
        self.assertLessEqual(len(history), 3)
        self.assertIsNotNone(threshold_alert)
        self.assertEqual(threshold_alert["evidence"]["distinct_subdomains"], 3)
        self.assertTrue(threshold_alert["evidence"]["distinct_subdomains_saturated"])

    def test_dns_retransmission_with_same_transaction_id_does_not_inflate_frequency(self):
        rule = DnsRule(entropy_threshold=9.0, max_query_len=200,
                       freq_threshold=2, freq_window=10)
        base = {
            "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.22",
            "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
            "dns_query": "api.example.com", "dns_qtype": 1, "dns_id": 417,
        }
        self.assertIsNone(rule.check(dict(base, timestamp=100.0)))
        self.assertIsNone(rule.check(dict(base, timestamp=101.0)))
        self.assertEqual(len(rule._freq[("192.0.2.22", "example.com")]), 1)

        # A new DNS transaction for the same question is a real query and counts.
        alert = rule.check(dict(base, timestamp=102.0, dns_id=418))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["query_count_in_window"], 2)

    def test_dns_transaction_retry_cache_expires_after_short_retry_window(self):
        rule = DnsRule(entropy_threshold=9.0, max_query_len=200,
                       freq_threshold=2, freq_window=10)
        record = {
            "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.23",
            "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
            "dns_query": "api.example.com", "dns_qtype": 1, "dns_id": 88,
        }
        self.assertIsNone(rule.check(dict(record, timestamp=100.0)))
        self.assertIsNotNone(rule.check(dict(record, timestamp=103.0)))

    def test_dns_transaction_retry_cache_is_bounded(self):
        rule = DnsRule(entropy_threshold=9.0, max_query_len=200,
                       freq_threshold=10, freq_window=60)
        rule._max_seen_queries = 2
        for i in range(3):
            record = {
                "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.24",
                "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
                "dns_query": f"api{i}.example.com", "dns_qtype": 1,
                "dns_id": i, "timestamp": 100.0 + i,
            }
            self.assertIsNone(rule.check(record))
        self.assertEqual(len(rule._seen_queries), 2)

    def test_late_dns_query_does_not_poison_retry_cache(self):
        rule = DnsRule(entropy_threshold=9.0, max_query_len=200,
                       freq_threshold=10, freq_window=10)
        def query(domain, dns_id, timestamp):
            return {
                "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.26",
                "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
                "dns_query": domain, "dns_qtype": 1, "dns_id": dns_id,
                "timestamp": timestamp,
            }

        rule.check(query("one.example.com", 1, 100.0))
        rule.check(query("two.example.com", 2, 102.0))
        # Reordered input is rejected and must not mark the transaction as seen.
        rule.check(query("three.example.com", 3, 101.0))
        self.assertIsNone(rule._seen_queries.get((
            "192.0.2.26", "192.0.2.53", 53000, 53, 3, 1,
            "three.example.com")))

        rule.check(query("three.example.com", 3, 103.0))
        self.assertEqual(len(rule._freq[("192.0.2.26", "example.com")]), 3)

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

    def test_active_dns_alert_cooldown_survives_key_churn(self):
        rule = DnsRule(entropy_threshold=3.0, max_query_len=200,
                       freq_threshold=0, subdomain_threshold=0,
                       max_seen_keys=2)

        def query(label, parent, timestamp):
            return {
                "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.45",
                "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
                "dns_query": f"{label}.{parent}", "timestamp": timestamp,
            }

        self.assertIsNotNone(rule.check(query(
            "xvqrztmplwbsnfhk", "example.com", 100)))  # alert A
        self.assertIsNotNone(rule.check(query(
            "qzmxncvbplokihgf", "example.net", 101)))  # alert B
        self.assertIsNone(rule.check(query(
            "asdfghjklqwertyu", "example.com", 102)))  # refresh A
        self.assertIsNotNone(rule.check(query(
            "plmoknijbuhvygct", "example.org", 103)))  # evict B

        a_key = ("192.0.2.45", "example.com", "DNS_DGA")
        b_key = ("192.0.2.45", "example.net", "DNS_DGA")
        self.assertIn(a_key, rule._seen)
        self.assertNotIn(b_key, rule._seen)
        self.assertIsNone(rule.check(query(
            "lkjhgfdsapoiuytr", "example.com", 104)))

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
        self.assertEqual(alert["evidence"]["subdomain"], "api.xvqrztmplwbsnfhk")
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

    def test_long_fqdn_with_normal_length_labels_is_not_flagged_by_length(self):
        rule = DnsRule(max_query_len=60, freq_threshold=0, subdomain_threshold=0)
        qname = "static-content-delivery.asset-management.googleusercontent.com"
        self.assertGreater(len(qname), 60)
        self.assertLessEqual(max(map(len, qname.split("."))), 60)
        alert = rule.check({
            "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.24",
            "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
            "dns_query": qname, "timestamp": 100,
        })
        self.assertIsNone(alert, "Total dotted QNAME length alone should not flag ordinary labels")

    def test_overlong_individual_label_is_reported_in_evidence(self):
        rule = DnsRule(max_query_len=60, freq_threshold=0, subdomain_threshold=0)
        qname = "a" * 61 + ".example.net"
        alert = rule.check({
            "type": "IP", "protocol": "UDP", "src_ip": "192.0.2.25",
            "dst_ip": "192.0.2.53", "src_port": 53000, "dst_port": 53,
            "dns_query": qname, "timestamp": 100,
        })
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_version"], "1.24")
        self.assertEqual(alert["evidence"]["sub_type"], "DNS_TUNNEL")
        self.assertEqual(alert["evidence"]["longest_label"], "a" * 61)
        self.assertEqual(alert["evidence"]["longest_label_length"], 61)
        self.assertEqual(alert["evidence"]["max_label_length"], 60)
        self.assertIn("label_length=61", alert["detail"])

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
        self.assertEqual(alert1["rule_version"], "1.8")
        self.assertEqual(alert1["severity"], "medium")
        self.assertEqual(alert1["confidence"], "heuristic")
        self.assertEqual(alert1["evidence"]["classification"], "ARP_IDENTITY_CHANGE")
        self.assertIn("legitimate host change", alert1["detail"])

        # Second conflicting MAC arrives 2 seconds later -> should be suppressed by cooldown
        alert2 = arp_rule.check({
            "type": "ARP",
            "src_ip": "192.168.1.1",
            "src_mac": "00:11:22:33:44:99",
            "timestamp": 103.0,
        })
        self.assertIsNone(alert2, "Rapid repeat ARP spoof for same IP should be suppressed by cooldown")

    def test_malformed_arp_timestamps_use_finite_cooldown_values(self):
        rule = ArpSpoofRule(self.arp_table_path)
        for index, timestamp in enumerate(("bad-timestamp", float("nan"), float("inf"))):
            with self.subTest(timestamp=timestamp):
                ip = f"192.0.2.{100 + index}"
                first_mac = f"00:11:22:33:44:{index + 1:02x}"
                rule.check({"type": "ARP", "src_ip": ip,
                            "src_mac": first_mac, "timestamp": 100.0})
                changed = {"type": "ARP", "src_ip": ip,
                           "src_mac": "00:11:22:33:44:99", "timestamp": timestamp}
                self.assertIsNotNone(rule.check(changed))
                self.assertTrue(math.isfinite(rule._cooldown[ip]))

                repeated = dict(changed, src_mac="00:11:22:33:44:98")
                self.assertIsNone(rule.check(repeated))

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

    def test_invalid_arp_capacities_use_defaults_and_keep_learning_mappings(self):
        rule = ArpSpoofRule(
            self.arp_table_path, max_entries=0, max_cooldowns="invalid")
        self.assertEqual(rule.max_entries, 65_536)
        self.assertEqual(rule.max_cooldowns, 10_000)
        for index in range(2):
            rule.check({
                "type": "ARP", "src_ip": f"192.0.2.{index + 1}",
                "src_mac": f"00:11:22:33:44:{index + 1:02x}",
                "timestamp": 100.0,
            })
        self.assertEqual(len(rule._table), 2)

    def test_arp_spoof_prune_stale_clears_expired_cooldowns(self):
        rule = ArpSpoofRule(self.arp_table_path)
        rule.check({
            "type": "ARP", "src_ip": "192.168.1.10",
            "src_mac": "00:11:22:33:44:01", "timestamp": 100.0,
        })
        alert = rule.check({
            "type": "ARP", "src_ip": "192.168.1.10",
            "src_mac": "00:11:22:33:44:02", "timestamp": 101.0,
        })
        self.assertIsNotNone(alert)
        self.assertIn("192.168.1.10", rule._cooldown)

        rule.prune_stale(150.0)
        self.assertIn("192.168.1.10", rule._cooldown)

        rule.prune_stale(222.0)
        self.assertNotIn("192.168.1.10", rule._cooldown)

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

    def test_invalid_timestamp_preserves_direct_dns_signal_without_temporal_state(self):
        for invalid_time in ("bad-time", float("nan"), float("inf")):
            with self.subTest(timestamp=invalid_time):
                rule = DnsRule(
                    entropy_threshold=9.0, max_query_len=200,
                    freq_threshold=2, subdomain_threshold=2)
                query = {
                    "type": "IP", "protocol": "UDP", "src_ip": "192.168.1.50",
                    "dst_ip": "8.8.8.8", "src_port": 53000, "dst_port": 53,
                    "dns_query": "61646d696e3a70617373776f7264.covert.net",
                    "timestamp": invalid_time,
                }
                alert = rule.check(query)
                self.assertIsNotNone(alert)
                self.assertEqual(alert["evidence"]["sub_type"], "DNS_TUNNEL")
                self.assertIsNone(alert["window_end"])
                self.assertEqual(rule._freq, {})
                self.assertEqual(rule._subdomain_freq, {})
                self.assertEqual(rule._seen, {})

    def test_invalid_timestamp_does_not_synthesize_dns_frequency_alert(self):
        rule = DnsRule(
            entropy_threshold=9.0, max_query_len=200,
            freq_threshold=2, subdomain_threshold=0)
        query = {
            "type": "IP", "protocol": "UDP", "src_ip": "203.0.113.45",
            "dst_ip": "192.0.2.53", "src_port": 40000, "dst_port": 53,
            "dns_query": "api.example.com", "timestamp": "invalid",
        }
        self.assertIsNone(rule.check(query))
        self.assertEqual(rule._freq, {})

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

    def test_dns_rule_string_src_port_normalized_in_alert(self):
        rule = DnsRule(max_query_len=30)
        query = {
            "type": "IP", "protocol": "UDP", "src_ip": "192.168.1.50",
            "dst_ip": "8.8.8.8", "src_port": "53000", "dst_port": "53",
            "dns_query": "thisisaverylongsubdomainlabelthatexceedsthirtychars.example.com",
            "timestamp": 100.0,
        }
        alert = rule.check(query)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["src_port"], 53000)
        self.assertIsInstance(alert["src_port"], int)
        self.assertEqual(alert["dst_port"], 53)

    def test_cctld_multi_label_parent_domain_grouping(self):
        rule = DnsRule()
        self.assertEqual(rule._parent_domain("host.company.com.ng"), "company.com.ng")
        self.assertEqual(rule._parent_domain("portal.service.com.es"), "service.com.es")
        self.assertEqual(rule._parent_domain("dept.intranet.gc.ca"), "intranet.gc.ca")
        self.assertEqual(rule._parent_domain("api.service.com.pl"), "service.com.pl")
        self.assertEqual(rule._parent_domain("dns.node.com.gr"), "node.com.gr")


    def test_shannon_entropy_edge_cases_and_punycode(self):
        from engine.rules import _shannon_entropy
        # Empty and non-string inputs produce 0.0
        self.assertEqual(_shannon_entropy(""), 0.0)
        self.assertEqual(_shannon_entropy(None), 0.0)
        self.assertEqual(_shannon_entropy(123), 0.0)
        # Single-character string produces 0.0
        self.assertEqual(_shannon_entropy("a"), 0.0)
        # Homogeneous repetitive string produces 0.0
        self.assertEqual(_shannon_entropy("aaaaaaa"), 0.0)
        # Punycode prefix is stripped before calculation
        self.assertEqual(_shannon_entropy("xn--a"), 0.0)
        # Valid non-zero entropy
        ent = _shannon_entropy("abcdefgh")
        self.assertAlmostEqual(ent, 3.0, places=2)

    def test_dns_prune_stale_optional_now_and_unconditional_seen_pruning(self):
        rule = DnsRule()
        # Plant stale seen entries (cutoff is now - 120)
        stale_key = ("192.168.1.1", "stale.com", "DNS_DGA")
        fresh_key = ("192.168.1.1", "fresh.com", "DNS_DGA")
        future_key = ("192.168.1.1", "future.com", "DNS_DGA")

        rule._seen[stale_key] = 10.0
        rule._seen[fresh_key] = 900.0
        rule._seen[future_key] = 1500.0

        # Prune with now=1000.0
        rule.prune_stale(now=1000.0)
        self.assertNotIn(stale_key, rule._seen)
        self.assertNotIn(future_key, rule._seen)
        self.assertIn(fresh_key, rule._seen)

        # Prune without explicit now (defaults to time.time())
        rule.prune_stale()

    def test_reverse_dns_ptr_queries_do_not_trigger_false_exfil_or_freq(self):
        """Standard IPv4/IPv6 reverse PTR queries must not alert as DNS_EXFIL or DNS_FREQ."""
        rule = DnsRule()
        alerts = []
        # Send 25 distinct reverse DNS lookups in 60 seconds
        for i in range(25):
            rec = {
                "type": "IP",
                "src_ip": "192.168.1.50",
                "dst_ip": "192.168.1.1",
                "dst_port": 53,
                "dns_query": f"{i}.1.168.192.in-addr.arpa",
                "timestamp": 1000.0 + i,
            }
            alert = rule.check(rec)
            if alert:
                alerts.append(alert)

        self.assertEqual(len(alerts), 0, f"Expected 0 alerts on reverse DNS lookups, got: {alerts}")

        # In contrast, 25 distinct subdomains under an attacker domain MUST trigger DNS_EXFIL
        exfil_alerts = []
        for i in range(25):
            rec = {
                "type": "IP",
                "src_ip": "192.168.1.50",
                "dst_ip": "192.168.1.1",
                "dst_port": 53,
                "dns_query": f"chunk{i}.attacker-domain.com",
                "timestamp": 1000.0 + i,
            }
            alert = rule.check(rec)
            if alert:
                exfil_alerts.append(alert)

        self.assertGreaterEqual(len(exfil_alerts), 1, "Exfiltration to attacker-domain.com must alert")
        self.assertIn("attacker-domain.com", exfil_alerts[0]["detail"])

    def test_reverse_dns_ipv6_ip6_arpa_exemption_from_subdomain_exfil(self):
        """IPv6 PTR lookups (*.ip6.arpa) must not trigger DNS_EXFIL or accumulate state in _subdomain_freq."""
        rule = DnsRule(subdomain_threshold=20, subdomain_window=60)
        alerts = []
        for i in range(25):
            rec = {
                "type": "IP",
                "protocol": "UDP",
                "src_ip": "192.168.1.50",
                "dst_ip": "8.8.8.8",
                "src_port": 50000,
                "dst_port": 53,
                "dns_query": f"{i % 16:x}.{i // 16:x}.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
                "timestamp": 1000.0 + i * 0.1,
            }
            alert = rule.check(rec)
            if alert:
                alerts.append(alert)

        self.assertEqual(len(alerts), 0, f"Expected 0 alerts for ip6.arpa reverse DNS, got: {alerts}")
        self.assertEqual(len(rule._subdomain_freq), 0, "Reverse DNS lookups must not accumulate state in _subdomain_freq")

    def test_covert_tunneling_under_in_addr_arpa_triggers_exfil(self):
        """Covert exfiltration tunneling alphanumeric data under in-addr.arpa must alert as DNS_EXFIL."""
        rule = DnsRule(subdomain_threshold=20, subdomain_window=60)
        alerts = []
        for i in range(25):
            rec = {
                "type": "IP",
                "protocol": "UDP",
                "src_ip": "192.168.1.50",
                "dst_ip": "8.8.8.8",
                "src_port": 50000,
                "dst_port": 53,
                "dns_query": f"covertchunk{i:02d}.tunnel.in-addr.arpa",
                "timestamp": 1000.0 + i * 0.1,
            }
            alert = rule.check(rec)
            if alert:
                alerts.append(alert)

        self.assertGreaterEqual(len(alerts), 1, "Exfiltration masquerading under in-addr.arpa must alert")
        self.assertEqual(alerts[0]["evidence"]["sub_type"], "DNS_EXFIL")


    def test_dns_query_bytes_and_malformed_type_handling(self):
        """DnsRule must safely handle bytes dns_query and discard non-string types without crashing."""
        rule = DnsRule()
        # Bytes query should decode properly and detect long label tunnel
        rec_bytes = {
            "type": "IP", "protocol": "UDP",
            "src_port": 53000, "dst_port": 53,
            "src_ip": "192.168.1.50", "dst_ip": "8.8.8.8",
            "dns_query": b"a" * 63 + b".tunnel.example.com",
            "timestamp": 1000.0,
        }
        alert = rule.check(rec_bytes)
        self.assertIsNotNone(alert, "Bytes dns_query should be decoded and inspected")
        self.assertEqual(alert["evidence"]["sub_type"], "DNS_TUNNEL")

        # Malformed types should safely return None without raising exceptions
        for malformed in (12345, 99.9, None, ["evil.com"], {"query": "evil.com"}, object()):
            rec_bad = {
                "type": "IP", "protocol": "UDP",
                "src_port": 53000, "dst_port": 53,
                "src_ip": "192.168.1.50", "dst_ip": "8.8.8.8",
                "dns_query": malformed,
                "timestamp": 1000.0,
            }
            try:
                res = rule.check(rec_bad)
                self.assertIsNone(res)
            except Exception as exc:
                self.fail(f"DnsRule.check crashed on non-string dns_query {malformed}: {exc}")

    def test_reverse_mapping_syntax_and_unicode_digit_rejection(self):
        """Reverse DNS validation must reject non-ASCII unicode digits and oversized octets."""
        rule = DnsRule(subdomain_threshold=20, subdomain_window=60)
        # Unicode Arabic-Indic digits are not RFC 1035 ASCII octets
        self.assertFalse(rule._is_valid_reverse_mapping("١.٢.٣.٤.in-addr.arpa"))
        # Octet longer than 3 characters is invalid
        self.assertFalse(rule._is_valid_reverse_mapping("1234.2.3.4.in-addr.arpa"))
        # 5000-digit string must safely return False without Integer conversion limits
        self.assertFalse(rule._is_valid_reverse_mapping("9" * 5000 + ".in-addr.arpa"))
        # Valid IPv4 reverse PTR
        self.assertTrue(rule._is_valid_reverse_mapping("4.3.2.1.in-addr.arpa"))
        # Valid IPv6 reverse PTR
        self.assertTrue(rule._is_valid_reverse_mapping("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"))
        # IPv6 with > 32 nibbles is invalid
        self.assertFalse(rule._is_valid_reverse_mapping("1." * 35 + "ip6.arpa"))


if __name__ == "__main__":
    unittest.main()
