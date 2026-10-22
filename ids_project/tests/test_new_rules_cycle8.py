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
        payload = b'value\r\nSet-Cookie: admin=1\r\n'
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
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["evidence"]["auth_port"], 22)

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


if __name__ == "__main__":
    unittest.main()
