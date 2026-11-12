"""
Unit and integration tests for Reverse DNS Resolution Service.
Verifies async non-blocking PTR resolution, dual positive/negative caching, timeout bounding, and batch lookup APIs.
"""

import os
import sys
import time
import pytest
from unittest.mock import patch, MagicMock

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from dashboard.app import app
from analytics.reverse_dns import ReverseDNSResolver


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_reverse_dns_positive_cache():
    resolver = ReverseDNSResolver(cache_ttl=10, negative_ttl=5, timeout_s=1.0)
    with patch("socket.gethostbyaddr", return_value=("dns.google", [], ["8.8.8.8"])) as mock_dns:
        host1 = resolver.resolve("8.8.8.8")
        assert host1 == "dns.google"
        assert mock_dns.call_count == 1

        # Second call must hit cache without invoking socket
        host2 = resolver.resolve("8.8.8.8")
        assert host2 == "dns.google"
        assert mock_dns.call_count == 1  # No second socket call


def test_reverse_dns_negative_cache():
    resolver = ReverseDNSResolver(cache_ttl=10, negative_ttl=5, timeout_s=1.0)
    import socket
    with patch("socket.gethostbyaddr", side_effect=socket.herror(1, "Unknown host")) as mock_dns:
        host1 = resolver.resolve("192.168.99.99")
        assert host1 is None
        assert mock_dns.call_count == 1

        # Second call must hit negative cache immediately
        host2 = resolver.resolve("192.168.99.99")
        assert host2 is None
        assert mock_dns.call_count == 1


def test_reverse_dns_timeout_bounding():
    # Verify slow DNS does not block beyond timeout limit
    resolver = ReverseDNSResolver(timeout_s=0.2)

    def slow_lookup(ip):
        time.sleep(1.0)
        return ("slow.domain.internal", [], [ip])

    with patch("socket.gethostbyaddr", side_effect=slow_lookup):
        t0 = time.time()
        res = resolver.resolve("10.254.254.1")
        elapsed = time.time() - t0
        # Must return in under 0.6 seconds, not 1.0+
        assert elapsed < 0.6
        assert res is None


def test_reverse_dns_batch_api(client):
    csrf_token = client.get("/api/csrf-token").get_json()["csrf_token"]
    with patch("analytics.reverse_dns.ReverseDNSResolver.resolve_batch") as mock_batch:
        mock_batch.return_value = {
            "8.8.8.8": "dns.google",
            "1.1.1.1": "one.one.one.one",
            "192.168.1.1": None,
        }
        res = client.post("/api/dns/reverse", headers={"X-CSRFToken": csrf_token}, json={"ips": ["8.8.8.8", "1.1.1.1", "192.168.1.1"]})
        assert res.status_code == 200
        data = res.get_json()
        assert "results" in data
        assert data["results"]["8.8.8.8"] == "dns.google"
        assert data["results"]["1.1.1.1"] == "one.one.one.one"


def test_reverse_dns_get_api(client):
    with patch("analytics.reverse_dns.ReverseDNSResolver.resolve") as mock_resolve:
        mock_resolve.return_value = "dns.google"
        res = client.get("/api/dns/reverse?ip=8.8.8.8")
        assert res.status_code == 200
        data = res.get_json()
        assert data["ip"] == "8.8.8.8"
        assert data["hostname"] == "dns.google"

