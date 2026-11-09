"""
tests/test_irc_c2_beaconing.py
-------------------------------
Unit tests for Rule 23: IrcC2BeaconingRule (IRC_C2_BEACONING).

Coverage:
  Positive detections:
    1.  IRC PING verb on port 6667 → IRC_PROTOCOL_SIGNATURE alert
    2.  IRC PONG verb on port 6667 → IRC_PROTOCOL_SIGNATURE alert
    3.  IRC NICK verb on port 6697 (SSL IRC) → IRC_PROTOCOL_SIGNATURE alert
    4.  IRC USER verb on port 194 (RFC canonical) → IRC_PROTOCOL_SIGNATURE alert
    5.  IRC JOIN verb on port 6666 → IRC_PROTOCOL_SIGNATURE alert
    6.  Repeated SYN packets to port 6667 trigger IRC_PORT_BEACONING at threshold
    7.  SYN beaconing across variant IRC ports (6660-6669 range)

  Benign suppression (true negatives):
    8.  Non-IRC TCP port (80, 443, 22) → no alert even with fake IRC verb payload
    9.  UDP traffic on IRC port → no alert
   10.  Payload verb on non-IRC port → no alert
   11.  Trusted host (src) → no alert for port beaconing
   12.  Below-threshold SYN count → no alert
   13.  Cooldown suppresses repeated signature alerts within cooldown window
   14.  Window reset: counters expire after window and restart cleanly

  Evasion edge cases:
   15.  SYN+ACK flags (server reply) → not counted as a client connection attempt
   16.  prune_stale() removes expired state; detection resumes after prune
   17.  Payload with partial IRC verb (only 3 chars) → no SIGNATURE alert
   18.  Payload is empty bytes → no SIGNATURE alert, beaconing path still works
"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from engine.rules import IrcC2BeaconingRule
import engine.rules as rules_mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_irc_rule(threshold=5, window=300, cooldown=300.0, max_sources=100):
    return IrcC2BeaconingRule(
        threshold=threshold,
        window=window,
        cooldown=cooldown,
        max_sources=max_sources,
    )


def _tcp_pkt(src="10.0.0.5", dst="185.244.25.235", dport=6667, flags="SYN",
             payload=b"", ts=1000.0):
    return {
        "type": "TCP",
        "protocol": "TCP",
        "src_ip": src,
        "dst_ip": dst,
        "src_port": 54321,
        "dst_port": dport,
        "flags": flags,
        "payload": payload,
        "timestamp": ts,
        "event_timestamp": ts,
    }


def _udp_pkt(src="10.0.0.5", dst="185.244.25.235", dport=6667, ts=1000.0):
    return {
        "type": "UDP",
        "protocol": "UDP",
        "src_ip": src,
        "dst_ip": dst,
        "src_port": 54321,
        "dst_port": dport,
        "timestamp": ts,
        "event_timestamp": ts,
    }


# ---------------------------------------------------------------------------
# Positive detections: IRC_PROTOCOL_SIGNATURE
# ---------------------------------------------------------------------------

class TestIrcSignatureDetection:

    def test_ping_verb_port_6667(self):
        """PING on port 6667 → IRC_PROTOCOL_SIGNATURE alert with heuristic confidence (generic command)."""
        rule = _make_irc_rule()
        pkt = _tcp_pkt(dport=6667, flags="ACK", payload=b"PING :server.irc.net\r\n")
        result = rule.check(pkt)
        assert result is not None
        assert result["rule_name"] == "IRC_C2_BEACONING"
        assert result["evidence"]["classification"] == "IRC_PROTOCOL_SIGNATURE"
        assert result["evidence"]["activity_assessment"] == "IRC_PROTOCOL_OBSERVED"
        assert result["evidence"]["irc_verb"] == "PING"
        assert result["confidence"] == "heuristic"
        assert result["severity"] == "medium"
        assert result["dst_port"] == 6667

    def test_mirai_botnet_command_confirmed_c2(self):
        """IRC command with botnet indicators (e.g. mirai/bot/#botnet) → confirmed high-severity C2 alert."""
        rule = _make_irc_rule()
        pkt = _tcp_pkt(dport=6667, flags="ACK", payload=b"PING :mirai.botnet.c2\r\n")
        result = rule.check(pkt)
        assert result is not None
        assert result["evidence"]["activity_assessment"] == "LIKELY_IRC_C2"
        assert result["confidence"] == "confirmed"
        assert result["severity"] == "high"

    def test_pong_verb_port_6667(self):
        """PONG on port 6667 → IRC_PROTOCOL_SIGNATURE."""
        rule = _make_irc_rule()
        pkt = _tcp_pkt(dport=6667, flags="ACK", payload=b"PONG :server.irc.net\r\n")
        result = rule.check(pkt)
        assert result is not None
        assert result["evidence"]["irc_verb"] == "PONG"

    def test_nick_verb_ssl_irc_port_6697(self):
        """NICK command on SSL IRC port 6697 → IRC_PROTOCOL_SIGNATURE."""
        rule = _make_irc_rule()
        pkt = _tcp_pkt(dport=6697, flags="ACK", payload=b"NICK bot-xz42\r\n")
        result = rule.check(pkt)
        assert result is not None
        assert result["evidence"]["irc_verb"] == "NICK"
        assert result["dst_port"] == 6697

    def test_user_verb_rfc_canonical_port_194(self):
        """USER command on RFC 1459 canonical port 194 → signature alert."""
        rule = _make_irc_rule()
        pkt = _tcp_pkt(dport=194, flags="PUSH-ACK", payload=b"USER mirai 0 * :Mirai Bot\r\n")
        result = rule.check(pkt)
        assert result is not None
        assert result["evidence"]["irc_verb"] == "USER"
        assert result["dst_port"] == 194

    def test_join_verb_port_6666(self):
        """JOIN on port 6666 → IRC_PROTOCOL_SIGNATURE."""
        rule = _make_irc_rule()
        pkt = _tcp_pkt(dport=6666, flags="ACK", payload=b"JOIN #botnet\r\n")
        result = rule.check(pkt)
        assert result is not None
        assert result["evidence"]["irc_verb"] == "JOIN"


# ---------------------------------------------------------------------------
# Positive detections: IRC_PORT_BEACONING (SYN rate)
# ---------------------------------------------------------------------------

class TestIrcPortBeaconing:

    def test_syn_beaconing_fires_at_threshold_port_6667(self):
        """5 SYN packets to port 6667 within window → IRC_PORT_BEACONING alert."""
        rule = _make_irc_rule(threshold=5, window=300)
        base_ts = 1000.0
        result = None
        for i in range(5):
            pkt = _tcp_pkt(dport=6667, flags="SYN", payload=b"", ts=base_ts + i)
            result = rule.check(pkt)
        assert result is not None
        assert result["evidence"]["classification"] == "IRC_PORT_BEACONING"
        assert result["evidence"]["connection_count"] >= 5
        assert result["confidence"] == "heuristic"
        assert result["dst_port"] == 6667

    def test_beaconing_on_variant_port_6660(self):
        """IRC_PORT_BEACONING fires on port 6660 (variant in known IRC range)."""
        rule = _make_irc_rule(threshold=3, window=60)
        result = None
        for i in range(3):
            pkt = _tcp_pkt(dport=6660, flags="SYN", ts=1000.0 + i)
            result = rule.check(pkt)
        assert result is not None
        assert result["evidence"]["classification"] == "IRC_PORT_BEACONING"
        assert result["dst_port"] == 6660


# ---------------------------------------------------------------------------
# Benign suppression (true negatives)
# ---------------------------------------------------------------------------

class TestBenignSuppression:

    def test_non_irc_port_no_alert(self):
        """TCP with PING payload to port 80 → no alert (not an IRC port)."""
        rule = _make_irc_rule()
        pkt = _tcp_pkt(dport=80, flags="ACK", payload=b"PING :server.irc.net\r\n")
        result = rule.check(pkt)
        assert result is None

    def test_udp_on_irc_port_no_alert(self):
        """UDP packet to port 6667 → no alert (rule is TCP-only)."""
        rule = _make_irc_rule()
        pkt = _udp_pkt(dport=6667)
        result = rule.check(pkt)
        assert result is None

    def test_payload_verb_on_non_irc_port_no_alert(self):
        """USER/NICK payload on port 443 → no alert."""
        rule = _make_irc_rule()
        for payload in [b"NICK bot\r\n", b"USER x 0 * :x\r\n", b"JOIN #c\r\n"]:
            pkt = _tcp_pkt(dport=443, flags="ACK", payload=payload)
            assert rule.check(pkt) is None

    def test_trusted_src_no_alert(self):
        """Source IP in TRUSTED_HOSTS → no beaconing alert."""
        rule = _make_irc_rule(threshold=3)
        orig = set(rules_mod.TRUSTED_HOSTS)
        try:
            rules_mod.TRUSTED_HOSTS.add("10.0.0.5")
            for i in range(5):
                pkt = _tcp_pkt(src="10.0.0.5", dport=6667, flags="SYN", ts=1000.0 + i)
                result = rule.check(pkt)
                assert result is None, f"Should be suppressed for trusted host (iteration {i})"
        finally:
            rules_mod.TRUSTED_HOSTS.clear()
            rules_mod.TRUSTED_HOSTS.update(orig)

    def test_below_threshold_no_beaconing_alert(self):
        """4 SYN packets with threshold=5 → no alert."""
        rule = _make_irc_rule(threshold=5, window=300)
        for i in range(4):
            pkt = _tcp_pkt(dport=6667, flags="SYN", ts=1000.0 + i)
            assert rule.check(pkt) is None

    def test_signature_cooldown_suppresses_repeats(self):
        """Repeated PING on same (src,dst,port) within cooldown → only 1 alert."""
        rule = _make_irc_rule(cooldown=120.0)
        pkt = _tcp_pkt(dport=6667, flags="ACK", payload=b"PING :srv\r\n", ts=1000.0)
        first = rule.check(pkt)
        assert first is not None
        # Same src/dst/port within cooldown window
        pkt2 = _tcp_pkt(dport=6667, flags="ACK", payload=b"PING :srv\r\n", ts=1030.0)
        second = rule.check(pkt2)
        assert second is None, "Should be suppressed by cooldown"

    def test_window_reset_after_expiry(self):
        """SYN counter resets after window expiry; detection restarts cleanly."""
        rule = _make_irc_rule(threshold=3, window=10, cooldown=0.0)
        # 2 SYNs within window (below threshold)
        for i in range(2):
            rule.check(_tcp_pkt(dport=6667, flags="SYN", ts=1000.0 + i))
        # Jump past window expiry
        result = rule.check(_tcp_pkt(dport=6667, flags="SYN", ts=1020.0))
        # Only 1 SYN in new window, so no alert
        assert result is None
        # 2 more SYNs in new window (count=2 total in new window)
        rule.check(_tcp_pkt(dport=6667, flags="SYN", ts=1021.0))
        # 3rd SYN in new window → triggers
        result = rule.check(_tcp_pkt(dport=6667, flags="SYN", ts=1022.0))
        assert result is not None
        assert result["evidence"]["classification"] == "IRC_PORT_BEACONING"


# ---------------------------------------------------------------------------
# Evasion edge cases
# ---------------------------------------------------------------------------

class TestEvasionEdgeCases:

    def test_syn_ack_not_counted(self):
        """SYN-ACK (server reply) must not count as a client connection attempt."""
        rule = _make_irc_rule(threshold=3, window=60)
        # Send 10 SYN-ACK packets (server replies)
        for i in range(10):
            pkt = _tcp_pkt(dport=6667, flags="SYN-ACK", ts=1000.0 + i)
            result = rule.check(pkt)
            assert result is None, "SYN-ACK should not count towards beaconing threshold"

    def test_prune_stale_clears_expired_state(self):
        """prune_stale() evicts old state; detection restarts after prune."""
        rule = _make_irc_rule(threshold=3, window=10, cooldown=5.0)
        # Send 2 SYNs (below threshold)
        rule.check(_tcp_pkt(dport=6667, flags="SYN", ts=1000.0))
        rule.check(_tcp_pkt(dport=6667, flags="SYN", ts=1001.0))
        # Prune at t=1020 (well past window + cooldown)
        rule.prune_stale(1020.0)
        # State should be cleared; 3 fresh SYNs should re-trigger
        for i in range(3):
            result = rule.check(_tcp_pkt(dport=6667, flags="SYN", ts=1025.0 + i))
        assert result is not None
        assert result["evidence"]["classification"] == "IRC_PORT_BEACONING"

    def test_partial_irc_verb_no_signature_alert(self):
        """3-char partial IRC verb (e.g., 'PIN') without space → no signature alert."""
        rule = _make_irc_rule()
        pkt = _tcp_pkt(dport=6667, flags="ACK", payload=b"PIN:malformed")
        result = rule.check(pkt)
        # May be none or beaconing (not signature) — confirm not IRC_PROTOCOL_SIGNATURE
        if result is not None:
            assert result["evidence"]["classification"] != "IRC_PROTOCOL_SIGNATURE"

    def test_empty_payload_no_signature_alert(self):
        """Empty payload → no IRC_PROTOCOL_SIGNATURE; beaconing path still works."""
        rule = _make_irc_rule(threshold=3, window=60)
        # Establish that signature path is skipped for empty payload
        pkt = _tcp_pkt(dport=6667, flags="ACK", payload=b"", ts=1000.0)
        result = rule.check(pkt)
        # ACK with empty payload is not SYN, signature is empty → no alert expected
        assert result is None

    def test_multiple_sources_independent_state(self):
        """Two different source IPs each track beaconing state independently."""
        rule = _make_irc_rule(threshold=3, window=60, cooldown=10.0)
        src_a, src_b = "10.0.0.1", "10.0.0.2"
        # src_a: 2 SYNs
        for i in range(2):
            rule.check(_tcp_pkt(src=src_a, dport=6667, flags="SYN", ts=1000.0 + i))
        # src_b: reaches threshold independently
        result = None
        for i in range(3):
            result = rule.check(_tcp_pkt(src=src_b, dport=6667, flags="SYN", ts=1010.0 + i))
        assert result is not None
        assert result["src_ip"] == src_b
        # src_a is still 1 shy — adding one more SYN should trigger for src_a
        result_a = rule.check(_tcp_pkt(src=src_a, dport=6667, flags="SYN", ts=1020.0))
        assert result_a is not None
        assert result_a["src_ip"] == src_a


# ---------------------------------------------------------------------------
# Scapy normalizer compatibility, TCP flags, deduplication & cardinality bounds
# ---------------------------------------------------------------------------

class TestScapyNormalizerAndIntegerFlags:
    """Verifies integer TCP flag masks, sequence-based retransmission deduplication, and state bounds."""

    def test_integer_syn_flag_mask_fires_beaconing(self):
        """Integer flag mask 0x02 (SYN) correctly triggers IRC_PORT_BEACONING."""
        rule = _make_irc_rule(threshold=5, window=300)
        result = None
        for i in range(5):
            rec = {
                "type": "IP",
                "protocol": "TCP",
                "src_ip": "10.0.0.99",
                "dst_ip": "185.244.25.235",
                "src_port": 50000 + i,
                "dst_port": 6667,
                "tcp_flags": 0x02,  # integer SYN mask
                "initial_syn": True,
                "tcp_seq": 1000 * (i + 1),
                "timestamp": 1000.0 + i,
                "event_timestamp": 1000.0 + i,
            }
            result = rule.check(rec)
        assert result is not None
        assert result["evidence"]["classification"] == "IRC_PORT_BEACONING"
        assert result["evidence"]["connection_count"] >= 5

    def test_syn_ack_integer_flag_mask_ignored(self):
        """Integer flag mask 0x12 (SYN+ACK) is ignored as a server response, not a client connection attempt."""
        rule = _make_irc_rule(threshold=3)
        for i in range(5):
            rec = {
                "type": "IP",
                "protocol": "TCP",
                "src_ip": "185.244.25.235",
                "dst_ip": "10.0.0.99",
                "src_port": 6667,
                "dst_port": 50000 + i,
                "tcp_flags": 0x12,  # SYN (0x02) + ACK (0x10)
                "initial_syn": False,
                "timestamp": 1000.0 + i,
            }
            assert rule.check(rec) is None

    def test_ack_only_integer_mask_ignored(self):
        """Integer flag mask 0x10 (ACK) is ignored on beaconing path."""
        rule = _make_irc_rule(threshold=3)
        for i in range(5):
            rec = {
                "type": "IP",
                "protocol": "TCP",
                "src_ip": "10.0.0.99",
                "dst_ip": "185.244.25.235",
                "src_port": 50000,
                "dst_port": 6667,
                "tcp_flags": 0x10,  # ACK only
                "initial_syn": False,
                "timestamp": 1000.0 + i,
            }
            assert rule.check(rec) is None

    def test_syn_retransmission_same_seq_deduplicated(self):
        """Retransmissions with identical (src_port, tcp_seq) are deduplicated and do not count toward threshold."""
        rule = _make_irc_rule(threshold=3, window=300)
        # Attempt 1: src_port 51000, seq 12345
        rec1 = {
            "type": "IP", "protocol": "TCP", "src_ip": "10.0.0.5", "dst_ip": "185.244.25.235",
            "src_port": 51000, "dst_port": 6667, "tcp_flags": 0x02, "tcp_seq": 12345, "timestamp": 1000.0
        }
        assert rule.check(rec1) is None

        # Retransmissions of Attempt 1 (same src_port, same seq) at RTO intervals (1s, 3s, 6s)
        for ts in [1001.0, 1003.0, 1006.0, 1012.0]:
            dup = dict(rec1, timestamp=ts)
            assert rule.check(dup) is None, "SYN retransmission must not trigger an alert"

        # Now send Attempt 2 (new src_port, new seq)
        rec2 = dict(rec1, src_port=51001, tcp_seq=67890, timestamp=1015.0)
        assert rule.check(rec2) is None

        # Retransmission of Attempt 2
        assert rule.check(dict(rec2, timestamp=1016.0)) is None

        # Attempt 3 (new src_port, new seq) -> should now reach threshold=3 independent attempts
        rec3 = dict(rec1, src_port=51002, tcp_seq=99999, timestamp=1020.0)
        result = rule.check(rec3)
        assert result is not None
        assert result["evidence"]["classification"] == "IRC_PORT_BEACONING"
        assert result["evidence"]["connection_count"] == 3
        assert result["evidence"]["retransmissions_suppressed"] >= 4

    def test_beacon_interval_regularity_detection(self):
        """Regular periodic beacon intervals (e.g. every 60s) are classified as LIKELY_IRC_C2."""
        rule = _make_irc_rule(threshold=4, window=600)
        result = None
        # Send 4 SYNs exactly 60 seconds apart (typical IRC keepalive / ping timer)
        for i in range(4):
            rec = {
                "type": "IP", "protocol": "TCP", "src_ip": "10.0.0.88", "dst_ip": "185.244.25.235",
                "src_port": 40000 + i, "dst_port": 6667, "tcp_flags": 0x02, "tcp_seq": i * 1000,
                "timestamp": 1000.0 + (i * 60.0),
            }
            result = rule.check(rec)
        assert result is not None
        assert result["evidence"]["activity_assessment"] == "LIKELY_IRC_C2"
        assert result["severity"] == "high"
        assert result["evidence"]["avg_interval_s"] == 60.0
        assert result["evidence"]["std_interval_s"] == 0.0

    def test_inner_destinations_per_source_bounded(self):
        """Inner destination tracking per source is bounded to MAX_DESTS_PER_SOURCE."""
        rule = _make_irc_rule(threshold=10, max_sources=10)
        src = "10.0.0.77"
        # Send SYN to 200 distinct destinations from the same source
        for d in range(200):
            dst = f"185.244.25.{d % 250 + 1}"
            rec = {
                "type": "IP", "protocol": "TCP", "src_ip": src, "dst_ip": dst,
                "src_port": 45000 + d, "dst_port": 6667, "tcp_flags": 0x02,
                "timestamp": 1000.0 + d,
            }
            rule.check(rec)
        assert len(rule._connections[src]) <= rule.MAX_DESTS_PER_SOURCE

    def test_malformed_ports_and_timestamps_rejected(self):
        """Malformed port numbers and invalid timestamps are safely rejected."""
        rule = _make_irc_rule()
        # Invalid port
        assert rule.check({"protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "dst_port": "not_a_port"}) is None
        assert rule.check({"protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "dst_port": 70000}) is None
        assert rule.check({"protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "dst_port": 0}) is None
        # Invalid timestamp
        assert rule.check({"protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "dst_port": 6667, "timestamp": -50.0}) is None
        assert rule.check({"protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "dst_port": 6667, "timestamp": float("nan")}) is None

    def test_interleaved_syn_retransmissions_deduplicated(self):
        """Interleaved connection attempts with retransmissions across multiple ports are properly deduplicated."""
        rule = _make_irc_rule(threshold=3, window=300)
        # Conn 1: port 50001, seq 11111 at t=1000.0
        rec1 = {
            "type": "IP", "protocol": "TCP", "src_ip": "10.0.0.5", "dst_ip": "185.244.25.235",
            "src_port": 50001, "dst_port": 6667, "tcp_flags": 0x02, "tcp_seq": 11111, "timestamp": 1000.0
        }
        assert rule.check(rec1) is None

        # Conn 2 (interleaved): port 50002, seq 22222 at t=1001.0
        rec2 = {
            "type": "IP", "protocol": "TCP", "src_ip": "10.0.0.5", "dst_ip": "185.244.25.235",
            "src_port": 50002, "dst_port": 6667, "tcp_flags": 0x02, "tcp_seq": 22222, "timestamp": 1001.0
        }
        assert rule.check(rec2) is None

        # Retransmission of Conn 1 (interleaved past Conn 2!): port 50001, seq 11111 at t=1002.0
        rec1_retrans = dict(rec1, timestamp=1002.0)
        assert rule.check(rec1_retrans) is None, "Interleaved Conn 1 retransmission must be recognized and suppressed"

        # Retransmission of Conn 2: port 50002, seq 22222 at t=1003.0
        rec2_retrans = dict(rec2, timestamp=1003.0)
        assert rule.check(rec2_retrans) is None, "Interleaved Conn 2 retransmission must be recognized and suppressed"

        # Conn 3: port 50003, seq 33333 at t=1004.0 -> reaches threshold=3!
        rec3 = {
            "type": "IP", "protocol": "TCP", "src_ip": "10.0.0.5", "dst_ip": "185.244.25.235",
            "src_port": 50003, "dst_port": 6667, "tcp_flags": 0x02, "tcp_seq": 33333, "timestamp": 1004.0
        }
        result = rule.check(rec3)
        assert result is not None
        assert result["evidence"]["classification"] == "IRC_PORT_BEACONING"
        assert result["evidence"]["connection_count"] == 3
        assert result["evidence"]["retransmissions_suppressed"] == 2

    def test_benign_bot_substrings_not_classified_as_c2(self):
        """Benign words containing 'bot' substrings (robot, bottleneck, botany, bother, bottle) are not elevated to LIKELY_IRC_C2."""
        rule = _make_irc_rule()
        benign_messages = [
            b"PRIVMSG #general :I am fascinated by botany.\r\n",
            b"PRIVMSG #general :The robot arm malfunctioned.\r\n",
            b"PRIVMSG #general :We hit a network bottleneck today.\r\n",
            b"PRIVMSG #general :Please pass the water bottle.\r\n",
            b"PRIVMSG #general :Do not bother with the bottom drawer.\r\n",
            b"NICK botanist_alice\r\n",
        ]
        for msg in benign_messages:
            pkt = _tcp_pkt(dport=6667, flags="ACK", payload=msg)
            res = rule.check(pkt)
            assert res is not None
            assert res["evidence"]["classification"] == "IRC_PROTOCOL_SIGNATURE"
            assert res["evidence"]["activity_assessment"] == "IRC_PROTOCOL_OBSERVED"
            assert res["severity"] == "medium"
            assert res["confidence"] == "heuristic"
            # Clear cooldown for the next message in loop
            rule._cooldown_map.clear()

    def test_botnet_indicators_classified_as_likely_c2(self):
        """Genuine botnet tokens and command indicators trigger confirmed high-severity LIKELY_IRC_C2."""
        rule = _make_irc_rule()
        c2_messages = [
            b"JOIN #botnet\r\n",
            b"PRIVMSG #c2 :!ddos 10.0.0.1 80\r\n",
            b"PRIVMSG #channel :flood 192.168.1.1 53\r\n",
            b"PRIVMSG #channel :infect target\r\n",
            b"NICK bot_1234\r\n",
            b"NICK ircbot\r\n",
            b"PING :mirai.botnet.c2\r\n",
        ]
        for msg in c2_messages:
            pkt = _tcp_pkt(dport=6667, flags="ACK", payload=msg)
            res = rule.check(pkt)
            assert res is not None
            assert res["evidence"]["classification"] == "IRC_PROTOCOL_SIGNATURE"
            assert res["evidence"]["activity_assessment"] == "LIKELY_IRC_C2"
            assert res["severity"] == "high"
            assert res["confidence"] == "confirmed"
            rule._cooldown_map.clear()

    def test_recent_syns_table_bounded_and_pruned(self):
        """recent_syns table is capped at 64 entries and pruned after 60s."""
        rule = _make_irc_rule(threshold=100)
        # Send 80 distinct SYNs from distinct ports
        for i in range(80):
            rec = {
                "type": "IP", "protocol": "TCP", "src_ip": "10.0.0.5", "dst_ip": "185.244.25.235",
                "src_port": 40000 + i, "dst_port": 6667, "tcp_flags": 0x02, "tcp_seq": i * 10,
                "timestamp": 1000.0 + i * 0.1
            }
            rule.check(rec)
        entry = rule._connections["10.0.0.5"][("185.244.25.235", 6667)]
        assert len(entry["recent_syns"]) <= 64

        # Prune at t=1100 (well past 60s expiration)
        rule.prune_stale(1100.0)
        # State should be pruned
        assert len(entry["recent_syns"]) == 0
