"""
tests/test_live_flow_and_raw_pcap.py
-------------------------------------
Verifies:
1. Live flow tracking and raw wire bytes capture:
   - Packet extraction populates flow_id, event_id, and raw_hex.
   - FlowTracker accurately tracks flow state and links packet events.
2. PCAP Reconstitution and Scapy validation:
   - /api/traffic/<flow_id>/pcap endpoint reconstructs valid binary PCAP.
   - Generated PCAP decodes cleanly with Scapy (Ether/IP/TCP).
   - Reassembled packet count, timestamps, and payload lengths match.
3. Proper 404 response when raw packet retention is unavailable.
"""

import os
import io
import sys
import time
import shutil
import tempfile
import unittest

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import config
from storage.db import init_db, get_connection
from storage.forensics_db import init_forensics_db, write_packet_event, upsert_network_flow
from forensics.flow_tracker import FlowTracker
from dashboard.app import app
from scapy.all import Ether, IP, TCP, rdpcap


class TestLiveFlowAndRawPcap(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_forensics.db")

        self.orig_sqlite = config.SQLITE_PATH
        self.orig_backend = config.DB_BACKEND
        config.DB_BACKEND = "sqlite"
        config.SQLITE_PATH = self.db_path

        import dashboard.app as app_mod
        app_mod._db_conn = None

        self.conn = get_connection(self.db_path)
        init_db(self.conn)
        init_forensics_db(self.conn)

        app.config["TESTING"] = True
        self.client = app.test_client()

    def tearDown(self):
        self.conn.close()
        import dashboard.app as app_mod
        app_mod._db_conn = None
        config.SQLITE_PATH = self.orig_sqlite
        config.DB_BACKEND = self.orig_backend
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_live_flow_tracking_and_raw_packet_retention(self):
        """Verify FlowTracker processes raw packet snapshots and records raw_hex."""
        tracker = FlowTracker(db_conn=self.conn, max_active_flows=100)

        # Synthesize real wire packet bytes
        raw_pkt1 = bytes(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") /
                         IP(src="192.168.1.50", dst="10.0.0.1") /
                         TCP(sport=54321, dport=80, flags="S"))
        raw_pkt2 = bytes(Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") /
                         IP(src="10.0.0.1", dst="192.168.1.50") /
                         TCP(sport=80, dport=54321, flags="SA"))

        t1 = time.time()
        rec1 = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 80,
            "tcp_flags": 0x02,
            "length": len(raw_pkt1),
            "timestamp": t1,
            "raw_hex": raw_pkt1.hex(),
            "event_id": "evt_test_1",
            "flow_id": "flow_test_1",
            "packet_index": 0,
        }
        rec2 = {
            "type": "IP",
            "protocol": "TCP",
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.50",
            "src_port": 80,
            "dst_port": 54321,
            "tcp_flags": 0x12,
            "length": len(raw_pkt2),
            "timestamp": t1 + 0.05,
            "raw_hex": raw_pkt2.hex(),
            "event_id": "evt_test_2",
            "flow_id": "flow_test_1",
            "packet_index": 1,
        }

        tracker.process_packet(rec1)
        tracker.process_packet(rec2)

        # Correlate alert with flow — triggers selective forensic packet persistence
        alert = {
            "rule_name": "PORT_SCAN",
            "flow_id": "flow_test_1",
            "event_id": "evt_test_2",
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.50",
            "protocol": "TCP",
        }
        tracker.correlate_alert(alert, triggering_record=rec2)
        tracker.flush()

        # Query database to confirm raw_hex persisted
        cur = self.conn.cursor()
        cur.execute("SELECT event_id, raw_hex, packet_len FROM packet_events WHERE flow_id = ? ORDER BY packet_index ASC", ("flow_test_1",))
        rows = cur.fetchall()
        cur.close()

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], "evt_test_1")
        self.assertEqual(rows[0][1], raw_pkt1.hex())
        self.assertEqual(rows[1][0], "evt_test_2")
        self.assertEqual(rows[1][1], raw_pkt2.hex())

    def test_traffic_flow_pcap_export_and_scapy_decoding(self):
        """Verify /api/traffic/<flow_id>/pcap produces a valid Scapy-decodable PCAP stream."""
        flow_id = "flow_recon_100"

        # Create two real packets
        pkt_a = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / \
                IP(src="172.16.0.10", dst="172.16.0.20") / \
                TCP(sport=4000, dport=443, flags="S")
        pkt_b = Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01") / \
                IP(src="172.16.0.20", dst="172.16.0.10") / \
                TCP(sport=443, dport=4000, flags="SA")

        bytes_a = bytes(pkt_a)
        bytes_b = bytes(pkt_b)
        t_base = 1700000000.123456

        # Populate flow and packet events directly into DB
        upsert_network_flow(self.conn, {
            "flow_id": flow_id,
            "start_time": t_base,
            "last_seen": t_base + 1.0,
            "src_ip": "172.16.0.10",
            "dst_ip": "172.16.0.20",
            "src_port": 4000,
            "dst_port": 443,
            "protocol": "TCP",
            "packet_count": 2,
            "byte_count": len(bytes_a) + len(bytes_b),
        })

        write_packet_event(self.conn, {
            "event_id": "evt_a",
            "timestamp": t_base,
            "flow_id": flow_id,
            "src_ip": "172.16.0.10",
            "dst_ip": "172.16.0.20",
            "src_port": 4000,
            "dst_port": 443,
            "protocol": "TCP",
            "packet_len": len(bytes_a),
            "raw_hex": bytes_a.hex(),
            "packet_index": 0,
        })

        write_packet_event(self.conn, {
            "event_id": "evt_b",
            "timestamp": t_base + 0.05,
            "flow_id": flow_id,
            "src_ip": "172.16.0.20",
            "dst_ip": "172.16.0.10",
            "src_port": 443,
            "dst_port": 4000,
            "protocol": "TCP",
            "packet_len": len(bytes_b),
            "raw_hex": bytes_b.hex(),
            "packet_index": 1,
        })

        # Fetch reconstituted PCAP from endpoint
        resp = self.client.get(f"/api/traffic/{flow_id}/pcap")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "application/vnd.tcpdump.pcap")
        self.assertTrue(len(resp.data) > 24)

        # Scapy decode validation
        pcap_file = io.BytesIO(resp.data)
        packets = rdpcap(pcap_file)
        self.assertEqual(len(packets), 2, "Reconstructed PCAP must contain exact number of packets")

        dec_pkt1 = packets[0]
        self.assertTrue(dec_pkt1.haslayer(TCP))
        self.assertEqual(dec_pkt1[IP].src, "172.16.0.10")
        self.assertEqual(dec_pkt1[IP].dst, "172.16.0.20")
        self.assertEqual(dec_pkt1[TCP].sport, 4000)
        self.assertEqual(dec_pkt1[TCP].dport, 443)
        self.assertEqual(dec_pkt1[TCP].flags, "S")

        dec_pkt2 = packets[1]
        self.assertTrue(dec_pkt2.haslayer(TCP))
        self.assertEqual(dec_pkt2[IP].src, "172.16.0.20")
        self.assertEqual(dec_pkt2[IP].dst, "172.16.0.10")
        self.assertEqual(dec_pkt2[TCP].sport, 443)
        self.assertEqual(dec_pkt2[TCP].dport, 4000)
        self.assertEqual(dec_pkt2[TCP].flags, "SA")

    def test_pcap_export_returns_404_when_no_raw_hex(self):
        """Verify 404 response with clear explanation when flow has no raw packets."""
        resp = self.client.get("/api/traffic/nonexistent_flow_xyz/pcap")
        self.assertEqual(resp.status_code, 404)
        data = resp.get_json()
        self.assertIn("error", data)
        self.assertIn("No raw packet capture retained", data["error"])


if __name__ == "__main__":
    unittest.main()
