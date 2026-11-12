"""
forensics/flow_tracker.py
-------------------------
Real-time bounded network flow session tracking, aggregation, and alert correlation.
Maintains $O(1)$ LRU in-memory active flow state and flushes aggregated flow records
to the database, avoiding synchronous per-packet DB writes.
"""

import time
import math
import uuid
import hashlib
import ipaddress
import logging
import threading
from collections import OrderedDict, deque
from typing import Any

from storage.forensics_db import upsert_network_flow, write_packet_event

logger = logging.getLogger(__name__)

# RFC-1918 / loopback / link-local definitions for direction determination
_INTERNAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
)


def is_ip_internal(ip: str | None) -> bool:
    """Return True if IP is in private/internal address space."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _INTERNAL_NETWORKS)
    except ValueError:
        return False


def determine_direction(src_ip: str | None, dst_ip: str | None) -> str:
    """Classify flow traffic direction."""
    src_int = is_ip_internal(src_ip)
    dst_int = is_ip_internal(dst_ip)
    if src_int and dst_int:
        return "internal"
    elif src_int and not dst_int:
        return "outbound"
    elif not src_int and dst_int:
        return "inbound"
    return "external"


def compute_flow_id(src_ip: str | None, dst_ip: str | None,
                    src_port: int | None, dst_port: int | None,
                    protocol: str | None) -> str:
    """
    Compute a deterministic canonical bidirectional 5-tuple flow identifier.
    Traffic in either direction maps to the identical flow_id.
    """
    s_ip = str(src_ip or "0.0.0.0")
    d_ip = str(dst_ip or "0.0.0.0")
    s_pt = int(src_port or 0)
    d_pt = int(dst_port or 0)
    proto = str(protocol or "RAW").upper()

    ep1 = (s_ip, s_pt)
    ep2 = (d_ip, d_pt)
    if ep1 > ep2:
        ep1, ep2 = ep2, ep1

    raw = f"{ep1[0]}:{ep1[1]}-{ep2[0]}:{ep2[1]}-{proto}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"flow_{digest}"


class FlowTracker:
    """
    Thread-safe, bounded in-memory flow tracker and alert correlator.
    """

    def __init__(self, conn=None, max_active_flows: int = 8192,
                 flow_idle_timeout: float = 60.0, max_context_packets: int = 8,
                 db_conn=None, db=None):
        self._conn = conn if conn is not None else (db_conn if db_conn is not None else db)
        self._max_active_flows = max_active_flows
        self._flow_idle_timeout = flow_idle_timeout
        self._max_context_packets = max_context_packets

        self._lock = threading.Lock()
        # flow_id -> flow_dict
        self._active_flows: OrderedDict[str, dict[str, Any]] = OrderedDict()
        # flow_id -> deque of recent packet snapshots
        self._flow_context: dict[str, deque[dict[str, Any]]] = {}
        # Set of flow_ids marked dirty that need flushing to DB
        self._dirty_flow_ids: set[str] = set()

        import queue as _queue
        self._write_queue: _queue.Queue = _queue.Queue(maxsize=4096)
        self._stop_event = threading.Event()
        self._writer_thread = threading.Thread(target=self._persistence_worker, daemon=True, name="flow-tracker-writer")
        self._writer_thread.start()

        self._last_prune = time.time()
        self._stats = {
            "packets_processed": 0,
            "flows_created": 0,
            "flows_flushed": 0,
            "alerts_correlated": 0,
        }

    def _persistence_worker(self):
        """Asynchronous database writer draining flow and packet event records off capture hot path."""
        import queue as _queue
        while not self._stop_event.is_set():
            try:
                item_type, data = self._write_queue.get(timeout=0.2)
                if item_type == "stop":
                    self._write_queue.task_done()
                    break
                if self._conn is not None:
                    try:
                        if item_type == "flow":
                            upsert_network_flow(self._conn, data)
                            self._stats["flows_flushed"] += 1
                        elif item_type == "event":
                            write_packet_event(self._conn, data)
                    except Exception as exc:
                        logger.debug(f"Flow async write error ({item_type}): {exc}")
                self._write_queue.task_done()
            except _queue.Empty:
                pass

    def set_connection(self, conn):
        """Update database connection reference."""
        with self._lock:
            self._conn = conn

    def process_packet(self, record: dict, pcap_segment_id: str | None = None,
                       packet_index: int | None = None) -> tuple[str, str]:
        """
        Ingest a packet record, update flow counters, and return (event_id, flow_id).
        Assigns 'event_id' and 'flow_id' directly into the record dict.
        """
        # Ensure event_id
        event_id = record.get("event_id")
        if not event_id:
            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            record["event_id"] = event_id

        src_ip = record.get("src_ip")
        dst_ip = record.get("dst_ip")
        src_port = record.get("src_port")
        dst_port = record.get("dst_port")
        protocol = record.get("protocol") or record.get("type") or "RAW"

        flow_id = record.get("flow_id")
        if not flow_id:
            flow_id = compute_flow_id(src_ip, dst_ip, src_port, dst_port, protocol)
            record["flow_id"] = flow_id

        pkt_time = record.get("event_timestamp")
        if pkt_time is None:
            pkt_time = record.get("timestamp", time.time())
        try:
            pkt_time = float(pkt_time)
            if not math.isfinite(pkt_time):
                pkt_time = time.time()
        except (ValueError, TypeError):
            pkt_time = time.time()

        pkt_len = int(record.get("ip_len") or record.get("payload_len") or len(record.get("payload") or b"") or 64)
        flags = record.get("tcp_flags")

        with self._lock:
            self._stats["packets_processed"] += 1

            if flow_id in self._active_flows:
                flow = self._active_flows[flow_id]
                self._active_flows.move_to_end(flow_id)
                flow["last_seen"] = max(flow["last_seen"], pkt_time)
                flow["packet_count"] += 1
                flow["byte_count"] += pkt_len
            else:
                # Evict oldest flow if cache saturated
                if len(self._active_flows) >= self._max_active_flows:
                    old_id, old_flow = self._active_flows.popitem(last=False)
                    self._flush_flow_locked(old_flow)
                    self._flow_context.pop(old_id, None)
                    self._dirty_flow_ids.discard(old_id)

                direction = determine_direction(src_ip, dst_ip)
                flow = {
                    "flow_id": flow_id,
                    "start_time": pkt_time,
                    "last_seen": pkt_time,
                    "src_ip": str(src_ip or "0.0.0.0"),
                    "dst_ip": str(dst_ip or "0.0.0.0"),
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": str(protocol),
                    "packet_count": 1,
                    "byte_count": pkt_len,
                    "tcp_flags": None,
                    "interface": record.get("interface"),
                    "src_mac": record.get("src_mac"),
                    "dst_mac": record.get("dst_mac"),
                    "direction": direction,
                    "hostname": None,
                    "app_protocol": None,
                    "dns_query": None,
                    "http_method": None,
                    "http_host": None,
                    "http_uri": None,
                    "tls_sni": None,
                    "alert_count": 0,
                    "last_alert_id": None,
                    "pcap_segment_id": pcap_segment_id,
                }
                self._active_flows[flow_id] = flow
                self._flow_context[flow_id] = deque(maxlen=self._max_context_packets)
                self._stats["flows_created"] += 1

            self._dirty_flow_ids.add(flow_id)

            # Metadata enrichment
            if record.get("dns_query") and not flow.get("dns_query"):
                flow["dns_query"] = str(record["dns_query"])
                flow["app_protocol"] = "DNS"
            if record.get("http_method") and not flow.get("http_method"):
                flow["http_method"] = str(record["http_method"])
                flow["app_protocol"] = "HTTP"
            if record.get("http_host") and not flow.get("http_host"):
                flow["http_host"] = str(record["http_host"])
            if record.get("http_uri") and not flow.get("http_uri"):
                flow["http_uri"] = str(record["http_uri"])
            if record.get("tls_sni") and not flow.get("tls_sni"):
                flow["tls_sni"] = str(record["tls_sni"])
                flow["app_protocol"] = "TLS"

            # Retain lightweight packet context in sliding buffer
            payload_sample = None
            raw_payload = record.get("payload")
            if raw_payload:
                if isinstance(raw_payload, bytes):
                    payload_sample = raw_payload[:96].decode("latin-1", errors="replace")
                else:
                    payload_sample = str(raw_payload)[:96]

            pkt_snapshot = {
                "event_id": event_id,
                "timestamp": pkt_time,
                "flow_id": flow_id,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "packet_len": pkt_len,
                "tcp_flags": flags,
                "payload_preview": payload_sample,
                "raw_hex": record.get("raw_hex"),
                "pcap_segment_id": pcap_segment_id,
                "packet_index": packet_index,
            }
            if flow_id in self._flow_context:
                self._flow_context[flow_id].append(pkt_snapshot)

        return event_id, flow_id

    def correlate_alert(self, alert: dict, triggering_record: dict | None = None, alert_id: int | None = None):
        """
        Correlate an alert with its flow and persist the forensic packet event sequence.
        """
        flow_id = alert.get("flow_id")
        event_id = alert.get("event_id")

        if not flow_id and triggering_record:
            flow_id = triggering_record.get("flow_id")
            alert["flow_id"] = flow_id
        if not event_id and triggering_record:
            event_id = triggering_record.get("event_id")
            alert["event_id"] = event_id

        if not flow_id:
            flow_id = compute_flow_id(
                alert.get("src_ip"), alert.get("dst_ip"),
                alert.get("src_port"), alert.get("dst_port"),
                alert.get("protocol")
            )
            alert["flow_id"] = flow_id

        with self._lock:
            self._stats["alerts_correlated"] += 1
            flow = self._active_flows.get(flow_id)
            if flow:
                flow["alert_count"] += 1
                if alert_id is not None:
                    flow["last_alert_id"] = alert_id
                self._dirty_flow_ids.add(flow_id)

            # Persist the triggering packet and context packets to packet_events table
            if self._conn is not None:
                context_pkts = list(self._flow_context.get(flow_id, []))
                for pkt in context_pkts:
                    evt_data = pkt.copy()
                    if pkt.get("event_id") == event_id or alert_id is not None:
                        evt_data["alert_id"] = alert_id
                    try:
                        self._write_queue.put_nowait(("event", evt_data))
                    except Exception:
                        try:
                            write_packet_event(self._conn, evt_data)
                        except Exception as exc:
                            logger.debug(f"Could not persist packet event {evt_data.get('event_id')}: {exc}")

    def flush(self):
        """Flush all modified active flows to the database and drain persistence queue."""
        with self._lock:
            if not self._conn or not self._dirty_flow_ids:
                return
            for f_id in list(self._dirty_flow_ids):
                flow = self._active_flows.get(f_id)
                if flow:
                    self._flush_flow_locked(flow)
            self._dirty_flow_ids.clear()
        try:
            self._write_queue.join()
        except Exception:
            pass

    def _flush_flow_locked(self, flow: dict):
        """Internal helper to enqueue a flow upsert off the capture hot path."""
        if not self._conn:
            return
        flow_copy = flow.copy()
        try:
            self._write_queue.put_nowait(("flow", flow_copy))
        except Exception:
            try:
                upsert_network_flow(self._conn, flow_copy)
                self._stats["flows_flushed"] += 1
            except Exception as exc:
                logger.warning(f"Flow flush error ({flow.get('flow_id')}): {exc}")

    def stop(self):
        """Stop background persistence worker thread cleanly."""
        self.flush()
        self._stop_event.set()
        try:
            self._write_queue.put_nowait(("stop", None))
        except Exception:
            pass
        if self._writer_thread.is_alive():
            self._writer_thread.join(timeout=2.0)

    def prune_stale(self, now: float | None = None):
        """Prune inactive flows older than flow_idle_timeout and flush them."""
        curr = now if now is not None else time.time()
        with self._lock:
            expired_ids = []
            for f_id, flow in self._active_flows.items():
                if curr - flow["last_seen"] > self._flow_idle_timeout:
                    expired_ids.append(f_id)

            for f_id in expired_ids:
                flow = self._active_flows.pop(f_id)
                self._flush_flow_locked(flow)
                self._flow_context.pop(f_id, None)
                self._dirty_flow_ids.discard(f_id)

    def get_stats(self) -> dict[str, Any]:
        """Return diagnostic metrics."""
        with self._lock:
            st = self._stats.copy()
            st["active_flows_count"] = len(self._active_flows)
            st["dirty_flows_count"] = len(self._dirty_flow_ids)
            return st
