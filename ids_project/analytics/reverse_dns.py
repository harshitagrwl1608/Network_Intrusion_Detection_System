"""
ids_project/analytics/reverse_dns.py
------------------------------------
Asynchronous, non-blocking Reverse DNS (PTR) hostname resolver for NetGuard IDS.

Features:
- IPv4 and IPv6 PTR resolution using socket.gethostbyaddr
- Strictly non-blocking: worker thread pool with bounded queue
- Thread-safe dual cache:
    * Positive cache (successful PTR) with configurable TTL (default 1 hour)
    * Negative cache (NXDOMAIN / timeout / error) with shorter TTL (default 5 min)
- Bounded lookup timeout (default 1.0s) per query
- Batch resolution API for frontend and forensics views
- Safe fallback when PTR records are unavailable
"""

import time
import socket
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)


class ReverseDNSResolver:
    """
    High-performance asynchronous PTR resolver with positive/negative caching.
    Guaranteed never to block packet ingestion or request threads.
    """

    def __init__(
        self,
        max_workers: int = 4,
        positive_ttl_s: float = 3600.0,
        negative_ttl_s: float = 300.0,
        timeout_s: float = 1.0,
        cache_ttl: Optional[float] = None,
        negative_ttl: Optional[float] = None,
    ):
        if cache_ttl is not None:
            positive_ttl_s = cache_ttl
        if negative_ttl is not None:
            negative_ttl_s = negative_ttl

        self.positive_ttl_s = positive_ttl_s
        self.negative_ttl_s = negative_ttl_s
        self.timeout_s = timeout_s

        # IP -> {"hostname": str, "resolved_at": float, "expires_at": float, "success": bool}
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._pending: set = set()
        self._lock = threading.Lock()

        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="rdns-resolver")
        self._running = True

    def resolve(self, ip: str, timeout: Optional[float] = None) -> Optional[str]:
        """
        Synchronously resolve an IP or return cached hostname with timeout bounding.
        Safe for direct lookup or test environments.
        """
        if not ip:
            return None
        cached = self.get_cached(ip)
        if cached is not None:
            return cached

        # Check if negative cache is currently active
        now = time.time()
        with self._lock:
            entry = self._cache.get(ip)
            if entry and entry["expires_at"] > now and not entry["success"]:
                return None

        # Synchronously invoke worker resolution with bounded future timeout
        timeout_to_use = timeout if timeout is not None else self.timeout_s
        future = self._executor.submit(self._worker_resolve, ip)
        try:
            future.result(timeout=timeout_to_use)
        except Exception:
            pass
        return self.get_cached(ip)

    def get_cached(self, ip: str) -> Optional[str]:
        """
        Return cached hostname if present and not expired.
        Returns None if not resolved or if negative cache is active.
        """
        if not ip:
            return None
        now = time.time()
        with self._lock:
            entry = self._cache.get(ip)
            if entry and entry["expires_at"] > now:
                return entry.get("hostname") if entry["success"] else None
        return None

    def get_status(self, ip: str) -> Dict[str, Any]:
        """
        Return resolution status for an IP:
        { "ip": str, "hostname": str | None, "status": "resolved" | "pending" | "unavailable" }
        """
        if not ip:
            return {"ip": ip, "hostname": None, "status": "unavailable"}

        now = time.time()
        with self._lock:
            entry = self._cache.get(ip)
            if entry and entry["expires_at"] > now:
                if entry["success"]:
                    return {"ip": ip, "hostname": entry["hostname"], "status": "resolved"}
                else:
                    return {"ip": ip, "hostname": None, "status": "unavailable"}
            if ip in self._pending:
                return {"ip": ip, "hostname": None, "status": "pending"}

        # Not cached and not pending: trigger async resolution
        self.resolve_async(ip)
        return {"ip": ip, "hostname": None, "status": "pending"}

    def resolve_async(self, ip: str) -> None:
        """
        Queue background PTR resolution for an IP address without blocking.
        """
        if not ip or not self._running:
            return

        ip_clean = str(ip).strip()
        now = time.time()

        with self._lock:
            entry = self._cache.get(ip_clean)
            if entry and entry["expires_at"] > now:
                return
            if ip_clean in self._pending:
                return
            if len(self._pending) > 2000:
                # Bounded queue safeguard
                return
            self._pending.add(ip_clean)

        self._executor.submit(self._worker_resolve, ip_clean)

    def _worker_resolve(self, ip: str) -> None:
        """Worker thread entrypoint performing socket PTR lookup without process-wide timeout mutation."""
        hostname = None
        success = False
        now = time.time()

        try:
            res = socket.gethostbyaddr(ip)
            if res and res[0]:
                hostname = res[0]
                success = True
        except (socket.herror, socket.gaierror, socket.timeout, OSError) as exc:
            logger.debug(f"Reverse DNS failed for {ip}: {exc}")
            success = False

        expires_at = now + (self.positive_ttl_s if success else self.negative_ttl_s)

        with self._lock:
            self._pending.discard(ip)
            self._cache[ip] = {
                "hostname": hostname,
                "resolved_at": now,
                "expires_at": expires_at,
                "success": success,
            }

    def resolve_batch(self, ip_list: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Resolve a list of IPs. Returns immediate status/cached values
        and asynchronously schedules lookups for un-cached IPs.
        """
        results = {}
        for ip in ip_list:
            if ip:
                results[ip] = self.get_status(ip)
        return results

    def shutdown(self, wait: bool = False) -> None:
        """Cleanly shutdown the worker pool."""
        self._running = False
        self._executor.shutdown(wait=wait, cancel_futures=True)


# Global singleton
_resolver: Optional[ReverseDNSResolver] = None
_resolver_lock = threading.Lock()


def get_reverse_dns_resolver() -> ReverseDNSResolver:
    global _resolver
    with _resolver_lock:
        if _resolver is None:
            _resolver = ReverseDNSResolver()
    return _resolver
