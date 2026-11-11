"""
analytics/baselines.py
----------------------
Statistical network traffic baselining and anomaly analytics.
Computes Rolling Median, Median Absolute Deviation (MAD), and EWMA.
Includes baseline quarantine safeguards to prevent incident poisoning.
"""

import time
import math
import logging
from collections import deque
from typing import Any

logger = logging.getLogger(__name__)


def compute_median_and_mad(samples: list[float]) -> tuple[float, float]:
    """Compute sample median and Median Absolute Deviation (MAD)."""
    if not samples:
        return 0.0, 0.0
    sorted_s = sorted(samples)
    n = len(sorted_s)
    mid = n // 2
    if n % 2 == 1:
        med = sorted_s[mid]
    else:
        med = (sorted_s[mid - 1] + sorted_s[mid]) / 2.0

    deviations = sorted(abs(x - med) for x in samples)
    if n % 2 == 1:
        mad = deviations[mid]
    else:
        mad = (deviations[mid - 1] + deviations[mid]) / 2.0

    return float(med), float(mad)


class BaselineEngine:
    """
    Maintains empirical traffic baselines and flags statistically significant deviations.
    """

    METRIC_NAMES = (
        "packets_per_sec",
        "bytes_per_sec",
        "active_flows",
        "unique_source_ips",
        "unique_dest_ips",
        "dns_query_rate",
    )

    def __init__(self, conn=None, min_samples: int = 10,
                 window_size: int = 60, alpha_ewma: float = 0.2,
                 mad_threshold: float = 3.5, main_conn=None):
        self._conn = conn if conn is not None else main_conn
        self._min_samples = min_samples
        self._window_size = window_size
        self._alpha_ewma = alpha_ewma
        self._mad_threshold = mad_threshold

        # In-memory sample windows: metric_name -> deque of floats
        self._samples: dict[str, deque[float]] = {
            m: deque(maxlen=window_size) for m in self.METRIC_NAMES
        }
        # In-memory baseline records
        self._baselines: dict[str, dict[str, Any]] = {}
        for m in self.METRIC_NAMES:
            self._baselines[m] = {
                "metric_name": m,
                "sample_count": 0,
                "rolling_median": 0.0,
                "mad": 0.0,
                "ewma": 0.0,
                "mean": 0.0,
                "std": 0.0,
                "p95": 0.0,
                "min_val": 0.0,
                "max_val": 0.0,
                "last_updated": time.time(),
            }

        # Quarantined / frozen flag
        self._quarantined: bool = False
        self._quarantine_reason: str = ""

    def set_connection(self, conn):
        self._conn = conn

    def set_quarantine(self, active: bool, reason: str = ""):
        """Freeze baseline model updates during active incidents to prevent contamination."""
        self._quarantined = active
        self._quarantine_reason = reason if active else ""
        if active:
            logger.info(f"Baseline engine quarantined: {reason}")
        else:
            logger.info("Baseline engine resumed normal learning.")

    @property
    def is_quarantined(self) -> bool:
        return self._quarantined

    def update_metric(self, metric_name: str, value: float, is_suspicious: bool = False,
                      timestamp: float | None = None):
        """
        Record a periodic metric observation into the baseline model.
        Skips update if quarantined or marked suspicious.
        """
        ts = time.time() if timestamp is None else float(timestamp)
        if metric_name not in self._samples:
            self._samples[metric_name] = deque(maxlen=self._window_size)
            self._baselines[metric_name] = {
                "metric_name": metric_name,
                "sample_count": 0,
                "rolling_median": 0.0,
                "mad": 0.0,
                "ewma": 0.0,
                "mean": 0.0,
                "std": 0.0,
                "p95": 0.0,
                "min_val": 0.0,
                "max_val": 0.0,
                "last_updated": ts,
            }

        if self._quarantined or is_suspicious:
            return  # preserve integrity of historical baseline

        val = float(value)
        samples = self._samples[metric_name]
        samples.append(val)
        count = len(samples)

        med, mad = compute_median_and_mad(list(samples))
        mean = sum(samples) / count
        variance = sum((x - mean) ** 2 for x in samples) / count
        std = math.sqrt(variance)

        # 95th percentile
        sorted_s = sorted(samples)
        p95_idx = min(int(0.95 * count), count - 1)
        p95 = sorted_s[p95_idx]

        b = self._baselines[metric_name]
        prev_ewma = b["ewma"]
        ewma = val if b["sample_count"] == 0 else (self._alpha_ewma * val + (1.0 - self._alpha_ewma) * prev_ewma)

        b.update({
            "sample_count": b["sample_count"] + 1,
            "rolling_median": round(med, 2),
            "mad": round(mad, 2),
            "ewma": round(ewma, 2),
            "mean": round(mean, 2),
            "std": round(std, 2),
            "p95": round(p95, 2),
            "min_val": round(min(samples), 2),
            "max_val": round(max(samples), 2),
            "last_updated": ts,
        })

        # Persist to database if connection available
        if self._conn:
            try:
                cur = self._conn.cursor()
                cur.execute(
                    """
                    INSERT INTO traffic_baselines (
                        metric_name, sample_count, rolling_median, mad, ewma, mean, std, p95, min_val, max_val, last_updated
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(metric_name) DO UPDATE SET
                        sample_count = excluded.sample_count,
                        rolling_median = excluded.rolling_median,
                        mad = excluded.mad,
                        ewma = excluded.ewma,
                        mean = excluded.mean,
                        std = excluded.std,
                        p95 = excluded.p95,
                        min_val = excluded.min_val,
                        max_val = excluded.max_val,
                        last_updated = excluded.last_updated
                    """,
                    (
                        metric_name, b["sample_count"], b["rolling_median"], b["mad"],
                        b["ewma"], b["mean"], b["std"], b["p95"], b["min_val"],
                        b["max_val"], b["last_updated"]
                    )
                )
                self._conn.commit()
                cur.close()
            except Exception as exc:
                logger.debug(f"Baseline persistence error ({metric_name}): {exc}")

    def evaluate_anomaly(self, metric_name: str, value: float, flow_id: str | None = None,
                         timestamp: float | None = None) -> dict[str, Any]:
        """
        Evaluate if observed value represents a statistical traffic anomaly.
        Returns explainable anomaly dict.
        """
        ts = time.time() if timestamp is None else float(timestamp)
        b = self._baselines.get(metric_name)
        if not b:
            return {"is_anomaly": False, "metric_name": metric_name, "reason": "unknown_metric"}

        samples = self._samples.get(metric_name, deque())
        if len(samples) < self._min_samples:
            return {"is_anomaly": False, "metric_name": metric_name, "reason": "warmup_state"}

        med = b["rolling_median"]
        mad = b["mad"]
        val = float(value)

        # Baseline effective scale: use MAD, fallback to std, fallback to max(1.0, 0.1 * med)
        scale = mad if mad > 0.001 else (b["std"] if b["std"] > 0.001 else max(1.0, 0.1 * med))
        dev = abs(val - med)
        score = dev / scale

        if score >= self._mad_threshold and val > med:
            confidence = "high" if score >= (self._mad_threshold * 1.5) else "medium"
            severity = "high" if score >= (self._mad_threshold * 2.0) else "medium"
            pct_over = ((val - med) / max(med, 1.0)) * 100.0
            explanation = (
                f"Observed {val:.1f} {metric_name} is {score:.1f}x MAD above expected baseline "
                f"(median: {med:.1f} ± {scale:.1f}, +{pct_over:.0f}% deviation over {len(samples)} observations)."
            )

            anomaly = {
                "is_anomaly": True,
                "severity": severity,
                "timestamp": ts,
                "metric_name": metric_name,
                "observed_value": round(val, 2),
                "expected_value": round(med, 2),
                "deviation_score": round(score, 2),
                "method": "Median Absolute Deviation (MAD)",
                "confidence": confidence,
                "explanation": explanation,
                "related_flow_id": flow_id,
            }

            if self._conn:
                try:
                    cur = self._conn.cursor()
                    cur.execute(
                        """
                        INSERT INTO traffic_anomalies (
                            timestamp, metric_name, observed_value, expected_value, deviation_score,
                            method, confidence, explanation, related_flow_id
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            anomaly["timestamp"], anomaly["metric_name"], anomaly["observed_value"],
                            anomaly["expected_value"], anomaly["deviation_score"], anomaly["method"],
                            anomaly["confidence"], anomaly["explanation"], anomaly["related_flow_id"]
                        )
                    )
                    self._conn.commit()
                    cur.close()
                except Exception as exc:
                    logger.debug(f"Could not persist anomaly: {exc}")

            return anomaly

        return {
            "is_anomaly": False,
            "metric_name": metric_name,
            "observed_value": round(val, 2),
            "expected_value": round(med, 2),
            "deviation_score": round(score, 2),
        }

    def get_all_baselines(self) -> dict[str, Any]:
        """Return all current baseline models and status."""
        res = {}
        for m, b in self._baselines.items():
            item = b.copy()
            active_cnt = len(self._samples.get(m, []))
            item["active_sample_count"] = active_cnt
            item["median"] = item["rolling_median"]
            item["is_ready"] = (active_cnt >= self._min_samples)
            item["status"] = "quarantined" if self._quarantined else ("warmup" if not item["is_ready"] else "calibrated")
            res[m] = item
        out = {
            "quarantined": self._quarantined,
            "quarantine_active": self._quarantined,
            "quarantine_reason": self._quarantine_reason,
            "metrics": res,
        }
        out.update(res)
        return out

    def get_recent_anomalies(self, limit: int = 50) -> list[dict[str, Any]]:
        """Fetch recorded statistical anomalies from DB."""
        if not self._conn:
            return []
        try:
            cur = self._conn.cursor()
            cur.execute("SELECT * FROM traffic_anomalies ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = [dict(r) for r in cur.fetchall()]
            cur.close()
            return rows
        except Exception as exc:
            logger.debug(f"Could not read anomalies: {exc}")
            return []
