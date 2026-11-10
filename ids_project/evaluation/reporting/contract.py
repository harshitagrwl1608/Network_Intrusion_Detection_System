"""
NetGuard IDS — Evaluation Reporting Standard Contract
Defines canonical data structures, evidence taxonomies, and metric specifications
for all independent evaluations and holdout audits.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class UnitOfAnalysis(str, Enum):
    PACKET = "packet"
    FLOW = "flow"
    EVENT = "event"
    ALERT = "alert"
    CAMPAIGN = "campaign"


class EvidenceStatus(str, Enum):
    MEASURED = "MEASURED"
    DERIVED = "DERIVED"
    INFERRED = "INFERRED"
    NOT_MEASURED = "NOT_MEASURED"
    UNVERIFIED = "UNVERIFIED"


class EvaluationVerdict(str, Enum):
    SUPPORTED = "SUPPORTED — EMPIRICALLY CONFIRMED"
    SUPPORTED_WITH_LIMITATIONS = "SUPPORTED WITH LIMITATIONS — BOUNDED TO OBSERVED SCOPE"
    INCONCLUSIVE = "INCONCLUSIVE — A REQUIRED RECONCILIATION GATE FAILED"
    REJECTED = "REJECTED — EVIDENCE CONTRADICTS CLAIMS"


@dataclass
class MetricDefinition:
    name: str
    unit: UnitOfAnalysis
    status: EvidenceStatus
    numerator: Optional[float] = None
    denominator: Optional[float] = None
    value: Optional[float] = None
    percentage: Optional[float] = None
    definition: str = ""
    ground_truth_source: str = ""
    treatment_of_unknowns: str = ""


@dataclass
class ProvenanceRecord:
    dataset_name: str
    pcap_file: str
    pcap_sha256: str
    pcap_size_bytes: int
    ground_truth_file: str
    ground_truth_sha256: str
    ground_truth_size_bytes: int
    db_file: str
    db_sha256: str
    db_size_bytes: int
    git_commit: str
    git_branch: str
    engine_fingerprint: str
    capture_start_ts: Optional[float] = None
    capture_end_ts: Optional[float] = None


@dataclass
class EvaluationResult:
    audit_name: str
    audit_version: str
    timestamp_utc: str
    provenance: ProvenanceRecord
    tier_counts: Dict[str, int] = field(default_factory=dict)
    total_alerts: int = 0
    metrics: Dict[str, MetricDefinition] = field(default_factory=dict)
    validation_checks: Dict[str, bool] = field(default_factory=dict)
    validation_failures: List[str] = field(default_factory=list)
    verdict: EvaluationVerdict = EvaluationVerdict.INCONCLUSIVE
    verdict_rationale: str = ""
    unsupported_categories: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    export_files: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    extra_metadata: Dict[str, Any] = field(default_factory=dict)

    def is_gate_passed(self, gate_name: str) -> bool:
        return self.validation_checks.get(gate_name, False)

