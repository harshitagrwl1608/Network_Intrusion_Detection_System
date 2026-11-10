"""
NetGuard IDS — Evaluation Reporting Package
"""

from ids_project.evaluation.reporting.contract import (
    UnitOfAnalysis,
    EvidenceStatus,
    EvaluationVerdict,
    MetricDefinition,
    ProvenanceRecord,
    EvaluationResult,
)
from ids_project.evaluation.reporting.validator import EvaluationValidator
from ids_project.evaluation.reporting.builder import ReportBuilder, get_file_sha256

__all__ = [
    "UnitOfAnalysis",
    "EvidenceStatus",
    "EvaluationVerdict",
    "MetricDefinition",
    "ProvenanceRecord",
    "EvaluationResult",
    "EvaluationValidator",
    "ReportBuilder",
    "get_file_sha256",
]

