"""Persistence record types.

These records capture only necessary analysis data. They never include
uploaded document contents, raw credentials, or unnecessary PII.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AnalysisRecord:
    """A unified analysis record."""

    analysis_id: str
    status: str
    timestamp: str = field(default_factory=_utcnow)
    risk: dict[str, Any] = field(default_factory=dict)
    fraud: dict[str, Any] = field(default_factory=dict)
    tampering: dict[str, Any] = field(default_factory=dict)
    fingerprint: dict[str, Any] = field(default_factory=dict)
    evidence_references: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class FingerprintRecord:
    """A stored fingerprint reference."""

    reference_id: str
    kind: str  # document | credential | analysis
    algorithm: str
    fingerprint: str
    timestamp: str = field(default_factory=_utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisSubResult:
    """A generic sub-result record (tampering/risk/fraud)."""

    analysis_id: str
    result_type: str  # tampering | risk | fraud | audit
    payload: dict[str, Any]
    timestamp: str = field(default_factory=_utcnow)
