"""Fraud Detection Models"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FraudContext:
    """Context for fraud analysis."""
    credential_id: str
    credential_type: str
    issuer_id: str
    holder_id: str | None = None
    metadata: dict[str, Any] = None
    fingerprints: list[str] = None
    verification_history: list[dict[str, Any]] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.fingerprints is None:
            self.fingerprints = []
        if self.verification_history is None:
            self.verification_history = []


@dataclass
class FraudSignal:
    """A single fraud detection signal."""
    type: str
    confidence: float = 0.0
    description: str = ""
    severity: str = "low"
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class FraudAnalysisResult:
    """Result of fraud analysis."""
    credential_id: str
    is_suspicious: bool
    fraud_score: float
    signals: list[FraudSignal]
    recommendation: str
