"""Tampering Detection Models (V1 + V2)."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TamperingIndicator:
    """A single tampering indicator."""

    type: str
    confidence: float = 0.0
    description: str = ""
    severity: str = "low"
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class TamperingResult:
    """Result of tampering analysis."""

    document_id: str
    is_tampered: bool
    tampering_score: float
    indicators: list[TamperingIndicator]
    recommendation: str
    confidence: float = 0.0
    severity: str = "low"
    explanation: str = ""
    fingerprint: str | None = None
    analysis_id: str | None = None
