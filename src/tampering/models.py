"""Tampering Detection Models"""

from dataclasses import dataclass


@dataclass
class TamperingIndicator:
    """A single tampering indicator."""

    type: str
    confidence: float = 0.0
    description: str = ""
    severity: str = "low"


@dataclass
class TamperingResult:
    """Result of tampering analysis."""

    document_id: str
    is_tampered: bool
    tampering_score: float
    indicators: list[TamperingIndicator]
    recommendation: str
