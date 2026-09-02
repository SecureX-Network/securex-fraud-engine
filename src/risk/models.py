"""Risk Analysis Models"""

from dataclasses import dataclass


@dataclass
class RiskFactor:
    """A single risk factor."""

    factor_name: str
    weight: float
    value: float
    contribution: float
    description: str


@dataclass
class RiskResult:
    """Result of risk analysis."""

    entity_type: str
    entity_id: str
    risk_score: float
    risk_level: str
    factors: list[RiskFactor]
    explanation: str
