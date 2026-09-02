"""Risk Analysis Models (V1 + V2)."""

from dataclasses import dataclass, field


@dataclass
class RiskFactor:
    """A single risk factor."""

    factor_name: str
    weight: float
    value: float
    contribution: float
    description: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class RiskResult:
    """Result of risk analysis (V1 + V2 fields)."""

    entity_type: str
    entity_id: str
    risk_score: float
    risk_level: str
    factors: list[RiskFactor]
    explanation: str
    severity: str = "low"
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    analysis_id: str | None = None
