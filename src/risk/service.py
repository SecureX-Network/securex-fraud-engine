"""Risk Analysis Service (V1 + V2)."""

from dataclasses import dataclass
from typing import Any

from .models import RiskFactor, RiskResult

SEVERITY_LEVELS = ["low", "medium", "high", "critical"]


@dataclass
class RiskContext:
    """Context for risk analysis."""

    entity_type: str
    entity_id: str
    context: dict[str, Any]
    signals: list[dict[str, Any]]


class RiskAnalysisService:
    """Service for computing risk scores."""

    def __init__(self):
        self.risk_factors = [
            self._entity_age_factor,
            self._historical_behavior_factor,
            self._signal_analysis_factor,
        ]

    def analyze(self, context: RiskContext) -> RiskResult:
        """Calculate risk score based on context (deterministic)."""
        factors = []
        weighted_sum = 0.0
        total_weight = 0.0

        for factor_fn in self.risk_factors:
            factor = factor_fn(context)
            if factor is not None:
                factors.append(factor)
                weighted_sum += factor.contribution
                total_weight += factor.weight

        risk_score = min(weighted_sum, 1.0) if total_weight > 0 else 0.1
        risk_level = self._get_risk_level(risk_score)

        result = RiskResult(
            entity_type=context.entity_type,
            entity_id=context.entity_id,
            risk_score=round(risk_score, 4),
            risk_level=risk_level,
            factors=factors,
            explanation=self._generate_explanation(factors),
        )

        # V2 fields
        result.severity = risk_level
        result.evidence = self._collect_evidence(factors)
        result.recommendation = self._get_recommendation(risk_level)
        return result

    def _entity_age_factor(self, context: RiskContext) -> RiskFactor | None:
        if "entity_age_days" not in context.context:
            return None

        age_days = context.context["entity_age_days"]
        if age_days < 7:
            return RiskFactor(
                factor_name="entity_age",
                weight=0.5,
                value=0.8,
                contribution=0.4,
                description="Entity is less than 7 days old",
                evidence=["entity_age_days < 7"],
            )
        return None

    def _historical_behavior_factor(self, context: RiskContext) -> RiskFactor | None:
        if "historical_risk_score" not in context.context:
            return None

        hist_score = context.context["historical_risk_score"]
        factor_value = min(hist_score, 1.0)
        return RiskFactor(
            factor_name="historical_behavior",
            weight=0.7,
            value=factor_value,
            contribution=factor_value * 0.7,
            description=f"Historical risk score: {hist_score}",
            evidence=["historical_risk_score present"],
        )

    def _signal_analysis_factor(self, context: RiskContext) -> RiskFactor | None:
        if not context.signals:
            return None

        high_risk = sum(1 for s in context.signals if s.get("risk_level") == "high")
        factor_value = min(high_risk / len(context.signals), 1.0)
        return RiskFactor(
            factor_name="signal_analysis",
            weight=0.5,
            value=factor_value,
            contribution=factor_value * 0.5,
            description=f"{high_risk} high-risk signals out of {len(context.signals)}",
            evidence=[f"{high_risk}/{len(context.signals)} high-risk signals"],
        )

    def _get_risk_level(self, risk_score: float) -> str:
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.3:
            return "medium"
        else:
            return "low"

    def _generate_explanation(self, factors: list[RiskFactor]) -> str:
        if not factors:
            return "No risk factors identified; default low risk assigned."
        factor_names = [f.factor_name for f in factors]
        return f"Risk analysis based on: {', '.join(factor_names)}"

    def _collect_evidence(self, factors: list[RiskFactor]) -> list[str]:
        evidence: list[str] = []
        for f in factors:
            evidence.extend(f.evidence)
        if not evidence:
            return ["no contributing factors"]
        return evidence

    def _get_recommendation(self, risk_level: str) -> str:
        mapping = {
            "critical": "BLOCK - Immediate action required",
            "high": "REVIEW - High risk, manual review recommended",
            "medium": "MONITOR - Moderate risk, monitor activity",
            "low": "ACCEPT - Low risk",
        }
        return mapping[risk_level]
