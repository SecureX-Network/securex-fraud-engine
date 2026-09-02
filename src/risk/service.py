"""Risk Analysis Service"""

from dataclasses import dataclass
from typing import Any

from .models import RiskFactor, RiskResult


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
        """Calculate risk score based on context."""
        factors = []
        total_weight = 0.0
        weighted_sum = 0.0

        for factor_fn in self.risk_factors:
            factor = factor_fn(context)
            if factor is not None:
                factors.append(factor)
                weighted_sum += factor.contribution
                total_weight += factor.weight

        risk_score = min(weighted_sum, 1.0) if total_weight > 0 else 0.1
        risk_level = self._get_risk_level(risk_score)

        return RiskResult(
            entity_type=context.entity_type,
            entity_id=context.entity_id,
            risk_score=risk_score,
            risk_level=risk_level,
            factors=factors,
            explanation=self._generate_explanation(factors),
        )

    def _entity_age_factor(self, context: RiskContext) -> RiskFactor | None:
        """Evaluate entity age as a risk factor."""
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
            )
        return None

    def _historical_behavior_factor(self, context: RiskContext) -> RiskFactor | None:
        """Evaluate historical behavior as a risk factor."""
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
        )

    def _signal_analysis_factor(self, context: RiskContext) -> RiskFactor | None:
        """Evaluate signals as a risk factor."""
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
        )

    def _get_risk_level(self, risk_score: float) -> str:
        """Get risk level from score."""
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.3:
            return "medium"
        else:
            return "low"

    def _generate_explanation(self, factors: list[RiskFactor]) -> str:
        """Generate explanation of risk assessment."""
        if not factors:
            return "No risk factors identified; default low risk assigned."
        factor_names = [f.factor_name for f in factors]
        return f"Risk analysis based on: {', '.join(factor_names)}"
