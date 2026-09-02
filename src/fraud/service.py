"""SecureX Fraud Detection Service"""

from .models import FraudAnalysisResult, FraudContext
from .rules import FraudRuleEngine

SEVERITY_WEIGHT = {"critical": 0.9, "high": 0.7, "medium": 0.5, "low": 0.3}


class FraudDetectionService:
    """Service for detecting credential fraud."""

    def __init__(self):
        self.rule_engine = FraudRuleEngine()

    def analyze(self, context: FraudContext) -> FraudAnalysisResult:
        """Analyze credential for fraud indicators."""
        signals = self.rule_engine.evaluate(context)

        # Calculate composite fraud score using severity-weighted contributions.
        # A single critical/high signal is sufficient to raise suspicion, so
        # contributions SUM rather than average (avoiding dilution).
        if signals:
            fraud_score = min(
                sum(SEVERITY_WEIGHT[s.severity] * s.confidence for s in signals),
                1.0,
            )
        else:
            fraud_score = 0.0

        is_suspicious = fraud_score >= 0.4

        return FraudAnalysisResult(
            credential_id=context.credential_id,
            is_suspicious=is_suspicious,
            fraud_score=fraud_score,
            signals=signals,
            recommendation=self._get_recommendation(fraud_score),
        )

    def _get_recommendation(self, fraud_score: float) -> str:
        """Generate recommendation based on fraud score."""
        if fraud_score >= 0.7:
            return "BLOCK - High fraud risk detected"
        elif fraud_score >= 0.5:
            return "REVIEW - Moderate fraud risk, manual review recommended"
        else:
            return "PASS - Low fraud risk"
