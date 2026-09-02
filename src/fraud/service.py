"""SecureX Fraud Detection Service (V1 + V2)."""

from .models import FraudAnalysisResult, FraudContext, FraudSignal
from .rules import FraudRuleEngine

SEVERITY_WEIGHT = {"critical": 0.9, "high": 0.7, "medium": 0.5, "low": 0.3}
SEVERITY_LEVELS = ["low", "medium", "high", "critical"]


class FraudDetectionService:
    """Service for detecting credential fraud."""

    def __init__(self):
        self.rule_engine = FraudRuleEngine()

    def analyze(self, context: FraudContext) -> FraudAnalysisResult:
        """Analyze credential for fraud indicators (V1 behavior preserved)."""
        signals = self.rule_engine.evaluate(context)
        return self._finalize(context.credential_id, signals)

    def analyze_unified(
        self,
        context: FraudContext,
        document_signals: list[FraudSignal] | None = None,
        blockchain_state: str | None = None,
        tampering_signals: list[str] | None = None,
    ) -> FraudAnalysisResult:
        """Analyze with V2 multi-signal aggregation.

        Combines the deterministic V1 credential rules with V2 document,
        tampering, and blockchain signals.
        """
        signals = self.rule_engine.evaluate(context)

        # Document / consistency signals
        if document_signals:
            signals.extend(document_signals)

        # Tampering signals -> fraud signals
        if tampering_signals:
            signals.append(
                FraudSignal(
                    type="document_tampering",
                    confidence=0.8,
                    description=f"Document tampering signals present: {', '.join(tampering_signals)}",
                    severity="critical" if "hash_mismatch" in tampering_signals else "high",
                )
            )

        # Blockchain evidence signals (never fabricated; driven by real provider state)
        if blockchain_state in ("REVOKED", "SUSPENDED", "VERIFICATION_FAILED", "NOT_FOUND"):
            signals.append(
                FraudSignal(
                    type="blockchain_evidence_mismatch",
                    confidence=0.9,
                    description=f"Blockchain evidence indicates credential is not cleanly verifiable: {blockchain_state}",
                    severity="critical" if blockchain_state in ("REVOKED", "SUSPENDED") else "high",
                    data={"blockchain_state": blockchain_state},
                )
            )

        return self._finalize(context.credential_id, signals, include_evidence=True)

    def _finalize(
        self,
        credential_id: str,
        signals: list[FraudSignal],
        include_evidence: bool = False,
    ) -> FraudAnalysisResult:
        # Composite fraud score using severity-weighted contributions (V1).
        if signals:
            fraud_score = min(
                sum(SEVERITY_WEIGHT[s.severity] * s.confidence for s in signals),
                1.0,
            )
        else:
            fraud_score = 0.0

        is_suspicious = fraud_score >= 0.4

        result = FraudAnalysisResult(
            credential_id=credential_id,
            is_suspicious=is_suspicious,
            fraud_score=round(fraud_score, 4),
            signals=signals,
            recommendation=self._get_recommendation(fraud_score),
        )

        result.confidence = self._compute_confidence(signals)
        result.severity = self._aggregate_severity(signals)
        result.explanation = self._build_explanation(signals)
        return result

    def _compute_confidence(self, signals: list[FraudSignal]) -> float:
        if not signals:
            return 0.0
        worst = max(SEVERITY_LEVELS.index(s.severity) for s in signals)
        return round((worst + 1) / 4.0, 4)

    def _aggregate_severity(self, signals: list[FraudSignal]) -> str:
        if not signals:
            return "low"
        return max(signals, key=lambda s: SEVERITY_LEVELS.index(s.severity)).severity

    def _build_explanation(self, signals: list[FraudSignal]) -> str:
        if not signals:
            return "No fraud signals detected (deterministic rules)."
        types = ", ".join(sorted({s.type for s in signals}))
        return (
            "Deterministic fraud analysis identified signals: "
            f"{types}. Scores derive from severity-weighted deterministic rules, not an ML model."
        )

    def _get_recommendation(self, fraud_score: float) -> str:
        if fraud_score >= 0.7:
            return "BLOCK - High fraud risk detected"
        elif fraud_score >= 0.5:
            return "REVIEW - Moderate fraud risk, manual review recommended"
        else:
            return "PASS - Low fraud risk"
