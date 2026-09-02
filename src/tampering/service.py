"""Tampering Detection Service"""

from dataclasses import dataclass
from typing import Any

from .models import TamperingIndicator, TamperingResult

SEVERITY_WEIGHT = {"critical": 0.9, "high": 0.7, "medium": 0.55, "low": 0.3}


@dataclass
class TamperingContext:
    """Context for tampering analysis."""
    document_id: str
    document_type: str
    document_hash: str | None = None
    metadata: dict[str, Any] = None
    content_hash: str | None = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class TamperingDetectionService:
    """Service for detecting document tampering.

    V1: Rule-based hash comparison and metadata analysis.
    Future: Image analysis, OCR-assisted checks, structural analysis.
    """

    ALLOWED_DOCUMENT_TYPES = {"pdf", "png", "jpg", "jpeg"}

    def analyze(self, context: TamperingContext) -> TamperingResult:
        """Analyze document for potential tampering."""
        indicators = self._evaluate_indicators(context)

        # Calculate composite tampering score using severity-weighted contributions.
        if indicators:
            tampering_score = min(
                sum(SEVERITY_WEIGHT[i.severity] * i.confidence for i in indicators),
                1.0,
            )
        else:
            tampering_score = 0.0

        is_tampered = tampering_score >= 0.4

        return TamperingResult(
            document_id=context.document_id,
            is_tampered=is_tampered,
            tampering_score=tampering_score,
            indicators=indicators,
            recommendation=self._get_recommendation(tampering_score),
        )

    def _evaluate_indicators(self, context: TamperingContext) -> list[TamperingIndicator]:
        """Evaluate all tampering indicators."""
        indicators = []

        # Hash comparison
        if context.document_hash and context.content_hash:
            if context.document_hash != context.content_hash:
                indicators.append(TamperingIndicator(
                    type="hash_mismatch",
                    confidence=0.95,
                    description="Document hash does not match expected value",
                    severity="critical",
                ))

        # Metadata analysis
        suspicious_fields = ["modified", "altered", "tampered"]
        for field in suspicious_fields:
            if field in context.metadata:
                indicators.append(TamperingIndicator(
                    type="suspicious_metadata",
                    confidence=0.8,
                    description=f"Suspicious metadata field detected: {field}",
                    severity="high",
                ))

        # Document type validation
        if context.document_type not in self.ALLOWED_DOCUMENT_TYPES:
            indicators.append(TamperingIndicator(
                type="unusual_document_type",
                confidence=0.5,
                description=f"Unusual document type: {context.document_type}",
                severity="low",
            ))

        return indicators

    def _get_recommendation(self, score: float) -> str:
        """Generate recommendation based on tampering score."""
        if score >= 0.7:
            return "REJECT - Document appears to be tampered"
        elif score >= 0.5:
            return "REVIEW - Potential tampering detected"
        else:
            return "ACCEPT - No significant tampering indicators"
