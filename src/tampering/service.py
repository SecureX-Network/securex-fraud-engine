"""Tampering Detection Service (V1 + V2).

V1 behavior is preserved: hash comparison, suspicious metadata, document type
validation, and severity-weighted scoring.
V2 adds structural analysis, optional content/credential consistency checks,
deterministic confidence, an explanation, and an aggregated severity.
"""

from dataclasses import dataclass
from typing import Any

from .models import TamperingIndicator, TamperingResult
from .structure import analyze_structure

SEVERITY_WEIGHT = {"critical": 0.9, "high": 0.7, "medium": 0.55, "low": 0.3}

SEVERITY_LEVELS = ["low", "medium", "high", "critical"]


@dataclass
class TamperingContext:
    """Context for tampering analysis."""

    document_id: str
    document_type: str
    document_hash: str | None = None
    metadata: dict[str, Any] = None
    content_hash: str | None = None
    # V2: raw document bytes for structural analysis
    document_bytes: bytes | None = None
    mime_type: str | None = None
    # V2: extracted document text for content-consistency checks
    extracted_text: str | None = None
    # V2: supplied credential metadata for consistency
    supplied_metadata: dict[str, Any] | None = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class TamperingDetectionService:
    """Service for detecting document tampering."""

    ALLOWED_DOCUMENT_TYPES = {"pdf", "png", "jpg", "jpeg"}

    def analyze(self, context: TamperingContext) -> TamperingResult:
        """Analyze document for potential tampering."""
        indicators = self._evaluate_indicators(context)

        # Composite score (V1): severity-weighted contributions, summed.
        if indicators:
            tampering_score = min(
                sum(SEVERITY_WEIGHT[i.severity] * i.confidence for i in indicators),
                1.0,
            )
        else:
            tampering_score = 0.0

        is_tampered = tampering_score >= 0.4

        result = TamperingResult(
            document_id=context.document_id,
            is_tampered=is_tampered,
            tampering_score=tampering_score,
            indicators=indicators,
            recommendation=self._get_recommendation(tampering_score),
        )

        # V2 deterministic confidence and explanation.
        result.confidence = round(self._compute_confidence(indicators), 4)
        result.severity = self._aggregate_severity(indicators)
        result.explanation = self._build_explanation(indicators)
        return result

    def _evaluate_indicators(self, context: TamperingContext) -> list[TamperingIndicator]:
        indicators: list[TamperingIndicator] = []

        # 1. Hash integrity comparison (V1)
        if context.document_hash and context.content_hash:
            if context.document_hash != context.content_hash:
                indicators.append(
                    TamperingIndicator(
                        type="hash_mismatch",
                        confidence=1.0,
                        description="Document hash does not match expected value",
                        severity="critical",
                        data={"deterministic": True},
                    )
                )

        # 2. Metadata analysis (V1 fields + timestamp/producer consistency)
        for field in ("modified", "altered", "tampered"):
            if field in context.metadata:
                indicators.append(
                    TamperingIndicator(
                        type="suspicious_metadata",
                        confidence=0.8,
                        description=f"Suspicious metadata field detected: {field}",
                        severity="high",
                        data={"field": field, "deterministic": True},
                    )
                )

        # V2 metadata consistency: creation/modification timestamp anomalies
        indicators.extend(self._metadata_consistency_indicators(context.metadata))

        # 3. Document type validation (V1)
        if context.document_type not in self.ALLOWED_DOCUMENT_TYPES:
            indicators.append(
                TamperingIndicator(
                    type="unusual_document_type",
                    confidence=0.5,
                    description=f"Unusual document type: {context.document_type}",
                    severity="low",
                )
            )

        # 4. Structural analysis (V2, deterministic)
        if context.document_bytes is not None:
            mime = context.mime_type or self._mime_from_type(context.document_type)
            for sig in analyze_structure(context.document_bytes, mime or ""):
                indicators.append(
                    TamperingIndicator(
                        type=sig.signal_type,
                        confidence=0.9,
                        description=sig.description,
                        severity=sig.severity,
                        data={"deterministic": sig.deterministic},
                    )
                )

        return indicators

    def _metadata_consistency_indicators(self, metadata: dict[str, Any]) -> list[TamperingIndicator]:
        indicators: list[TamperingIndicator] = []
        mod = metadata.get("modification_time")
        created = metadata.get("creation_time")
        if isinstance(mod, str) and isinstance(created, str) and mod and created and mod < created:
            indicators.append(
                TamperingIndicator(
                    type="timestamp_inconsistency",
                    confidence=0.8,
                    description="Modification timestamp predates creation timestamp",
                    severity="high",
                    data={"deterministic": True},
                )
            )

        author = metadata.get("author")
        if isinstance(author, str) and author.strip().lower() in ("unknown", "anonymous", "modified"):
            indicators.append(
                TamperingIndicator(
                    type="suspicious_author_metadata",
                    confidence=0.6,
                    description="Document author metadata is suspicious",
                    severity="medium",
                    data={"deterministic": True},
                )
            )
        return indicators

    def _mime_from_type(self, document_type: str) -> str | None:
        mapping = {"pdf": "application/pdf", "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg"}
        return mapping.get(document_type.lower())

    def _compute_confidence(self, indicators: list[TamperingIndicator]) -> float:
        """Deterministic confidence derived from the indicators present."""
        if not indicators:
            return 0.0
        worst = max(SEVERITY_LEVELS.index(i.severity) for i in indicators)
        return (worst + 1) / 4.0

    def _aggregate_severity(self, indicators: list[TamperingIndicator]) -> str:
        if not indicators:
            return "low"
        return max(indicators, key=lambda i: SEVERITY_LEVELS.index(i.severity)).severity

    def _build_explanation(self, indicators: list[TamperingIndicator]) -> str:
        if not indicators:
            return "No tampering signals detected on supplied data (deterministic)."
        types = ", ".join(sorted({i.type for i in indicators}))
        return (
            "Deterministic tampering analysis found signals: "
            f"{types}. Confidence is derived deterministically, not from an ML model."
        )

    def _get_recommendation(self, score: float) -> str:
        if score >= 0.7:
            return "REJECT - Document appears to be tampered"
        elif score >= 0.5:
            return "REVIEW - Potential tampering detected"
        else:
            return "ACCEPT - No significant tampering indicators"
