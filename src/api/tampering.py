"""Tampering Detection API Endpoints"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter
from pydantic import BaseModel, Field

from src.tampering.models import TamperingIndicator
from src.tampering.service import TamperingContext, TamperingDetectionService

router = APIRouter()


class TamperingAnalysisRequest(BaseModel):
    """Request model for tampering analysis."""

    document_id: str = Field(..., description="Document identifier")
    document_type: str = Field(..., description="Document type (pdf, image, etc.)")
    document_hash: str | None = Field(None, description="Known document hash for comparison")
    metadata: dict[str, Any] | None = Field(default_factory=dict, description="Document metadata")
    content_hash: str | None = Field(None, description="Content hash for integrity check")


class TamperingIndicatorResponse(BaseModel):
    """Individual tampering indicator."""

    indicator_type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    description: str
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")


class TamperingAnalysisResponse(BaseModel):
    """Response model for tampering analysis."""

    request_id: str
    document_id: str
    is_tampered: bool
    tampering_score: float = Field(..., ge=0.0, le=1.0)
    indicators: list[TamperingIndicatorResponse]
    recommendation: str
    analysis_timestamp: str


def _indicator_to_response(indicator: TamperingIndicator) -> TamperingIndicatorResponse:
    """Convert internal indicator model to response model."""
    return TamperingIndicatorResponse(
        indicator_type=indicator.type,
        confidence=indicator.confidence,
        description=indicator.description,
        severity=indicator.severity,
    )


@router.post("/analyze", response_model=TamperingAnalysisResponse)
async def analyze_tampering(request: TamperingAnalysisRequest):
    """Analyze a document for potential tampering."""
    service = TamperingDetectionService()

    context = TamperingContext(
        document_id=request.document_id,
        document_type=request.document_type,
        document_hash=request.document_hash,
        metadata=request.metadata,
        content_hash=request.content_hash,
    )

    result = service.analyze(context)

    return TamperingAnalysisResponse(
        request_id=str(uuid4()),
        document_id=result.document_id,
        is_tampered=result.is_tampered,
        tampering_score=result.tampering_score,
        indicators=[_indicator_to_response(i) for i in result.indicators],
        recommendation=result.recommendation,
        analysis_timestamp=datetime.now(timezone.utc).isoformat(),
    )
