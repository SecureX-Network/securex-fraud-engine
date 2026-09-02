"""Risk Analysis API Endpoints"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter
from pydantic import BaseModel, Field

from src.risk.models import RiskFactor
from src.risk.service import RiskAnalysisService, RiskContext

router = APIRouter()


class RiskAnalysisRequest(BaseModel):
    """Request model for risk analysis."""

    entity_type: str = Field(..., description="Entity type (credential, issuer, holder)")
    entity_id: str = Field(..., description="Entity identifier")
    context: dict[str, Any] | None = Field(
        default_factory=dict, description="Analysis context"
    )
    signals: list[dict[str, Any]] | None = Field(
        default_factory=list, description="Input signals"
    )


class RiskFactorResponse(BaseModel):
    """Individual risk factor."""

    factor_name: str
    weight: float = Field(..., ge=0.0, le=1.0)
    value: float = Field(..., ge=0.0, le=1.0)
    contribution: float = Field(..., ge=0.0, le=1.0)
    description: str


class RiskAnalysisResponse(BaseModel):
    """Response model for risk analysis."""

    request_id: str
    entity_type: str
    entity_id: str
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: str = Field(..., pattern="^(low|medium|high|critical)$")
    factors: list[RiskFactorResponse]
    explanation: str
    analysis_timestamp: str


def _factor_to_response(factor: RiskFactor) -> RiskFactorResponse:
    """Convert internal factor model to response model."""
    return RiskFactorResponse(
        factor_name=factor.factor_name,
        weight=factor.weight,
        value=factor.value,
        contribution=factor.contribution,
        description=factor.description,
    )


@router.post("/score", response_model=RiskAnalysisResponse)
async def calculate_risk_score(request: RiskAnalysisRequest):
    """Calculate a risk score for an entity using deterministic rules."""
    service = RiskAnalysisService()

    context = RiskContext(
        entity_type=request.entity_type,
        entity_id=request.entity_id,
        context=request.context,
        signals=request.signals,
    )

    result = service.analyze(context)

    return RiskAnalysisResponse(
        request_id=str(uuid4()),
        entity_type=result.entity_type,
        entity_id=result.entity_id,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        factors=[_factor_to_response(f) for f in result.factors],
        explanation=result.explanation,
        analysis_timestamp=datetime.now(timezone.utc).isoformat(),
    )
