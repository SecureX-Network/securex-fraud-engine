"""V2 risk analysis endpoints."""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from src.api.v2.deps import require_auth
from src.risk.service import RiskAnalysisService, RiskContext

router = APIRouter()


class RiskFactorBody(BaseModel):
    factor_name: str
    weight: float = Field(..., ge=0.0, le=1.0)
    value: float = Field(..., ge=0.0, le=1.0)
    contribution: float = Field(..., ge=0.0, le=1.0)
    description: str
    evidence: list[str] = Field(default_factory=list)


class RiskResponse(BaseModel):
    request_id: str
    entity_type: str
    entity_id: str
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: str = Field(..., pattern="^(low|medium|high|critical)$")
    severity: str
    factors: list[RiskFactorBody]
    evidence: list[str]
    recommendation: str
    explanation: str
    analysis_timestamp: str


class RiskV2Request(BaseModel):
    entity_type: str
    entity_id: str
    context: dict[str, Any] = Field(default_factory=dict)
    signals: list[dict[str, Any]] = Field(default_factory=list)


@router.post("/score", response_model=RiskResponse, dependencies=[Depends(require_auth)])
async def score_risk(request: RiskV2Request):
    service = RiskAnalysisService()
    result = service.analyze(
        RiskContext(
            entity_type=request.entity_type,
            entity_id=request.entity_id,
            context=request.context,
            signals=request.signals,
        )
    )
    return RiskResponse(
        request_id=str(uuid4()),
        entity_type=result.entity_type,
        entity_id=result.entity_id,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        severity=result.severity,
        factors=[
            RiskFactorBody(
                factor_name=f.factor_name,
                weight=f.weight,
                value=f.value,
                contribution=f.contribution,
                description=f.description,
                evidence=f.evidence,
            )
            for f in result.factors
        ],
        evidence=result.evidence,
        recommendation=result.recommendation,
        explanation=result.explanation,
        analysis_timestamp=datetime.now(timezone.utc).isoformat(),
    )
