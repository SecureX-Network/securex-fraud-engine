"""Fraud Detection API Endpoints"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter
from pydantic import BaseModel, Field

from src.fraud.models import FraudSignal
from src.fraud.service import FraudContext, FraudDetectionService

router = APIRouter()


class FraudAnalysisRequest(BaseModel):
    """Request model for fraud analysis."""

    credential_id: str = Field(..., description="Credential identifier")
    credential_type: str = Field(..., description="Type of credential")
    issuer_id: str = Field(..., description="Issuer identifier")
    holder_id: str | None = Field(None, description="Credential holder identifier")
    metadata: dict[str, Any] | None = Field(
        default_factory=dict, description="Additional metadata"
    )
    fingerprints: list[str] | None = Field(
        default_factory=list, description="Credential fingerprints"
    )
    verification_history: list[dict[str, Any]] | None = Field(
        default_factory=list, description="Verification history"
    )


class FraudSignalResponse(BaseModel):
    """Individual fraud signal."""

    signal_type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    description: str
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")


class FraudAnalysisResponse(BaseModel):
    """Response model for fraud analysis."""

    request_id: str
    credential_id: str
    is_suspicious: bool
    fraud_score: float = Field(..., ge=0.0, le=1.0)
    signals: list[FraudSignalResponse]
    recommendation: str
    analysis_timestamp: str


def _signal_to_response(signal: FraudSignal) -> FraudSignalResponse:
    """Convert internal signal model to response model."""
    return FraudSignalResponse(
        signal_type=signal.type,
        confidence=signal.confidence,
        description=signal.description,
        severity=signal.severity,
    )


@router.post("/analyze", response_model=FraudAnalysisResponse)
async def analyze_fraud(request: FraudAnalysisRequest):
    """Analyze a credential for potential fraud indicators."""
    service = FraudDetectionService()

    context = FraudContext(
        credential_id=request.credential_id,
        credential_type=request.credential_type,
        issuer_id=request.issuer_id,
        holder_id=request.holder_id,
        metadata=request.metadata,
        fingerprints=request.fingerprints,
        verification_history=request.verification_history,
    )

    result = service.analyze(context)

    return FraudAnalysisResponse(
        request_id=str(uuid4()),
        credential_id=result.credential_id,
        is_suspicious=result.is_suspicious,
        fraud_score=result.fraud_score,
        signals=[_signal_to_response(s) for s in result.signals],
        recommendation=result.recommendation,
        analysis_timestamp=datetime.now(timezone.utc).isoformat(),
    )
