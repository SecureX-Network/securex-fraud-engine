"""V2 fraud analysis endpoints."""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from src.api.v2.deps import require_auth
from src.fraud.service import FraudContext, FraudDetectionService

router = APIRouter()


class FraudSignalBody(BaseModel):
    type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    description: str = ""
    deterministic: bool = True
    data: dict[str, Any] = Field(default_factory=dict)


class FraudResponse(BaseModel):
    request_id: str
    credential_id: str
    is_suspicious: bool
    fraud_score: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: str
    signals: list[FraudSignalBody]
    explanation: str
    recommendation: str
    analysis_timestamp: str


class FraudV2Request(BaseModel):
    credential_id: str = Field(..., description="Credential identifier")
    credential_type: str = Field(..., description="Type of credential")
    issuer_id: str = Field(..., description="Issuer identifier")
    holder_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    fingerprints: list[str] = Field(default_factory=list)
    verification_history: list[dict[str, Any]] = Field(default_factory=list)
    document_signals: list[str] = Field(default_factory=list)
    blockchain_state: str | None = None


@router.post("/analyze", response_model=FraudResponse, dependencies=[Depends(require_auth)])
async def analyze_fraud(request: FraudV2Request):
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
    result = service.analyze_unified(
        context,
        tampering_signals=request.document_signals or None,
        blockchain_state=request.blockchain_state,
    )
    return FraudResponse(
        request_id=str(uuid4()),
        credential_id=result.credential_id,
        is_suspicious=result.is_suspicious,
        fraud_score=result.fraud_score,
        confidence=result.confidence,
        severity=result.severity,
        signals=[
            FraudSignalBody(
                type=s.type,
                confidence=s.confidence,
                severity=s.severity,
                description=s.description,
                deterministic=True,
                data=s.data,
            )
            for s in result.signals
        ],
        explanation=result.explanation,
        recommendation=result.recommendation,
        analysis_timestamp=datetime.now(timezone.utc).isoformat(),
    )
