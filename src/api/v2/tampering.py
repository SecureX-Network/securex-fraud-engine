"""V2 tampering analysis endpoints."""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from src.api.v2.deps import require_auth
from src.tampering.service import TamperingContext, TamperingDetectionService

router = APIRouter()


class SignalBody(BaseModel):
    type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    description: str
    deterministic: bool = True


class TamperingRequest(BaseModel):
    document_id: str
    document_type: str = Field(..., description="pdf|png|jpg|jpeg")
    document_hash: str | None = None
    content_hash: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    document_bytes_b64: str | None = Field(None, description="Optional base64 document bytes for structural analysis")
    mime_type: str | None = None


class TamperingResponse(BaseModel):
    request_id: str
    document_id: str
    tampering_detected: bool
    confidence: float
    severity: str
    tampering_score: float = Field(..., ge=0.0, le=1.0)
    signals: list[SignalBody]
    explanation: str
    recommendation: str
    analysis_timestamp: str


@router.post("/analyze", response_model=TamperingResponse, dependencies=[Depends(require_auth)])
async def analyze_tampering(request: TamperingRequest):
    import base64

    service = TamperingDetectionService()
    doc_bytes = None
    if request.document_bytes_b64:
        try:
            doc_bytes = base64.b64decode(request.document_bytes_b64)
        except Exception:
            doc_bytes = None

    context = TamperingContext(
        document_id=request.document_id,
        document_type=request.document_type,
        document_hash=request.document_hash,
        metadata=request.metadata,
        content_hash=request.content_hash,
        document_bytes=doc_bytes,
        mime_type=request.mime_type,
    )
    result = service.analyze(context)

    return TamperingResponse(
        request_id=str(uuid4()),
        document_id=result.document_id,
        tampering_detected=result.is_tampered,
        confidence=result.confidence,
        severity=result.severity,
        tampering_score=result.tampering_score,
        signals=[
            SignalBody(
                type=i.type,
                confidence=i.confidence,
                severity=i.severity,
                description=i.description,
                deterministic=i.data.get("deterministic", True),
            )
            for i in result.indicators
        ],
        explanation=result.explanation,
        recommendation=result.recommendation,
        analysis_timestamp=datetime.now(timezone.utc).isoformat(),
    )
