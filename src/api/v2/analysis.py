"""V2 unified analysis endpoints.

POST /api/v2/analysis      -> run a unified analysis
GET  /api/v2/analysis/{id} -> retrieve a stored analysis
GET  /api/v2/analysis/{id}/evidence -> retrieve evidence references
"""

import base64
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.analysis.service import AnalysisRequest, AnalysisService
from src.api.v2.deps import require_auth

router = APIRouter()

# Shared analysis service so in-memory persistence persists across requests
# within the process (dev/test substitute for the planned PostgreSQL store).
_ANALYSIS_SERVICE: "AnalysisService" | None = None


def _get_service() -> "AnalysisService":
    global _ANALYSIS_SERVICE
    if _ANALYSIS_SERVICE is None:
        _ANALYSIS_SERVICE = AnalysisService()
    return _ANALYSIS_SERVICE



class AnalysisCreateRequest(BaseModel):
    credential_id: str | None = None
    credential_type: str | None = None
    issuer_id: str | None = None
    holder_id: str | None = None
    credential_metadata: dict[str, Any] = Field(default_factory=dict)
    fingerprints: list[str] = Field(default_factory=list)
    verification_history: list[dict[str, Any]] = Field(default_factory=list)
    # Document (bytes are base64-encoded in the request)
    document_id: str | None = None
    document_b64: str | None = Field(None, description="Base64-encoded document bytes")
    document_filename: str | None = None
    expected_document_fingerprint: str | None = None
    # Credential consistency
    supplied_credential_fields: dict[str, Any] = Field(default_factory=dict)
    extracted_credential_fields: dict[str, Any] = Field(default_factory=dict)
    # Risk
    entity_type: str = "credential"
    risk_context: dict[str, Any] = Field(default_factory=dict)
    risk_signals: list[dict[str, Any]] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    analysis_id: str
    status: str
    timestamp: str
    risk: dict[str, Any] | None = None
    fraud: dict[str, Any] | None = None
    tampering: dict[str, Any] | None = None
    fingerprint: dict[str, Any] | None = None
    document: dict[str, Any] | None = None
    blockchain: dict[str, Any] | None = None
    consistency: list[dict[str, Any]] = Field(default_factory=list)
    evidence_references: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class EvidenceResponse(BaseModel):
    analysis_id: str
    evidence_references: list[str]
    fingerprint: dict[str, Any] | None = None


@router.post("", response_model=AnalysisResponse, status_code=201, dependencies=[Depends(require_auth)])
async def create_analysis(request: AnalysisCreateRequest):
    service = _get_service()
    doc_bytes = None
    if request.document_b64:
        try:
            doc_bytes = base64.b64decode(request.document_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 document payload")

    analysis_request = AnalysisRequest(
        credential_id=request.credential_id,
        credential_type=request.credential_type,
        issuer_id=request.issuer_id,
        holder_id=request.holder_id,
        credential_metadata=request.credential_metadata,
        fingerprints=request.fingerprints,
        verification_history=request.verification_history,
        document_id=request.document_id,
        document_bytes=doc_bytes,
        document_filename=request.document_filename,
        expected_document_fingerprint=request.expected_document_fingerprint,
        supplied_credential_fields=request.supplied_credential_fields,
        extracted_credential_fields=request.extracted_credential_fields,
        entity_type=request.entity_type,
        risk_context=request.risk_context,
        risk_signals=request.risk_signals,
    )
    result = service.run(analysis_request)
    return AnalysisResponse(**result.to_dict())


@router.get("/{analysis_id}", response_model=AnalysisResponse, dependencies=[Depends(require_auth)])
async def get_analysis(analysis_id: str):
    service = _get_service()
    result = service.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return AnalysisResponse(**result.to_dict())


@router.get("/{analysis_id}/evidence", response_model=EvidenceResponse, dependencies=[Depends(require_auth)])
async def get_analysis_evidence(analysis_id: str):
    service = _get_service()
    result = service.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return EvidenceResponse(
        analysis_id=analysis_id,
        evidence_references=result.evidence_references,
        fingerprint=result.fingerprint,
    )
