"""V2 document analysis endpoint (secure upload pipeline)."""

from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from src.api.v2.deps import require_auth
from src.config.settings import get_settings
from src.documents.pipeline import DocumentAnalysisService
from src.security.file_security import validate_file_size

router = APIRouter()


class DocumentAnalysisResponse(BaseModel):
    request_id: str
    document_id: str
    mime_type: str
    detected_extension: str
    file_size: int
    fingerprint: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    text_extraction: dict[str, Any] = Field(default_factory=dict)
    tampering: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


@router.post("/analyze", response_model=DocumentAnalysisResponse, dependencies=[Depends(require_auth)])
async def analyze_document(
    file: UploadFile = File(...),
    document_id: str | None = Form(default=None),
):
    settings = get_settings()
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Document is empty")

    validate_file_size(len(data), max_bytes)

    service = DocumentAnalysisService()
    doc_id = document_id or f"doc_{uuid4().hex}"
    result = service.analyze(
        document_id=doc_id,
        data=data,
        filename=file.filename,
        expected_fingerprint=None,
    )

    return DocumentAnalysisResponse(
        request_id=str(uuid4()),
        document_id=doc_id,
        mime_type=result.mime_type,
        detected_extension=result.validation.extension,
        file_size=result.file_size,
        fingerprint=result.fingerprint,
        metadata=result.metadata.to_dict(),
        text_extraction=result.extraction.to_dict(),
        tampering={
            "tampering_detected": result.tampering.is_tampered,
            "score": result.tampering.tampering_score,
            "confidence": result.tampering.confidence,
            "severity": result.tampering.severity,
            "signals": [
                {
                    "type": i.type,
                    "confidence": i.confidence,
                    "severity": i.severity,
                    "description": i.description,
                }
                for i in result.tampering.indicators
            ],
            "explanation": result.tampering.explanation,
            "recommendation": result.tampering.recommendation,
        },
        notes=result.notes,
    )
