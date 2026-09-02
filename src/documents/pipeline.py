"""Document analysis pipeline.

Runs the secure end-to-end pipeline:
validate -> fingerprint -> metadata extraction -> text extraction/OCR ->
tampering analysis -> structured result. Temporary files are handled by the
caller and cleaned up; nothing about the uploaded content is permanently
stored here.
"""

from dataclasses import dataclass, field
from typing import Any

from src.config.settings import get_settings
from src.documents.extraction import TextExtractionService
from src.documents.extraction.service import OCRResult
from src.documents.metadata.service import DocumentMetadata, extract_metadata
from src.documents.validation.service import DetectionResult, validate_document
from src.fingerprint.service import FingerprintService
from src.tampering.models import TamperingResult
from src.tampering.service import TamperingContext, TamperingDetectionService


@dataclass
class DocumentAnalysisResult:
    """Structured result of the document analysis pipeline."""

    document_id: str
    validation: DetectionResult
    fingerprint: str
    metadata: DocumentMetadata
    extraction: OCRResult
    tampering: TamperingResult
    mime_type: str
    file_size: int
    analysis_id: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_id": self.document_id,
            "analysis_id": self.analysis_id,
            "mime_type": self.mime_type,
            "detected_extension": self.validation.extension,
            "file_size": self.file_size,
            "fingerprint": self.fingerprint,
            "fingerprint_algorithm": "sha256",
            "metadata": self.metadata.to_dict(),
            "text_extraction": self.extraction.to_dict(),
            "tampering": {
                "tampering_detected": self.tampering.is_tampered,
                "score": self.tampering.tampering_score,
                "confidence": self.tampering.confidence,
                "severity": self.tampering.severity,
                "signals": [
                    {
                        "type": i.type,
                        "confidence": i.confidence,
                        "severity": i.severity,
                        "description": i.description,
                        "deterministic": i.data.get("deterministic", True),
                    }
                    for i in self.tampering.indicators
                ],
                "explanation": self.tampering.explanation,
                "recommendation": self.tampering.recommendation,
            },
            "notes": self.notes,
        }


class DocumentAnalysisService:
    """Orchestrates the secure document analysis pipeline."""

    def __init__(self):
        self.fingerprint_service = FingerprintService()
        self.tampering_service = TamperingDetectionService()
        self.text_service = TextExtractionService()

    def analyze(
        self,
        document_id: str,
        data: bytes,
        filename: str | None = None,
        expected_fingerprint: str | None = None,
        supplied_metadata: dict[str, Any] | None = None,
    ) -> DocumentAnalysisResult:
        """Run the full document analysis pipeline with secure processing."""
        settings = get_settings()
        max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024

        # 1. Validate
        validation = validate_document(
            data,
            filename=filename,
            max_bytes=max_bytes,
            allowed_extensions=settings.ALLOWED_EXTENSIONS,
        )

        # 2. Fingerprint
        fingerprint = self.fingerprint_service.fingerprint_bytes(data, "sha256")

        # 3. Metadata
        metadata = extract_metadata(data, validation.mime_type)

        # 4. Text extraction / OCR (never mandatory, never fabricated)
        extraction = self.text_service.extract(data, validation.mime_type)

        # 5. Tampering analysis
        tamper_context = TamperingContext(
            document_id=document_id,
            document_type=validation.extension,
            document_hash=expected_fingerprint,
            metadata=metadata.to_dict(),
            content_hash=fingerprint,
            document_bytes=data,
            mime_type=validation.mime_type,
            extracted_text=extraction.text,
            supplied_metadata=supplied_metadata,
        )
        tampering = self.tampering_service.analyze(tamper_context)

        return DocumentAnalysisResult(
            document_id=document_id,
            validation=validation,
            fingerprint=fingerprint,
            metadata=metadata,
            extraction=extraction,
            tampering=tampering,
            mime_type=validation.mime_type,
            file_size=len(data),
        )
