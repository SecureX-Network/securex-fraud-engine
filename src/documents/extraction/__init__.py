"""TextExtractionService - high level text extraction orchestrator.

Wraps a ``DocumentExtractor`` and provides a stable service boundary for the
rest of the engine (documents pipeline, tampering, credential consistency).
"""

from src.documents.extraction.pipeline import DefaultDocumentExtractor
from src.documents.extraction.service import DocumentExtractor, OCRResult
from src.documents.ocr.provider import OCRProvider


class TextExtractionService:
    """High-level text extraction service."""

    def __init__(self, extractor: DocumentExtractor | None = None):
        self.extractor = extractor or DefaultDocumentExtractor()

    def extract(self, data: bytes, mime_type: str) -> OCRResult:
        """Extract text from document bytes, never fabricating content."""
        return self.extractor.extract(data, mime_type)

    def with_ocr(self, ocr_provider: OCRProvider) -> "TextExtractionService":
        """Return a service backed by the given OCR provider."""
        from src.documents.extraction.pipeline import DefaultDocumentExtractor

        return TextExtractionService(DefaultDocumentExtractor(ocr_provider))
