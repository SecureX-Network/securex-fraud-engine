"""Document text extraction service.

Provides an abstraction (``DocumentExtractor``) with a graceful default. The
engine does NOT fabricate extracted content: if no real extraction library or
OCR provider is available, extraction reports that the capability is not
installed rather than returning invented text.
"""

from abc import ABC, abstractmethod

from src.documents.ocr.noop import NoOCRProvider
from src.documents.ocr.provider import OCRProvider


class OCRResult:
    """Outcome of a text extraction request."""

    __slots__ = ("text", "method", "available", "note")

    def __init__(self, text: str | None, method: str, available: bool, note: str = ""):
        self.text = text
        self.method = method
        self.available = available
        self.note = note

    @property
    def has_text(self) -> bool:
        return bool(self.text and self.text.strip())

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "method": self.method,
            "available": self.available,
            "note": self.note,
        }


class DocumentExtractor(ABC):
    """Interface for extracting text from document byte content."""

    def __init__(self, ocr_provider: OCRProvider | None = None):
        self.ocr_provider = ocr_provider or NoOCRProvider()

    @abstractmethod
    def extract(self, data: bytes, mime_type: str) -> OCRResult:
        """Extract text from ``data`` of the given ``mime_type``."""
