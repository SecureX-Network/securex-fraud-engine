"""A no-op OCR provider used when no real OCR engine is installed.

This is the default. It never fabricates extracted text and reports itself
unavailable, so callers can distinguish "OCR planned/unavailable" from actual
extracted content.
"""

from src.documents.ocr.provider import OCRProvider


class NoOCRProvider(OCRProvider):
    """Placeholder provider that reports OCR as unavailable."""

    name = "none"

    def available(self) -> bool:
        return False

    def extract_text(self, image_bytes: bytes) -> str | None:
        return None
