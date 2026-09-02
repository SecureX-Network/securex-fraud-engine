"""OCR provider abstraction.

Provider-specific logic stays isolated behind this interface. Real OCR is a
PLANNED capability; when a provider (e.g. Tesseract) is available it can be
wired in here without affecting the rest of the engine. When none is
configured, extraction reports OCR as unavailable and never fabricates text.
"""

from abc import ABC, abstractmethod


class OCRProvider(ABC):
    """Interface for an OCR engine that converts images to text."""

    name: str = "base"

    @abstractmethod
    def available(self) -> bool:
        """Return whether this provider can run in the current environment."""

    @abstractmethod
    def extract_text(self, image_bytes: bytes) -> str | None:
        """Return OCR text for an image, or None on failure/unsupported."""
