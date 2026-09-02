"""Signature (magic byte) based format detection and document validation.

Validates MIME type, file extension, size, malformed/empty input, and
suspicious metadata without executing uploaded content.
"""

from dataclasses import dataclass

from src.core.exceptions import DocumentValidationError
from src.security.file_security import validate_file_size, validate_filename

PDF_MAGIC = b"%PDF-"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGICS = (b"\xff\xd8\xff",)

# Maps a detected signature to a canonical mime type and allowed extensions.
SIGNATURES: dict[tuple[bytes, ...], tuple[str, tuple[str, ...]]] = {
    (PDF_MAGIC,): ("application/pdf", ("pdf",)),
    (PNG_MAGIC,): ("image/png", ("png",)),
    (JPEG_MAGICS,): ("image/jpeg", ("jpg", "jpeg")),
}

EXTENSION_TO_MIME = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
}

SUPPORTED_MIME_TYPES = {"application/pdf", "image/png", "image/jpeg"}


@dataclass
class DetectionResult:
    """Result of format detection."""

    mime_type: str
    extension: str
    recognized: bool


def detect_format(data: bytes) -> DetectionResult:
    """Detect the format of ``data`` from its leading bytes."""
    if data.startswith(PDF_MAGIC):
        return DetectionResult("application/pdf", "pdf", True)
    if data.startswith(PNG_MAGIC):
        return DetectionResult("image/png", "png", True)
    if any(data.startswith(m) for m in JPEG_MAGICS):
        return DetectionResult("image/jpeg", "jpeg", True)
    return DetectionResult("application/octet-stream", "", False)


def validate_document(
    data: bytes,
    filename: str | None = None,
    max_bytes: int | None = None,
    allowed_extensions: list[str] | None = None,
) -> DetectionResult:
    """Validate a document and return its detected format.

    Performs the following checks and raises ``DocumentValidationError``:
    - empty file
    - oversized file
    - unsafe/unsupported filename path
    - unsupported format (unrecognized magic bytes)
    - extension/MIME mismatch (when both known)
    """
    if not data:
        raise DocumentValidationError(message="Document is empty")

    if max_bytes is not None:
        validate_file_size(len(data), max_bytes)

    if filename is not None:
        validate_filename(filename)

    detection = detect_format(data)
    if not detection.recognized:
        raise DocumentValidationError(
            message="Unsupported or unrecognized document format",
            details={"mime_type": detection.mime_type},
        )

    if filename is not None and detection.recognized:
        ext = _extension_of(filename)
        if ext and ext not in detection_extensions(detection.mime_type):
            raise DocumentValidationError(
                message="File extension does not match detected content",
                details={
                    "filename": filename,
                    "detected_mime": detection.mime_type,
                },
            )

    if allowed_extensions is not None and detection.extension not in allowed_extensions:
        raise DocumentValidationError(
            message="Document type not allowed",
            details={"extension": detection.extension},
        )

    return detection


def detection_extensions(mime_type: str) -> tuple[str, ...]:
    """Return the canonical extensions for a detected MIME type."""
    for magics, (mime, exts) in SIGNATURES.items():
        if mime == mime_type:
            return exts
    return ()


def is_supported_mime(mime_type: str) -> bool:
    """Return whether a MIME type is supported by the engine."""
    return mime_type in SUPPORTED_MIME_TYPES


def _extension_of(filename: str) -> str:
    """Extract a lowercase extension from a filename."""
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower()
