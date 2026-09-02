"""Secure file handling utilities.

Provides path-traversal protection, safe temporary-file handling, upload size
validation, and a redaction helper to keep logging free of secrets/PII.
"""

import os
import tempfile
from pathlib import Path, PurePosixPath

from src.core.exceptions import DocumentValidationError


def resolve_safe_path(base_dir: str | Path, filename: str) -> Path:
    """Resolve ``filename`` under ``base_dir`` guarding against path traversal.

    Raises ``DocumentValidationError`` if the filename contains traversal or
    would resolve outside the base directory.
    """
    validate_filename(filename)
    base = Path(base_dir).resolve()
    clean = PurePosixPath(filename.replace("\\", "/")).name
    if clean != filename and ("/" in filename or "\\" in filename):
        raise DocumentValidationError(
            message="Unsafe filename",
            details={"filename": filename},
        )
    candidate = (base / clean).resolve()
    if base not in candidate.parents and candidate != base:
        raise DocumentValidationError(
            message="Unsafe filename",
            details={"filename": filename},
        )
    return candidate


def validate_filename(filename: str | None) -> None:
    """Reject filenames that attempt path traversal or contain path separators."""
    if not filename:
        return
    if filename.startswith(("/", "\\")) or ".." in Path(filename).parts:
        raise DocumentValidationError(
            message="Unsafe filename",
            details={"filename": filename},
        )
    if "/" in filename or "\\" in filename:
        raise DocumentValidationError(
            message="Unsafe filename",
            details={"filename": filename},
        )


def validate_file_size(size_bytes: int, max_bytes: int) -> None:
    """Reject files larger than ``max_bytes``."""
    if size_bytes > max_bytes:
        raise DocumentValidationError(
            message="File too large",
            details={
                "size_bytes": size_bytes,
                "max_bytes": max_bytes,
            },
        )


class SecureTempFile:
    """Context manager producing a secure named temporary file with cleanup.

    Guarantees the temporary file is removed on exit, even on error.
    """

    def __init__(self, suffix: str = "", prefix: str = "securex-"):
        self.suffix = suffix
        self.prefix = prefix
        self.path: Path | None = None

    def __enter__(self) -> Path:
        fd, name = tempfile.mkstemp(prefix=self.prefix, suffix=self.suffix)
        os.close(fd)
        self.path = Path(name)
        return self.path

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.path is not None:
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                pass


REDACTED = "[REDACTED]"

SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "secret",
    "secret_key",
    "password",
    "passwd",
    "token",
    "authorization",
    "private_key",
    "credential_data",
    "document_content",
    "file_content",
    "raw",
}


def redact(value: object, _depth: int = 0) -> object:
    """Return a deep copy of ``value`` with sensitive keys redacted.

    Used to keep structured logs free of secrets, keys, and PII.
    """
    if _depth > 20:
        return REDACTED
    if isinstance(value, dict):
        return {
            k: (REDACTED if str(k).lower() in SENSITIVE_KEYS else redact(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v, _depth + 1) for v in value]
    if isinstance(value, tuple):
        return tuple(redact(v, _depth + 1) for v in value)
    return value
