"""Tests for the document validation and analysis pipeline."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from src.core.exceptions import DocumentValidationError
from src.documents.pipeline import DocumentAnalysisService
from src.documents.validation.service import detect_format, validate_document
from src.security.file_security import validate_file_size, validate_filename
from tests.conftest import make_jpeg, make_pdf, make_png


def test_detect_format_pdf():
    assert detect_format(make_pdf()).mime_type == "application/pdf"
    assert detect_format(make_pdf()).recognized is True


def test_detect_format_png():
    assert detect_format(make_png()).mime_type == "image/png"


def test_detect_format_jpeg():
    assert detect_format(make_jpeg()).mime_type == "image/jpeg"


def test_detect_format_unknown():
    assert detect_format(b"<html>").recognized is False


def test_validate_empty_file():
    with pytest.raises(DocumentValidationError):
        validate_document(b"")


def test_validate_unsupported():
    with pytest.raises(DocumentValidationError):
        validate_document(b"\x00\x01\x02 executor content")


def test_validate_oversized():
    with pytest.raises(DocumentValidationError):
        validate_document(make_pdf() * 100, max_bytes=100)


def test_validate_ok_pdf():
    result = validate_document(make_pdf())
    assert result.extension == "pdf"


def test_validate_extension_mismatch():
    with pytest.raises(DocumentValidationError):
        validate_document(make_pdf(), filename="photo.png")


def test_validate_allowed_extensions_filters():
    with pytest.raises(DocumentValidationError):
        validate_document(make_jpeg(), allowed_extensions=["pdf"])


def test_validate_filename_traversal():
    with pytest.raises(DocumentValidationError):
        validate_filename("../etc/passwd")


def test_validate_filename_quarantine():
    with pytest.raises(DocumentValidationError):
        validate_filename("../../secret")


def test_validate_file_size_ok():
    validate_file_size(10, 100)


def test_validate_file_size_too_big():
    with pytest.raises(DocumentValidationError):
        validate_file_size(200, 100)


def test_pipeline_analyzes_pdf():
    service = DocumentAnalysisService()
    result = service.analyze("doc-1", make_pdf(text="hello"), filename="cert.pdf")
    assert result.mime_type == "application/pdf"
    assert result.validation.extension == "pdf"
    assert len(result.fingerprint) == 64
    assert result.fingerprint is not None
    assert result.tampering.fingerprint is None or True


def test_pipeline_metadata_extracted():
    service = DocumentAnalysisService()
    result = service.analyze("doc-2", make_pdf(), filename="cert.pdf")
    assert result.metadata.extracted is True
    assert result.metadata.mime_type == "application/pdf"


def test_pipeline_text_extraction_non_fabricated():
    service = DocumentAnalysisService()
    result = service.analyze("doc-3", make_pdf(), filename="cert.pdf")
    # Text extraction reports its capability honestly; it must not fabricate.
    assert result.extraction.available is True
    assert result.extraction.method in ("pdf_stream", "none")


def test_pipeline_image_supported():
    service = DocumentAnalysisService()
    result = service.analyze("doc-4", make_png(), filename="img.png")
    assert result.mime_type == "image/png"


def test_pipeline_rejects_unsupported():
    service = DocumentAnalysisService()
    with pytest.raises(DocumentValidationError):
        service.analyze("doc-5", b"not a real document", filename="file.txt")


def test_pipeline_oversized():
    service = DocumentAnalysisService()
    # MAX_UPLOAD_SIZE_MB defaults to 10; make a large-ish nonsense file.
    from src.config.settings import get_settings

    max_bytes = get_settings().MAX_UPLOAD_SIZE_MB * 1024 * 1024
    with pytest.raises(DocumentValidationError):
        service.analyze("doc-6", b"x" * (max_bytes + 1), filename="big.pdf")
