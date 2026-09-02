"""Tests for V2 tampering analysis (structure, metadata, determinism)."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from src.tampering.service import TamperingContext, TamperingDetectionService
from tests.conftest import make_pdf


@pytest.fixture
def service():
    return TamperingDetectionService()


def test_matching_fingerprint_no_tampering(service):
    ctx = TamperingContext(
        document_id="d1", document_type="pdf",
        document_hash="abc", content_hash="abc", metadata={},
    )
    result = service.analyze(ctx)
    assert result.is_tampered is False
    assert result.tampering_score == 0.0
    assert result.confidence == 0.0


def test_mismatched_fingerprint_tampering(service):
    ctx = TamperingContext(
        document_id="d2", document_type="pdf",
        document_hash="abc", content_hash="def", metadata={},
    )
    result = service.analyze(ctx)
    assert result.is_tampered is True
    types = [i.type for i in result.indicators]
    assert "hash_mismatch" in types


def test_suspicious_metadata(service):
    ctx = TamperingContext(
        document_id="d3", document_type="pdf", metadata={"modified": "today"},
    )
    result = service.analyze(ctx)
    types = [i.type for i in result.indicators]
    assert "suspicious_metadata" in types


def test_timestamp_inconsistency(service):
    ctx = TamperingContext(
        document_id="d4", document_type="pdf",
        metadata={"creation_time": "2026-01-02", "modification_time": "2026-01-01"},
    )
    result = service.analyze(ctx)
    types = [i.type for i in result.indicators]
    assert "timestamp_inconsistency" in types


def test_suspicious_author(service):
    ctx = TamperingContext(
        document_id="d5", document_type="pdf", metadata={"author": "unknown"},
    )
    result = service.analyze(ctx)
    types = [i.type for i in result.indicators]
    assert "suspicious_author_metadata" in types


def test_structural_anomaly_missing_trailer(service):
    # Valid PDF header but no trailer -> structural signal.
    data = b"%PDF-1.4\n%%EOF\n"
    ctx = TamperingContext(
        document_id="d6", document_type="pdf",
        metadata={}, document_bytes=data, mime_type="application/pdf",
    )
    result = service.analyze(ctx)
    types = [i.type for i in result.indicators]
    assert any("structure" in t or "trailer" in t or "page" in t for t in types)


def test_clean_pdf_structure(service):
    pdf = make_pdf()
    ctx = TamperingContext(
        document_id="d7", document_type="pdf",
        metadata={}, document_bytes=pdf, mime_type="application/pdf",
    )
    result = service.analyze(ctx)
    assert result.is_tampered is False


def test_content_mismatch_clean(service):
    # No content hashes supplied but a clean document -> no tampering.
    pdf = make_pdf()
    ctx = TamperingContext(
        document_id="d8", document_type="pdf", metadata={}, document_bytes=pdf,
        mime_type="application/pdf",
    )
    result = service.analyze(ctx)
    assert result.explanation  # deterministic explanation present
    assert result.confidence >= 0.0


def test_severity_aggregation(service):
    ctx = TamperingContext(
        document_id="d9", document_type="pdf",
        document_hash="a", content_hash="b", metadata={"modified": "x"},
    )
    result = service.analyze(ctx)
    assert result.severity in ("low", "medium", "high", "critical")
    assert result.severity in ("high", "critical")


def test_unusual_document_type(service):
    ctx = TamperingContext(document_id="d10", document_type="exe", metadata={})
    result = service.analyze(ctx)
    types = [i.type for i in result.indicators]
    assert "unusual_document_type" in types


def test_deterministic_same_input_same_output(service):
    a = service.analyze(TamperingContext("x", "pdf", document_hash="1", content_hash="2"))
    b = service.analyze(TamperingContext("x", "pdf", document_hash="1", content_hash="2"))
    assert a.tampering_score == b.tampering_score
    assert a.explanation == b.explanation
