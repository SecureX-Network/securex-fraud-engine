"""Tests for the Tampering Detection Service"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest

from src.tampering.service import TamperingContext, TamperingDetectionService


@pytest.fixture
def tampering_service():
    """Create tampering detection service instance."""
    return TamperingDetectionService()


def test_hash_match_no_tampering(tampering_service):
    """Test that matching hashes indicate no tampering."""
    context = TamperingContext(
        document_id="doc-1",
        document_type="pdf",
        document_hash="abc123",
        metadata={},
        content_hash="abc123",
    )

    result = tampering_service.analyze(context)

    assert result.is_tampered is False
    assert result.tampering_score == 0.0
    assert result.recommendation.startswith("ACCEPT")


def test_hash_mismatch_detected(tampering_service):
    """Test that hash mismatch indicates tampering."""
    context = TamperingContext(
        document_id="doc-2",
        document_type="pdf",
        document_hash="originalhash",
        metadata={},
        content_hash="modifiedhash",
    )

    result = tampering_service.analyze(context)

    assert result.is_tampered is True
    assert any(i.type == "hash_mismatch" for i in result.indicators)


def test_suspicious_metadata_detected(tampering_service):
    """Test that suspicious metadata is flagged."""
    context = TamperingContext(
        document_id="doc-3",
        document_type="pdf",
        metadata={"modified": "today", "author": "unknown"},
    )

    result = tampering_service.analyze(context)

    assert result.is_tampered is True
    assert any(i.type == "suspicious_metadata" for i in result.indicators)


def test_unusual_document_type(tampering_service):
    """Test that unusual document types produce an indicator."""
    context = TamperingContext(
        document_id="doc-4",
        document_type="exe",
        metadata={},
    )

    result = tampering_service.analyze(context)

    assert any(i.type == "unusual_document_type" for i in result.indicators)
    assert result.tampering_score > 0.0


def test_empty_hashes_low_score(tampering_service):
    """Test that no hashes provided results in low score."""
    context = TamperingContext(
        document_id="doc-5",
        document_type="pdf",
        metadata={},
    )

    result = tampering_service.analyze(context)

    assert result.is_tampered is False
    assert result.tampering_score == 0.0
