"""Tests for the Fraud Detection Service"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest

from src.fraud.service import FraudContext, FraudDetectionService


@pytest.fixture
def fraud_service():
    """Create fraud detection service instance."""
    return FraudDetectionService()


def test_no_signals_returns_low_score(fraud_service):
    """Test that valid credential returns low fraud score."""
    context = FraudContext(
        credential_id="cred-test-1",
        credential_type="education",
        issuer_id="issuer-university",
        metadata={"issuer_reputation": 0.9},
        fingerprints=["fingerprint1"],
        verification_history=[],
    )

    result = fraud_service.analyze(context)

    assert result.is_suspicious is False
    assert result.fraud_score == 0.0
    assert result.recommendation == "PASS - Low fraud risk"


def test_low_issuer_reputation_flagged(fraud_service):
    """Test that low issuer reputation is a fraud signal."""
    context = FraudContext(
        credential_id="cred-test-2",
        credential_type="passport",
        issuer_id="issuer-government",
        metadata={"issuer_reputation": 0.1},
        fingerprints=[],
        verification_history=[],
    )

    result = fraud_service.analyze(context)

    assert result.is_suspicious is True
    assert result.fraud_score > 0.0
    signal_types = [s.type for s in result.signals]
    assert "low_issuer_reputation" in signal_types


def test_duplicate_fingerprints_critical(fraud_service):
    """Test that duplicate fingerprints trigger critical signal."""
    context = FraudContext(
        credential_id="cred-test-3",
        credential_type="certificate",
        issuer_id="issuer-org",
        metadata={},
        fingerprints=["same-fingerprint", "same-fingerprint", "another"],
        verification_history=[],
    )

    result = fraud_service.analyze(context)

    assert result.is_suspicious is True
    signal_types = [s.type for s in result.signals]
    assert "duplicate_fingerprints" in signal_types


def test_issuer_mismatch_detected(fraud_service):
    """Test that issuer mismatch is detected."""
    context = FraudContext(
        credential_id="cred-test-4",
        credential_type="degree",
        issuer_id="issuer-university",
        metadata={
            "expected_issuer": "university-aa",
            "actual_issuer": "university-bb",
            "issuer_reputation": 0.8,
        },
        fingerprints=[],
        verification_history=[],
    )

    result = fraud_service.analyze(context)

    assert result.is_suspicious is True
    signal_types = [s.type for s in result.signals]
    assert "issuer_mismatch" in signal_types


def test_high_verification_failure_rate(fraud_service):
    """Test that high verification failure rate is flagged."""
    context = FraudContext(
        credential_id="cred-test-5",
        credential_type="license",
        issuer_id="issuer-gov",
        metadata={},
        fingerprints=[],
        verification_history=[
            {"success": False} for _ in range(15)  # All failures
        ],
    )

    result = fraud_service.analyze(context)

    signal_types = [s.type for s in result.signals]
    assert "high_verification_failure" in signal_types
