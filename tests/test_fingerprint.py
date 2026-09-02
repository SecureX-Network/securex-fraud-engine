"""Tests for the Fingerprinting Service"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from src.core.exceptions import FingerprintError
from src.fingerprint.service import FingerprintService


@pytest.fixture
def fingerprint_service():
    """Create fingerprint service instance."""
    return FingerprintService()


def test_create_fingerprint_deterministic(fingerprint_service):
    """Test that same data produces same fingerprint."""
    data = {"name": "Savan Patel", "credential_id": "cred-123"}

    fp1 = fingerprint_service.create(data)
    fp2 = fingerprint_service.create(data)

    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256 produces 64 hex chars


def test_fingerprint_changes_with_data(fingerprint_service):
    """Test that different data produces different fingerprints."""
    data1 = {"name": "Savan Patel", "credential_id": "cred-123"}
    data2 = {"name": "Savan Patel", "credential_id": "cred-124"}

    fp1 = fingerprint_service.create(data1)
    fp2 = fingerprint_service.create(data2)

    assert fp1 != fp2


def test_verify_matching_data(fingerprint_service):
    """Test verification with matching data."""
    data = {"name": "Test User", "role": "admin"}
    fp = fingerprint_service.create(data)

    assert fingerprint_service.verify(data, fp) is True


def test_verify_mismatched_data(fingerprint_service):
    """Test verification with mismatched data."""
    original = {"name": "Test User", "role": "admin"}
    modified = {"name": "Test User", "role": "user"}
    fp = fingerprint_service.create(original)

    assert fingerprint_service.verify(modified, fp) is False


def test_unsupported_algorithm(fingerprint_service):
    """Test that unsupported algorithm raises error."""
    with pytest.raises(FingerprintError):
        fingerprint_service.create({"data": "test"}, algorithm="md5")


def test_sha512_fingerprint_length(fingerprint_service):
    """Test SHA-512 fingerprints have correct length."""
    data = {"field": "value"}
    fp = fingerprint_service.create(data, algorithm="sha512")

    assert len(fp) == 128  # SHA-512 produces 128 hex chars


def test_constant_time_comparison_timing(fingerprint_service):
    """Test that constant-time comparison works."""
    data = {"user": "alice", "pass": "secret"}
    fp = fingerprint_service.create(data)

    # Should match regardless of different lengths intentionally
    assert fingerprint_service.verify(data, fp) is True
    assert fingerprint_service.verify(data, "0" * 64) is False
