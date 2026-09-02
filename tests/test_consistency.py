"""Tests for credential consistency analysis."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.credential.consistency import (
    DATE_MISMATCH,
    IDENTIFIER_MISMATCH,
    ISSUER_MISMATCH,
    MISSING_REQUIRED_FIELD,
    compare_credentials,
)


def test_matching_credentials_no_signals():
    extracted = {
        "credential_id": "ABC-123",
        "issuer_id": "issuer-u",
        "credential_type": "degree",
    }
    supplied = dict(extracted)
    assert compare_credentials(extracted, supplied) == []


def test_issuer_mismatch():
    extracted = {"issuer_id": "issuer-a"}
    supplied = {"issuer_id": "issuer-b"}
    signals = compare_credentials(extracted, supplied, required_fields=["issuer_id"])
    assert any(s.signal_type == ISSUER_MISMATCH for s in signals)


def test_identifier_mismatch():
    extracted = {"credential_id": "ABC-1"}
    supplied = {"credential_id": "ABC-2"}
    signals = compare_credentials(extracted, supplied, required_fields=["credential_id"])
    assert any(s.signal_type == IDENTIFIER_MISMATCH for s in signals)


def test_date_mismatch():
    extracted = {"issue_date": "2026-01-01"}
    supplied = {"issue_date": "2026-02-01"}
    signals = compare_credentials(extracted, supplied, required_fields=["issue_date"])
    assert any(s.signal_type == DATE_MISMATCH for s in signals)


def test_missing_required_field():
    supplied = {}
    signals = compare_credentials({}, supplied, required_fields=["issuer_id"])
    assert any(s.signal_type == MISSING_REQUIRED_FIELD for s in signals)


def test_case_insensitive_identifier_match():
    extracted = {"credential_id": "ABC-123"}
    supplied = {"credential_id": "abc-123"}
    signals = compare_credentials(extracted, supplied, required_fields=["credential_id"])
    assert signals == []


def test_issuer_mismatch_high_severity():
    extracted = {"issuer_id": "issuer-a"}
    supplied = {"issuer_id": "issuer-b"}
    signals = compare_credentials(extracted, supplied, required_fields=["issuer_id"])
    assert signals[0].severity in ("high", "critical")


def test_partial_overlap():
    # Only common fields are compared; extras ignored.
    extracted = {"credential_id": "X", "extra": "ignored"}
    supplied = {"credential_id": "X"}
    assert compare_credentials(extracted, supplied, required_fields=["credential_id"]) == []
