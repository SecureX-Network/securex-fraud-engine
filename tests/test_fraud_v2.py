"""Tests for V2 fraud engine (unified multi-signal aggregation)."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.fraud.service import FraudContext, FraudDetectionService


def service():
    return FraudDetectionService()


def test_v1_no_signals_low():
    result = service().analyze(
        FraudContext("c-1", "degree", "issuer-1", metadata={"issuer_reputation": 0.9})
    )
    assert result.is_suspicious is False
    assert result.fraud_score == 0.0


def test_issuer_mismatch_flag():
    result = service().analyze(
        FraudContext(
            "c-1",
            "degree",
            "issuer-1",
            metadata={"expected_issuer": "a", "actual_issuer": "b"},
        )
    )
    types = [s.type for s in result.signals]
    assert "issuer_mismatch" in types


def test_duplicate_fingerprints():
    result = service().analyze(
        FraudContext("c-1", "cert", "issuer-1", fingerprints=["fp", "fp"])
    )
    types = [s.type for s in result.signals]
    assert "duplicate_fingerprints" in types


def test_suspicious_verification_behavior():
    result = service().analyze(
        FraudContext(
            "c-1",
            "license",
            "issuer-1",
            verification_history=[{"success": False}] * 15,
        )
    )
    types = [s.type for s in result.signals]
    assert "high_verification_failure" in types


def test_multiple_signals_severity_aggregation():
    result = service().analyze_unified(
        FraudContext(
            "c-1",
            "degree",
            "issuer-1",
            metadata={"expected_issuer": "a", "actual_issuer": "b"},
        ),
        tampering_signals=["hash_mismatch"],
    )
    assert result.is_suspicious is True
    assert result.severity in ("high", "critical")
    types = {s.type for s in result.signals}
    assert "issuer_mismatch" in types
    assert "document_tampering" in types


def test_blockchain_evidence_signal():
    result = service().analyze_unified(
        FraudContext("c-1", "degree", "issuer-1"),
        blockchain_state="REVOKED",
    )
    types = [s.type for s in result.signals]
    assert "blockchain_evidence_mismatch" in types


def test_clean_deterministic():
    a = service().analyze_unified(FraudContext("c-1", "d", "i"))
    b = service().analyze_unified(FraudContext("c-1", "d", "i"))
    assert a.fraud_score == b.fraud_score
    assert a.fraud_score == 0.0


def test_document_signals_feed_fraud():
    from src.fraud.service import FraudSignal

    result = service().analyze_unified(
        FraudContext("c-1", "degree", "issuer-1"),
        document_signals=[FraudSignal(type="issuer_mismatch", confidence=0.9, severity="high")],
    )
    assert result.is_suspicious is True
