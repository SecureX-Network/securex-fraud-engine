"""Tests for V2 risk engine (evidence, recommendation, determinism)."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from src.risk.service import RiskAnalysisService, RiskContext


@pytest.fixture
def service():
    return RiskAnalysisService()


def test_no_factors_low_risk(service):
    result = service.analyze(RiskContext("credential", "c-1", {}, []))
    assert result.risk_level == "low"
    assert result.risk_score <= 0.3
    assert result.severity == "low"
    assert result.evidence == ["no contributing factors"]
    assert result.recommendation


def test_young_entity_medium(service):
    result = service.analyze(RiskContext("issuer", "i-1", {"entity_age_days": 1}, []))
    assert result.risk_level == "medium"


def test_high_signals(service):
    result = service.analyze(
        RiskContext(
            "credential",
            "c-2",
            {"entity_age_days": 100},
            [{"risk_level": "high"}, {"risk_level": "high"}, {"risk_level": "low"}],
        )
    )
    assert any(f.factor_name == "signal_analysis" for f in result.factors)


def test_historical_risk(service):
    result = service.analyze(
        RiskContext("credential", "c-3", {"historical_risk_score": 0.9}, [])
    )
    assert result.risk_level in ("high", "critical")


def test_deterministic_scoring(service):
    ctx = RiskContext("credential", "c", {"historical_risk_score": 0.5}, [{"risk_level": "high"}])
    a = service.analyze(ctx)
    b = service.analyze(ctx)
    assert a.risk_score == b.risk_score


def test_score_boundaries(service):
    assert service._get_risk_level(0.0) == "low"
    assert service._get_risk_level(0.3) == "medium"
    assert service._get_risk_level(0.6) == "high"
    assert service._get_risk_level(0.8) == "critical"
    assert service._get_risk_level(0.99) == "critical"


def test_evidence_and_recommendation(service):
    result = service.analyze(RiskContext("credential", "c", {"entity_age_days": 1}, []))
    assert result.evidence
    assert result.recommendation in ("ACCEPT - Low risk", "MONITOR - Moderate risk, monitor activity",
                                     "REVIEW - High risk, manual review recommended",
                                     "BLOCK - Immediate action required")


def test_factors_carry_evidence(service):
    result = service.analyze(RiskContext("credential", "c", {"historical_risk_score": 0.8}, []))
    assert all(hasattr(f, "evidence") for f in result.factors)
