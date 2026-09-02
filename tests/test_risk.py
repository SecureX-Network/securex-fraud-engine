"""Tests for the Risk Analysis Service"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from src.risk.service import RiskAnalysisService, RiskContext


@pytest.fixture
def risk_service():
    """Create risk analysis service instance."""
    return RiskAnalysisService()


def test_no_factors_returns_low_risk(risk_service):
    """Test that no factors results in default low risk."""
    context = RiskContext(
        entity_type="credential",
        entity_id="cred-1",
        context={},
        signals=[],
    )

    result = risk_service.analyze(context)

    assert result.risk_level == "low"
    assert result.risk_score <= 0.3


def test_young_entity_is_risky(risk_service):
    """Test that young entities get higher risk."""
    context = RiskContext(
        entity_type="issuer",
        entity_id="issuer-1",
        context={"entity_age_days": 2},
        signals=[],
    )

    result = risk_service.analyze(context)

    assert result.risk_level == "medium"
    assert result.risk_score >= 0.2


def test_high_signals_increase_risk(risk_service):
    """Test that high-risk signals increase score."""
    context = RiskContext(
        entity_type="credential",
        entity_id="cred-2",
        context={"entity_age_days": 100},
        signals=[
            {"risk_level": "high"},
            {"risk_level": "high"},
            {"risk_level": "low"},
        ],
    )

    result = risk_service.analyze(context)

    assert result.risk_score > 0.1
    assert any(f.factor_name == "signal_analysis" for f in result.factors)


def test_historical_risk_contributes(risk_service):
    """Test that historical risk contributes to score."""
    context = RiskContext(
        entity_type="credential",
        entity_id="cred-3",
        context={"historical_risk_score": 0.9},
        signals=[],
    )

    result = risk_service.analyze(context)

    assert result.risk_level in ("high", "critical")
    assert result.risk_score >= 0.3


def test_risk_score_range(risk_service):
    """Test that risk score is always in valid range."""
    for i in range(20):
        context = RiskContext(
            entity_type="credential",
            entity_id=f"cred-{i}",
            context={"historical_risk_score": i / 20, "entity_age_days": i},
            signals=[{"risk_level": "high"}] if i % 2 == 0 else [],
        )

        result = risk_service.analyze(context)

        assert 0.0 <= result.risk_score <= 1.0
        assert result.risk_level in ("low", "medium", "high", "critical")
