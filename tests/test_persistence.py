"""Tests for the persistence interfaces and in-memory repositories."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.persistence.factory import create_persistence
from src.persistence.models.records import (
    AnalysisRecord,
    AnalysisSubResult,
    FingerprintRecord,
)


def test_persistence_container_full():
    persistence = create_persistence()
    assert persistence.analyses is not None
    assert persistence.tampering is not None
    assert persistence.risk is not None
    assert persistence.fraud is not None
    assert persistence.fingerprints is not None
    assert persistence.audit is not None


def test_analysis_repository_save_get():
    p = create_persistence()
    rec = AnalysisRecord(analysis_id="an_1", status="completed", risk={"risk_score": 0.5})
    p.analyses.save_analysis(rec)
    got = p.analyses.get_analysis("an_1")
    assert got is not None
    assert got.risk["risk_score"] == 0.5
    assert p.analyses.get_analysis("missing") is None


def test_sub_result_repositories():
    p = create_persistence()
    p.tampering.save(AnalysisSubResult("an_1", "tampering", {"score": 0.2}))
    p.risk.save(AnalysisSubResult("an_1", "risk", {"score": 0.3}))
    p.fraud.save(AnalysisSubResult("an_1", "fraud", {"score": 0.4}))
    assert p.tampering.get("an_1").payload["score"] == 0.2
    assert p.risk.get("an_1").payload["score"] == 0.3
    assert p.fraud.get("an_1").payload["score"] == 0.4


def test_fingerprint_repository():
    p = create_persistence()
    rec = FingerprintRecord("fp_1", "document", "sha256", "abcd")
    p.fingerprints.save(rec)
    got = p.fingerprints.get("fp_1")
    assert got is not None
    assert got.fingerprint == "abcd"
    assert got.kind == "document"


def test_audit_repository():
    p = create_persistence()
    p.audit.record("auth.login", None, "analysis", "an_1", "success", {"k": 1})
    # In-memory audit repo stores events for later inspection.
    assert len(p.audit._events) == 1


def test_analysis_record_does_not_store_pii_required():
    # Records only carry analysis data, not full credential contents.
    rec = AnalysisRecord("an_2", "completed", risk={}, fraud={}, tampering={}, fingerprint={})
    assert "credential_data" not in rec.risk
    assert "credential_data" not in rec.fraud
    assert rec.analysis_id == "an_2"
