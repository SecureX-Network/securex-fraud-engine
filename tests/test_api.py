"""API tests using FastAPI TestClient"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from fastapi.testclient import TestClient

from src.main import app


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


def test_health_endpoint(client):
    """Test health check endpoint."""
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "securex-fraud-engine"


def test_fraud_analyze_valid(client):
    """Test fraud analysis with valid data."""
    response = client.post("/api/v1/fraud/analyze", json={
        "credential_id": "cred-1",
        "credential_type": "degree",
        "issuer_id": "issuer-u1",
        "metadata": {"issuer_reputation": 0.9},
    })

    assert response.status_code == 200
    data = response.json()
    assert "request_id" in data
    assert "is_suspicious" in data
    assert "fraud_score" in data
    assert 0.0 <= data["fraud_score"] <= 1.0


def test_fraud_analyze_validation_error(client):
    """Test fraud analysis with missing required fields."""
    response = client.post("/api/v1/fraud/analyze", json={
        "credential_type": "degree",
    })

    assert response.status_code == 422
    assert "detail" in response.json()


def test_risk_score_valid(client):
    """Test risk scoring endpoint."""
    response = client.post("/api/v1/risk/score", json={
        "entity_type": "credential",
        "entity_id": "cred-1",
        "context": {"entity_age_days": 30},
    })

    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert "risk_level" in data
    assert data["risk_level"] in ("low", "medium", "high", "critical")


def test_fingerprint_create(client):
    """Test fingerprint creation endpoint."""
    response = client.post("/api/v1/fingerprint/create", json={
        "credential_id": "cred-1",
        "credential_data": {"name": "Test", "id": "123"},
    })

    assert response.status_code == 200
    data = response.json()
    assert "fingerprint" in data
    assert len(data["fingerprint"]) == 64


def test_fingerprint_verify_match(client):
    """Test fingerprint verification with matching data."""
    create_resp = client.post("/api/v1/fingerprint/create", json={
        "credential_id": "cred-2",
        "credential_data": {"name": "Savan", "id": "456"},
    })
    fingerprint = create_resp.json()["fingerprint"]

    verify_resp = client.post("/api/v1/fingerprint/verify", json={
        "credential_id": "cred-2",
        "credential_data": {"name": "Savan", "id": "456"},
        "expected_fingerprint": fingerprint,
    })

    assert verify_resp.status_code == 200
    assert verify_resp.json()["is_valid"] is True


def test_tampering_analyze(client):
    """Test tampering analysis endpoint."""
    response = client.post("/api/v1/tampering/analyze", json={
        "document_id": "doc-1",
        "document_type": "pdf",
        "document_hash": "abc",
        "content_hash": "def",
    })

    assert response.status_code == 200
    data = response.json()
    assert "is_tampered" in data
    assert "tampering_score" in data


def test_404_for_unknown_endpoint(client):
    """Test unknown endpoint returns 404."""
    response = client.get("/api/v1/unknown")

    assert response.status_code == 404
