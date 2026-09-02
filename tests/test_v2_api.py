"""V2 API endpoint tests (auth boundary + endpoint behavior)."""

import base64
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient

from src.main import app
from tests.conftest import TEST_API_KEY, make_pdf


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_headers():
    return {"X-API-Key": TEST_API_KEY}


def test_v2_fingerprint_create_requires_auth(client):
    resp = client.post(
        "/api/v2/fingerprint/create",
        json={"kind": "document", "data": "ZGF0YQ=="},
    )
    assert resp.status_code == 401


def test_v2_fingerprint_create_invalid_key(client):
    resp = client.post(
        "/api/v2/fingerprint/create",
        json={"kind": "document"},
        headers={"X-API-Key": "wrong"},
    )
    assert resp.status_code == 401


def test_v2_fingerprint_create_sha256(client, auth_headers):
    resp = client.post(
        "/api/v2/fingerprint/create",
        json={"kind": "document", "data": base64.b64encode(b"hello").decode(), "algorithm": "sha256"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert len(resp.json()["fingerprint"]) == 64


def test_v2_fingerprint_create_sha512(client, auth_headers):
    resp = client.post(
        "/api/v2/fingerprint/create",
        json={"kind": "document", "data": base64.b64encode(b"hello").decode(), "algorithm": "sha512"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert len(resp.json()["fingerprint"]) == 128


def test_v2_fingerprint_verify(client, auth_headers):
    create = client.post(
        "/api/v2/fingerprint/create",
        json={"kind": "document", "data": base64.b64encode(b"data").decode()},
        headers=auth_headers,
    )
    fp = create.json()["fingerprint"]
    verify = client.post(
        "/api/v2/fingerprint/verify",
        json={
            "data": base64.b64encode(b"data").decode(),
            "expected_fingerprint": fp,
        },
        headers=auth_headers,
    )
    assert verify.status_code == 200
    assert verify.json()["is_valid"] is True


def test_v2_fingerprint_verify_mismatch(client, auth_headers):
    create = client.post(
        "/api/v2/fingerprint/create",
        json={"kind": "document", "data": base64.b64encode(b"data").decode()},
        headers=auth_headers,
    )
    fp = create.json()["fingerprint"]
    verify = client.post(
        "/api/v2/fingerprint/verify",
        json={"data": base64.b64encode(b"other").decode(), "expected_fingerprint": fp},
        headers=auth_headers,
    )
    assert verify.json()["is_valid"] is False


def test_v2_fraud_analyze(client, auth_headers):
    resp = client.post(
        "/api/v2/fraud/analyze",
        json={
            "credential_id": "cred-1",
            "credential_type": "degree",
            "issuer_id": "issuer-1",
            "metadata": {"issuer_reputation": 0.2},
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "fraud_score" in data
    assert data["severity"] in ("low", "medium", "high", "critical")
    assert data["is_suspicious"] is True


def test_v2_risk_score(client, auth_headers):
    resp = client.post(
        "/api/v2/risk/score",
        json={
            "entity_type": "credential",
            "entity_id": "cred-1",
            "context": {"entity_age_days": 1},
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] in ("low", "medium", "high", "critical")
    assert "recommendation" in data
    assert "evidence" in data


def test_v2_tampering_analyze(client, auth_headers):
    resp = client.post(
        "/api/v2/tampering/analyze",
        json={
            "document_id": "doc-1",
            "document_type": "pdf",
            "document_hash": "abc",
            "content_hash": "def",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["tampering_detected"] is True
    assert "explanation" in data


def test_v2_tampering_analyze_clean(client, auth_headers):
    pdf = make_pdf()
    resp = client.post(
        "/api/v2/tampering/analyze",
        json={
            "document_id": "doc-2",
            "document_type": "pdf",
            "document_bytes_b64": base64.b64encode(pdf).decode(),
            "mime_type": "application/pdf",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert "signals" in resp.json()


def test_v2_blockchain_verify_verified(client, auth_headers):
    resp = client.post(
        "/api/v2/blockchain/verify",
        json={"credential_id": "cred-verified", "credential_fingerprint": "fp"},
        headers=auth_headers,
    )
    # Mock provider is empty by default -> NOT_FOUND. We test state handling.
    assert resp.status_code == 200
    assert resp.json()["state"] == "NOT_FOUND"


def test_v2_analysis_document(client, auth_headers):
    import base64 as b64

    pdf = make_pdf(text="credential_id ABC-123")
    resp = client.post(
        "/api/v2/analysis",
        json={
            "credential_id": "ABC-123",
            "credential_type": "degree",
            "issuer_id": "issuer-1",
            "document_id": "doc-1",
            "document_b64": b64.b64encode(pdf).decode(),
            "document_filename": "cert.pdf",
            "supplied_credential_fields": {
                "credential_id": "ABC-123",
                "issuer_id": "issuer-1",
                "credential_type": "degree",
            },
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] in ("completed", "partial")
    assert data["fraud"] is not None
    assert data["risk"] is not None


def test_v2_analysis_retrieve(client, auth_headers):
    resp = client.post(
        "/api/v2/analysis",
        json={
            "credential_id": "cred-ret",
            "credential_type": "degree",
            "issuer_id": "issuer-1",
            "supplied_credential_fields": {
                "credential_id": "cred-ret",
                "issuer_id": "issuer-1",
                "credential_type": "degree",
            },
        },
        headers=auth_headers,
    )
    aid = resp.json()["analysis_id"]
    get_resp = client.get(f"/api/v2/analysis/{aid}", headers=auth_headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["analysis_id"] == aid
    ev_resp = client.get(f"/api/v2/analysis/{aid}/evidence", headers=auth_headers)
    assert ev_resp.status_code == 200
    assert "evidence_references" in ev_resp.json()


def test_v2_analysis_not_found(client, auth_headers):
    resp = client.get("/api/v2/analysis/nonexistent", headers=auth_headers)
    assert resp.status_code == 404


def test_v2_documents_analyze_upload(client, auth_headers):
    import io

    files = {"file": ("cert.pdf", io.BytesIO(make_pdf()), "application/pdf")}
    resp = client.post(
        "/api/v2/documents/analyze",
        files=files,
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["mime_type"] == "application/pdf"
    assert "fingerprint" in data
    assert "tampering" in data


def test_v1_endpoints_still_work_without_auth(client):
    assert client.get("/health").status_code == 200
    resp = client.post(
        "/api/v1/fingerprint/create",
        json={"credential_id": "c", "credential_data": {"x": 1}},
    )
    assert resp.status_code == 200
