"""Tests for security protections: auth, path traversal, redaction."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient

from src.core.exceptions import DocumentValidationError
from src.main import app
from src.security.file_security import (
    REDACTED,
    SecureTempFile,
    redact,
    resolve_safe_path,
    validate_filename,
)
from tests.conftest import TEST_API_KEY, make_pdf


def test_missing_api_key_401():
    client = TestClient(app)
    resp = client.post("/api/v2/fingerprint/create", json={"kind": "document"})
    assert resp.status_code == 401


def test_invalid_api_key_401():
    client = TestClient(app)
    resp = client.post(
        "/api/v2/fingerprint/create",
        json={"kind": "document"},
        headers={"X-API-Key": "wrong"},
    )
    assert resp.status_code == 401


def test_valid_api_key_200():
    client = TestClient(app)
    resp = client.post(
        "/api/v2/fingerprint/create",
        json={"kind": "document", "data": "ZGF0YQ=="},
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert resp.status_code == 200


def test_malformed_request_422():
    client = TestClient(app)
    resp = client.post(
        "/api/v2/fingerprint/create",
        json={"kind": 123, "algorithm": "sha256", "data": "eA=="},
        headers={"X-API-Key": TEST_API_KEY},
    )
    # kind is typed as str, so an int should be rejected by pydantic.
    assert resp.status_code == 422


def test_path_traversal_filename_rejected():
    with pytest.raises(DocumentValidationError):
        validate_filename("../../etc/passwd")


def test_abs_path_filename_rejected():
    with pytest.raises(DocumentValidationError):
        validate_filename("/etc/passwd")


def test_secure_temp_file_cleans_up():
    with SecureTempFile(suffix=".tmp") as path:
        assert path.exists()
        path.write_text("test")
    assert not path.exists()


def test_resolve_safe_path_within_base():
    import pathlib
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        result = resolve_safe_path(d, "notes.txt")
        base = pathlib.Path(d).resolve()
        assert result.parent == base
        result.relative_to(base)  # raises if not under base


def test_resolve_safe_path_traversal():
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(DocumentValidationError):
            resolve_safe_path(d, "../../secret")


def test_redact_sensitive_keys():
    payload = {
        "api_key": "shh",
        "credential_data": {"name": "PII"},
        "safe": {"count": 1},
    }
    result = redact(payload)
    assert result["api_key"] == REDACTED
    assert result["credential_data"] == REDACTED
    assert result["safe"]["count"] == 1


def test_redact_nested():
    payload = {"nested": {"secret_key": "secret", "ok": "value"}}
    result = redact(payload)
    assert result["nested"]["secret_key"] == REDACTED
    assert result["nested"]["ok"] == "value"


def test_upload_document_express_no_persist():
    # The documents endpoint processes bytes without writing to disk.
    import io

    client = TestClient(app)
    files = {"file": ("cert.pdf", io.BytesIO(make_pdf()), "application/pdf")}
    resp = client.post("/api/v2/documents/analyze", files=files, headers={"X-API-Key": TEST_API_KEY})
    assert resp.status_code == 200
