"""Tests for V2 fingerprinting extensions."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from src.core.exceptions import FingerprintError
from src.fingerprint.service import FingerprintService
from tests.conftest import make_pdf


@pytest.fixture
def service():
    return FingerprintService()


def test_fingerprint_bytes_sha256(service):
    fp = service.fingerprint_bytes(b"hello", "sha256")
    assert len(fp) == 64


def test_fingerprint_bytes_sha384(service):
    fp = service.fingerprint_bytes(b"hello", "sha384")
    assert len(fp) == 96


def test_fingerprint_bytes_sha512(service):
    fp = service.fingerprint_bytes(b"hello", "sha512")
    assert len(fp) == 128


def test_fingerprint_bytes_deterministic(service):
    assert service.fingerprint_bytes(b"data") == service.fingerprint_bytes(b"data")


def test_fingerprint_bytes_differ_for_different_input(service):
    assert service.fingerprint_bytes(b"a") != service.fingerprint_bytes(b"b")


def test_fingerprint_data_structured(service):

    a = service.fingerprint_data({"b": 2, "a": 1})
    b = service.fingerprint_data({"a": 1, "b": 2})
    assert a == b


def test_fingerprint_normalized(service):
    fp = service.fingerprint_normalized(b"abc", content_type="application/pdf")
    assert len(fp) == 64
    assert fp == service.fingerprint_normalized(b"abc", content_type="application/pdf")


def test_verify_bytes_match(service):
    fp = service.fingerprint_bytes(b"hello")
    assert service.verify_bytes(b"hello", fp) is True


def test_verify_bytes_mismatch(service):
    fp = service.fingerprint_bytes(b"hello")
    assert service.verify_bytes(b"world", fp) is False


def test_verify_normalized_match(service):
    fp = service.fingerprint_normalized(b"abc", content_type="image/png")
    assert service.verify_normalized(b"abc", fp, content_type="image/png") is True


def test_constant_time_comparison_path(service):
    # Verified through the public API exercising hmac.compare_digest path.
    fp = service.fingerprint_bytes(b"x")
    assert service.verify_bytes(b"x", fp) is True
    assert service.verify_bytes(b"y", fp) is False


def test_unsupported_algorithm_raises(service):
    with pytest.raises(FingerprintError):
        service.fingerprint_bytes(b"x", "md5")


def test_v1_api_preserved(service):
    # V1 create/verify still work.
    fp = service.create({"role": "admin"})
    assert service.verify({"role": "admin"}, fp) is True
    assert service.verify({"role": "user"}, fp) is False


def test_document_fingerprint_with_pdf(service):
    pdf = make_pdf()
    fp = service.fingerprint_bytes(pdf)
    assert len(fp) == 64
    assert fp == service.fingerprint_bytes(pdf)
