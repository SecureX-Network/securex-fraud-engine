"""Tests for blockchain evidence integration (mock + adapter)."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


from src.blockchain.adapter.live import LiveBlockchainEvidenceProvider
from src.blockchain.adapter.mock import MockBlockchainEvidenceProvider
from src.blockchain.client.service import SecureXBlockchainClient
from src.blockchain.verification.provider import (
    NOT_CONFIGURED,
    NOT_FOUND,
    VERIFIED,
)


def test_mock_verified():
    provider = MockBlockchainEvidenceProvider()
    provider.set_verified("cred-1", "fp-1")
    evidence = provider.verify_credential("cred-1")
    assert evidence.state == VERIFIED
    assert evidence.exists is True
    assert evidence.issuance_state == "issued"


def test_mock_missing_credential():
    provider = MockBlockchainEvidenceProvider()
    evidence = provider.verify_credential("missing")
    assert evidence.state == NOT_FOUND
    assert evidence.exists is False


def test_mock_revoked():
    provider = MockBlockchainEvidenceProvider()
    provider.set_revoked("cred-2")
    evidence = provider.verify_credential("cred-2")
    assert evidence.state == "REVOKED"
    assert evidence.revocation_state == "revoked"


def test_mock_suspended():
    provider = MockBlockchainEvidenceProvider()
    provider.set_suspended("cred-3")
    evidence = provider.verify_credential("cred-3")
    assert evidence.state == "SUSPENDED"
    assert evidence.suspension_state == "suspended"


def test_mock_fingerprint_mismatch():
    provider = MockBlockchainEvidenceProvider()
    provider.set_verified("cred-4", "fp-1")
    evidence = provider.verify_credential("cred-4", credential_fingerprint="wrong")
    assert evidence.state == NOT_FOUND


def test_mock_never_fakes_success():
    # A provider with no configured data must not report VERIFIED.
    provider = MockBlockchainEvidenceProvider()
    assert provider.verify_credential("anything").state != VERIFIED


def test_unavailable_provider():
    from src.blockchain.adapter import UnavailableBlockchainProvider

    provider = UnavailableBlockchainProvider()
    evidence = provider.verify_credential("x")
    assert evidence.state == NOT_CONFIGURED


def test_live_not_configured():
    provider = LiveBlockchainEvidenceProvider(base_url=None)
    evidence = provider.verify_credential("cred")
    assert evidence.state == NOT_CONFIGURED


def test_live_parse_verified():
    provider = LiveBlockchainEvidenceProvider(client=_FakeClient({"exists": True, "status": "issued", "credential_fingerprint": "fp"}))
    evidence = provider.verify_credential("cred")
    assert evidence.state == VERIFIED


def test_live_parse_revoked():
    provider = LiveBlockchainEvidenceProvider(client=_FakeClient({"exists": True, "status": "revoked"}))
    evidence = provider.verify_credential("cred")
    assert evidence.state == "REVOKED"


def test_live_parse_not_found():
    provider = LiveBlockchainEvidenceProvider(client=_FakeClient({"exists": False}))
    evidence = provider.verify_credential("cred")
    assert evidence.state == NOT_FOUND


def test_live_malformed_response():
    provider = LiveBlockchainEvidenceProvider(client=_FakeClient("not-a-dict"))
    evidence = provider.verify_credential("cred")
    assert evidence.state == "VERIFICATION_FAILED"


def test_live_client_builds_url():
    client = SecureXBlockchainClient("http://bc.example", timeout=2)
    assert client.base_url == "http://bc.example"


class _FakeClient:
    """Stand-in for the real blockchain client returning canned responses."""

    def __init__(self, response):
        self.response = response

    def verify_credential(self, credential_id, credential_fingerprint=None):
        return self.response
