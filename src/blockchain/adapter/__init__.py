"""Blockchain evidence provider factory.

Wires the provider from configuration. ``mock`` is for tests/dev only;
``live`` uses the configured ``SECUREX_BLOCKCHAIN_URL``; anything else means
the engine runs without blockchain evidence (NOT_CONFIGURED / UNAVAILABLE).
"""

from src.blockchain.adapter.live import LiveBlockchainEvidenceProvider
from src.blockchain.adapter.mock import MockBlockchainEvidenceProvider
from src.blockchain.verification.provider import BlockchainEvidenceProvider
from src.config.settings import get_settings


def build_blockchain_provider() -> BlockchainEvidenceProvider:
    """Build the evidence provider from current configuration."""
    settings = get_settings()
    mode = (settings.BLOCKCHAIN_VERIFY_MODE or "unavailable").lower()

    if mode == "mock":
        return MockBlockchainEvidenceProvider()

    if mode == "live":
        base_url = settings.SECUREX_BLOCKCHAIN_URL
        return LiveBlockchainEvidenceProvider(
            base_url=base_url,
        ) if base_url else LiveBlockchainEvidenceProvider(base_url=None)

    return UnavailableBlockchainProvider()


class UnavailableBlockchainProvider(BlockchainEvidenceProvider):
    """Provider that reports blockchain evidence as unavailable/unconfigured."""

    def verify_credential(
        self,
        credential_id: str,
        credential_fingerprint: str | None = None,
    ):
        from src.blockchain.verification.provider import (
            NOT_CONFIGURED,
            BlockchainEvidence,
        )

        return BlockchainEvidence(state=NOT_CONFIGURED, details="Blockchain integration not configured")
