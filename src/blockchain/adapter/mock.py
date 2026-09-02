"""Mock blockchain evidence provider for tests.

Deterministic and offline-safe. Only used in tests and dev; never used to fake
successful blockchain verification in production code.
"""

from src.blockchain.verification.provider import (
    NOT_FOUND,
    VERIFIED,
    BlockchainEvidence,
    BlockchainEvidenceProvider,
)


class MockBlockchainEvidenceProvider(BlockchainEvidenceProvider):
    """In-memory provider backed by a credential registry."""

    def __init__(self, registry: dict[str, dict] | None = None):
        # store -> {credential_id: {fingerprint, revoked, suspended, ...}}
        self.registry = registry or {}

    def set_verified(self, credential_id: str, fingerprint: str | None = None, **extra) -> None:
        self.registry[credential_id] = {"verified": True, "fingerprint": fingerprint, **extra}

    def set_revoked(self, credential_id: str, fingerprint: str | None = None) -> None:
        self.registry[credential_id] = {"verified": True, "revoked": True, "fingerprint": fingerprint}

    def set_suspended(self, credential_id: str, fingerprint: str | None = None) -> None:
        self.registry[credential_id] = {"verified": True, "suspended": True, "fingerprint": fingerprint}

    def verify_credential(
        self,
        credential_id: str,
        credential_fingerprint: str | None = None,
    ) -> BlockchainEvidence:
        record = self.registry.get(credential_id)
        if record is None or not record.get("verified"):
            return BlockchainEvidence(state=NOT_FOUND, exists=False, details="Credential not found on blockchain")

        fp = record.get("fingerprint")
        if credential_fingerprint and fp and credential_fingerprint != fp:
            return BlockchainEvidence(state=NOT_FOUND, exists=False, details="Fingerprint does not match on blockchain")

        if record.get("revoked"):
            return BlockchainEvidence(
                state="REVOKED",
                exists=True,
                credential_fingerprint=fp,
                issuance_state="issued",
                revocation_state="revoked",
                suspension_state="active",
                transaction_reference=f"tx-{credential_id}",
                block_reference=f"block-{credential_id}",
                proof_metadata={"source": "mock"},
                details="Credential revoked",
            )

        if record.get("suspended"):
            return BlockchainEvidence(
                state="SUSPENDED",
                exists=True,
                credential_fingerprint=fp,
                issuance_state="issued",
                revocation_state="active",
                suspension_state="suspended",
                transaction_reference=f"tx-{credential_id}",
                block_reference=f"block-{credential_id}",
                proof_metadata={"source": "mock"},
                details="Credential suspended",
            )

        return BlockchainEvidence(
            state=VERIFIED,
            exists=True,
            credential_fingerprint=fp,
            issuance_state="issued",
            revocation_state="active",
            suspension_state="active",
            transaction_reference=f"tx-{credential_id}",
            block_reference=f"block-{credential_id}",
            proof_metadata={"source": "mock"},
            details="Credential verified on blockchain",
        )
